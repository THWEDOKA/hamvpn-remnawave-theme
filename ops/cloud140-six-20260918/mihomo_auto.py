"""Template-only Mihomo auto-pool prototype; no CLI, credentials or deployment.

Main owns publication and execution. Backend contract inspected: Remnawave
2.8.1, https://github.com/remnawave/backend. Installed generateConfig supports
includeHiddenHosts but NOT Xray injectHosts. User rights are applied before it.
Use native installed generators for previews, never reconstruct client wires.

API: build_plan(record, parsed_yaml, catalog, recipient_uuid, happ_template),
native_preview(plan, authorized_resolved_hosts), validate_preview(...), then
Transaction with a PROTECTED store and an INDEPENDENT verified timer adapter.
No user/host/profile mutation; Happ and other subscription formats untouched.
The old placeholder must remain a uniquely named, unselected proxy because a
template cannot suppress one generated proxy. The new group has a PC suffix.
"""
import base64
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time

AUTO = '⚡ Автовыбор Серверов · ПК'
TAG = 'AUTO_BASE_POOL'
PATCH = '/api/subscription-templates/'


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def wire(value, key='name'):
    return {k: v for k, v in value.items() if k != key}


def exact_regex(names):
    # RE2-compatible literal escaping (Python re.escape adds invalid RE2 \ escapes).
    require(names and len(names) == len(set(names)), 'Empty or ambiguous literal names')
    escaped = [re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', n) for n in names]
    require(all(isinstance(n, str) and n and '\n' not in n and '```' not in n for n in names), 'Unsupported name')
    return '^(' + '|'.join(escaped) + ')$'


def catalog_scope(catalog):
    # Endpoint changes from the main route rollout are intentionally NOT locked.
    # The exact per-user wires are independently refreshed for every proof.
    keys = ('uuid', 'remark', 'tags', 'isHidden', 'isDisabled', 'excludeFromSubscriptionTypes')
    return sorted(({k: h.get(k) for k in keys} for h in catalog), key=lambda h: h['uuid'])


def build_plan(record, template, catalog, recipient_uuid, happ_template):
    require(record['templateType'] == 'MIHOMO', 'Mihomo template only')
    require(not template.get('proxies') and not template.get('proxy-providers'), 'Static proxy/provider template requires separate review')
    require(not template.get('remnawave'), 'Existing template extensions require separate review')
    groups = template.get('proxy-groups')
    require(isinstance(groups, list) and len(groups) == 1, 'Expected reviewed single selector')
    original = groups[0]
    require(set(original) <= {'name', 'type', 'proxies'} and original.get('type') == 'select'
            and not original.get('proxies'), 'Custom selector requires separate review')
    require(template.get('rules') == ['MATCH,' + original['name']], 'Custom routing requires separate review')
    require(happ_template['templateType'] == 'XRAY_JSON', 'Expected Xray auto template')
    injector = happ_template['templateJson'].get('remnawave')
    require(injector == {'injectHosts': [{'selector': {'type': 'tagRegex', 'pattern': '^AUTO_BASE_POOL$'},
            'tagPrefix': 'basepool', 'selectFrom': 'ALL'}]}, 'Auto injector changed')
    recipients = [h for h in catalog if h['uuid'] == recipient_uuid]
    require(len(recipients) == 1, 'Recipient missing/ambiguous')
    recipient = recipients[0]
    require(not recipient['isDisabled'] and not recipient['isHidden'] and
            recipient.get('xrayJsonTemplateUuid') == happ_template['uuid'], 'Recipient contract changed')
    enabled = [h for h in catalog if not h['isDisabled']]
    require(len({h['remark'] for h in enabled}) == len(enabled), 'Duplicate remarks require separate review')
    require(not any('{' in h['remark'] or '}' in h['remark'] for h in enabled), 'Templated remarks require separate review')
    require(AUTO not in {h['remark'] for h in catalog} | {original['name']}, 'PC group name collision')
    pool = [h['remark'] for h in enabled if TAG in h.get('tags', []) and h['uuid'] != recipient_uuid]
    require(pool and recipient['remark'] not in pool, 'Empty/self-containing pool')
    # Refuse a missing Mihomo member instead of silently shrinking the Happ pool.
    require(all('MIHOMO' not in h.get('excludeFromSubscriptionTypes', []) for h in enabled
                if TAG in h.get('tags', [])), 'Pool member excludes Mihomo')
    hidden = [h['remark'] for h in enabled if h['isHidden']]
    after = deepcopy(template)
    after['remnawave'] = {'includeHiddenHosts': True}
    after['proxy-groups'] = [
        {'name': original['name'], 'type': 'select', 'proxies': [AUTO],
         'remnawave': {'include-proxies': False}, 'include-all-proxies': True,
         'exclude-filter': exact_regex(hidden + [recipient['remark']])},
        {'name': AUTO, 'type': 'url-test', 'proxies': [], 'remnawave': {'include-proxies': False},
         'include-all-proxies': True, 'filter': exact_regex(pool),
         'url': 'https://www.gstatic.com/generate_204', 'expected-status': 204,
         'interval': 300, 'timeout': 15000, 'tolerance': 100, 'lazy': True,
         'empty-fallback': 'REJECT'}]
    candidate = deepcopy(record)
    # JSON is YAML 1.2; no external serializer, secrets or static credentials.
    candidate['encodedTemplateYaml'] = base64.b64encode(encoded(after)).decode()
    plan = dict(before=deepcopy(record), after=candidate, template=after,
                baseline_template=deepcopy(template), catalog=catalog_scope(catalog),
                happ_template_sha256=digest(happ_template), recipient_uuid=recipient_uuid,
                recipient_name=recipient['remark'], main_group=original['name'],
                pool_names=pool, hidden_names=hidden)
    plan['sha256'] = digest(plan)
    return plan


# Code runs in a separate Node process with payload on stdin only. It imports
# installed public generators, not a Nest application or caches/DB writers.
NATIVE_PREVIEW_JS = r'''
const fs=require('fs'),yaml=require('yaml');
const {MihomoGeneratorService}=require('/opt/app/dist/src/modules/subscription-template/generators/mihomo.generator.service.js');
const {XrayJsonGeneratorService}=require('/opt/app/dist/src/modules/subscription-template/generators/xray-json.generator.service.js');
(async()=>{
 const p=JSON.parse(fs.readFileSync(0,'utf8'));
 const render=async t=>yaml.parse(await new MihomoGeneratorService({getCachedTemplateByType:async()=>structuredClone(t)}).generateConfig(structuredClone(p.hosts),false,false));
 const all=structuredClone(p.baseline);all.remnawave={includeHiddenHosts:true};
 const m=new MihomoGeneratorService({}),x=new XrayJsonGeneratorService({});
 const pairs=p.hosts.filter(h=>!h.metadata.excludeFromSubscriptionTypes.includes('MIHOMO')).map(h=>({
   name:h.finalRemark,id:h.metadata.uuid,hidden:h.metadata.isHidden,tags:h.metadata.tags,
   disabled:h.metadata.isDisabled,proxy:m.buildProxyNode(h,false),outbound:x.buildOutbound(h,'proof')}));
 process.stdout.write(JSON.stringify({baseline:await render(p.baseline),candidate:await render(p.candidate),all_native:await render(all),pairs}));
})().catch(()=>{process.stderr.write('Native preview failed (private input suppressed)');process.exitCode=1;});
'''


def native_preview(plan, authorized_resolved_hosts, container='remnawave'):
    require(container == 'remnawave', 'Reviewed installed generator required')
    payload = dict(hosts=authorized_resolved_hosts, baseline=plan['baseline_template'], candidate=plan['template'])
    r = subprocess.run(['docker', 'exec', '-i', container, 'node', '-e', NATIVE_PREVIEW_JS],
                       input=encoded(payload), capture_output=True, timeout=30)
    require(r.returncode == 0, 'Installed generator preview failed')
    return json.loads(r.stdout)


def by_name(proxies):
    require(isinstance(proxies, list) and all(isinstance(p, dict) and p.get('name') for p in proxies), 'Invalid proxy list')
    require(len({p['name'] for p in proxies}) == len(proxies), 'Duplicate generated names')
    return {p['name']: p for p in proxies}


def group_members(group, proxies):
    """Expected native core resolution; actual controller readback also required."""
    require(group.get('include-all-proxies') is True, 'Dynamic membership missing')
    members = [n for n in proxies if not group.get('filter') or re.search(group['filter'], n)]
    members = [n for n in members if not group.get('exclude-filter') or not re.search(group['exclude-filter'], n)]
    return set(group.get('proxies', [])) | set(members)


def validate_preview(plan, native, fresh_mihomo, fresh_happ, *, published=False):
    """RAM-only actual generated output, ALL fields compared, no unknown skips."""
    before, candidate, all_native = (native[k] for k in ('baseline', 'candidate', 'all_native'))
    require((candidate if published else before) == fresh_mihomo, 'Public output differs from installed generator; overrides/drift')
    old = by_name(before['proxies']); new = by_name(candidate['proxies'])
    require(candidate['proxies'] == all_native['proxies'], 'Generator wires changed')
    require(all(new.get(n) == p for n, p in old.items()), 'Ordinary client wire changed')
    require({k: v for k, v in before.items() if k not in ('proxies', 'proxy-groups')} ==
            {k: v for k, v in candidate.items() if k not in ('proxies', 'proxy-groups')}, 'Unrelated config changed')
    require(len(candidate['proxy-groups']) == 2, 'Unexpected groups')
    main, auto = candidate['proxy-groups']
    expected_groups = deepcopy(plan['template']['proxy-groups'])
    for g in expected_groups:
        g.pop('remnawave')
    require(candidate['proxy-groups'] == expected_groups, 'Group definition drift')
    pool_pairs = [p for p in native['pairs'] if TAG in p['tags'] and p['id'] != plan['recipient_uuid']]
    require(pool_pairs and all(not p['disabled'] and p['proxy'] is not None for p in pool_pairs), 'Unsupported/disabled pool member')
    expected_pool = {p['name'] for p in pool_pairs}
    require(group_members(auto, new) == expected_pool, 'Pool not exactly user-authorized Happ members')
    require(group_members(main, new) == (set(old) - {plan['recipient_name']}) | {AUTO}, 'Manual selector changed legitimate visibility')
    require(all(new[p['name']] == p['proxy'] for p in pool_pairs), 'Native hidden wire mismatch')
    happ = [c for c in fresh_happ if c.get('remarks') == plan['recipient_name']]
    require(len(happ) == 1, 'Actual Happ auto missing/ambiguous')
    balances = happ[0].get('routing', {}).get('balancers', [])
    require(len(balances) == 1 and balances[0].get('selector') == ['basepool'], 'Happ balance selector changed')
    actual = [o for o in happ[0].get('outbounds', []) if o.get('tag', '').startswith('basepool')]
    require(Counter(digest(wire(o, 'tag')) for o in actual) ==
            Counter(digest(wire(p['outbound'], 'tag')) for p in pool_pairs), 'Actual Happ pool wire mismatch')
    # Never report secret configs. This digest binds ALL generated fields.
    return dict(plan_sha256=plan['sha256'], generated_sha256=digest(candidate),
                baseline_sha256=digest(before), happ_sha256=digest(fresh_happ),
                pool_names=sorted(expected_pool), main_names=sorted(group_members(main, new)),
                pool_wire_sha256={p['name']: digest(wire(p['proxy'])) for p in pool_pairs},
                ordinary_wire_sha256={n: digest(wire(p)) for n, p in old.items()},
                published=published, passed=True)


def validate_measurement(plan, preview, proof, phase, now):
    require(proof.get('phase') == phase and proof.get('plan_sha256') == plan['sha256'] and
            proof.get('generated_sha256') == preview['generated_sha256'], 'Wrong measured candidate')
    require(0 <= now - proof.get('timestamp', 0) <= 300, 'Stale/future measurement; use source clock')
    require(proof.get('config_test_exit_code') == 0 and proof.get('client_version') and proof.get('test_id'), 'Actual installed core proof required')
    require(proof.get('cleanup') == {'process': True, 'listener': True, 'directory': True}, 'Probe cleanup incomplete')
    groups = proof.get('groups', {})
    require(groups.get(AUTO, {}).get('type') == 'URLTest' and
            set(groups[AUTO].get('all', [])) == set(preview['pool_names']), 'Actual core auto membership wrong')
    require(set(groups.get(plan['main_group'], {}).get('all', [])) == set(preview['main_names']) and
            groups[plan['main_group']].get('now') == AUTO, 'Actual main selector must select auto group')
    attempts = proof.get('attempts', [])
    require(len(attempts) >= 2 and len({a.get('test_id') for a in attempts}) == len(attempts), 'Two distinct actual traffic measurements required')
    for a in attempts:
        require(a.get('http') == 204 and a.get('egress_http') == 200 and a.get('curl_exit_codes') == [0, 0], 'Traffic did not pass')
        require(a.get('selected_member') in preview['pool_names'] and
                a.get('selected_wire_sha256') == preview['pool_wire_sha256'][a['selected_member']], 'Selected pool wire not proven')
        require(a.get('selection_stable') is True, 'Auto selection changed during measured request pair')
        ipaddress.ip_address(a.get('egress_ip', ''))
    return True


class ProtectedStore:
    """Linux root-only state; main supplies a dedicated absolute subdirectory.

    Immutable numbered events, fsync before API calls; global template flock.
    A separate systemd rollback process uses this same store/lock. The module
    deliberately has no deployment CLI or automatic API client construction.
    """
    def __init__(self, path, lock_path='/run/lock/hamvpn-mihomo-auto.lock'):
        self.path, self.lock_path = Path(path), Path(lock_path)
        require(os.name == 'posix' and os.geteuid() == 0, 'Production store requires Linux root')
        require(self.path.is_absolute() and len(self.path.parts) >= 4, 'Dedicated absolute state directory required')
        require(not self.path.is_symlink(), 'Symlink state rejected')
        self.path.mkdir(mode=0o700, parents=False, exist_ok=True)
        require(self.path.stat().st_uid == 0 and self.path.stat().st_mode & 0o077 == 0, 'Unprotected state directory')

    @contextmanager
    def locked(self):
        import fcntl
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def read(self, name):
        require(re.fullmatch(r'[a-z0-9-]+', name), 'Invalid state name')
        p = self.path / (name + '.json')
        if not p.exists():
            return None
        require(not p.is_symlink() and p.stat().st_uid == 0 and p.stat().st_mode & 0o077 == 0, 'Unprotected snapshot')
        return json.loads(p.read_bytes())

    def save(self, name, data):
        require(re.fullmatch(r'[a-z0-9-]+', name), 'Invalid state name')
        fd = os.open(self.path / (name + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(encoded(data)); f.flush(); os.fsync(f.fileno())
        fd = os.open(self.path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Transaction:
    """Template PATCH only, no POST/new identities. Callback boundaries:

    timer.arm(plan_sha), timer.active(plan_sha), timer.disarm(plan_sha) MUST
    manage/verify an independent rollback service, not in-process threading.
    context() returns (catalog, happ_template) freshly via read-only API.
    proof is validated actual generator/controller/traffic output, not booleans.
    Main must call validate_preview again on real public output before finish.
    """
    def __init__(self, api, store, timer, context, clock=time.time):
        self.api, self.store, self.timer, self.context, self.clock = api, store, timer, context, clock

    def current(self, plan):
        return self.api('GET', PATCH + plan['before']['uuid'])

    def guard(self, plan):
        catalog, happ = self.context()
        require(catalog_scope(catalog) == plan['catalog'] and digest(happ) == plan['happ_template_sha256'], 'Relevant catalog/Happ changed; rebuild fresh plan')

    def prepare(self, plan):
        with self.store.locked():
            require(self.store.read('plan') is None, 'Existing transaction; inspect, never replace snapshot')
            require(digest({k: v for k, v in plan.items() if k != 'sha256'}) == plan['sha256'], 'Invalid plan hash')
            self.guard(plan)
            require(self.current(plan) == plan['before'], 'Template changed before snapshot')
            self.store.save('plan', plan)
        return {'prepared': True, 'plan_sha256': plan['sha256']}

    def apply(self, preview, proof):
        with self.store.locked():
            plan = self.store.read('plan'); require(plan, 'Protected snapshot required')
            require(not self.store.read('finished') and not self.store.read('rolled-back'), 'Transaction terminal')
            self.guard(plan)
            require(preview.get('passed') is True and preview.get('plan_sha256') == plan['sha256'] and
                    preview.get('published') is False, 'Validated candidate preview required')
            validate_measurement(plan, preview, proof, 'candidate', self.clock())
            current = self.current(plan)
            if current == plan['after']:
                require(self.store.read('apply-intent') and self.timer.active(plan['sha256']), 'Unowned/unprotected candidate')
                return {'applied': True, 'readback_recovery': True}
            require(current == plan['before'], 'Template concurrent drift')
            require(not self.store.read('apply-intent'), 'Uncertain previous PATCH; do not blindly retry')
            self.timer.arm(plan['sha256'])
            require(self.timer.active(plan['sha256']), 'Independent rollback not verified')
            self.store.save('apply-intent', dict(timestamp=self.clock(), preview=preview, proof=proof))
            # Fresh check after timer/snapshot. PATCH only one field; not name/type.
            require(self.current(plan) == plan['before'], 'Template changed immediately before PATCH')
            try:
                self.api('PATCH', PATCH, {'uuid': plan['before']['uuid'], 'encodedTemplateYaml': plan['after']['encodedTemplateYaml']})
            except Exception:
                # Lost response is resolved by exact readback; never blind retry.
                require(self.current(plan) == plan['after'], 'Uncertain PATCH; rollback remains armed')
            require(self.current(plan) == plan['after'], 'PATCH exact readback failed')
            self.store.save('applied', {'timestamp': self.clock(), 'sha256': digest(plan['after'])})
            return {'applied': True, 'rollback_armed': True}

    def finish(self, preview, proof):
        with self.store.locked():
            plan = self.store.read('plan'); intent = self.store.read('apply-intent')
            require(plan and intent and not self.store.read('rolled-back') and not self.store.read('finished'), 'No active transaction')
            self.guard(plan)
            require(self.timer.active(plan['sha256']) and self.current(plan) == plan['after'], 'Current candidate/timer drift')
            require(preview.get('passed') is True and preview.get('plan_sha256') == plan['sha256'] and
                    preview.get('published') is True, 'Fresh public validation required')
            require(preview['happ_sha256'] == intent['preview']['happ_sha256'], 'Happ changed during publication')
            require(preview['ordinary_wire_sha256'] == intent['preview']['ordinary_wire_sha256'], 'Ordinary wires changed during publication')
            validate_measurement(plan, preview, proof, 'public', self.clock())
            require(proof['timestamp'] >= intent['timestamp'] and proof['test_id'] != intent['proof']['test_id'], 'Fresh post-publication measurement required')
            self.store.save('finish-proof', {'timestamp': self.clock(), 'preview': preview, 'proof': proof})
            # Persist terminal decision before disarm: a queued rollback obtains
            # the same lock and sees this marker, including after process crash.
            self.store.save('finished', {'timestamp': self.clock()})
            self.timer.disarm(plan['sha256'])
            require(not self.timer.active(plan['sha256']), 'Finish recorded; timer disarm needs operator retry')
            return {'finished': True}

    def rollback(self):
        with self.store.locked():
            plan = self.store.read('plan'); require(plan, 'Missing rollback snapshot')
            if self.store.read('finished'):
                return {'skipped_finished': True}
            if self.store.read('rolled-back'):
                return {'rolled_back': True}
            current = self.current(plan)
            if current == plan['after']:
                require(self.store.read('apply-intent'), 'Candidate not owned')
                try:
                    self.api('PATCH', PATCH, {'uuid': plan['before']['uuid'], 'encodedTemplateYaml': plan['before']['encodedTemplateYaml']})
                except Exception:
                    require(self.current(plan) == plan['before'], 'Uncertain rollback; inspect')
            else:
                require(current == plan['before'], 'Rollback refuses concurrent template changes')
            require(self.current(plan) == plan['before'], 'Rollback exact readback failed')
            self.store.save('rolled-back', {'timestamp': self.clock()})
            self.timer.disarm(plan['sha256'])
            if hasattr(self.timer, 'is_current_rollback') and self.timer.is_current_rollback(plan['sha256']):
                return {'rolled_back': True, 'rollback_service_exiting': True, 'verify_inactive_via_status': True}
            require(not self.timer.active(plan['sha256']), 'Rollback timer remains active')
            return {'rolled_back': True}
