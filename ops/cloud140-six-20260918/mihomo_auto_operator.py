"""Main-owned explicit operator CLI. No publish/deploy/host edits.

Windows: preview|prepare|apply|finish|status|rollback --release <12hex>
Apply additionally requires --allow-publication AFTER other subscription gates.
Preview is read-only: secret raw subscription -> RAM -> isolated local core.
Prepare only writes a root-private snapshot. Main archives published code first.
Panel local export is private stdout for the parent SSH pipe, never user output.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

import mihomo_auto as m

STATE = Path('/root/hamvpn-mihomo-auto-20260918/state')
TIMER = 'hamvpn-mihomo-auto-rollback'
ROOT = Path(__file__).resolve().parent


class Store(m.ProtectedStore):
    """Reuse the already-reviewed protected/hash-checked snapshot store."""
    def __init__(self):
        import preflight as p
        self.delegate = p.Store(STATE)
        self.lock_path = Path('/run/lock/hamvpn-mihomo-auto.lock')
    def read(self, name):
        return self.delegate.get(name) if self.delegate.exists(name) else None
    def save(self, name, data): self.delegate.put(name, data)


class Timer:
    def __init__(self, runner=subprocess.run): self.runner = runner
    def run(self, args, checked=True):
        r = self.runner(args, capture_output=True, text=True, timeout=20)
        if checked: m.require(r.returncode == 0, 'Independent timer command failed')
        return r
    def command(self, sha):
        m.require(re.fullmatch(r'[a-f0-9]{64}', sha), 'Invalid timer ownership hash')
        script = str(ROOT / 'mihomo_auto_operator.py')
        m.require(re.fullmatch(r'/opt/hamvpn-cloud140-six/releases/[a-f0-9]{12}/ops/cloud140-six-20260918/mihomo_auto_operator.py', script), 'Timer requires published release path')
        return ['/usr/bin/python3', '-B', script, 'local', 'rollback', '--owned-sha', sha]
    def arm(self, sha):
        m.require(self.status(sha)['all_inactive'], 'Rollback timer/service not quiescent; inspect ownership')
        self.run(['systemd-run', '--quiet', '--unit='+TIMER, '--on-active=20m', *self.command(sha)])
        state = self.status(sha)
        m.require(state['timer_state'] == 'active' and state['service_state'] == 'inactive' and
                  not state['service_job'], 'Independent timer did not arm cleanly')
    def status(self, sha):
        def show(unit, properties):
            r = self.run(['systemctl', 'show', TIMER+unit, '--property='+properties], False)
            fields = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
            m.require(fields.get('LoadState') in ('loaded', 'not-found') and
                      fields.get('ActiveState') in ('active', 'inactive', 'activating', 'deactivating', 'failed', 'reloading'), 'Unknown rollback unit state')
            return fields
        timer = show('.timer', 'LoadState,ActiveState,Unit,NextElapseUSecMonotonic,Job')
        service = show('.service', 'LoadState,ActiveState,SubState,ExecStart,MainPID,Job,Result')
        command = self.command(sha)
        if service.get('LoadState') == 'loaded':
            m.require(('argv[]='+' '.join(command)+' ;') in service.get('ExecStart', ''), 'Rollback service command/owner differs')
        if timer.get('ActiveState') == 'active':
            m.require(timer.get('Unit') == TIMER+'.service' and service.get('LoadState') == 'loaded' and
                      timer.get('NextElapseUSecMonotonic') not in ('', '0', None), 'Rollback deadline/owner not armed')
        job = lambda fields: fields.get('Job', '') not in ('', '0')
        return dict(timer_state=timer['ActiveState'], service_state=service['ActiveState'],
                    service_substate=service.get('SubState'), service_result=service.get('Result'),
                    timer_job=job(timer), service_job=job(service), service_pid=int(service.get('MainPID', '0')),
                    all_inactive=timer['ActiveState'] == service['ActiveState'] == 'inactive' and
                    not job(timer) and not job(service))
    def active(self, sha):
        return not self.status(sha)['all_inactive']
    def is_current_rollback(self, sha):
        state = self.status(sha)
        return (state['service_pid'] == os.getpid() and state['service_state'] in ('active', 'activating')
                and state['timer_state'] == 'inactive' and not state['timer_job'])
    def cancelled(self, sha):
        # Own rollback cannot become inactive until this process returns. Do not
        # lie that it is inactive: caller returns service-exiting and polls status.
        return self.status(sha)['all_inactive'] or self.is_current_rollback(sha)
    def disarm(self, sha):
        state = self.status(sha)  # verify BOTH unit owners before stopping either
        if state['timer_state'] != 'inactive' or state['timer_job']:
            self.run(['systemctl', 'stop', TIMER+'.timer'])
        if (state['service_state'] != 'inactive' or state['service_job']) and state['service_pid'] != os.getpid():
            self.run(['systemctl', 'stop', TIMER+'.service'])
        # Failed units are never reported inactive or silently reset/reused.
        m.require(self.cancelled(sha), 'Rollback timer/service cancellation incomplete')


def client():
    import preflight as p
    return p.load_file('mihomo_auto_api', p.ROOT.parent/'selfsteal-us3'/'panel_api.py').create_client()[0]


def context(api, plan=None):
    hosts = api('GET', '/api/hosts/')
    if plan:
        recipient = next(h for h in hosts if h['uuid'] == plan['recipient_uuid'])
    else:
        found = [h for h in hosts if h['remark'] == '⚡ Автовыбор Серверов' and not h['isDisabled']]
        m.require(len(found) == 1, 'Auto recipient changed')
        recipient = found[0]
    return hosts, api('GET', '/api/subscription-templates/' + recipient['xrayJsonTemplateUuid'])


def gather(api, headers, plan=None, published=False):
    import preflight as p
    import frontend_stage as f
    import yaml
    # fetch_subscription validates exact existing-device header names/values.
    user = p.probe_user(api, p.Store())
    sub = api('GET', '/api/subscriptions/by-uuid/'+user['uuid'])
    fresh = f.fetch_subscription(sub['subscriptionUrl'], headers, 'mihomo')
    happ = f.fetch_subscription(sub['subscriptionUrl'], headers, 'happ')
    catalog, ht = context(api, plan)
    if plan is None:
        candidates = [t for t in api('GET', '/api/subscription-templates')['templates']
                      if t['templateType'] == 'MIHOMO' and t['name'] == 'Default']
        m.require(len(candidates) == 1, 'Mihomo default template ambiguous')
        record = api('GET', '/api/subscription-templates/'+candidates[0]['uuid'])
        recipient = next(h for h in catalog if h['xrayJsonTemplateUuid'] == ht['uuid'] and h['remark'] == '⚡ Автовыбор Серверов')
        plan = m.build_plan(record, yaml.safe_load(base64.b64decode(record['encodedTemplateYaml'])), catalog, recipient['uuid'], ht)
    else:
        m.require(m.catalog_scope(catalog) == plan['catalog'] and m.digest(ht) == plan['happ_template_sha256'], 'Catalog/Happ drift')
        m.require(api('GET', m.PATCH+plan['before']['uuid']) == plan['after' if published else 'before'], 'Template drift')
    rawpath = '/api/subscriptions/by-short-uuid/'+user['shortUuid']+'/raw?withDisabledHosts=false'
    original = urllib.request.Request
    def with_headers(*args, **kwargs):
        request = original(*args, **kwargs)
        if rawpath in request.full_url:
            for key, value in {**headers, 'User-Agent': 'mihomo/1.19.29'}.items(): request.add_header(key, value)
        return request
    # Single-threaded private process, no logging or tokens in command arguments.
    urllib.request.Request = with_headers
    try: raw = api('GET', rawpath)
    finally: urllib.request.Request = original
    m.require(raw['convertedUserInfo']['hwidCheckup'] is None or raw['convertedUserInfo']['hwidCheckup']['subscriptionAllowed'], 'Owned device subscription not allowed')
    native = m.native_preview(plan, raw['resolvedProxyConfigs'])
    preview = m.validate_preview(plan, native, fresh, happ, published=published)
    return plan, preview, native['candidate']


def local(action, payload, owned_sha=None, allow=False):
    api = client()
    if action == 'export':
        # No private state directory creation during read-only preview.
        plan = Store().read('plan') if STATE.exists() else None
        plan, preview, candidate = gather(api, payload['headers'], plan, payload.get('phase') == 'public')
        return dict(plan_sha256=plan['sha256'], preview=preview, candidate=candidate,
                    phase=payload.get('phase', 'candidate'))
    store = Store()
    if action == 'prepare':
        plan, _, _ = gather(api, payload['headers'])
    else:
        plan = store.read('plan'); m.require(plan, 'Prepare snapshot first')
    m.require(m.digest({k:v for k,v in plan.items() if k != 'sha256'}) == plan['sha256'], 'Snapshot hash mismatch')
    if owned_sha: m.require(owned_sha == plan['sha256'], 'Rollback owner changed')
    tx = m.Transaction(api, store, Timer(), lambda: context(api, plan))
    if action == 'prepare': return tx.prepare(plan)
    if action == 'status':
        status = tx.timer.status(plan['sha256'])
        return dict(prepared=True, applied=bool(store.read('apply-intent')), finished=bool(store.read('finished')),
                    rolled_back=bool(store.read('rolled-back')), rollback_units=status,
                    current_is_candidate=tx.current(plan) == plan['after'])
    if action == 'rollback': return tx.rollback()
    if action in ('apply', 'finish'):
        m.require(action != 'apply' or allow, 'Explicit publication flag required')
        _, preview, _ = gather(api, payload['headers'], plan, action == 'finish')
        m.require(preview == payload['preview'], 'Fresh output changed since local measurement')
        return getattr(tx, action)(preview, payload['proof'])
    raise ValueError('Unsupported action')


def remote_command(release, action, secret=False, allow=False):
    m.require(re.fullmatch(r'[a-f0-9]{12}', release), 'Exact published release required')
    m.require(action in ('export', 'prepare', 'apply', 'finish', 'status', 'rollback'), 'Invalid action')
    return ('python3 -B /opt/hamvpn-cloud140-six/releases/'+release+'/ops/cloud140-six-20260918/mihomo_auto_operator.py local '+action
            + (' --secret-stdout' if secret else '') + (' --allow-publication' if allow else ''))


def control(action, release, allow=False):
    import operator_session as o
    def call(name, payload=None, secret=False):
        return json.loads(o.transport.remote('panel', remote_command(release, name, secret, allow),
                          None if payload is None else m.encoded(payload)))
    if action in ('status', 'rollback'): return call(action)
    headers = json.loads(subprocess.check_output(['node', '-e',
        "process.stdout.write(JSON.stringify(require('./ops/pc-outage-20260918/subscription_readback.cjs').deviceHeaders()))"], timeout=20))
    if action == 'prepare': return call('prepare', {'headers': headers})
    m.require(action != 'apply' or allow, 'Explicit publication flag required')
    data = call('export', dict(headers=headers, phase='public' if action == 'finish' else 'candidate'), True)
    data['binaries'] = dict(mihomo='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe', curl='C:/Windows/System32/curl.exe')
    r = subprocess.run(['node', str(ROOT/'mihomo_auto_measure.cjs')], input=m.encoded(data), capture_output=True, timeout=180)
    m.require(r.returncode == 0, 'Actual group measurement failed')
    proof = json.loads(r.stdout)
    m.validate_measurement({'sha256': data['plan_sha256'], 'main_group': data['candidate']['proxy-groups'][0]['name']}, data['preview'], proof, data['phase'], time.time())
    print(json.dumps({'measurement': proof}, ensure_ascii=False), flush=True)
    if action == 'preview': return {'read_only_preview_passed': True, 'pool_count': len(data['preview']['pool_names'])}
    remote_now = float(o.transport.remote('panel', "python3 -c 'import time;print(time.time())'"))
    ahead = proof['timestamp']-remote_now
    m.require(ahead <= 45, 'Local/panel clock skew exceeds bound')
    if ahead > 0: time.sleep(ahead+1)  # bounded <46s, never rewrite measured timestamps
    return call(action, dict(headers=headers, preview=data['preview'], proof=proof))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('control', 'local'))
    parser.add_argument('action', choices=('preview', 'export', 'prepare', 'apply', 'finish', 'status', 'rollback'))
    parser.add_argument('--release'); parser.add_argument('--owned-sha')
    parser.add_argument('--secret-stdout', action='store_true'); parser.add_argument('--allow-publication', action='store_true')
    args = parser.parse_args()
    if args.mode == 'local':
        m.require(os.name == 'posix' and os.geteuid() == 0, 'Panel root required')
        m.require(args.action != 'export' or (args.secret_stdout and not sys.stdout.isatty()), 'Private export requires explicit pipe')
        payload = {} if args.action in ('status', 'rollback') else json.load(sys.stdin)
        result = local(args.action, payload, args.owned_sha, args.allow_publication)
    else:
        m.require(args.release and args.action != 'export', 'Published release required')
        result = control(args.action, args.release, args.allow_publication)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    try: main()
    except Exception:
        print('Mihomo auto operator stopped safely; private details suppressed', file=sys.stderr)
        sys.exit(1)
