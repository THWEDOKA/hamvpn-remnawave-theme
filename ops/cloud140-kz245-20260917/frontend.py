"""DE245-only frontend lifecycle; secrets are exported ONLY by export-* actions.

Panel sequence (core de245 must be prepared/tested/staged first):
 prepare, export-config -> node_check installed --id entry -> accept-installed;
 accept-tls, arm (10 min); core arm/activate-exit (25 min); export-backend ->
 node_check backend -> accept-backend; stage; export-public -> node_check public
 -> accept-public; publish; export-subscription -> node_check public ->
 accept-subscription; accept-renewal; finish. No KZ record/credential is needed.

Installed and traffic proofs use node_check.py unchanged. Traffic acceptors
require the exact IDs of their saved request, not merely all_passed. All proofs
have candidate sha256/timestamp, are <=1800s old and never future dated.
TLS proof tests: [{id:'de245-local-tls', passed:true, sni:<domain>,
 address:'127.0.0.1', port:9443, tls:'TLSv1.3', alpn:'h2', chain_verified:true}].
Renewal proof tests: [{id:'de245-renewal', passed:true, domain:<domain>,
 dry_run:true, performed_at:<actual renewal time, <=24h>},
 {id:'de245-renewal-health', passed:true, domain:<domain>, nginx_test:true,
 cert_valid:true, deploy_hook:true, timer_enabled:true, timer_active:true,
 tls:'TLSv1.3', alpn:'h2'}]. Its envelope timestamp is the actual fresh health
check (<=1800s), never a relabeling of an old dry-run timestamp.
These are external actual-test attestations; this code never manufactures them.

Both rollback handlers serialize on coordinator's lock. Frontend rollback
preflights all resources, restores hosts/entry/own grants FIRST, then invokes
core rollback. Original profiles, other hosts and KZ are never written.
"""

import argparse
import base64
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import coordinator as c
import preflight as p
import route_model as model

ID = 'de245'
FRONT_TIMER = 'ham-cloud140-de245-frontend-rollback'
CUSTOMERS = {'WHITE', 'BASE', 'OLD', 'site'}
AUTO_REMARK = '\u26a1 \u0410\u0432\u0442\u043e\u0432\u044b\u0431\u043e\u0440 \u0421\u0435\u0440\u0432\u0435\u0440\u043e\u0432'
HOST_FIELDS = ('nodes', 'inbound', 'address', 'port', 'sni', 'host')
PHASES = ('installed', 'tls', 'backend', 'public', 'subscription', 'renewal')
PROBE_IDS = {
    'backend': {'de245-backend'},
    'public': {'de245-public-chrome', 'de245-public-firefox', 'de245-host-main',
               'de245-host-auto', 'de245-legacy-reality', 'de245-legacy-tls'},
    'subscription': {'de245-sub-main', 'de245-sub-auto'},
}
require = c.require


class Store(c.RootStore):
    def __init__(self, root=p.STATE):
        super().__init__(root)
        self.directory = self.root / 'frontend-de245'


class Timers(c.SystemdTimer):
    @staticmethod
    def name(route_id=ID):
        require(route_id == ID, 'Frontend timer is DE245-only')
        return FRONT_TIMER

    def start(self, route_id=ID):
        name = self.name(route_id)
        for suffix in ('.timer', '.service'):
            state = self.state(name + suffix, allow_missing=True)
            require(state.get('LoadState') == 'not-found' and state.get('ActiveState') == 'inactive',
                    'Frontend rollback unit exists; no blind replacement')
        result = self.run(['systemd-run', '--unit=' + name, '--on-active=10m',
                          '--timer-property=AccuracySec=1s', '--property=UMask=0077',
                          'python3', str(Path(__file__).resolve()), 'rollback'],
                         capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Frontend timer creation uncertain; reconcile')
        self.armed(ID)

    def stop(self, name):
        require(name in (FRONT_TIMER, c.SystemdTimer.name(ID)), 'Unowned timer')
        result = self.run(['systemctl', 'stop', name + '.timer'], capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Timer stop failed')

    def inactive(self, name):
        require(name in (FRONT_TIMER, c.SystemdTimer.name(ID)), 'Unowned timer')
        for suffix in ('.timer', '.service'):
            state = self.state(name + suffix, allow_missing=True)
            require(state.get('ActiveState') == 'inactive' and state.get('SubState') == 'dead'
                    and state.get('LoadState') in ('loaded', 'not-found')
                    and state.get('Result', 'success') in ('', 'success'), 'Rollback service failed or changed')

    def service_idle(self, name):
        require(name in (FRONT_TIMER, c.SystemdTimer.name(ID)), 'Unowned timer')
        state = self.state(name + '.service', allow_missing=True)
        require(state.get('ActiveState') == 'inactive' and state.get('SubState') == 'dead'
                and state.get('LoadState') in ('loaded', 'not-found')
                and state.get('Result', 'success') in ('', 'success'), 'Rollback service failed')


def identity():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    key = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return dict(privateKey=base64.urlsafe_b64encode(key).decode().rstrip('='), shortIds=[secrets.token_hex(8)])


def fresh(proof, digest, now, earliest=0):
    require(isinstance(proof, dict) and proof.get('sha256') == digest, 'Proof candidate digest mismatch')
    stamp = proof.get('timestamp')
    require(type(stamp) in (int, float) and math.isfinite(stamp)
            and earliest <= stamp <= now and now - stamp <= 1800, 'Proof is stale or future dated')
    tests = proof.get('tests')
    require(isinstance(tests, list) and tests and all(isinstance(test, dict) and test.get('passed') is True for test in tests),
            'Proof needs nonempty successful actual tests')
    return tests


def traffic_proof(proof, request, digest, now, earliest):
    tests = fresh(proof, digest, now, earliest)
    expected = {item['id']: item['ip'] for item in request['items']}
    require(expected and len(tests) == len(expected) and {test.get('id') for test in tests} == set(expected),
            'Traffic proof IDs must exactly cover the exported request')
    require(proof.get('all_passed') is True and all(
        test.get('http') == '204' and test.get('exit_ip') == expected[test['id']]
        and test.get('curl_codes') == [0, 0]
        and all(type(code) is int for code in test['curl_codes']) for test in tests),
        'Traffic proof failed HTTP, egress or curl checks')


def client(address, port, user, security, settings, fingerprint='chrome'):
    stream = dict(network='raw', security=security)
    if security == 'reality':
        stream['realitySettings'] = dict(serverName=settings['serverNames'][0], fingerprint=fingerprint,
                                        publicKey=p.public_key(settings['privateKey']), shortId=settings['shortIds'][0])
    else:
        require(security == 'tls', 'Unexpected client security')
        stream['tlsSettings'] = dict(serverName=settings['serverName'], fingerprint=fingerprint,
                                     alpn=['h2', 'http/1.1'], allowInsecure=False)
    return dict(protocol='vless', settings=dict(vnext=[dict(address=address, port=port, users=[dict(
        id=user, encryption='none', flow='xtls-rprx-vision')])]), streamSettings=stream)


def read_probe_intent(store):
    path = store.root / 'test-intent.json'
    store._check()
    store.secure(path)
    require(not (store.root / 'test-cleanup.json').exists(), 'Technical probe was already cleaned up')
    return json.loads(path.read_bytes())


def fetch_happ(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password,
            'Subscription URL must use authenticated HTTPS transport')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise c.SafetyError('Subscription redirect requires review')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={
        'User-Agent': 'Happ/5.7.0', 'X-Hwid': 'ham-cloud140-de245-probe',
        'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with opener.open(request, timeout=30) as response:
        require(response.status == 200, 'Subscription HTTP failure')
        result = json.load(response)
    require(isinstance(result, list) and all(isinstance(item, dict) for item in result), 'Unexpected Happ subscription format')
    return result


class Frontend:
    def __init__(self, api, store, core, timers, clock=time.time, key_factory=identity,
                 probe_intent=None, subscription_fetch=fetch_happ):
        self.api, self.store, self.core, self.timers, self.clock = api, store, core, timers, clock
        self.key_factory, self.subscription_fetch = key_factory, subscription_fetch
        self.probe_intent = probe_intent or (lambda: read_probe_intent(core.store))

    def _save(self, record): self.store.save('state', record)

    def _load(self):
        record = self.store.read('state')
        before, digest = self.store.before()
        core = self.core._load(ID)
        require(record['snapshot_sha256'] == digest and record['core_sha256'] == core['sha256'], 'Frontend snapshot/core changed')
        require(record['profile'] == c.binding(next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID))['profile'],
                'Entry profile identity mismatch')
        expected = model.build_entry_config(before['profiles'][record['profile']]['config'], {ID: record['identity']},
                                           {ID: core['service_uuid']}, route_ids=[ID])
        require(record['candidate'] == expected and c.checksum(expected) == record['sha256'], 'Frontend candidate integrity failure')
        return record, before, core

    def _customers(self, before, core):
        node = c.target(ID)
        original = [s for s in before['squads'] if node['inbound'] in c.ids(s['inbounds']) and s['name'] in CUSTOMERS]
        require(len(original) == 4 and {s['name'] for s in original} == CUSTOMERS, 'Four original customer squads required')
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        indexed = {s['uuid']: s for s in squads}
        selected = {}
        for old in original:
            current = indexed[old['uuid']]
            require(current['name'] == old['name'] and node['inbound'] in c.ids(current['inbounds'])
                    and current['uuid'] != core['objects']['squad'], 'Customer squad identity/access changed')
            selected[current['uuid']] = current
        # No service/backend squad is ever selected, even if it has old access.
        return selected, squads

    def _core_guard(self, record, before, core, active=False):
        node = c.target(ID)
        require('staged' in core and ('rolled_back' not in core or 'rollback_intent' in record), 'Core is not staged/live')
        for target in p.NODES:  # Read-only preservation; never requires a KZ core record.
            old = before['profiles'][target['profile']]
            actual = self.api('GET', '/api/config-profiles/' + target['profile'])
            require(actual['config'] == old['config'] and c.metadata(actual) == c.metadata(old), 'Original exit profile changed')
        self.core._validate_profile(core, self.api('GET', '/api/config-profiles/' + core['objects']['profile']))
        self.core._squad_check(core, self.api('GET', '/api/internal-squads/' + core['objects']['squad']))
        self.core._user_check(core, self.api('GET', '/api/users/' + core['objects']['user']))
        nodes = self.api('GET', '/api/nodes/')
        actual = next(n for n in nodes if n['uuid'] == node['node'])
        original = next(n for n in before['nodes'] if n['uuid'] == node['node'])
        require(all(actual.get(k) == original.get(k) for k in ('address', 'name', 'port', 'isDisabled'))
                and actual['address'] == node['ip'] and not actual['isDisabled'], 'Exit node identity changed')
        allowed = [c.binding(original)]
        if 'activation_intent' in core and 'rolled_back' not in core:
            allowed.append(core['desired_binding'])
        require(c.binding(actual) in allowed, 'Unexpected exit binding')
        require({n['uuid'] for n in nodes if c.binding(n)['profile'] == core['objects']['profile']} <= {node['node']},
                'Exit clone has an unexpected consumer')
        if active:
            require('activated' in core and c.binding(actual) == core['desired_binding'] and actual['isConnected'],
                    'DE245 backend clone is not active and connected')
            self.core._resources(core)
        return nodes

    def _scope(self, record, before, core, mixed=False, live=False, published=False):
        nodes = self._core_guard(record, before, core, active=live)
        original = next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID)
        entry = next(n for n in nodes if n['uuid'] == p.ENTRY_ID)
        require(all(entry.get(k) == original.get(k) for k in ('address', 'name', 'port', 'isDisabled'))
                and entry['address'] == p.ENTRY and not entry['isDisabled'], 'Entry identity changed')
        require({n['uuid'] for n in nodes if c.binding(n)['profile'] == record['profile']} == {p.ENTRY_ID},
                'Entry profile has another consumer')
        old_profile = before['profiles'][record['profile']]
        profile = self.api('GET', '/api/config-profiles/' + record['profile'])
        allowed_configs = [record['candidate']] if live else [old_profile['config']]
        if mixed and not live and 'apply_intent' in record: allowed_configs = [old_profile['config'], record['candidate']]
        require(profile['config'] in allowed_configs, 'Entry configuration drift')
        old_meta, now_meta = c.metadata(old_profile), c.metadata(profile)
        require(all(now_meta.get(tag) == value for tag, value in old_meta.items()), 'Legacy entry metadata changed')
        if profile['config'] == record['candidate']:
            require(set(now_meta) == set(old_meta) | {model.route_tags(ID)['front']}, 'Unexpected entry inbound metadata')
            front = now_meta[model.route_tags(ID)['front']]
            if 'front' in record: require(record['front'] == front, 'Frontend metadata changed')
        else:
            require(now_meta == old_meta, 'Old entry metadata mismatch')
            front = record.get('front')
        original_binding = c.binding(original)
        new_binding = dict(profile=record['profile'], inbounds=sorted(original_binding['inbounds'] + ([front] if front else [])))
        allowed_bindings = [new_binding] if live else [original_binding]
        if mixed and not live and 'apply_intent' in record: allowed_bindings = [original_binding, new_binding]
        require(c.binding(entry) in allowed_bindings, 'Unexpected entry active inbounds')
        if live: require(entry['isConnected'], 'Entry node not connected')
        hosts = {h['uuid']: h for h in self.api('GET', '/api/hosts/')}
        selected = set(c.target(ID)['hosts'])
        for host in hosts.values():
            if host['uuid'] not in selected:
                require(not (host.get('inbound', {}).get('configProfileUuid') == record['profile']
                             and host.get('inbound', {}).get('configProfileInboundUuid') == front), 'Foreign host uses our frontend')
            require(host.get('inbound', {}).get('configProfileUuid') != core['objects']['profile'], 'Host uses backend clone')
        for old in record['hosts']:
            desired = self._desired({**record, 'front': front}, old) if front else old
            permitted = [desired] if published else [old]
            if mixed and 'publish_intent' in record: permitted = [old, desired]
            require(c.stable_host(hosts[old['uuid']]) in [c.stable_host(h) for h in permitted], 'Selected host drift')
        return profile, front, entry

    def _desired(self, record, old):
        node = c.target(ID)
        value = deepcopy(old)
        value.update(nodes=[p.ENTRY_ID], inbound=dict(configProfileUuid=record['profile'], configProfileInboundUuid=record['front']),
                     address=p.ENTRY, port=node['port'], sni=node['domain'], host=node['domain'])
        return value

    def prepare(self):
        if self.store.exists('state'):
            record, before, core = self._load()
            require('rolled_back' not in record and 'finished' not in record, 'Frontend operation is closed')
            self._scope(record, before, core, mixed=True)
            return dict(candidate_ready=True, sha256=record['sha256'])
        before, digest = self.store.before()
        core = self.core._load(ID)
        require('staged' in core and 'rolled_back' not in core, 'Stage DE245 backend core first')
        entry = next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID)
        profile_id = c.binding(entry)['profile']
        profile = before['profiles'][profile_id]
        require(len(profile['config']['inbounds']) == len(c.binding(entry)['inbounds']) == 4, 'Expected four entry legacy inbounds')
        key = self.key_factory()
        config = model.build_entry_config(profile['config'], {ID: key}, {ID: core['service_uuid']}, route_ids=[ID])
        hosts = [h for h in before['hosts'] if h['uuid'] in c.target(ID)['hosts']]
        require(len(hosts) == 2 and sum(h['isHidden'] for h in hosts) == 1, 'One main and one auto host required')
        for host in hosts:
            require(set(HOST_FIELDS) <= set(host) and host['nodes'] == [c.target(ID)['node']] and not host['isDisabled']
                    and host['inbound'] == dict(configProfileUuid=c.target(ID)['profile'], configProfileInboundUuid=c.target(ID)['inbound']),
                    'Original host scope mismatch')
        record = dict(snapshot_sha256=digest, core_sha256=core['sha256'], profile=profile_id,
                      candidate=config, sha256=c.checksum(config), identity=key, hosts=deepcopy(hosts),
                      proofs={}, requests={}, grants={}, prepared=self.clock())
        self._scope(record, before, core)
        self._customers(before, core)
        self._save(record)
        return dict(candidate_ready=True, sha256=record['sha256'])

    def _validate_proof(self, phase, proof, record, core):
        tests = fresh(proof, record['sha256'], self.clock())
        if phase == 'installed':
            require(proof.get('id') == 'entry' and proof.get('node') == p.ENTRY_ID and proof.get('ip') == p.ENTRY,
                    'Installed proof is not from entry')
            require(all(t.get('kind') == 'installed-xray' and type(t.get('returncode')) is int and t['returncode'] == 0
                        and isinstance(t.get('version'), str) and re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}', t['version'])
                        for t in tests), 'Installed Xray proof failed')
        elif phase in ('backend', 'public', 'subscription'):
            exported = record['requests'].get(phase)
            require(exported is not None, 'Export the exact probe request first')
            request = exported['request']
            require(c.checksum(request) == exported['digest'] and request['sha256'] == record['sha256']
                    and len(request['items']) == len(PROBE_IDS[phase])
                    and {item['id'] for item in request['items']} == PROBE_IDS[phase]
                    and all(item['ip'] == c.target(ID)['ip'] for item in request['items']),
                    'Saved probe request integrity or coverage failure')
            earliest = exported['timestamp']
            if phase in ('public', 'subscription'):
                require('staged' in record and 'activated' in core, 'Frontend/backend activation required')
                earliest = max(earliest, record['staged'], core['activated'])
            if phase == 'subscription':
                require('published' in record, 'Publish before real subscription probes')
                earliest = max(earliest, record['published'])
            traffic_proof(proof, exported['request'], record['sha256'], self.clock(), earliest)
        elif phase == 'tls':
            require(len(tests) == 1 and all(tests[0].get(k) == value for k, value in dict(
                id='de245-local-tls', sni=c.target(ID)['domain'], address='127.0.0.1', port=9443,
                tls='TLSv1.3', alpn='h2', chain_verified=True).items()), 'Local trusted TLS1.3/h2 proof required')
            require(tests[0]['chain_verified'] is True, 'TLS chain verification required')
        elif phase == 'renewal':
            require(len(tests) == 2 and {t.get('id') for t in tests} == {'de245-renewal', 'de245-renewal-health'},
                    'Actual renewal and separate fresh health checks required')
            renewal = next(t for t in tests if t['id'] == 'de245-renewal')
            health = next(t for t in tests if t['id'] == 'de245-renewal-health')
            performed = renewal.get('performed_at')
            require(type(performed) in (int, float) and math.isfinite(performed)
                    and 0 <= self.clock() - performed <= 86400 and performed <= proof['timestamp']
                    and renewal.get('dry_run') is True, 'Actual renewal is missing, future dated or older than 24h')
            require(all(t.get('domain') == c.target(ID)['domain'] for t in tests)
                    and all(health.get(k) is True for k in ('nginx_test', 'cert_valid', 'deploy_hook', 'timer_enabled', 'timer_active'))
                    and health.get('tls') == 'TLSv1.3' and health.get('alpn') == 'h2', 'Fresh renewal health proof failed')
        else:
            raise c.SafetyError('Unknown proof phase')

    def accept(self, phase, proof):
        require(phase in PHASES, 'Unknown proof phase')
        record, _, core = self._load()
        require('rolled_back' not in record and 'finished' not in record, 'Frontend operation is closed')
        record['proofs'].pop(phase, None)
        self._save(record)
        self._validate_proof(phase, proof, record, core)
        record['proofs'][phase] = deepcopy(proof)
        self._save(record)
        return dict(proof_accepted=phase)

    def _proofs(self, record, core, phases):
        for phase in phases:
            require(phase in record['proofs'], 'Required proof missing')
            self._validate_proof(phase, record['proofs'][phase], record, core)

    def arm(self):
        record, before, core = self._load()
        require('apply_intent' not in record and 'rolled_back' not in record and 'finished' not in record, 'Cannot arm this frontend state')
        self._scope(record, before, core)
        self._proofs(record, core, ('installed', 'tls'))
        if 'armed' in core:
            require(self.clock() + 600 < core['armed'] + 1500 - 60, 'Frontend rollback must precede core rollback')
            self.core.timer.armed(ID)
        if 'arm_intent' in record:
            require(0 <= self.clock() - record['arm_intent'] < 600, 'Frontend timer deadline passed')
            self.timers.armed(ID)
        else:
            record['arm_intent'] = self.clock()
            self._save(record)
            self.timers.start(ID)
        record['armed'] = record['arm_intent']
        self._save(record)
        return dict(frontend_rollback_armed=True)

    def _armed(self, record, core):
        require('armed' in record and 'armed' in core and 0 <= self.clock() - record['armed'] < 600
                and 0 <= self.clock() - core['armed'] < 1500
                and record['armed'] + 600 < core['armed'] + 1500 - 60, 'Rollback timing is unsafe')
        require('rollback_intent' not in record and 'rolled_back' not in record and 'rolled_back' not in core
                and 'rollback_intent' not in core and 'finished' not in record, 'Rollback/final state blocks mutation')
        self.timers.armed(ID)
        self.core.timer.armed(ID)

    def _base_grants(self, core, squad_id, plan):
        # Core removes its own clone grants only AFTER frontend restoration.
        # A resumed frontend rollback must tolerate that already-completed step.
        return set(plan['before']) - set(core['rights'].get(squad_id, {}).get('added', []))

    def _front_rights(self, record, before, core, required=False):
        selected, squads = self._customers(before, core)
        for squad in squads:
            granted = set(c.ids(squad['inbounds']))
            if record.get('front') in granted:
                require(squad['uuid'] in record['grants'], 'Frontend grant has no ownership intent')
                require(squad['uuid'] in selected, 'Backend/service squad received customer frontend')
        for squad_id, plan in record['grants'].items():
            require(squad_id in selected, 'Owned customer squad changed')
            granted = set(c.ids(selected[squad_id]['inbounds']))
            require(self._base_grants(core, squad_id, plan) <= granted, 'Existing customer rights changed')
            if required:
                require(record['front'] in granted, 'Customer frontend grant missing')
        if required:
            require(set(record['grants']) == set(selected), 'Customer grant coverage incomplete')
        return selected

    def stage(self):
        record, before, core = self._load()
        self._armed(record, core)
        self._proofs(record, core, ('installed', 'tls', 'backend'))
        self._core_guard(record, before, core, active=True)
        profile, front, _ = self._scope(record, before, core, mixed=True)
        selected = self._front_rights(record, before, core)
        if 'apply_intent' not in record:
            tag = model.route_tags(ID)['front']
            for candidate in self.api('GET', '/api/config-profiles/')['configProfiles']:
                if candidate['uuid'] != record['profile']:
                    require(tag not in c.metadata(self.api('GET', '/api/config-profiles/' + candidate['uuid'])),
                            'Frontend tag collides with another profile')
            record['grants'] = {key: dict(before=c.ids(squad['inbounds'])) for key, squad in selected.items()}
            record['apply_intent'] = self.clock()
            self._save(record)
            self.api('PATCH', '/api/config-profiles/', dict(uuid=record['profile'], config=record['candidate']))
        # Resume reads back a lost PATCH result; an unchanged old profile is NOT
        # blindly patched again after an ambiguous previous attempt.
        profile = self.api('GET', '/api/config-profiles/' + record['profile'])
        require(profile['config'] == record['candidate'], 'Profile apply intent unresolved; inspect without retrying PATCH')
        now_meta = c.metadata(profile)
        old_meta = c.metadata(before['profiles'][record['profile']])
        require(set(now_meta) == set(old_meta) | {model.route_tags(ID)['front']}
                and all(now_meta[tag] == old_meta[tag] for tag in old_meta), 'Profile metadata readback failed')
        record['front'] = now_meta[model.route_tags(ID)['front']]
        self._save(record)
        self._front_rights(record, before, core)
        for squad_id, plan in record['grants'].items():
            current = c.ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])
            require(self._base_grants(core, squad_id, plan) <= set(current), 'Squad drift before additive grant')
            wanted = list(dict.fromkeys(current + [record['front']]))
            if set(current) != set(wanted):
                self.api('PATCH', '/api/internal-squads/', dict(uuid=squad_id, inbounds=wanted))
            require(set(c.ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])) == set(wanted), 'Frontend grant readback failed')
        original = next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID)
        old_binding = c.binding(original)
        wanted = dict(profile=record['profile'], inbounds=sorted(old_binding['inbounds'] + [record['front']]))
        actual = c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID))
        require(actual in (old_binding, wanted), 'Entry binding changed before activation')
        self._armed(record, core)
        if actual != wanted:
            require('binding_intent' not in record, 'Entry binding apply uncertain; inspect instead of repeating')
            record['binding_intent'] = self.clock()
            self._save(record)
            self.api('PATCH', '/api/nodes/', dict(uuid=p.ENTRY_ID, configProfile=dict(
                activeConfigProfileUuid=wanted['profile'], activeInbounds=wanted['inbounds'])))
        self._scope(record, before, core, live=True)
        self._front_rights(record, before, core, required=True)
        self._armed(record, core)
        record.setdefault('staged', self.clock())
        self._save(record)
        return dict(frontend_staged=True, legacy_inbounds_preserved=4)

    def _user(self, before, core):
        intent = self.probe_intent()
        user = self.api('GET', '/api/users/' + intent['uuid'])
        require(all(user.get(k) == intent[k] for k in ('uuid', 'username', 'tag', 'description'))
                and user['status'] == 'ACTIVE' and user['uuid'] != core['objects']['user'], 'Technical probe identity mismatch')
        model._service_uuid(user['vlessUuid'])
        selected, _ = self._customers(before, core)
        base = next(key for key, squad in selected.items() if squad['name'] == 'BASE')
        require(base in c.ids(user['activeInternalSquads'])
                and core['objects']['squad'] not in c.ids(user['activeInternalSquads']), 'Probe is not a customer-path technical account')
        return user

    def _request(self, record, phase, items):
        require(items and len({item['id'] for item in items}) == len(items)
                and all(item['ip'] == c.target(ID)['ip'] for item in items), 'Invalid DE245 probe request')
        request = dict(sha256=record['sha256'], items=items)
        record['requests'][phase] = dict(timestamp=self.clock(), request=deepcopy(request), digest=c.checksum(request))
        record['proofs'].pop(phase, None)
        self._save(record)
        return request

    def _begin_export(self, record, phase):
        require('finished' not in record and 'rolled_back' not in record and 'rollback_intent' not in record,
                'Frontend operation is closed to new probes')
        # A fresh failed attempt must not leave an older success eligible for
        # publication/finalization, particularly if Happ now returns bad wire.
        record['proofs'].pop(phase, None)
        record['requests'].pop(phase, None)
        self._save(record)

    def export_config(self):
        return deepcopy(self._load()[0]['candidate'])

    def export_backend(self):
        record, before, core = self._load()
        self._begin_export(record, 'backend')
        self._core_guard(record, before, core, active=True)
        out = next(o for o in record['candidate']['outbounds'] if o.get('tag') == model.route_tags(ID)['exit'])
        return self._request(record, 'backend', [dict(id='de245-backend', ip=c.target(ID)['ip'], outbound=deepcopy(out))])

    def export_public(self):
        record, before, core = self._load()
        self._begin_export(record, 'public')
        require('staged' in record, 'Stage frontend before external client probes')
        self._scope(record, before, core, live=True, published='published' in record)
        self._front_rights(record, before, core, required=True)
        user = self._user(before, core)['vlessUuid']
        node = c.target(ID)
        reality = record['candidate']['inbounds'][-1]['streamSettings']['realitySettings']
        items = [dict(id='de245-public-' + fp, ip=node['ip'],
                      outbound=client(p.ENTRY, node['port'], user, 'reality', reality, fp)) for fp in ('chrome', 'firefox')]
        for host in record['hosts']:
            role = 'auto' if host['isHidden'] else 'main'
            items.append(dict(id='de245-host-' + role, ip=node['ip'], outbound=client(
                p.ENTRY, node['port'], user, 'reality', reality, host.get('fingerprint') or 'chrome')))
        source = before['profiles'][node['profile']]
        source_tag = next(tag for tag, value in c.metadata(source).items() if value == node['inbound'])
        original = next(i for i in source['config']['inbounds'] if i['tag'] == source_tag)
        rs = original['streamSettings']['realitySettings']
        require(original['port'] == 443 and node['sni'] in rs['serverNames'], 'Original REALITY endpoint changed')
        rs = deepcopy(rs); rs['serverNames'] = [node['sni']]
        items.append(dict(id='de245-legacy-reality', ip=node['ip'], outbound=client(node['ip'], 443, user, 'reality', rs)))
        # Cached TLS connects to the OLD public 443 and is forwarded by REALITY
        # to its preserved loopback TLS compatibility inbound, not to public 8443.
        compat = [i for i in source['config']['inbounds'] if i.get('streamSettings', {}).get('security') == 'tls'
                  and i.get('listen') == '127.0.0.1'
                  and '127.0.0.1:' + str(i.get('port')) == rs.get('target', rs.get('dest'))]
        require(len(compat) == 1 and compat[0]['protocol'] == 'vless', 'Cached TLS compatibility target is ambiguous')
        items.append(dict(id='de245-legacy-tls', ip=node['ip'], outbound=client(
            node['ip'], 443, user, 'tls', dict(serverName=node['sni']))))
        return self._request(record, 'public', items)

    def publish(self):
        record, before, core = self._load()
        self._armed(record, core)
        self._proofs(record, core, ('installed', 'tls', 'backend', 'public'))
        require('staged' in record, 'Frontend is not staged')
        self._scope(record, before, core, mixed=True, live=True)
        self._front_rights(record, before, core, required=True)
        record.setdefault('publish_intent', self.clock())
        self._save(record)
        for old in record['hosts']:
            current = self.api('GET', '/api/hosts/' + old['uuid'])
            desired = self._desired(record, old)
            require(c.stable_host(current) in (c.stable_host(old), c.stable_host(desired)), 'Host changed before publication')
            if c.stable_host(current) != c.stable_host(desired):
                self.api('PATCH', '/api/hosts/', dict(uuid=old['uuid'], **{k: desired[k] for k in HOST_FIELDS}))
            require(c.stable_host(self.api('GET', '/api/hosts/' + old['uuid'])) == c.stable_host(desired), 'Host publish readback failed')
        self._scope(record, before, core, live=True, published=True)
        record.setdefault('published', self.clock())
        self._save(record)
        return dict(published_hosts=2, remarks_fingerprint_hidden_disabled_preserved=True)

    def _wire(self, outbound, record, user, host):
        node = c.target(ID)
        require(outbound.get('protocol') == 'vless', 'Subscription protocol differs')
        endpoints = outbound.get('settings', {}).get('vnext', [])
        require(len(endpoints) == 1 and endpoints[0].get('address') == p.ENTRY
                and endpoints[0].get('port') == node['port'], 'Subscription endpoint differs')
        users = endpoints[0].get('users', [])
        require(len(users) == 1 and users[0].get('id') == user and users[0].get('encryption') == 'none'
                and users[0].get('flow') == 'xtls-rprx-vision', 'Subscription user/encryption/flow differs')
        stream = outbound.get('streamSettings', {})
        require(stream.get('network') in ('raw', 'tcp') and stream.get('security') == 'reality', 'Subscription transport/security differs')
        rs = stream.get('realitySettings', {})
        require(rs.get('serverName') == node['domain'] and rs.get('fingerprint') == (host.get('fingerprint') or 'chrome')
                and rs.get('publicKey') == p.public_key(record['identity']['privateKey'])
                and rs.get('shortId') in record['identity']['shortIds'], 'Subscription REALITY identity differs')
        require(not outbound.get('proxySettings') and not stream.get('sockopt', {}).get('dialerProxy'), 'Unexpected subscription proxy hop')

    def export_subscription(self):
        record, before, core = self._load()
        self._begin_export(record, 'subscription')
        require('published' in record, 'Publish before fetching actual subscription')
        self._scope(record, before, core, live=True, published=True)
        self._front_rights(record, before, core, required=True)
        user = self._user(before, core)
        response = self.api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])
        configs = self.subscription_fetch(response['subscriptionUrl'])  # Never persist/log this URL.
        items = []
        for host in record['hosts']:
            role = 'auto' if host['isHidden'] else 'main'
            remark = AUTO_REMARK if host['isHidden'] else host['remark']
            matching = [config for config in configs if config.get('remarks') == remark]
            require(len(matching) == 1, 'Expected one actual main/auto subscription config')
            outputs = [out for out in matching[0].get('outbounds', []) if out.get('protocol') == 'vless'
                       and any(v.get('address') == p.ENTRY and v.get('port') == c.target(ID)['port']
                               for v in out.get('settings', {}).get('vnext', []))]
            require(len(outputs) == 1, 'Expected one DE245 outbound in each actual subscription config')
            self._wire(outputs[0], record, user['vlessUuid'], host)
            items.append(dict(id='de245-sub-' + role, ip=c.target(ID)['ip'], outbound=deepcopy(outputs[0])))
        return self._request(record, 'subscription', items)

    def verify(self):
        record, before, core = self._load()
        require('staged' in record and 'rolled_back' not in record, 'Frontend is not live')
        self._scope(record, before, core, live=True, published='published' in record)
        self._front_rights(record, before, core, required=True)
        return dict(entry_candidate_unchanged=True, legacy_inbounds_preserved=4,
                    original_exit_profiles_unchanged=True, customer_front_squads=4, published='published' in record)

    def _core_rollback_preflight(self, core):
        # Equivalent resource checks to core.rollback, without its entry/host
        # baseline gate (those resources are still in our old/desired states).
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        indexed = {s['uuid']: s for s in squads}
        owned = set(core['metadata'].values()) - {core['backend']}
        for squad in squads:
            granted = set(c.ids(squad['inbounds']))
            require(squad['uuid'] == core['objects']['squad'] or core['backend'] not in granted,
                    'Unowned backend grant prevents rollback')
            if owned & granted:
                require(squad['uuid'] in core['rights'] and owned & granted <= set(core['rights'][squad['uuid']]['added']),
                        'Unowned exit clone grant prevents rollback')
        for key, plan in core['rights'].items():
            require(key in indexed and self.core._required_before(core, key, plan) <= set(c.ids(indexed[key]['inbounds'])),
                    'Core squad preflight failed before frontend rollback')

    def rollback(self):
        record, before, core = self._load()
        require('finished' not in record, 'Finalized frontend cannot be automatically rolled back')
        # Persist intent to allow safe resumption after core has already restored
        # its binding. No API mutations have happened in this invocation yet.
        record.setdefault('rollback_intent', self.clock())
        self._save(record)
        _, front, _ = self._scope(record, before, core, mixed=True)
        if front and 'front' not in record:
            record['front'] = front
            self._save(record)
        self._front_rights(record, before, core)
        self._core_rollback_preflight(core)  # Whole affected scope before first PATCH.
        for old in record['hosts']:
            actual = self.api('GET', '/api/hosts/' + old['uuid'])
            desired = self._desired(record, old) if record.get('front') else old
            require(c.stable_host(actual) in (c.stable_host(old), c.stable_host(desired)), 'Concurrent host edit during rollback')
            if c.stable_host(actual) != c.stable_host(old):
                self.api('PATCH', '/api/hosts/', dict(uuid=old['uuid'], **{key: old[key] for key in HOST_FIELDS}))
            require(c.stable_host(self.api('GET', '/api/hosts/' + old['uuid'])) == c.stable_host(old), 'Host rollback readback failed')
        original = next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID)
        old_binding = c.binding(original)
        if c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID)) != old_binding:
            self.api('PATCH', '/api/nodes/', dict(uuid=p.ENTRY_ID, configProfile=dict(
                activeConfigProfileUuid=old_binding['profile'], activeInbounds=old_binding['inbounds'])))
        require(c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID)) == old_binding, 'Entry binding rollback failed')
        for squad_id, plan in record['grants'].items():
            current = c.ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])
            require(self._base_grants(core, squad_id, plan) <= set(current), 'Customer squad changed during rollback')
            wanted = [item for item in current if item != record.get('front')]
            if current != wanted:
                self.api('PATCH', '/api/internal-squads/', dict(uuid=squad_id, inbounds=wanted))
            require(set(c.ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])) == set(wanted), 'Frontend rights rollback failed')
        profile = self.api('GET', '/api/config-profiles/' + record['profile'])
        old_config = before['profiles'][record['profile']]['config']
        require(profile['config'] in (old_config, record['candidate']), 'Entry profile changed during rollback')
        if profile['config'] != old_config:
            self.api('PATCH', '/api/config-profiles/', dict(uuid=record['profile'], config=old_config))
        # This exact baseline gate makes it safe to call the core rollback next.
        self._scope(record, before, core)
        restored = self.api('GET', '/api/config-profiles/' + record['profile'])
        require(restored['config'] == old_config and c.metadata(restored) == c.metadata(before['profiles'][record['profile']]),
                'Entry profile rollback readback failed')
        self.core.rollback(ID)
        record['rolled_back'] = self.clock()
        self._save(record)
        return dict(frontend_restored=True, exit_core_restored=True, inactive_backend_objects_retained=True)

    def finish(self):
        record, before, core = self._load()
        require('rolled_back' not in record and 'rollback_intent' not in record and 'rolled_back' not in core
                and 'rollback_intent' not in core and 'published' in record, 'Cannot finalize rolled-back/unpublished state')
        self._proofs(record, core, PHASES)
        self.verify()
        if 'finished' in record:
            for name in (FRONT_TIMER, c.SystemdTimer.name(ID)): self.timers.inactive(name)
            return dict(frontend_finalized=True, both_rollback_timers_inactive=True)
        if 'finish_intent' not in record:
            self._armed(record, core)
            record['finish_intent'] = self.clock()
            self._save(record)
        for name in (FRONT_TIMER, c.SystemdTimer.name(ID)):
            self.timers.service_idle(name)
        # Do not stop an executing rollback service; check both again afterwards.
        for name in (c.SystemdTimer.name(ID), FRONT_TIMER): self.timers.stop(name)
        for name in (FRONT_TIMER, c.SystemdTimer.name(ID)): self.timers.inactive(name)
        latest, _, latest_core = self._load()
        require('rollback_intent' not in latest and 'rolled_back' not in latest
                and 'rollback_intent' not in latest_core and 'rolled_back' not in latest_core, 'Rollback raced finalization')
        self.verify()
        self._proofs(latest, latest_core, PHASES)
        latest['finished'] = self.clock()
        self._save(latest)
        return dict(frontend_finalized=True, both_rollback_timers_inactive=True)


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    actions = ['prepare', 'arm', 'stage', 'publish', 'verify', 'rollback', 'finish',
               'export-config', 'export-backend', 'export-public', 'export-subscription']
    parser.add_argument('action', choices=actions + ['accept-' + phase for phase in PHASES])
    args = parser.parse_args(argv)
    core_store, store = c.RootStore(), Store()
    # Lock ordering shared with the existing core timer. Never nest a second
    # core lock in methods; core.rollback below runs under this same lock.
    with core_store.locked():
        with store.locked():
            api = None
            if not args.action.startswith('accept-') and args.action != 'export-config':
                api, _ = p.create_client()
            core = c.Coordinator(api, core_store, c.SystemdTimer())
            worker = Frontend(api, store, core, Timers())
            if args.action.startswith('accept-'):
                result = worker.accept(args.action.removeprefix('accept-'), json.load(sys.stdin))
            else:
                result = getattr(worker, args.action.replace('-', '_'))()
            print(json.dumps(result))  # Secret material only for explicit export-*.


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, c.SafetyError) else 'Frontend failed; inspect protected state'
        print(json.dumps(dict(error=message)), file=sys.stderr)
        sys.exit(1)
