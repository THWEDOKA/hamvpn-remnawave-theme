"""Guarded EXIT-ONLY coordinator for the six approved CLOUDru routes.

No DNS/site/entry/frontend publication, SSH, firewall or network probes here.
External attestations are not tests performed by this module. All exports are
secret: pipe stdout directly to protected RAM/stdin, never log it.

CLI: prepare (JSON stdin), export-candidate, accept-installed (JSON stdin),
accept-baseline (JSON stdin), stage, apply, export-backend, accept-backend (JSON stdin), finish, status,
rollback; all require --id. Exports additionally require --secret-stdout.
stage arms a 25-minute independent rollback BEFORE the first panel write.
finish means verified backend + legacy ONLY, not a completed customer migration.
Inactive owned objects are retained on rollback; no destructive DELETE exists.

prepare input:
 {mode:'reality',backend_port:<checked free>,expected_egress:<observed IP>,
  target:'explicit.name:443',server_names:['explicit.name'],
  runtime:{id,node,ip,timestamp,backend_port,port_free:true,
    namespace_verified:true,xray_version:'26.7.28',firewall_source:<entry IP>},
  target_checks:[{target,server_name,trusted_tls:true,tls_version:'TLSv1.3',alpn:'h2'}]}
Optional direct_tag selects an EXISTING freedom outbound. REALITY identity is
generated locally in protected state, never copied from a customer or caller.
For explicit mode:'ssh', omit target/server_names/target_checks; runtime requires
loopback_only:true instead of firewall_source, plus direct_failure and tunnel
attestations validated below. No automatic fallback or mode-changing resume.

Proofs carry {id,node,ip,sha256,timestamp,tests:[...]}. Installed tests must name
kind:'installed-xray', version, passed:true, returncode:0. Backend proof also
carries entry, mode and exactly one kind:'backend' test (namespace:'entry-xray')
with authenticated:true,http_code:204,exit_ip:<expected>,returncode:0.
Before apply, accept-baseline requires source_sha256 (original config hash) and
at least one actual legacy case for EACH originally ACTIVE inbound tag:
 {kind:'legacy',test_id,tag,namespace:'entry-xray'|'external-client',client,
  wire_sha256:<canonical exact client config hash>,passed:<actual bool>,
  authenticated:<actual bool>,http_code:<0 if no response>,exit_ip:<IP or null>,
  returncodes:[<HTTPS curl>,<egress curl>]}
The baseline may truthfully contain failures. The post-apply backend proof must
contain exactly the same legacy cases and wire hashes. Baseline successes must
still succeed; pre-existing failures need no loss of any observed partial
success (authentication/204/egress/zero returncode). The original legacy config
is also preserved exactly by the model. Remaining old failures are reported,
never called PASS. No empty/future/stale/cross-candidate proof can finalize.
"""

import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid

import preflight as p
import route_model as model

STATE = Path('/root/hamvpn-cloud140-six-20260918/exit-stage')
TTL = 1500
MAX_PROOF_AGE = 1800
# User narrowed the deployment scope; retained IDs support inspection/rollback
# only if a prior operation exists. The main coordinator owns retirement.
ACTIVE_ROUTES = frozenset(('at', 'pl', 'cz', 'gbpower'))


class SafetyError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise SafetyError(message)


checksum = p.digest


def target(route_id):
    require(route_id in model.TARGETS, 'Unknown approved route')
    rows = [t for t in p.TARGETS if t['id'] == route_id]
    require(len(rows) == 1 and rows[0]['ip'] == model.TARGETS[route_id]['ip'], 'Inventory/model disagreement')
    return deepcopy(rows[0])


def service_tag(route_id):
    target(route_id)
    # Verified installed create-user.command.js: /^[A-Z0-9_]+$/, .max(16).
    # C1406_GBPOWER_SVC was 17 characters; C146 retains the complete route ID.
    value = 'C146_' + route_id.upper() + '_SVC'
    require(re.fullmatch(r'[A-Z0-9_]{1,16}', value) is not None, 'Service tag violates installed API contract')
    return value


def ids(rows):
    require(isinstance(rows, list), 'Invalid ID relation')
    values = [r if isinstance(r, str) else r['uuid'] for r in rows]
    require(all(isinstance(v, str) and v for v in values) and len(set(values)) == len(values), 'Duplicate or invalid ID')
    return sorted(values)


def binding(node):
    cp = node.get('configProfile') or {}
    return dict(profile=cp.get('activeConfigProfileUuid'), inbounds=ids(cp.get('activeInbounds', [])))


def metadata(profile):
    rows = profile['inbounds']
    ids(rows)
    result = {r['tag']: r['uuid'] for r in rows}
    require(len(result) == len(rows), 'Duplicate inbound tag')
    return result


def host_binding(host):
    value = host.get('inbound') or {}
    return dict(configProfileUuid=value.get('configProfileUuid'),
                configProfileInboundUuid=value.get('configProfileInboundUuid'))


def stable_host(host):
    value = deepcopy({k: v for k, v in host.items() if k not in ('createdAt', 'updatedAt')})
    if 'excludedInternalSquads' in value:
        value['excludedInternalSquads'] = ids(value['excludedInternalSquads'])
    return value


def fresh(stamp, now, minimum=0):
    require(type(stamp) in (int, float) and math.isfinite(stamp) and
            minimum <= stamp <= now and now - stamp <= MAX_PROOF_AGE, 'Proof is stale, future or invalid')


def scope_proof(value, route, now):
    require(isinstance(value, dict) and all(value.get(k) == route[k] for k in ('id', 'node', 'ip')),
            'Proof target mismatch')
    fresh(value.get('timestamp'), now)


def validate_inputs(value, route, now):
    require(isinstance(value, dict) and value.get('mode') in ('reality', 'ssh'), 'Explicit transport mode required')
    mode = value['mode']
    allowed = {'mode', 'backend_port', 'expected_egress', 'runtime', 'direct_tag'} | (
        {'target', 'server_names', 'target_checks'} if mode == 'reality' else {'direct_failure', 'tunnel'})
    require(set(value) <= allowed, 'Unexpected preparation input')
    model._port(value.get('backend_port'))
    address = ipaddress.ip_address(value['expected_egress'])
    require(address.is_global, 'Expected egress must be independently observed public IP')
    runtime = value.get('runtime')
    scope_proof(runtime, route, now)
    require(runtime.get('backend_port') == value['backend_port'] and runtime.get('port_free') is True
            and runtime.get('namespace_verified') is True, 'Runtime port/namespace not verified')
    require(isinstance(runtime.get('xray_version'), str) and
            re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}', runtime['xray_version']), 'Installed version missing')
    if mode == 'reality':
        require(runtime.get('firewall_source') == p.ENTRY, 'New public backend needs scoped entry-source firewall')
        model._target(value.get('target'))
        names = model._server_names(value.get('server_names'))
        checks = value.get('target_checks')
        require(isinstance(checks, list) and len(checks) == len(names), 'Missing checked TLS targets')
        require({c.get('server_name') for c in checks} == set(names) and all(
            c.get('target') == value['target'] and c.get('trusted_tls') is True and
            c.get('tls_version') == 'TLSv1.3' and c.get('alpn') == 'h2' for c in checks),
            'REALITY target/SNI checks failed')
    else:
        require(runtime.get('loopback_only') is True, 'Plain backend must be loopback only')
        failed, tunnel = value.get('direct_failure'), value.get('tunnel')
        scope_proof(failed, route, now)
        require(failed.get('entry') == p.ENTRY and failed.get('authenticated_direct_attempted') is True
                and failed.get('passed') is False, 'SSH needs actual failed direct authentication attempt')
        scope_proof(tunnel, route, now)
        require(tunnel.get('entry') == p.ENTRY and tunnel.get('backend_port') == value['backend_port'] and
                tunnel.get('target_address') == '127.0.0.1' and tunnel.get('listener_address') == '127.0.0.1'
                and tunnel.get('host_key_pinned') is True and tunnel.get('restricted_identity') is True
                and tunnel.get('fixed_target_verified') is True and tunnel.get('persistent_service_verified') is True,
                'Restricted persistent SSH tunnel not verified')
        model._port(tunnel.get('listener_port'))


def new_identity():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    private = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return dict(privateKey=base64.urlsafe_b64encode(private).decode().rstrip('='), shortIds=[secrets.token_hex(8)])


class RootStore(p.Store):
    """Immutable before/plan plus atomically replaced hash-checked state.

    Every Coordinator call must hold locked(); CLI does. File updates do not
    erase before/plan or change an intent after an uncertain network mutation.
    """
    def __init__(self, route_id, path=None):
        target(route_id)
        super().__init__(path or STATE / route_id)

    def save(self, name, value):
        require(name == 'operation', 'Only the operation journal may be replaced')
        if not self.exists(name):
            return self.put(name, value)
        self.get(name)  # Integrity, no symlinks, ownership/mode checks before replacing.
        pending = self.path / 'operation.pending'
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(p.encoded(dict(sha256=checksum(value), value=value)))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, self.file(name))
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        require(self.get(name) == value, 'State save/readback mismatch')

    @contextmanager
    def locked(self):
        import fcntl
        self.secure()
        fd = os.open(self.path / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1, 'Unsafe operation lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


class SystemdTimer:
    def __init__(self, runner=subprocess.run):
        self.run = runner

    def name(self, route_id):
        target(route_id)
        return 'ham-cloud140-six-' + route_id + '-exit-rollback'

    def state(self, unit, allow_missing=False):
        result = self.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState',
                           '-p', 'SubState', '-p', 'Result'], capture_output=True, text=True, timeout=15)
        value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        missing = allow_missing and result.returncode == 1 and value.get('LoadState') == 'not-found' and \
            value.get('ActiveState') == 'inactive' and value.get('SubState') == 'dead'
        require(result.returncode == 0 or missing, 'Cannot inspect rollback units')
        require({'LoadState', 'ActiveState', 'SubState'} <= set(value), 'Incomplete rollback unit state')
        return value

    def start(self, route_id):
        name = self.name(route_id)
        for suffix in ('.timer', '.service'):
            state = self.state(name + suffix, True)
            require(state['LoadState'] == 'not-found' and state['ActiveState'] == 'inactive'
                    and state['SubState'] == 'dead', 'Existing rollback unit must not be replaced')
        result = self.run(['systemd-run', '--unit=' + name, '--on-active=' + str(TTL) + 's',
                           '--timer-property=AccuracySec=1s', '--property=UMask=0077',
                           sys.executable, str(Path(__file__).resolve()), 'rollback', '--id', route_id],
                          capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Timer creation uncertain; inspect without blind retry')
        self.armed(route_id)

    def armed(self, route_id):
        name = self.name(route_id)
        timer, service = self.state(name + '.timer'), self.state(name + '.service')
        require(timer['LoadState'] == 'loaded' and timer['ActiveState'] == 'active' and
                timer['SubState'] == 'waiting', 'Rollback timer is not waiting')
        require(service['LoadState'] == 'loaded' and service['ActiveState'] == 'inactive' and
                service['SubState'] == 'dead' and service.get('Result') == 'success', 'Rollback service ran or is running')

    def cancel(self, route_id):
        name = self.name(route_id)
        self.run(['systemctl', 'stop', name + '.timer', name + '.service'], capture_output=True, text=True, timeout=30)
        # systemctl may report a disappeared transient service after stopping its
        # timer. Only fresh, independently verified inactive states count.
        for suffix in ('.timer', '.service'):
            state = self.state(name + suffix, True)
            require(state['ActiveState'] == 'inactive' and state['SubState'] == 'dead' and
                    state['LoadState'] in ('loaded', 'not-found'), 'Rollback cancellation not verified')


class Coordinator:
    def __init__(self, api, store, timer, baseline_store=None, clock=time.time, identity_factory=new_identity):
        self.api, self.store, self.timer = api, store, timer
        self.baseline_store = baseline_store or p.Store()
        self.clock, self.identity_factory = clock, identity_factory

    def _save(self, record):
        self.store.save('operation', record)

    def _load(self, route_id):
        route = target(route_id)
        before, plan, record = self.store.get('before'), self.store.get('plan'), self.store.get('operation')
        require(before['route'] == route and plan['id'] == record['id'] == route_id and
                record['snapshot_sha256'] == plan['snapshot_sha256'] == checksum(before)
                and record['plan_sha256'] == checksum(plan), 'Protected scope/integrity mismatch')
        inputs = plan['inputs']
        config = model.build_exit_config(before['profile']['config'], route_id, inputs['backend_port'],
            mode=inputs['mode'], identity=plan['identity'], server_names=inputs.get('server_names'),
            target=inputs.get('target'), direct_tag=inputs.get('direct_tag'))
        require(config == plan['candidate'] and checksum(config) == record['sha256'], 'Candidate/model drift')
        return before, plan, record

    @staticmethod
    def summary(record):
        return dict(id=record['id'], candidate_sha256=record['sha256'], staged='staged' in record,
                    binding_applied='applied' in record and 'rolled_back' not in record,
                    rolled_back='rolled_back' in record, backend_finished='finished' in record,
                    frontend_published=False)

    def prepare(self, route_id, inputs):
        require(route_id in ACTIVE_ROUTES, 'Route withdrawn from current deployment scope')
        route = target(route_id)
        service_tag(route_id)  # Validate before any snapshot or panel mutation.
        validate_inputs(inputs, route, self.clock())
        if self.store.exists('plan'):
            before, plan, record = self._load(route_id)
            require(plan['inputs'] == inputs and 'rolled_back' not in record, 'Cannot replace an existing plan')
            self._guard(before, plan, record)
            return self.summary(record)
        baseline = p.baseline(self.baseline_store)
        reference = next(r for r in baseline['routes'] if r['id'] == route_id)
        node = self.api('GET', '/api/nodes/' + route['node'])
        require(node['address'] == route['ip'] and node['isConnected'] and not node['isDisabled'], 'Exit identity/health mismatch')
        require(binding(node) == binding(p.indexed(baseline['nodes'])[route['node']]) and
                binding(node)['profile'] == reference['profile'], 'Refresh preflight after node binding change')
        profile = self.api('GET', '/api/config-profiles/' + binding(node)['profile'])
        previous = baseline['profiles'][profile['uuid']]
        require(profile['config'] == previous['config'] and metadata(profile) == metadata(previous), 'Preflight source profile drift')
        require(set(binding(node)['inbounds']) <= set(metadata(profile).values()), 'Active inbound metadata mismatch')
        hosts = [h for h in self.api('GET', '/api/hosts/') if route['node'] in h.get('nodes', [])]
        old_hosts = [h for h in baseline['hosts'] if route['node'] in h.get('nodes', [])]
        require(p.indexed([stable_host(h) for h in hosts]) == p.indexed([stable_host(h) for h in old_hosts]), 'Preflight target host drift')
        require(all(h['nodes'] == [route['node']] for h in hosts), 'Shared multi-node host requires explicit separate workflow')
        require(set(reference['hosts']) <= set(p.indexed(hosts)), 'Approved customer hosts missing')
        for host in hosts:
            hb = host_binding(host)
            if hb['configProfileUuid'] == profile['uuid']:
                require(hb['configProfileInboundUuid'] in metadata(profile).values(), 'Host inbound absent from source clone')
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        # Fresh snapshot is per-route. No original profile/consumer-count assumptions.
        before = dict(route=route, node=node, profile=profile, hosts=hosts, squads=squads,
                      preflight_sha256=checksum(baseline), preflight_timestamp=baseline['timestamp'], timestamp=self.clock())
        if self.store.exists('before'):
            saved = self.store.get('before')
            require(all(saved[k] == before[k] for k in ('route', 'node', 'profile', 'hosts', 'squads', 'preflight_sha256')),
                    'Incomplete prepare snapshot requires manual inspection')
            before = saved
        else:
            self.store.put('before', before)
        identity = self.identity_factory() if inputs['mode'] == 'reality' else None
        candidate = model.build_exit_config(profile['config'], route_id, inputs['backend_port'], mode=inputs['mode'],
                    identity=identity, server_names=inputs.get('server_names'), target=inputs.get('target'),
                    direct_tag=inputs.get('direct_tag'))
        name, squad_name = 'HAM-C1406-' + route_id.upper() + '-EXIT', 'HAM-C1406-' + route_id.upper() + '-SVC'
        require(all(re.fullmatch(r'[A-Za-z0-9_-]{2,30}', n) for n in (name, squad_name)), 'Panel name length/format invalid')
        plan = dict(id=route_id, snapshot_sha256=checksum(before), inputs=deepcopy(inputs), identity=identity,
                    candidate=candidate, name=name, squad_name=squad_name, prepared_at=self.clock())
        self.store.put('plan', plan)
        record = dict(id=route_id, snapshot_sha256=checksum(before), plan_sha256=checksum(plan),
                      sha256=checksum(candidate), objects={}, intents={}, rights={}, host_intents={})
        self._save(record)
        return self.summary(record)

    def export_candidate(self, route_id):
        return deepcopy(self._load(route_id)[1]['candidate'])

    def _proof(self, proof, before, plan, record, kind):
        scope_proof(proof, before['route'], self.clock())
        require(proof.get('sha256') == record['sha256'], 'Proof candidate mismatch')
        minimum = plan['prepared_at'] if kind == 'installed' else (
            before['preflight_timestamp'] if kind == 'baseline' else record['applied'])
        fresh(proof.get('timestamp'), self.clock(), minimum)
        tests = proof.get('tests')
        require(isinstance(tests, list) and bool(tests) and all(isinstance(t, dict) for t in tests), 'No actual proof tests')
        if kind == 'installed':
            require(len(tests) == 1 and tests[0].get('kind') == 'installed-xray' and tests[0].get('passed') is True
                    and type(tests[0].get('returncode')) is int and tests[0]['returncode'] == 0
                    and tests[0].get('version') == plan['inputs']['runtime']['xray_version'], 'Installed Xray test failed/version mismatch')
        elif kind == 'baseline':
            require(proof.get('source_sha256') == checksum(before['profile']['config']), 'Legacy baseline source hash mismatch')
            original_tags = {tag for tag, iid in metadata(before['profile']).items() if iid in binding(before['node'])['inbounds']}
            require({t.get('tag') for t in tests} == original_tags and len({t.get('test_id') for t in tests}) == len(tests),
                    'Legacy baseline must cover every original active inbound with unique case IDs')
            for test in tests:
                self._legacy_test(test, plan)
        else:
            require(proof.get('entry') == p.ENTRY and proof.get('mode') == plan['inputs']['mode'], 'Backend proof source/transport mismatch')
            if 'forward_tunnel' in record:
                fresh(proof['timestamp'],self.clock(),record['forward_tunnel']['timestamp'])
            backend = [t for t in tests if t.get('kind') == 'backend']
            legacy = [t for t in tests if t.get('kind') == 'legacy']
            require(len(backend) == 1 and backend[0].get('namespace') == 'entry-xray'
                    and len(tests) == len(legacy) + 1, 'Backend or cached legacy probes incomplete')
            if 'forward_tunnel' in record:
                require(backend[0].get('transport')=='forward-ssh+reality','Probe must exercise attached SSH forward')
            require(all(t.get('authenticated') is True and type(t.get('returncode')) is int and t['returncode'] == 0
                        and type(t.get('http_code')) is int and t['http_code'] == 204
                        and t.get('exit_ip') == plan['inputs']['expected_egress'] for t in backend), 'Backend authentication/status/egress mismatch')
            self._proof(record.get('baseline_proof'), before, plan, record, 'baseline')
            baseline = {t['test_id']: t for t in record['baseline_proof']['tests']}
            require(len(legacy) == len(baseline) and {t.get('test_id') for t in legacy} == set(baseline), 'Legacy post-probe case set differs')
            for test in legacy:
                self._legacy_test(test, plan)
                old = baseline[test['test_id']]
                require(all(test[k] == old[k] for k in ('tag', 'namespace', 'client', 'wire_sha256')), 'Legacy wire/probe identity changed')
                require(not old['passed'] or test['passed'], 'Previously working legacy case regressed')
                require(not old['authenticated'] or test['authenticated'], 'Legacy authentication regressed')
                require(old['http_code'] != 204 or test['http_code'] == 204, 'Legacy HTTPS partial success regressed')
                require(old['exit_ip'] != plan['inputs']['expected_egress'] or test['exit_ip'] == old['exit_ip'], 'Legacy egress partial success regressed')
                require(all(prior != 0 or current == 0 for prior, current in zip(old['returncodes'], test['returncodes'])), 'Legacy successful request regressed')

    @staticmethod
    def _legacy_test(test, plan):
        require(test.get('kind') == 'legacy' and isinstance(test.get('test_id'), str)
                and bool(re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', test['test_id']))
                and test.get('namespace') in ('entry-xray', 'external-client')
                and isinstance(test.get('client'), str) and bool(re.fullmatch(r'[A-Za-z0-9._:+-]{1,80}', test['client']))
                and isinstance(test.get('wire_sha256'), str) and bool(re.fullmatch(r'[0-9a-f]{64}', test['wire_sha256'])), 'Legacy test provenance is incomplete')
        codes = test.get('returncodes')
        require(isinstance(codes, list) and len(codes) == 2 and all(type(code) is int and 0 <= code <= 255 for code in codes)
                and type(test.get('passed')) is bool and type(test.get('authenticated')) is bool
                and type(test.get('http_code')) is int and 0 <= test['http_code'] <= 599, 'Legacy test outcome is invalid')
        if test.get('exit_ip') is not None:
            ipaddress.ip_address(test['exit_ip'])
        actual = (test['authenticated'] and codes == [0, 0] and test['http_code'] == 204
                  and test.get('exit_ip') == plan['inputs']['expected_egress'])
        require(test['passed'] is actual, 'Legacy passed flag contradicts measured result')

    def _accept(self, route_id, proof, kind):
        before, plan, record = self._load(route_id)
        require('rolled_back' not in record and 'finished' not in record, 'Proof lifecycle closed')
        record.pop(kind + '_proof', None)
        self._save(record)  # Failed recheck invalidates earlier success.
        self._proof(proof, before, plan, record, kind)
        record[kind + '_proof'] = deepcopy(proof)
        self._save(record)
        return dict(id=route_id, proof_accepted=True, kind=kind)

    def accept_installed(self, route_id, proof):
        return self._accept(route_id, proof, 'installed')

    def accept_backend(self, route_id, proof):
        return self._accept(route_id, proof, 'backend')

    def accept_baseline(self, route_id, proof):
        require('apply_intent' not in self._load(route_id)[2], 'Legacy baseline must precede activation')
        return self._accept(route_id, proof, 'baseline')

    def _profile_check(self, profile, plan, record):
        require(profile['name'] == plan['name'] and profile['config'] == plan['candidate'] and
                set(metadata(profile)) == {i['tag'] for i in plan['candidate']['inbounds']}, 'Owned clone content drift')
        if 'profile' in record['objects']:
            require(profile['uuid'] == record['objects']['profile'], 'Owned clone ID drift')
        if 'metadata' in record:
            require(metadata(profile) == record['metadata'], 'Owned clone metadata drift')

    def _guard(self, before, plan, record):
        route = before['route']
        original = self.api('GET', '/api/config-profiles/' + before['profile']['uuid'])
        require(original['config'] == before['profile']['config'] and metadata(original) == metadata(before['profile']), 'Original shared profile drift')
        nodes = p.indexed(self.api('GET', '/api/nodes/'))
        node = nodes[route['node']]
        require(all(node.get(k) == before['node'].get(k) for k in ('address', 'port', 'name', 'isDisabled')), 'Exit management identity drift')
        allowed = [binding(before['node'])]
        if 'apply_intent' in record and 'rolled_back' not in record:
            allowed.append(record['desired_binding'])
        require(binding(node) in allowed, 'Unexpected target node binding')
        hosts = p.indexed(self.api('GET', '/api/hosts/'))
        actual_target = {hid for hid, h in hosts.items() if route['node'] in h.get('nodes', [])}
        require(actual_target == set(p.indexed(before['hosts'])), 'Target host set changed')
        for old in before['hosts']:
            allowed_hosts = [stable_host(old)]
            if old['uuid'] in record['host_intents'] and 'rolled_back' not in record:
                clone = deepcopy(old)
                clone['inbound'] = record['host_intents'][old['uuid']]['wanted']
                allowed_hosts.append(stable_host(clone))
            require(stable_host(hosts[old['uuid']]) in allowed_hosts, 'Host changed outside owned binding delta')
        if 'profile' in record['objects']:
            pid = record['objects']['profile']
            self._profile_check(self.api('GET', '/api/config-profiles/' + pid), plan, record)
            consumers = {n['uuid'] for n in nodes.values() if binding(n)['profile'] == pid}
            require(consumers <= ({route['node']} if 'apply_intent' in record and 'rolled_back' not in record else set()), 'Foreign clone consumer')
            clone_hosts = {h['uuid'] for h in hosts.values() if host_binding(h)['configProfileUuid'] == pid}
            require(clone_hosts <= set(record['host_intents']), 'Foreign clone host reference')
        return node, hosts

    def _named(self, record, kind, path, collection, body):
        rows = [v for v in self.api('GET', path)[collection] if v['name'] == body['name']]
        require(len(rows) <= 1, 'Duplicate operation object name')
        if kind in record['objects']:
            require(len(rows) == 1 and rows[0]['uuid'] == record['objects'][kind], 'Owned object disappeared')
        elif kind in record['intents']:
            require(record['intents'][kind] == body and len(rows) == 1, 'Unresolved creation; never repeat POST blindly')
        else:
            require(not rows, 'Unowned matching name')
            record['intents'][kind] = deepcopy(body)
            self._save(record)
            try:
                self.api('POST', path, body)
            except Exception:
                pass  # Always resolve by readback, never print a secret response.
            rows = [v for v in self.api('GET', path)[collection] if v['name'] == body['name']]
            require(len(rows) == 1, 'Create not confirmed; inspect recorded intent')
        record['objects'][kind] = rows[0]['uuid']
        self._save(record)
        return self.api('GET', path + rows[0]['uuid'])

    def _squad_check(self, value, plan, record):
        require(value['uuid'] == record['objects']['squad'] and value['name'] == plan['squad_name'] and
                ids(value['inbounds']) == [record['backend']], 'Private backend squad escaped scope')

    def _user_check(self, value, record):
        body = record['intents']['user']
        require(all(value.get(k) == body[k] for k in ('uuid', 'username', 'tag', 'description', 'trafficLimitBytes', 'trafficLimitStrategy')),
                'Backend service user identity drift')
        require(ids(value['activeInternalSquads']) == body['activeInternalSquads'] and value['status'] == 'ACTIVE', 'Backend service user access drift')
        require(abs(p.timestamp(value['expireAt']) - p.timestamp(body['expireAt'])) < 1, 'Service expiry drift')
        model._service_uuid(value['vlessUuid'])
        if 'service_uuid' in record:
            require(value['vlessUuid'] == record['service_uuid'], 'Service VLESS identity drift')

    def _private_user(self, plan, record):
        if 'user' not in record['intents']:
            body = dict(uuid=str(uuid.uuid4()), username='c140six_' + record['id'] + '_backend',
                        expireAt=(datetime.fromtimestamp(self.clock(), timezone.utc) + timedelta(days=3650)).isoformat(),
                        trafficLimitBytes=0, trafficLimitStrategy='NO_RESET', tag=service_tag(record['id']),
                        description='Private CLOUD140 six-route backend; not a customer', activeInternalSquads=[record['objects']['squad']])
            record['intents']['user'] = body
            self._save(record)
            try:
                self.api('POST', '/api/users/', body)
            except Exception:
                pass
        user = self.api('GET', '/api/users/' + record['intents']['user']['uuid'])
        self._user_check(user, record)
        record['objects']['user'], record['service_uuid'] = user['uuid'], user['vlessUuid']
        self._save(record)

    def _mapping(self, before, record):
        names = model.legacy_tag_map(before['profile']['config'], record['id'])
        return {iid: record['metadata'][names[tag]] for tag, iid in metadata(before['profile']).items()}

    def _rights(self, before, plan, record, apply=False, rollback=False):
        squads = p.indexed(self.api('GET', '/api/internal-squads/')['internalSquads'])
        mapping = self._mapping(before, record)
        cloned = set(mapping.values())
        original_rights = {s['uuid']: set(ids(s['inbounds'])) & set(mapping) for s in before['squads']}
        for sid, old in original_rights.items():
            require(not old or sid in squads and old <= set(ids(squads[sid]['inbounds'])), 'Original legacy rights revoked')
        for sid, squad in squads.items():
            current = set(ids(squad['inbounds']))
            if sid == record['objects'].get('squad'):
                self._squad_check(squad, plan, record)
                continue
            require(record['backend'] not in current, 'Backend access granted to a customer/foreign squad')
            owned = set(record['rights'].get(sid, {}).get('added', []))
            require(current & cloned <= owned, 'Clone grant has no ownership intent')
            needed = {new for old, new in mapping.items() if old in current}
            if apply and needed - owned:
                grant = record['rights'].setdefault(sid, dict(added=[]))
                grant['added'] = sorted(owned | needed)
            elif not rollback and not apply:
                require(needed | owned <= current, 'Legacy clone rights incomplete; restage before applying')
        require(set(record['rights']) <= set(squads), 'Owned grant squad disappeared')
        if apply:
            self._save(record)  # Every ownership intent before any grant PATCH.
            for sid, grant in record['rights'].items():
                current = ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
                desired = sorted(set(current) | set(grant['added']))
                if desired != current:
                    self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=desired))
                actual = ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
                require(set(desired) <= set(actual), 'Grant readback lost rights')

    def _resources(self, before, plan, record):
        self._squad_check(self.api('GET', '/api/internal-squads/' + record['objects']['squad']), plan, record)
        self._user_check(self.api('GET', '/api/users/' + record['objects']['user']), record)
        self._rights(before, plan, record)

    def _armed(self, record):
        require('arm_intent' in record and 0 <= self.clock() - record['arm_intent'] < TTL, 'Rollback deadline passed')
        self.timer.armed(record['id'])

    def stage(self, route_id):
        require(route_id in ACTIVE_ROUTES, 'Route withdrawn from current deployment scope')
        before, plan, record = self._load(route_id)
        require(not any(k in record for k in ('apply_intent', 'rolled_back', 'finished')), 'Staging lifecycle closed')
        validate_inputs(plan['inputs'], before['route'], self.clock())
        self._proof(record.get('installed_proof'), before, plan, record, 'installed')
        self._guard(before, plan, record)
        if 'arm_intent' not in record:
            record['arm_intent'] = self.clock()
            self._save(record)
            self.timer.start(route_id)
        self._armed(record)
        tags = {v['tag'] for v in plan['candidate']['inbounds']}
        for value in self.api('GET', '/api/config-profiles/')['configProfiles']:
            if value['name'] != plan['name']:
                require(not tags & set(metadata(self.api('GET', '/api/config-profiles/' + value['uuid']))), 'Clone inbound tag collision')
        profile = self._named(record, 'profile', '/api/config-profiles/', 'configProfiles', dict(name=plan['name'], config=plan['candidate']))
        self._profile_check(profile, plan, record)
        record['metadata'] = metadata(profile)
        record['backend'] = record['metadata'][model.route_tags(route_id)['backend']]
        mapping = self._mapping(before, record)
        record['desired_binding'] = dict(profile=profile['uuid'], inbounds=sorted(
            [mapping[iid] for iid in binding(before['node'])['inbounds']] + [record['backend']]))
        self._save(record)
        squad = self._named(record, 'squad', '/api/internal-squads/', 'internalSquads', dict(name=plan['squad_name'], inbounds=[record['backend']]))
        self._squad_check(squad, plan, record)
        self._private_user(plan, record)
        # Service identity may not match any pre-existing manually configured client.
        require(all(c.get('id') != record['service_uuid'] for raw in before['profile']['config']['inbounds']
                    for c in raw.get('settings', {}).get('clients', [])), 'Service identity collides with legacy client')
        self._rights(before, plan, record, apply=True)
        self._resources(before, plan, record)
        self._guard(before, plan, record)
        self._armed(record)
        record['staged'] = self.clock()
        self._save(record)
        return self.summary(record)

    def _node_patch(self, node_id, wanted):
        self.api('PATCH', '/api/nodes/', dict(uuid=node_id, configProfile=dict(
            activeConfigProfileUuid=wanted['profile'], activeInbounds=wanted['inbounds'])))
        require(binding(self.api('GET', '/api/nodes/' + node_id)) == wanted, 'Node binding PATCH readback failed')

    def apply(self, route_id):
        require(route_id in ACTIVE_ROUTES, 'Route withdrawn from current deployment scope')
        before, plan, record = self._load(route_id)
        require('staged' in record and not any(k in record for k in ('rolled_back', 'finished', 'rollback_intent')), 'Cannot apply this lifecycle')
        validate_inputs(plan['inputs'], before['route'], self.clock())
        self._proof(record.get('installed_proof'), before, plan, record, 'installed')
        self._proof(record.get('baseline_proof'), before, plan, record, 'baseline')
        node, _ = self._guard(before, plan, record)
        self._resources(before, plan, record)
        self._armed(record)
        if binding(node) != record['desired_binding']:
            require(node['isConnected'] and 'apply_intent' not in record, 'Prior activation uncertain or node disconnected')
            record['apply_intent'] = self.clock()
            self._save(record)
            self._node_patch(before['route']['node'], record['desired_binding'])
        mapping = self._mapping(before, record)
        for old in before['hosts']:
            hb = host_binding(old)
            # Known GB main/auto mismatch remains unchanged; only active-profile
            # hosts (including its bypass) map to an equivalent cloned inbound.
            if hb['configProfileUuid'] != before['profile']['uuid']:
                continue
            wanted = dict(configProfileUuid=record['objects']['profile'], configProfileInboundUuid=mapping[hb['configProfileInboundUuid']])
            current = self.api('GET', '/api/hosts/' + old['uuid'])
            if host_binding(current) != wanted:
                require(old['uuid'] not in record['host_intents'] and stable_host(current) == stable_host(old), 'Host activation uncertain/drift')
                record['host_intents'][old['uuid']] = dict(wanted=wanted)
                self._save(record)
                self.api('PATCH', '/api/hosts/', dict(uuid=old['uuid'], inbound=wanted))
            require(host_binding(self.api('GET', '/api/hosts/' + old['uuid'])) == wanted, 'Host clone binding readback failed')
        self._guard(before, plan, record)
        self._resources(before, plan, record)
        self._armed(record)
        record.setdefault('applied', self.clock())
        self._save(record)
        return self.summary(record)

    def export_backend(self, route_id):
        before, plan, record = self._load(route_id)
        require('staged' in record and 'rolled_back' not in record, 'Backend is not staged')
        self._guard(before, plan, record)
        self._resources(before, plan, record)
        inputs = plan['inputs']
        user = dict(id=record['service_uuid'], encryption='none')
        if inputs['mode'] == 'reality':
            user['flow'] = 'xtls-rprx-vision'
            stream = dict(network='raw', security='reality', realitySettings=dict(
                serverName=inputs['server_names'][0], fingerprint='chrome',
                publicKey=p.public_key(plan['identity']['privateKey']), shortId=plan['identity']['shortIds'][0]))
            address, port = before['route']['ip'], inputs['backend_port']
            if 'forward_tunnel' in record:
                address, port = '127.0.0.1', record['forward_tunnel']['tunnel']['listener_port']
        else:
            stream = dict(network='raw', security='none')
            address, port = '127.0.0.1', inputs['tunnel']['listener_port']
        outbound = dict(protocol='vless', settings=dict(vnext=[dict(address=address, port=port, users=[user])]), streamSettings=stream)
        return dict(id=route_id, sha256=record['sha256'], expected_egress=inputs['expected_egress'], mode=inputs['mode'],
                    transport='forward-ssh+reality' if 'forward_tunnel' in record else inputs['mode'], outbound=outbound)

    def attach_forward(self, route_id, proof):
        """Use an independently verified fixed SSH forward; exit wire stays exact.

        No profile/node/host mutation. The old direct REALITY endpoint is kept
        source-restricted, and REALITY still authenticates inside the SSH leg.
        Only two approved fallback loopback ports are accepted.
        """
        before, plan, record = self._load(route_id)
        require(route_id in ('at','gbpower') and plan['inputs']['mode']=='reality'
                and 'applied' in record and not any(k in record for k in ('finished','rolled_back','rollback_intent')),
                'Forward fallback lifecycle unavailable')
        self._guard(before,plan,record);self._resources(before,plan,record);self._armed(record)
        scope_proof(proof,before['route'],self.clock())
        fresh(proof['timestamp'],self.clock(),record['applied'])
        require(proof.get('sha256')==record['sha256'] and proof.get('entry')==p.ENTRY,'Forward proof candidate/source mismatch')
        failed=proof['direct_failure'];tunnel=proof['tunnel']
        require(failed.get('sha256')==record['sha256'] and failed.get('entry')==p.ENTRY
                and failed.get('authenticated_direct_attempted') is True and failed.get('passed') is False,
                'Actual direct failure required')
        fresh(failed.get('timestamp'),self.clock(),record['applied'])
        require(tunnel.get('listener_address')=='127.0.0.1' and tunnel.get('listener_port')=={'at':21445,'gbpower':21448}[route_id]
                and tunnel.get('target_address')==before['route']['ip'] and tunnel.get('target_port')==plan['inputs']['backend_port']
                and tunnel.get('ssh_server')==before['route']['ip'],'Forward endpoints escaped scope')
        require(all(tunnel.get(k) is True for k in ('host_key_pinned','restricted_identity','fixed_target_verified',
                    'persistent_service_verified','restart_recovery_verified','loopback_only')),'Fixed persistent forward not verified')
        if 'forward_tunnel' in record:
            require(record['forward_tunnel']==proof,'Cannot replace attached forward')
        else:
            record['forward_tunnel']=deepcopy(proof)
            record.pop('backend_proof',None)
            self._save(record)
        return dict(id=route_id,forward_attached=True,exit_config_unchanged=True,backend_proof_still_required=True)

    def finish(self, route_id):
        before, plan, record = self._load(route_id)
        require('applied' in record and 'rolled_back' not in record and 'rollback_intent' not in record, 'Backend not applied or rollback started')
        node, hosts = self._guard(before, plan, record)
        require(node['isConnected'] and binding(node) == record['desired_binding'], 'Node not connected on candidate')
        require(all(host_binding(hosts[hid]) == intent['wanted'] for hid, intent in record['host_intents'].items()), 'Legacy host binding incomplete')
        self._resources(before, plan, record)
        if 'finished' not in record:
            self._armed(record)
            self._proof(record.get('backend_proof'), before, plan, record, 'backend')
            record['finished'] = self.clock()
            self._save(record)  # Under flock: a racing rollback must skip success.
        self.timer.cancel(route_id)
        self._guard(before, plan, record)
        legacy = [t for t in record['backend_proof']['tests'] if t['kind'] == 'legacy']
        return dict(**self.summary(record), rollback_timer_and_service_inactive=True,
                    legacy_cases_passed=sum(t['passed'] for t in legacy),
                    preexisting_legacy_failures_remaining=sum(not t['passed'] for t in legacy))

    def status(self, route_id):
        before, plan, record = self._load(route_id)
        node, _ = self._guard(before, plan, record)
        if 'staged' in record and 'rolled_back' not in record:
            self._resources(before, plan, record)
        return dict(**self.summary(record), node_connected=node['isConnected'])

    def rollback(self, route_id):
        before, plan, record = self._load(route_id)
        if 'finished' in record:
            return dict(id=route_id, rollback_skipped_finished=True)
        node, hosts = self._guard(before, plan, record)
        # Guard every owned resource BEFORE the first rollback mutation. A
        # half-created inactive profile may remain, but no new objects are made.
        if 'metadata' in record:
            self._rights(before, plan, record, rollback=True)
        if 'squad' in record['objects']:
            self._squad_check(self.api('GET', '/api/internal-squads/' + record['objects']['squad']), plan, record)
        if 'user' in record['objects']:
            self._user_check(self.api('GET', '/api/users/' + record['objects']['user']), record)
            # Once a LIVE entry profile consumes this service identity, its
            # owner must roll back the frontend first. Never strand users.
            active_profiles = {binding(n)['profile'] for n in self.api('GET', '/api/nodes/')}
            for pid in active_profiles - {None, record['objects']['profile']}:
                config = self.api('GET', '/api/config-profiles/' + pid)['config']
                require(not any(u.get('id') == record['service_uuid'] for out in config.get('outbounds', [])
                    for hop in out.get('settings', {}).get('vnext', []) for u in hop.get('users', [])),
                    'Live frontend consumes backend; coordinate frontend rollback first')
        record.setdefault('rollback_intent', self.clock())
        self._save(record)
        # Restore node before hosts/rights; the original profile and original
        # grants have never been changed or removed by this operation.
        original = binding(before['node'])
        if binding(node) != original:
            self._node_patch(before['route']['node'], original)
        for old in before['hosts']:
            hid = old['uuid']
            if hid not in record['host_intents']:
                continue
            current = self.api('GET', '/api/hosts/' + hid)
            if host_binding(current) != host_binding(old):
                require(host_binding(current) == record['host_intents'][hid]['wanted'], 'Host changed during rollback')
                self.api('PATCH', '/api/hosts/', dict(uuid=hid, inbound=host_binding(old)))
            require(stable_host(self.api('GET', '/api/hosts/' + hid)) == stable_host(old), 'Host restoration readback failed')
        for sid, grant in record['rights'].items():
            current = ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
            desired = [v for v in current if v not in grant['added']]
            if desired != current:
                self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=desired))
            actual = ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
            require(set(desired) <= set(actual) and not set(grant['added']) & set(actual), 'Rollback rights readback failed')
        record['rolled_back'] = self.clock()
        self._save(record)
        self._guard(before, plan, record)
        # Do not systemctl-stop our own running rollback service. It exits
        # naturally; caller verifies timer/service after completion.
        return dict(id=route_id, original_binding_restored=True, own_legacy_grants_removed=True,
                    inactive_owned_objects_retained=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = ('prepare', 'export-candidate', 'accept-installed', 'accept-baseline', 'stage', 'apply', 'export-backend', 'attach-forward',
               'accept-backend', 'finish', 'status', 'rollback')
    parser.add_argument('action', choices=actions)
    parser.add_argument('--id', required=True, choices=tuple(model.TARGETS))
    parser.add_argument('--secret-stdout', action='store_true')
    args = parser.parse_args(argv)
    exports = args.action in ('export-candidate', 'export-backend')
    require(args.secret_stdout == exports and (not exports or not sys.stdout.isatty()), 'Explicit private export pipe required')
    os.umask(0o077)
    store = RootStore(args.id)
    with store.locked():
        adapter = p.load_file('six_exit_panel_api', p.ROOT.parent / 'selfsteal-us3' / 'panel_api.py')
        api, _query = adapter.create_client()
        worker = Coordinator(api, store, SystemdTimer())
        method = getattr(worker, args.action.replace('-', '_'))
        result = method(args.id, json.load(sys.stdin)) if args.action in ('prepare', 'accept-installed', 'accept-baseline', 'accept-backend','attach-forward') else method(args.id)
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, SafetyError) else 'Exit stage failed; inspect protected state'
        print(json.dumps(dict(error=message)), file=sys.stderr)
        sys.exit(1)
