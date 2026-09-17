"""One-at-a-time CLOUDru frontend lifecycle; no SSH/DNS/site/exit mutation.

Approved --id at|pl|cz|gbpower uses 18445|18446|18447|18448 respectively.
Each route snapshots the CURRENT dedicated entry profile, preserving previously
finished routes, all legacy identities/listeners and existing host UUIDs. A
global frontend flock forbids concurrent unfinished route operations. Rollback
is exact owned-state guarded; it never overwrites a later/foreign profile edit.

Lifecycle (JSON stdin for prepare/accept-*/export-baseline/export-subscription):
 prepare -> export-config -> accept-installed; export-baseline -> actual tests
 -> accept-baseline; stage -> export-public -> tests -> accept-public -> publish
 -> export-subscription -> tests -> accept-subscription -> finish.
stage arms an independent 20-minute rollback before the first panel PATCH.
The exit must already be finished; this module never rolls it back.

prepare input: {runtime:{id:'entry',node,ip,timestamp,port,port_free:true,
 namespace_verified:true,firewall_ready:true,xray_version}, site:<below>,
 auto_remark:<actual existing Happ aggregate remark, only when an auto exists>}.
site attestation: {entry,timestamp,loopback_port:9444,chain_verified:true,
 certificate_valid:true,dns_verified:true,checks:[{sni,tls:'TLSv1.3',alpn:'h2'}],
 https_sites:[{sni,status:200,sha256}],renewal_dry_run_passed:true,
 renewal_performed_at:<actual <=24h>,deploy_hook:true,timer_enabled:true,
 timer_active:true}. Both lists must cover exactly the four approved names.
accept-site refreshes this independent actual check, never fabricates it.

export-baseline input: {items:[{id,client:'xray'|'mihomo',wire:<exact outbound
 or proxy object>,expected_egress:<observed IP>}]}; cover entry ports443/18444,
using cached SAME UUID/settings, never a full config with random local ports.
Export results are SECRET and require --secret-stdout. Each request contains
sha256, request_sha256 and items with a stable wire_sha256. Proofs contain these
hashes, timestamp, tests:[{id,client,wire_sha256,passed,authenticated,http_code,
 exit_ip,returncodes:[HTTPS,egress]}]. Baseline may record real old failures;
public legacy rechecks may not regress successes or observed partial success.
New candidate and actual-subscription tests must ALL pass204+expectedegress.
Candidate requests exercise Xray AND Mihomo for main AND existing auto; fresh
subscription requests exercise Happ/Xray main/auto and Mihomo main (no invented
Mihomo auto membership). GBpower has no auto; none is created.

export-subscription input: {headers:<existing authorized device headers>}.
The link is fetched privately from the supported panel API for the owned probe
user; HTTPS/no redirects, actual Happ JSON and Mihomo YAML are fetched anew.
PyYAML is required by the CLI fetcher; verify availability before publication.
No invented HWID, secret URL in argv/logs, customer edits or reload of user apps.
"""

import argparse
from contextlib import contextmanager
from copy import deepcopy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import exit_stage as c
import preflight as p
import route_model as model

PORTS = {'at': 18445, 'pl': 18446, 'cz': 18447, 'gbpower': 18448}
DOMAINS = {model.DOMAINS[key] for key in PORTS}
STATE = Path('/root/hamvpn-cloud140-six-20260918/frontend')
TTL = 1200
HOST_FIELDS = ('nodes', 'inbound', 'address', 'port', 'sni', 'host')
require, checksum = c.require, p.digest


def route(route_id):
    require(route_id in PORTS, 'Frontend route is outside current scope')
    return c.target(route_id)


def wire_hash(client, wire):
    require(client in ('xray', 'mihomo') and isinstance(wire, dict), 'Unsupported client wire')
    # Same convention as node_ops. Only local labels are omitted. Credentials,
    # fingerprints, flags and unknown meaningful fields remain in the digest.
    label = 'tag' if client == 'xray' else 'name'
    return checksum({k: v for k, v in wire.items() if k != label})


def wire_endpoint(client, wire):
    if client == 'xray':
        require(wire.get('protocol') == 'vless' and not wire.get('proxySettings'), 'Probe must be direct VLESS')
        hops = wire.get('settings', {}).get('vnext', [])
        require(len(hops) == 1 and len(hops[0].get('users', [])) == 1, 'Ambiguous VLESS destination/identity')
        stream = wire.get('streamSettings', {})
        require(stream.get('network', 'raw') in ('raw', 'tcp') and stream.get('security') in ('tls', 'reality')
                and not stream.get('sockopt', {}).get('dialerProxy')
                and stream.get('tlsSettings', {}).get('allowInsecure', False) is False
                and not wire.get('mux', {}).get('enabled', False), 'Unsupported/insecure probe transport')
        return hops[0]['address'], hops[0]['port'], hops[0]['users'][0]['id']
    require(client == 'mihomo' and wire.get('type') == 'vless' and wire.get('tls') is True
            and wire.get('network', 'tcp') == 'tcp' and not wire.get('dialer-proxy')
            and wire.get('skip-cert-verify', False) is False, 'Unsupported/insecure Mihomo proxy')
    return wire['server'], wire['port'], wire['uuid']


def site_check(proof, now):
    require(isinstance(proof, dict) and proof.get('entry') == p.ENTRY and proof.get('loopback_port') == 9444,
            'Site proof targets another entry/port')
    c.fresh(proof.get('timestamp'), now)
    for flag in ('chain_verified', 'certificate_valid', 'dns_verified', 'renewal_dry_run_passed',
                 'deploy_hook', 'timer_enabled', 'timer_active'):
        require(proof.get(flag) is True, 'Site/renewal verification incomplete')
    performed = proof.get('renewal_performed_at')
    require(type(performed) in (int, float) and 0 <= now - performed <= 86400 and performed <= proof['timestamp'],
            'Actual renewal timestamp missing/stale/future')
    checks, sites = proof.get('checks'), proof.get('https_sites')
    require(isinstance(checks, list) and len(checks) == len(DOMAINS) and {v.get('sni') for v in checks} == DOMAINS
            and all(v.get('tls') == 'TLSv1.3' and v.get('alpn') == 'h2' for v in checks), 'All four local TLS names must pass')
    require(isinstance(sites, list) and len(sites) == len(DOMAINS) and {v.get('sni') for v in sites} == DOMAINS
            and all(type(v.get('status')) is int and v['status'] == 200 and
                    isinstance(v.get('sha256'), str) and re.fullmatch('[a-f0-9]{64}', v['sha256']) for v in sites), 'All four actual HTTPS pages must pass')


def runtime_check(value, route_id, now):
    require(isinstance(value, dict) and value.get('id') == 'entry' and value.get('node') == p.ENTRY_ID
            and value.get('ip') == p.ENTRY and value.get('port') == PORTS[route_id], 'Entry runtime scope mismatch')
    c.fresh(value.get('timestamp'), now)
    require(all(value.get(flag) is True for flag in ('port_free', 'namespace_verified', 'firewall_ready')), 'Frontend runtime not verified')
    require(isinstance(value.get('xray_version'), str) and re.fullmatch('[0-9][A-Za-z0-9.+_-]{0,63}', value['xray_version']), 'Installed entry version missing')


class RootStore(c.RootStore):
    def __init__(self, route_id):
        route(route_id)
        super().__init__(route_id, STATE / route_id)
        self.route_id = route_id

    def serial(self):
        for key in PORTS:
            path = STATE / key
            if key == self.route_id or not path.exists():
                continue
            store = p.Store(path)
            if store.exists('operation'):
                record = store.get('operation')
                require('finished' in record or 'rolled_back' in record, 'Finish or roll back the other frontend route first')
            else:
                require(not store.exists('before') and not store.exists('plan'), 'Other route has incomplete protected state')

    @contextmanager
    def locked(self):
        import fcntl
        self.secure()
        fd = os.open(STATE / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1, 'Unsafe global frontend lock')
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


class Timers(c.SystemdTimer):
    def name(self, route_id):
        route(route_id)
        return 'ham-cloud140-six-' + route_id + '-front-rollback'

    def start(self, route_id):
        name = self.name(route_id)
        for suffix in ('.timer', '.service'):
            value = self.state(name + suffix, True)
            require(value['LoadState'] == 'not-found' and value['ActiveState'] == 'inactive' and value['SubState'] == 'dead', 'Frontend rollback unit already exists')
        result = self.run(['systemd-run', '--unit=' + name, '--on-active=' + str(TTL) + 's',
            '--timer-property=AccuracySec=1s', '--property=UMask=0077', sys.executable,
            str(Path(__file__).resolve()), 'rollback', '--id', route_id], capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Frontend timer creation uncertain')
        self.armed(route_id)


def fetch_subscription(url, headers, kind):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password, 'Subscription URL must use HTTPS')
    allowed = {'x-hwid', 'x-device-os', 'x-ver-os', 'x-device-model'}
    require(isinstance(headers, dict) and set(headers) <= allowed and 'x-hwid' in headers and
            all(isinstance(v, str) and v and '\r' not in v and '\n' not in v for v in headers.values()), 'Existing device headers required; no invented HWID')
    require(kind in ('happ', 'mihomo'), 'Unknown subscription format')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise c.SafetyError('Subscription redirects require review')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={'User-Agent': 'Happ/5.7.0' if kind == 'happ' else 'mihomo/1.19.29', **headers})
    with opener.open(request, timeout=30) as response:
        require(response.status == 200, 'Subscription request failed')
        data = response.read(8 * 1024 * 1024 + 1)
    require(len(data) <= 8 * 1024 * 1024, 'Subscription exceeds bounded size')
    if kind == 'happ':
        value = json.loads(data)
        require(isinstance(value, list) and all(isinstance(v, dict) for v in value), 'Unsupported Happ subscription response')
    else:
        import yaml
        value = yaml.safe_load(data)
        require(isinstance(value, dict) and isinstance(value.get('proxies'), list), 'Unsupported Mihomo subscription response')
    return value


class Frontend:
    def __init__(self, api, store, core, timer, baseline_store=None, clock=time.time,
                 identity_factory=c.new_identity, subscription_fetch=fetch_subscription):
        self.api, self.store, self.core, self.timer = api, store, core, timer
        self.baseline_store, self.clock = baseline_store or p.Store(), clock
        self.identity_factory, self.subscription_fetch = identity_factory, subscription_fetch

    def _save(self, value):
        self.store.save('operation', value)

    def _core(self, route_id, expected=None):
        before, plan, record = self.core._load(route_id)
        require('finished' in record and 'rolled_back' not in record and 'rollback_intent' not in record, 'Finish verified backend before frontend preparation')
        if expected:
            require(record['sha256'] == expected['candidate_sha256'] and record['objects'] == expected['objects']
                    and record['service_uuid'] == expected['service_uuid'], 'Backend identity changed')
        self.core._profile_check(self.api('GET', '/api/config-profiles/' + record['objects']['profile']), plan, record)
        source = self.api('GET', '/api/config-profiles/' + before['profile']['uuid'])
        require(source['config'] == before['profile']['config'] and c.metadata(source) == c.metadata(before['profile']), 'Original exit profile changed')
        node = self.api('GET', '/api/nodes/' + before['route']['node'])
        require(node['address'] == before['route']['ip'] and node['isConnected'] and not node['isDisabled']
                and c.binding(node) == record['desired_binding'], 'Backend node not connected on verified clone')
        self.core._resources(before, plan, record)
        return before, plan, record

    def _load(self, route_id):
        route(route_id)
        before, plan, record = self.store.get('before'), self.store.get('plan'), self.store.get('operation')
        require(plan['id'] == record['id'] == route_id and record['snapshot_sha256'] == plan['snapshot_sha256'] == checksum(before)
                and record['plan_sha256'] == checksum(plan), 'Frontend state scope/hash mismatch')
        expected = model.build_entry_config(before['profile']['config'], route_id, PORTS[route_id], model.DOMAINS[route_id],
                                           plan['identity'], plan['backend']['outbound'])
        require(expected == plan['candidate'] and checksum(expected) == record['sha256'], 'Frontend model/candidate mismatch')
        require(expected['inbounds'][-1]['streamSettings']['realitySettings']['minClientVer'] == '1.8.2', 'New frontend must retain approved Mihomo compatibility')
        return before, plan, record

    @staticmethod
    def summary(record):
        return dict(id=record['id'], sha256=record['sha256'], staged='staged' in record,
                    published='published' in record and 'rolled_back' not in record,
                    finished='finished' in record, rolled_back='rolled_back' in record)

    def _user(self, before=None):
        user = p.probe_user(self.api, self.baseline_store)
        model._service_uuid(user['vlessUuid'])
        if before:
            require(user['uuid'] == before['probe']['uuid'] and user['vlessUuid'] == before['probe']['vlessUuid'], 'Technical probe identity changed')
            require(set(before['customers']) <= set(c.ids(user['activeInternalSquads'])), 'Probe lacks selected customer rights')
        return user

    def prepare(self, route_id, request):
        selected = route(route_id)
        self.store.serial()
        require(set(request) <= {'runtime', 'site', 'auto_remark'}, 'Unknown frontend preparation input')
        runtime_check(request['runtime'], route_id, self.clock())
        site_check(request['site'], self.clock())
        if self.store.exists('operation'):
            before, plan, record = self._load(route_id)
            require('finished' not in record and 'rolled_back' not in record and request['runtime'] == plan['runtime'], 'Existing operation cannot be replaced')
            self._guard(before, plan, record)
            return self.summary(record)
        require(not self.store.exists('before') and not self.store.exists('plan'), 'Incomplete preparation needs explicit inspection')
        _exit_before, _exit_plan, core = self._core(route_id)
        backend = self.core.export_backend(route_id)
        baseline = p.baseline(self.baseline_store)
        node = self.api('GET', '/api/nodes/' + p.ENTRY_ID)
        require(node['address'] == p.ENTRY and node['isConnected'] and not node['isDisabled'], 'Entry identity/health mismatch')
        profile = self.api('GET', '/api/config-profiles/' + c.binding(node)['profile'])
        require({n['uuid'] for n in self.api('GET', '/api/nodes/') if c.binding(n)['profile'] == profile['uuid']} == {p.ENTRY_ID}, 'Entry profile must be dedicated')
        require({443, 18444} <= {i.get('port') for i in profile['config']['inbounds']}, 'Expected legacy entry endpoints missing')
        require(set(c.binding(node)['inbounds']) <= set(c.metadata(profile).values()), 'Entry metadata/binding mismatch')
        host_ids = [selected['host']] + ([p.AUTOS[route_id]] if p.AUTOS[route_id] else [])
        all_hosts = p.indexed(self.api('GET', '/api/hosts/'))
        hosts = [all_hosts[hid] for hid in host_ids]
        squads = p.indexed(self.api('GET', '/api/internal-squads/')['internalSquads'])
        rights = []
        for index, host in enumerate(hosts):
            require(host['nodes'] == [selected['node']] and not host['isDisabled'] and host['isHidden'] is bool(index), 'Selected main/auto host identity changed')
            require(set(HOST_FIELDS) <= set(host), 'Host API projection lacks restorable publication fields')
            original = p.indexed(baseline['hosts'])[host['uuid']]
            wire = deepcopy(host); wire['inbound'] = original['inbound']
            require(c.stable_host(wire) == c.stable_host(original), 'Selected host wire differs from approved preflight')
            require(c.host_binding(host)['configProfileUuid'] == core['objects']['profile'], 'Host must use the finished exit clone')
            inbound = c.host_binding(host)['configProfileInboundUuid']
            actual = {sid for sid, s in squads.items() if s['name'] in p.CUSTOMER_NAMES and inbound in c.ids(s['inbounds'])}
            require(actual == set(baseline['customer_rights'][host['uuid']]) and actual and core['objects']['squad'] not in actual, 'Customer rights changed or include backend squad')
            rights.append(actual)
        require(all(value == rights[0] for value in rights), 'Main/auto need identical inbound rights; cannot silently broaden access')
        require((len(hosts) == 1 and 'auto_remark' not in request) or (len(hosts) == 2 and isinstance(request.get('auto_remark'), str) and bool(request['auto_remark'])), 'Supply only the observed existing auto-group remark')
        identity = self.identity_factory()
        candidate = model.build_entry_config(profile['config'], route_id, PORTS[route_id], model.DOMAINS[route_id], identity, backend['outbound'])
        require(candidate['inbounds'][-1]['streamSettings']['realitySettings']['minClientVer'] == '1.8.2', 'Model compatibility floor missing')
        probe = self._user()
        require(rights[0] <= set(c.ids(probe['activeInternalSquads'])), 'Probe lacks ordinary customer membership')
        before = dict(entry=node, profile=profile, hosts=hosts, customers={sid: squads[sid] for sid in sorted(rights[0])},
            probe=dict(uuid=probe['uuid'], vlessUuid=probe['vlessUuid']), timestamp=self.clock(),
            untouched_hosts=[h for h in all_hosts.values() if p.ENTRY_ID in h.get('nodes', [])],
            core=dict(candidate_sha256=core['sha256'], objects=deepcopy(core['objects']), service_uuid=core['service_uuid']))
        plan = dict(id=route_id, snapshot_sha256=checksum(before), candidate=candidate, identity=identity,
                    backend=backend, runtime=deepcopy(request['runtime']), auto_remark=request.get('auto_remark'), prepared_at=self.clock())
        self.store.put('before', before); self.store.put('plan', plan)
        record = dict(id=route_id, snapshot_sha256=checksum(before), plan_sha256=checksum(plan), sha256=checksum(candidate),
                      proofs=dict(site=deepcopy(request['site'])), requests={}, grants={}, host_intents={})
        self._save(record)
        self._guard(before, plan, record)
        return self.summary(record)

    def _desired(self, old, plan, record):
        require(record.get('front'), 'Frontend metadata is not known')
        host = deepcopy(old)
        # Address, Host and SNI use the approved own DNS name. Site proof must
        # verify that name resolves to the entry, before candidate/public tests.
        host.update(nodes=[p.ENTRY_ID], inbound=dict(configProfileUuid=record['profile'], configProfileInboundUuid=record['front']),
                    address=model.DOMAINS[plan['id']], port=PORTS[plan['id']], sni=model.DOMAINS[plan['id']], host=model.DOMAINS[plan['id']])
        return host

    def _guard(self, before, plan, record, live=False, published=False):
        self._core(plan['id'], before['core'])
        nodes = self.api('GET', '/api/nodes/')
        node = next(n for n in nodes if n['uuid'] == p.ENTRY_ID)
        require(all(node.get(k) == before['entry'].get(k) for k in ('address', 'name', 'port', 'isDisabled')), 'Entry management fields changed')
        pid = before['profile']['uuid']
        require({n['uuid'] for n in nodes if c.binding(n)['profile'] == pid} == {p.ENTRY_ID}, 'Entry profile acquired another consumer')
        profile = self.api('GET', '/api/config-profiles/' + pid)
        allowed = [before['profile']['config']]
        if 'apply_intent' in record and 'rolled_back' not in record: allowed.append(plan['candidate'])
        require(profile['config'] in allowed and (not live or profile['config'] == plan['candidate']), 'Entry profile drift')
        original_meta, current_meta = c.metadata(before['profile']), c.metadata(profile)
        require(all(current_meta.get(tag) == uid for tag, uid in original_meta.items()), 'Legacy entry metadata changed')
        front_tag = model.route_tags(plan['id'])['front']
        if profile['config'] == plan['candidate']:
            require(set(current_meta) == set(original_meta) | {front_tag}, 'Unexpected frontend metadata')
            front = current_meta[front_tag]
            require(not record.get('front') or record['front'] == front, 'Frontend inbound identity changed')
        else:
            require(current_meta == original_meta, 'Original profile metadata mismatch')
            front = record.get('front')
        original_binding = c.binding(before['entry'])
        wanted = dict(profile=pid, inbounds=sorted(original_binding['inbounds'] + ([front] if front else [])))
        allowed_bindings = [original_binding]
        if 'binding_intent' in record and 'rolled_back' not in record: allowed_bindings.append(wanted)
        require(c.binding(node) in allowed_bindings and (not live or c.binding(node) == wanted and node['isConnected']), 'Unexpected entry active inbounds')
        hosts = p.indexed(self.api('GET', '/api/hosts/'))
        for old in before['untouched_hosts']:
            require(c.stable_host(hosts[old['uuid']]) == c.stable_host(old), 'Existing entry host changed')
        selected_ids = {h['uuid'] for h in before['hosts']}
        for host in hosts.values():
            hb = c.host_binding(host)
            require(not (front and hb['configProfileUuid'] == pid and hb['configProfileInboundUuid'] == front and host['uuid'] not in selected_ids), 'Foreign host references new frontend')
        for old in before['hosts']:
            permitted = [c.stable_host(old)]
            desired = self._desired(old, plan, {**record, 'profile': pid, 'front': front}) if front else None
            if old['uuid'] in record['host_intents'] and 'rolled_back' not in record:
                require(desired is not None and record['host_intents'][old['uuid']] == checksum(c.stable_host(desired)), 'Host intent hash differs from owned delta')
                permitted.append(c.stable_host(desired))
            require(c.stable_host(hosts[old['uuid']]) in permitted, 'Selected host edited outside owned publication delta')
            if published: require(c.stable_host(hosts[old['uuid']]) == c.stable_host(desired), 'Host publication incomplete')
        return profile, front, node

    def _rights(self, before, record, apply=False, required=False):
        squads = p.indexed(self.api('GET', '/api/internal-squads/')['internalSquads'])
        front = record.get('front')
        for sid, old in before['customers'].items():
            require(sid in squads and squads[sid]['name'] == old['name'] and set(c.ids(old['inbounds'])) <= set(c.ids(squads[sid]['inbounds'])), 'Original customer rights changed')
        for sid, squad in squads.items():
            if front in c.ids(squad['inbounds']):
                require(sid in before['customers'] and sid in record['grants'], 'Unowned/service frontend grant')
        if apply:
            record['grants'] = {sid: front for sid in before['customers']}
            self._save(record)
            for sid in record['grants']:
                current = c.ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
                desired = sorted(set(current) | {front})
                if desired != current: self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=desired))
                require(set(desired) <= set(c.ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])), 'Frontend grant readback failed')
        if required:
            require(set(record['grants']) == set(before['customers']) and all(front in c.ids(squads[sid]['inbounds']) for sid in record['grants']), 'Customer frontend grants incomplete')

    def _armed(self, record):
        require('arm_intent' in record and 0 <= self.clock() - record['arm_intent'] < TTL and
                not any(k in record for k in ('rolled_back', 'rollback_intent', 'finished')), 'Frontend rollback/lifecycle deadline')
        self.timer.armed(record['id'])

    def export_config(self, route_id):
        return deepcopy(self._load(route_id)[1]['candidate'])

    def _request(self, record, phase, items):
        require(items and len({v['id'] for v in items}) == len(items), 'Probe request must have unique nonempty cases')
        request = dict(sha256=record['sha256'], items=deepcopy(items))
        request['request_sha256'] = checksum(request)
        record['requests'][phase] = dict(timestamp=self.clock(), request=request)
        record['proofs'].pop(phase, None)
        self._save(record)
        return deepcopy(request)

    def _begin(self, record, phase):
        require(not any(k in record for k in ('finished', 'rolled_back', 'rollback_intent')), 'Probe lifecycle closed')
        record['proofs'].pop(phase, None); record['requests'].pop(phase, None)
        self._save(record)

    def export_baseline(self, route_id, request):
        before, plan, record = self._load(route_id)
        require('apply_intent' not in record, 'Baseline must precede entry mutation')
        self._begin(record, 'baseline')
        items = request.get('items')
        require(isinstance(items, list) and 2 <= len(items) <= 12, 'Provide bounded actual cached entry cases')
        output, ports = [], set()
        for item in items:
            require(set(item) == {'id', 'client', 'wire', 'expected_egress'} and isinstance(item['id'], str)
                    and re.fullmatch('[A-Za-z0-9._:-]{1,120}', item['id']), 'Invalid baseline probe case')
            address, port, _ = wire_endpoint(item['client'], item['wire'])
            require(address == p.ENTRY and port in (443, 18444), 'Legacy probe must use exact physical entry endpoints')
            require(ipaddress.ip_address(item['expected_egress']).is_global, 'Legacy expected egress must be observed public IP')
            ports.add(port)
            output.append(dict(**deepcopy(item), legacy=True, wire_sha256=wire_hash(item['client'], item['wire'])))
        require(ports == {443, 18444}, 'Baseline must cover 443 and 18444')
        return self._request(record, 'baseline', output)

    def _proof(self, phase, proof, before, plan, record):
        if phase == 'site':
            site_check(proof, self.clock()); return
        require(isinstance(proof, dict) and proof.get('sha256') == record['sha256'], 'Proof candidate mismatch')
        c.fresh(proof.get('timestamp'), self.clock(), plan['prepared_at'])
        tests = proof.get('tests')
        require(isinstance(tests, list) and tests and all(isinstance(t, dict) for t in tests), 'Actual proof tests required')
        if phase == 'installed':
            require(proof.get('id') == 'entry' and proof.get('node') == p.ENTRY_ID and proof.get('ip') == p.ENTRY
                    and len(tests) == 1 and tests[0].get('kind') == 'installed-xray' and tests[0].get('passed') is True
                    and type(tests[0].get('returncode')) is int and tests[0]['returncode'] == 0
                    and tests[0].get('version') == plan['runtime']['xray_version'], 'Installed entry test failed')
            return
        require(phase in ('baseline', 'public', 'subscription') and phase in record['requests'], 'Export actual probe request first')
        saved = record['requests'][phase]
        expected = saved['request']
        require(checksum({k: v for k, v in expected.items() if k != 'request_sha256'}) == expected['request_sha256']
                and proof.get('request_sha256') == expected['request_sha256'], 'Probe request hash mismatch')
        earliest = saved['timestamp']
        if phase in ('public', 'subscription'): earliest = max(earliest, record['staged'])
        if phase == 'subscription': earliest = max(earliest, record['published'])
        c.fresh(proof['timestamp'], self.clock(), earliest)
        indexed = {v['id']: v for v in expected['items']}
        require(len(tests) == len(indexed) and {t.get('id') for t in tests} == set(indexed), 'Probe cases incomplete/duplicate')
        baseline = {t['id']: t for t in record['proofs'].get('baseline', {}).get('tests', [])}
        for test in tests:
            item = indexed[test['id']]
            require(test.get('client') == item['client'] and test.get('wire_sha256') == item['wire_sha256'], 'Actual client wire/probe identity mismatch')
            normalized = dict(test, kind='legacy', test_id=test['id'], namespace='external-client')
            c.Coordinator._legacy_test(normalized, {'inputs': {'expected_egress': item['expected_egress']}})
            if phase == 'baseline': continue
            if item.get('legacy'):
                require(test['id'] in baseline, 'Missing pre-mutation legacy baseline')
                old = baseline[test['id']]
                require(not old['passed'] or test['passed'], 'Working entry legacy case regressed')
                require(not old['authenticated'] or test['authenticated'], 'Entry legacy authentication regressed')
                require(old['http_code'] != 204 or test['http_code'] == 204, 'Entry legacy HTTPS regressed')
                require(old['exit_ip'] != item['expected_egress'] or test['exit_ip'] == old['exit_ip'], 'Entry legacy egress regressed')
                require(all(a != 0 or b == 0 for a, b in zip(old['returncodes'], test['returncodes'])), 'Entry legacy partial success regressed')
            else:
                require(test['passed'] is True, 'New frontend/subscription must pass authenticated HTTPS and expected egress')

    def accept(self, route_id, phase, proof):
        before, plan, record = self._load(route_id)
        require(phase in ('site', 'installed', 'baseline', 'public', 'subscription') and
                not any(k in record for k in ('finished', 'rolled_back', 'rollback_intent')), 'Proof lifecycle closed')
        require(phase != 'baseline' or 'apply_intent' not in record, 'Cannot replace original baseline after mutation')
        record['proofs'].pop(phase, None); self._save(record)
        self._proof(phase, proof, before, plan, record)
        record['proofs'][phase] = deepcopy(proof); self._save(record)
        return dict(id=route_id, accepted=phase)

    def _gates(self, before, plan, record, phases):
        for phase in phases:
            self._proof(phase, record['proofs'].get(phase), before, plan, record)

    def stage(self, route_id):
        self.store.serial()
        before, plan, record = self._load(route_id)
        runtime_check(plan['runtime'], route_id, self.clock())
        self._gates(before, plan, record, ('site', 'installed', 'baseline'))
        self._guard(before, plan, record)
        self._rights(before, record)
        require(not any(k in record for k in ('finished', 'rolled_back', 'rollback_intent')), 'Stage lifecycle closed')
        if 'arm_intent' not in record:
            record['arm_intent'] = self.clock(); self._save(record); self.timer.start(route_id)
        self._armed(record)
        pid = before['profile']['uuid']
        if 'apply_intent' not in record:
            tag = model.route_tags(route_id)['front']
            for value in self.api('GET', '/api/config-profiles/')['configProfiles']:
                if value['uuid'] != pid:
                    require(tag not in c.metadata(self.api('GET', '/api/config-profiles/' + value['uuid'])), 'Frontend tag collision')
            record['apply_intent'] = self.clock(); self._save(record)
            self.api('PATCH', '/api/config-profiles/', dict(uuid=pid, config=plan['candidate']))
        profile = self.api('GET', '/api/config-profiles/' + pid)
        require(profile['config'] == plan['candidate'], 'Profile PATCH unresolved; no automatic repeat')
        metadata = c.metadata(profile)
        require(all(metadata.get(tag) == iid for tag, iid in c.metadata(before['profile']).items()), 'Legacy metadata changed on apply')
        record.update(profile=pid, front=metadata[model.route_tags(route_id)['front']]); self._save(record)
        self._rights(before, record, apply=True)
        original = c.binding(before['entry'])
        wanted = dict(profile=pid, inbounds=sorted(original['inbounds'] + [record['front']]))
        actual = c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID))
        require(actual in (original, wanted), 'Entry binding changed before activation')
        if actual != wanted:
            require('binding_intent' not in record, 'Binding PATCH unresolved; no automatic repeat')
            record['binding_intent'] = self.clock(); self._save(record)
            self.api('PATCH', '/api/nodes/', dict(uuid=p.ENTRY_ID, configProfile=dict(activeConfigProfileUuid=pid, activeInbounds=wanted['inbounds'])))
        self._guard(before, plan, record, live=True); self._rights(before, record, required=True); self._armed(record)
        record.setdefault('staged', self.clock()); self._save(record)
        return self.summary(record)

    def _client(self, plan, user, old, kind):
        reality = plan['candidate']['inbounds'][-1]['streamSettings']['realitySettings']
        pubkey, short_id = p.public_key(reality['privateKey']), reality['shortIds'][0]
        fp = old.get('fingerprint') or 'chrome'
        if kind == 'xray':
            return dict(protocol='vless', settings=dict(vnext=[dict(address=model.DOMAINS[plan['id']], port=PORTS[plan['id']],
                users=[dict(id=user, encryption='none', flow='xtls-rprx-vision')])]), streamSettings=dict(network='raw', security='reality',
                realitySettings=dict(serverName=model.DOMAINS[plan['id']], fingerprint=fp, publicKey=pubkey, shortId=short_id)))
        return {'name': old['remark'], 'type': 'vless', 'server': model.DOMAINS[plan['id']], 'port': PORTS[plan['id']], 'uuid': user,
                'network': 'tcp', 'tls': True, 'udp': True, 'flow': 'xtls-rprx-vision', 'servername': model.DOMAINS[plan['id']],
                'client-fingerprint': fp, 'reality-opts': {'public-key': pubkey, 'short-id': short_id}}

    def export_public(self, route_id):
        before, plan, record = self._load(route_id)
        self._begin(record, 'public')
        require('staged' in record, 'Stage before public client tests')
        self._guard(before, plan, record, live=True); self._rights(before, record, required=True)
        user = self._user(before)['vlessUuid']
        items = []
        for host in before['hosts']:
            role = 'auto' if host['isHidden'] else 'main'
            for kind in ('xray', 'mihomo'):
                wire = self._client(plan, user, host, kind)
                items.append(dict(id=route_id + '-' + role + '-' + kind, client=kind, wire=wire,
                    expected_egress=plan['backend']['expected_egress'], wire_sha256=wire_hash(kind, wire), legacy=False))
        items.extend(deepcopy(record['requests']['baseline']['request']['items']))
        return self._request(record, 'public', items)

    def publish(self, route_id):
        before, plan, record = self._load(route_id)
        self._armed(record); self._gates(before, plan, record, ('site', 'installed', 'baseline', 'public'))
        self._guard(before, plan, record, live=True); self._rights(before, record, required=True)
        for old in before['hosts']:
            desired = self._desired(old, plan, record)
            current = self.api('GET', '/api/hosts/' + old['uuid'])
            if c.stable_host(current) != c.stable_host(desired):
                require(c.stable_host(current) == c.stable_host(old) and old['uuid'] not in record['host_intents'], 'Host publication uncertain or concurrent edit')
                record['host_intents'][old['uuid']] = checksum(c.stable_host(desired)); self._save(record)
                self.api('PATCH', '/api/hosts/', dict(uuid=old['uuid'], **{k: desired[k] for k in HOST_FIELDS}))
            require(c.stable_host(self.api('GET', '/api/hosts/' + old['uuid'])) == c.stable_host(desired), 'Host publication readback failed')
        self._guard(before, plan, record, live=True, published=True); self._armed(record)
        record.setdefault('published', self.clock()); self._save(record)
        return dict(**self.summary(record), published_hosts=len(before['hosts']), existing_host_properties_preserved=True)

    def _wire_matches(self, actual, expected, kind):
        address, port, user = wire_endpoint(kind, actual)
        ea, ep, eu = wire_endpoint(kind, expected)
        require((address, port, user) == (ea, ep, eu), 'Subscription endpoint/identity mismatch')
        if kind == 'xray':
            stream, wanted = actual['streamSettings'], expected['streamSettings']
            require(stream.get('security') == 'reality', 'Subscription REALITY missing')
            users = actual['settings']['vnext'][0]['users'][0]
            require(users.get('encryption') == 'none' and users.get('flow') == 'xtls-rprx-vision', 'Subscription encryption/flow differs')
            rs, desired = stream.get('realitySettings', {}), wanted['realitySettings']
            require(all(rs.get(k) == desired[k] for k in ('serverName', 'fingerprint', 'shortId')) and
                    (rs.get('publicKey') or rs.get('password')) == desired['publicKey'] and
                    not (rs.get('publicKey') and rs.get('password')), 'Subscription REALITY key/SNI/fingerprint mismatch')
        else:
            require(all(actual.get(k) == expected[k] for k in ('flow', 'servername', 'client-fingerprint'))
                    and actual.get('reality-opts') == expected['reality-opts'], 'Mihomo REALITY wire differs')

    def export_subscription(self, route_id, request):
        before, plan, record = self._load(route_id)
        self._begin(record, 'subscription')
        require('published' in record, 'Publish before fresh actual subscription fetch')
        self._guard(before, plan, record, live=True, published=True); self._rights(before, record, required=True)
        user = self._user(before)
        response = self.api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])
        headers = request['headers']
        happ = self.subscription_fetch(response['subscriptionUrl'], headers, 'happ')
        mihomo = self.subscription_fetch(response['subscriptionUrl'], headers, 'mihomo')
        require(isinstance(happ, list) and isinstance(mihomo, dict) and isinstance(mihomo.get('proxies'), list), 'Real application subscription shape mismatch')
        items = []
        for old in before['hosts']:
            role = 'auto' if old['isHidden'] else 'main'
            remark = plan['auto_remark'] if old['isHidden'] else old['remark']
            matches = [cfg for cfg in happ if cfg.get('remarks') == remark]
            require(len(matches) == 1, 'Main/auto Happ config ambiguous or missing')
            outputs = [out for out in matches[0].get('outbounds', []) if out.get('protocol') == 'vless' and any(
                d.get('address') == model.DOMAINS[route_id] and d.get('port') == PORTS[route_id] for d in out.get('settings', {}).get('vnext', []))]
            require(len(outputs) == 1, 'Main/auto subscription route ambiguous or missing')
            self._wire_matches(outputs[0], self._client(plan, user['vlessUuid'], old, 'xray'), 'xray')
            items.append(dict(id=route_id + '-sub-' + role + '-xray', client='xray', wire=deepcopy(outputs[0]),
                expected_egress=plan['backend']['expected_egress'], wire_sha256=wire_hash('xray', outputs[0]), legacy=False))
            if not old['isHidden']:
                proxies = [v for v in mihomo['proxies'] if v.get('name') == old['remark']]
                require(len(proxies) == 1, 'Actual Mihomo main proxy ambiguous or missing')
                self._wire_matches(proxies[0], self._client(plan, user['vlessUuid'], old, 'mihomo'), 'mihomo')
                items.append(dict(id=route_id + '-sub-main-mihomo', client='mihomo', wire=deepcopy(proxies[0]),
                    expected_egress=plan['backend']['expected_egress'], wire_sha256=wire_hash('mihomo', proxies[0]), legacy=False))
        return self._request(record, 'subscription', items)

    def finish(self, route_id):
        before, plan, record = self._load(route_id)
        require('published' in record and not any(k in record for k in ('rollback_intent', 'rolled_back')), 'Cannot finish unpublished/rolled-back frontend')
        self._guard(before, plan, record, live=True, published=True); self._rights(before, record, required=True)
        if 'finished' not in record:
            self._armed(record); self._gates(before, plan, record, ('site', 'installed', 'baseline', 'public', 'subscription'))
            record['finished'] = self.clock(); self._save(record)
        self.timer.cancel(route_id)
        self._guard(before, plan, record, live=True, published=True)
        remaining = sum(not t['passed'] for t in record['proofs']['public']['tests'] if
            t['id'] in {v['id'] for v in record['requests']['baseline']['request']['items']})
        return dict(**self.summary(record), rollback_timer_and_service_inactive=True,
                    actual_subscription_verified=True, preexisting_entry_failures_remaining=remaining)

    def status(self, route_id):
        before, plan, record = self._load(route_id)
        self._guard(before, plan, record, live='staged' in record and 'rolled_back' not in record,
                    published='published' in record and 'rolled_back' not in record)
        return self.summary(record)

    def rollback(self, route_id):
        before, plan, record = self._load(route_id)
        if 'finished' in record: return dict(id=route_id, rollback_skipped_finished=True)
        _profile, front, _node = self._guard(before, plan, record)
        if front and not record.get('front'):
            record.update(profile=before['profile']['uuid'], front=front); self._save(record)
        self._rights(before, record)
        record.setdefault('rollback_intent', self.clock()); self._save(record)
        for old in before['hosts']:
            actual = self.api('GET', '/api/hosts/' + old['uuid'])
            if c.stable_host(actual) != c.stable_host(old):
                require(c.stable_host(actual) == c.stable_host(self._desired(old, plan, record)), 'Host drift during rollback')
                self.api('PATCH', '/api/hosts/', dict(uuid=old['uuid'], **{k: old.get(k) for k in HOST_FIELDS}))
            require(c.stable_host(self.api('GET', '/api/hosts/' + old['uuid'])) == c.stable_host(old), 'Host rollback readback failed')
        original = c.binding(before['entry'])
        if c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID)) != original:
            self.api('PATCH', '/api/nodes/', dict(uuid=p.ENTRY_ID, configProfile=dict(activeConfigProfileUuid=original['profile'], activeInbounds=original['inbounds'])))
        require(c.binding(self.api('GET', '/api/nodes/' + p.ENTRY_ID)) == original, 'Entry rollback binding readback failed')
        for sid in record['grants']:
            current = c.ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
            require(set(c.ids(before['customers'][sid]['inbounds'])) <= set(current), 'Customer rights drift during rollback')
            desired = [v for v in current if v != record.get('front')]
            if desired != current: self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=desired))
            actual = c.ids(self.api('GET', '/api/internal-squads/' + sid)['inbounds'])
            require(set(desired) <= set(actual) and record.get('front') not in actual, 'Frontend grant removal readback failed')
        profile = self.api('GET', '/api/config-profiles/' + before['profile']['uuid'])
        require(profile['config'] in (before['profile']['config'], plan['candidate']), 'Concurrent entry profile edit prevents rollback')
        if profile['config'] != before['profile']['config']:
            self.api('PATCH', '/api/config-profiles/', dict(uuid=profile['uuid'], config=before['profile']['config']))
        actual = self.api('GET', '/api/config-profiles/' + before['profile']['uuid'])
        require(actual['config'] == before['profile']['config'] and c.metadata(actual) == c.metadata(before['profile']), 'Entry profile restoration readback failed')
        record['rolled_back'] = self.clock(); self._save(record); self._guard(before, plan, record)
        return dict(id=route_id, own_frontend_delta_restored=True, finished_exit_untouched=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    phases = ('site', 'installed', 'baseline', 'public', 'subscription')
    parser.add_argument('action', choices=('prepare', 'stage', 'publish', 'finish', 'rollback', 'status',
        'export-config', 'export-baseline', 'export-public', 'export-subscription') + tuple('accept-' + p for p in phases))
    parser.add_argument('--id', required=True, choices=tuple(PORTS))
    parser.add_argument('--secret-stdout', action='store_true')
    args = parser.parse_args(argv)
    export = args.action.startswith('export-')
    require(args.secret_stdout == export and (not export or not sys.stdout.isatty()), 'Explicit protected secret export pipe required')
    os.umask(0o077)
    store = RootStore(args.id)
    with store.locked():
        adapter = p.load_file('six_front_panel_api', p.ROOT.parent / 'selfsteal-us3' / 'panel_api.py')
        api, _ = adapter.create_client()
        core = c.Coordinator(api, c.RootStore(args.id), c.SystemdTimer())
        worker = Frontend(api, store, core, Timers())
        if args.action.startswith('accept-'):
            result = worker.accept(args.id, args.action.removeprefix('accept-'), json.load(sys.stdin))
        else:
            method = getattr(worker, args.action.replace('-', '_'))
            result = method(args.id, json.load(sys.stdin)) if args.action in ('prepare', 'export-baseline', 'export-subscription') else method(args.id)
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, c.SafetyError) else 'Frontend stopped; inspect protected state'
        print(json.dumps(dict(error=message)), file=sys.stderr)
        sys.exit(1)
