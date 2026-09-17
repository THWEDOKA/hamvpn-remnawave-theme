"""Six-exit panel preflight. No SSH, DNS, profile, host or squad mutations.

snapshot is GET-only; account/cleanup mutate ONLY an intent-owned temporary
identity. Export requires --secret-stdout and a private stdout -> RAM/stdin pipe.
Run on the panel as root, from the same release as inventory.py and panel_api.py.
Normal results/errors deliberately omit identifiers, credentials and API bodies.
"""
import argparse
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-cloud140-six-20260918/preflight')
SCOPE = 'cloud140-six-20260918'
ENTRY_ID = 'f67527b4-9685-41a3-8bd1-c1538724b4a1'
CUSTOMER_NAMES = frozenset(('WHITE', 'BASE', 'OLD', 'site'))
AUTOS = {
    'at': '17323e32-fb2c-4e4c-896d-07313101248a',
    'pl': '858a888d-a7fe-4459-9762-fb3e92bee10e',
    'cz': 'b8047ae6-2472-410c-9303-af78c3441682',
    'gb': 'ff845a81-3183-4439-990a-07089a776418',
    'us1': '2935d939-15da-4c96-9f20-2060497fb4fa',
    'gbpower': None,
}
GB_ACTIVE = '447f780a-3a46-4f7e-ba55-74e80f4f2dfb'
GB_SOURCE = ('d354e2ac-4b86-40a7-a0b3-ef9499d329b1',
             '41b6c310-32dd-4845-acc6-816ed48e2ff9')
GB_BYPASS = '92f1e0c1-90d3-4ed1-b532-88f3c5f0fdfc'
LIMIT = 512 * 1024 * 1024


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load_file('cloud140_six_inventory', ROOT / 'inventory.py')
ENTRY = inventory.ENTRY
TARGETS = deepcopy(inventory.TARGETS)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


class Store:
    """Immutable, hash-checked records. Partial writes stop; never overwrite.

    Parent and leaf checks reject symlinks and writable ancestors. CLI holds an
    exclusive flock for the entire operation, including intent/readback.
    """
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else STATE

    def secure(self):
        require(os.name == 'posix' and os.geteuid() == 0, 'Linux root is required')
        require(self.path.is_absolute(), 'Absolute state path required')
        for directory in reversed((self.path, *self.path.parents)):
            if not directory.exists() and not directory.is_symlink():
                directory.mkdir(mode=0o700)
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                    not info.st_mode & 0o022, 'Unsafe state ancestor')
        require(self.path.stat().st_mode & 0o077 == 0, 'State directory is not private')

    def file(self, name):
        require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name) is not None, 'Invalid record name')
        return self.path / (name + '.json')

    def exists(self, name):
        path = self.file(name)
        return path.exists() or path.is_symlink()

    def put(self, name, value):
        self.secure()
        path = self.file(name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(dict(sha256=digest(value), value=value)))
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        require(self.get(name) == value, 'Saved record readback differs')

    def get(self, name):
        self.secure()
        fd = os.open(self.file(name), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'Unsafe record permissions or ownership')
            record = json.load(stream)
        require(set(record) == {'sha256', 'value'} and record['sha256'] == digest(record['value']),
                'Record integrity check failed')
        return record['value']


def indexed(rows):
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), 'Unexpected API list shape')
    result = {row['uuid']: row for row in rows}
    require(len(result) == len(rows), 'Duplicate API identity')
    return result


def binding(host):
    value = host['inbound']
    require(isinstance(value, dict), 'Unexpected host binding shape')
    return value['configProfileUuid'], value['configProfileInboundUuid']


def active(node):
    value = node['configProfile']
    return value['activeConfigProfileUuid'], set(indexed(value['activeInbounds']))


def customer_rights(hosts, squads):
    """Actual selected-host inbound rights, never the node's alternate inbound."""
    by_name = {}
    for squad in squads:
        if squad['name'] in CUSTOMER_NAMES:
            require(squad['name'] not in by_name, 'Ambiguous customer squad name')
            by_name[squad['name']] = squad
    require(set(by_name) == CUSTOMER_NAMES, 'Customer squad inventory changed')
    result = {}
    for host in hosts:
        inbound_id = binding(host)[1]
        ids = sorted(s['uuid'] for s in by_name.values() if inbound_id in indexed(s['inbounds']))
        require(bool(ids), 'Selected host has no customer rights')
        result[host['uuid']] = ids
    return result


def collect(api):
    nodes = indexed(api('GET', '/api/nodes/'))
    hosts = indexed(api('GET', '/api/hosts/'))
    squads = list(indexed(api('GET', '/api/internal-squads/')['internalSquads']).values())
    entry = nodes[ENTRY_ID]
    require(entry['address'] == ENTRY and entry['isConnected'] and not entry['isDisabled'], 'Entry identity/health changed')
    pids = {active(entry)[0]}
    routes, selected = [], []
    for target in TARGETS:
        node = nodes[target['node']]
        require(node['address'] == target['ip'] and node['isConnected'] and not node['isDisabled'], 'Exit identity/health changed')
        pid, aids = active(node)
        require(bool(aids), 'Exit has no active inbound')
        pids.add(pid)
        host_ids = [target['host']] + ([AUTOS[target['id']]] if AUTOS[target['id']] else [])
        mismatches = []
        for index, hid in enumerate(host_ids):
            host = hosts[hid]
            require(host['nodes'] == [target['node']] and not host['isDisabled'] and
                    host['isHidden'] is bool(index), 'Selected host identity changed')
            hp, hi = binding(host)
            pids.add(hp)
            if hp != pid or hi not in aids:
                require(target['id'] == 'gb' and pid == GB_ACTIVE and (hp, hi) == GB_SOURCE,
                        'Unexpected selected host/inbound mismatch')
                mismatches.append(hid)
            selected.append(host)
        if target['id'] == 'gbpower':
            require(not any(h['isHidden'] and (target['node'] in h.get('nodes', []) or
                        h.get('address') == target['ip']) for h in hosts.values()), 'Unexpected GBpower auto host')
        routes.append(dict(**target, hosts=host_ids, profile=pid, known_mismatch_hosts=mismatches))
    require(hosts[GB_BYPASS]['nodes'] == [next(t['node'] for t in TARGETS if t['id'] == 'gb')], 'GB bypass identity changed')
    profiles = {pid: api('GET', '/api/config-profiles/' + pid) for pid in sorted(pids)}
    all_inbounds = set()
    for pid, profile in profiles.items():
        require(profile['uuid'] == pid and isinstance(profile['config'], dict), 'Unexpected profile shape')
        metadata = indexed(profile['inbounds'])
        raw_tags = [raw['tag'] for raw in profile['config']['inbounds']]
        require(len(raw_tags) == len(set(raw_tags)) and all(m['tag'] in raw_tags for m in metadata.values()), 'Profile inbound metadata mismatch')
        all_inbounds.update(metadata)
    for host in selected:
        pid, iid = binding(host)
        require(iid in indexed(profiles[pid]['inbounds']), 'Selected host source inbound missing')
    scope_nodes = {ENTRY_ID, *(t['node'] for t in TARGETS)}
    for node_id in scope_nodes:
        pid, aids = active(nodes[node_id])
        require(aids <= set(indexed(profiles[pid]['inbounds'])), 'Active inbound absent from profile metadata')
    consumers = {pid: sorted(n['uuid'] for n in nodes.values()
                            if (n.get('configProfile') or {}).get('activeConfigProfileUuid') == pid)
                 for pid in pids}
    relevant_nodes = scope_nodes | {uid for values in consumers.values() for uid in values}
    relevant_hosts = [h for h in hosts.values() if set(h.get('nodes', [])) & relevant_nodes or
                      (h.get('inbound') or {}).get('configProfileInboundUuid') in all_inbounds]
    relevant_squads = [s for s in squads if s['name'] in CUSTOMER_NAMES or set(indexed(s['inbounds'])) & all_inbounds]
    return dict(scope=SCOPE, timestamp=time.time(), entry=dict(uuid=ENTRY_ID, address=ENTRY), routes=routes,
                nodes=[nodes[key] for key in sorted(relevant_nodes)], hosts=relevant_hosts,
                squads=relevant_squads, profiles=profiles, profile_consumers=consumers,
                customer_rights=customer_rights(selected, squads), preserved_host_ids=[GB_BYPASS])


def baseline(store):
    value = store.get('before')
    require(value['scope'] == SCOPE and value['entry'] == dict(uuid=ENTRY_ID, address=ENTRY), 'Foreign snapshot scope')
    require([{key: route[key] for key in ('id', 'ip', 'node', 'host')} for route in value['routes']] == TARGETS,
            'Foreign snapshot targets')
    return value


def snapshot(api, store):
    require(not store.exists('before'), 'Immutable snapshot exists; inspect instead of overwriting')
    value = collect(api)
    store.put('before', value)
    return dict(snapshot_verified=True, sha256=digest(baseline(store)), selected_nodes=7, selected_hosts=11,
                profiles=len(value['profiles']), known_binding_mismatches=sum(len(r['known_mismatch_hosts']) for r in value['routes']))


def live_rights(api, before):
    """Re-read selected hosts/rights before creation; do not silently grant more."""
    old = indexed(before['hosts'])
    hosts = [api('GET', '/api/hosts/' + hid) for r in before['routes'] for hid in r['hosts']]
    for host in hosts:
        prior = old[host['uuid']]
        require(all(host[key] == prior[key] for key in ('nodes', 'inbound', 'isHidden', 'isDisabled')),
                'Selected host binding drift')
    rights = customer_rights(hosts, api('GET', '/api/internal-squads/')['internalSquads'])
    require(rights == before['customer_rights'], 'Selected host customer rights drift')
    return sorted({sid for values in rights.values() for sid in values})


def remaining(query, identifier):
    identifier = str(uuid.UUID(identifier))
    result = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + identifier + "'")
    require(type(result.get('remaining')) is int and result['remaining'] in (0, 1), 'Unexpected SQL absence result')
    return result['remaining']


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None, 'Expiry lacks timezone')
    return parsed.timestamp()


def owned(user, intent, usable=False):
    for key in ('uuid', 'username', 'tag', 'description', 'trafficLimitBytes', 'trafficLimitStrategy'):
        require(user.get(key) == intent[key], 'Temporary identity ownership mismatch')
    require(abs(timestamp(user['expireAt']) - timestamp(intent['expireAt'])) < 1, 'Temporary expiry mismatch')
    values = user['activeInternalSquads']
    actual = [s['uuid'] if isinstance(s, dict) else s for s in values]
    require(sorted(actual) == sorted(intent['activeInternalSquads']), 'Temporary identity rights mismatch')
    if usable:
        require(timestamp(user['expireAt']) > time.time() and user.get('status', 'ACTIVE') == 'ACTIVE', 'Temporary identity expired/disabled')
    return user


def read_intent(store):
    intent = store.get('test-intent')
    before = baseline(store)
    require(intent['scope'] == SCOPE and intent['snapshot_sha256'] == digest(before), 'Foreign identity intent')
    body = intent['body']
    require(body['tag'] == 'C140_SIX_PROBE' and body['description'] == 'Temporary six-exit CLOUDru route verification' and
            body['username'] == 'c140six_' + str(uuid.UUID(body['uuid'])).replace('-', '')[:24] and
            body['trafficLimitBytes'] == LIMIT and body['trafficLimitStrategy'] == 'NO_RESET' and
            sorted(body['activeInternalSquads']) == sorted({s for ids in before['customer_rights'].values() for s in ids}),
            'Invalid identity intent')
    require(0 < timestamp(body['expireAt']) - intent['created_at'] <= 10801, 'Identity lifetime out of scope')
    return body


def probe_user(api, store):
    require(not store.exists('test-cleanup') and not store.exists('test-cleanup-intent'), 'Probe cleanup started/completed')
    intent = read_intent(store)
    return owned(api('GET', '/api/users/' + intent['uuid']), intent, usable=True)


def account(api, query, store):
    require(not store.exists('test-cleanup') and not store.exists('test-cleanup-intent'), 'Probe lifecycle finished')
    before = baseline(store)
    rights = live_rights(api, before)
    if store.exists('test-intent'):
        intent = read_intent(store)
        require(remaining(query, intent['uuid']) == 1, 'Unresolved previous create; never repeat POST blindly')
    else:
        identifier = str(uuid.uuid4())
        require(remaining(query, identifier) == 0, 'Proposed identity already exists')
        now = datetime.now(timezone.utc)
        intent = dict(uuid=identifier, username='c140six_' + identifier.replace('-', '')[:24],
                      tag='C140_SIX_PROBE', description='Temporary six-exit CLOUDru route verification',
                      expireAt=(now + timedelta(hours=3)).isoformat(), trafficLimitBytes=LIMIT,
                      trafficLimitStrategy='NO_RESET', activeInternalSquads=rights)
        store.put('test-intent', dict(scope=SCOPE, snapshot_sha256=digest(before), created_at=now.timestamp(), body=intent))
        try:
            api('POST', '/api/users/', intent)
        except Exception:
            # Readback below is mandatory even when POST reports success. Never
            # expose transport exceptions, response bodies or credentials.
            pass
        require(remaining(query, intent['uuid']) == 1, 'Create not confirmed; inspect intent without retrying POST')
    user = probe_user(api, store)
    if not store.exists('test-created'):
        store.put('test-created', dict(uuid=intent['uuid'], snapshot_sha256=digest(before)))
    return user


def cleanup(api, query, store):
    intent = read_intent(store)
    if store.exists('test-cleanup'):
        require(remaining(query, intent['uuid']) == 0, 'Deleted probe identity reappeared')
        return dict(disposable_user_deleted=True, absence_verified=True)
    if remaining(query, intent['uuid']):
        owned(api('GET', '/api/users/' + intent['uuid']), intent)
        if not store.exists('test-cleanup-intent'):
            store.put('test-cleanup-intent', dict(uuid=intent['uuid']))
        require(store.get('test-cleanup-intent') == dict(uuid=intent['uuid']), 'Foreign cleanup intent')
        try:
            api('DELETE', '/api/users/' + intent['uuid'])
        except Exception:
            pass
    require(remaining(query, intent['uuid']) == 0, 'Disposable removal not confirmed')
    store.put('test-cleanup', dict(uuid=intent['uuid'], absence_verified=True, timestamp=time.time()))
    return dict(disposable_user_deleted=True, absence_verified=True)


def public_key(private):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = base64.urlsafe_b64decode(private + '=' * (-len(private) % 4))
    key = X25519PrivateKey.from_private_bytes(raw)
    return base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')


def export_baseline(api, store, route_ids=None):
    """SECRET result: active VLESS candidates only, not a success claim.

    Hysteria/user-specific subscription handling belongs to the coordinator.
    No fake VLESS endpoint is created for an UDP-only active profile. Exports
    never create an account and never expose server private keys/old clients.
    """
    before = baseline(store)
    if route_ids is not None:
        require(bool(route_ids) and len(route_ids) == len(set(route_ids)) and
                set(route_ids) <= {'at', 'pl', 'cz', 'gbpower'}, 'Only remaining selected routes may be exported')
    user = probe_user(api, store)
    nodes = indexed(before['nodes'])
    items, unsupported = [], []
    for route in before['routes']:
        if route_ids is not None and route['id'] not in route_ids:
            continue
        profile = before['profiles'][route['profile']]
        live_profile = api('GET', '/api/config-profiles/' + route['profile'])
        require(live_profile['config'] == profile['config'] and
                {v['uuid']:v['tag'] for v in live_profile['inbounds']} ==
                {v['uuid']:v['tag'] for v in profile['inbounds']}, 'Baseline profile drift')
        node = api('GET', '/api/nodes/' + route['node'])
        require(node['address'] == route['ip'] and active(node) == active(nodes[route['node']]), 'Baseline node drift')
        metadata = indexed(profile['inbounds'])
        for inbound_id in sorted(active(node)[1]):
            tag = metadata[inbound_id]['tag']
            raw = next(i for i in profile['config']['inbounds'] if i['tag'] == tag)
            stream = raw.get('streamSettings', {})
            protocol, network, security = raw['protocol'], stream.get('network', 'raw'), stream.get('security')
            if protocol != 'vless' or network not in ('raw', 'tcp') or security not in ('tls', 'reality'):
                unsupported.append(dict(id=route['id'], inbound=inbound_id, protocol=protocol,
                                        reason='Requires separate protocol-aware subscription probe'))
                continue
            permitted = {s['uuid'] for s in before['squads'] if s['name'] in CUSTOMER_NAMES and inbound_id in indexed(s['inbounds'])}
            require(bool(permitted & set(read_intent(store)['activeInternalSquads'])), 'Probe lacks active inbound rights')
            settings = dict(id=user['vlessUuid'], encryption='none', flow='xtls-rprx-vision')
            if security == 'reality':
                rs = stream['realitySettings']
                require(bool(rs['serverNames']) and bool(rs['shortIds']), 'Incomplete REALITY identity')
                client_stream = dict(network=network, security=security, realitySettings=dict(
                    serverName=rs['serverNames'][0], fingerprint='chrome',
                    publicKey=public_key(rs['privateKey']), shortId=rs['shortIds'][0]))
            else:
                tls = stream['tlsSettings']
                require(bool(tls.get('serverName')), 'TLS client serverName missing')
                client_stream = dict(network=network, security=security, tlsSettings=dict(
                    serverName=tls['serverName'], fingerprint='chrome', allowInsecure=False))
            out = dict(protocol='vless', settings=dict(vnext=[dict(address=route['ip'], port=raw['port'], users=[settings])]),
                       streamSettings=client_stream)
            items.append(dict(id=route['id'] + '-' + tag, node=route['node'], inbound=inbound_id,
                              expected_egress=None, outbound=out))
    return dict(scope=SCOPE, snapshot_sha256=digest(before), items=items, unsupported=unsupported,
                authenticated_test_performed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'inspect', 'account', 'cleanup', 'export-baseline'))
    parser.add_argument('--secret-stdout', action='store_true')
    parser.add_argument('--routes', nargs='+', choices=['at', 'pl', 'cz', 'gbpower'])
    args = parser.parse_args()
    try:
        require(args.secret_stdout == (args.action == 'export-baseline'), 'Explicit secret export flag required only for export')
        require(args.routes is None or args.action == 'export-baseline', 'Route selection is only valid for export')
        require(args.action != 'export-baseline' or not sys.stdout.isatty(), 'Do not export secrets to a terminal')
        os.umask(0o077)
        store = Store()
        store.secure()
        import fcntl
        fd = os.open(store.path / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'Unsafe operation lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'inspect':
                before = baseline(store)
                result = dict(snapshot_verified=True, sha256=digest(before), routes=len(before['routes']),
                              account_intent=store.exists('test-intent'), cleanup_complete=store.exists('test-cleanup'))
            else:
                adapter = load_file('cloud140_six_panel_api', ROOT.parent / 'selfsteal-us3' / 'panel_api.py')
                api, query = adapter.create_client()
                if args.action == 'snapshot': result = snapshot(api, store)
                elif args.action == 'account':
                    account(api, query, store)
                    result = dict(disposable_probe_ready=True, traffic_limit_bytes=LIMIT)
                elif args.action == 'cleanup': result = cleanup(api, query, store)
                else: result = export_baseline(api, store, args.routes)
            print(json.dumps(result))
    except Exception:
        print(json.dumps(dict(error='PreflightFailed', message='Check protected state; no automatic repeat or secret diagnostic output')), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
