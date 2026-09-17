"""Additive, fail-closed panel rollout. Runtime secrets only in root-owned state."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'selfsteal-us3'))
from panel_api import create_client

STATE = Path('/root/hamvpn-selfsteal-eu-20260917')
NORMAL_PROFILE = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
NORMAL_INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
XRAY = '/root/selfsteal-us3-test/xray'
NODES = json.loads((ROOT / 'nodes.json').read_text())


def save(name, data):
    STATE.mkdir(mode=0o700, exist_ok=True)
    p = STATE / (name + '.json'); temp = p.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False)); temp.chmod(0o600); temp.replace(p)


def read(name): return json.loads((STATE / (name + '.json')).read_text())
def exists(name): return (STATE / (name + '.json')).exists()
def ids(s): return [i['uuid'] for i in s['inbounds']]


def binding(n):
    return {k: n['configProfile'][k] for k in ('activeConfigProfileUuid', 'activeInbounds')}


def candidate(original, n, key):
    config = copy.deepcopy(original)
    assert len(config['inbounds']) == 1
    old = config['inbounds'][0]; old_tag = old['tag']
    assert old['protocol'] == 'vless' and old['port'] == 443
    tag = 'ham-' + n['id'] + '-selfsteal'
    config['inbounds'] = [{'tag': tag, 'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'sniffing': copy.deepcopy(old.get('sniffing', {'enabled': True, 'destOverride': ['http', 'tls', 'quic']})),
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'show': False, 'target': '127.0.0.1:8443', 'xver': 0, 'serverNames': [n['domain']],
            'privateKey': key, 'shortIds': [secrets.token_hex(8)]}}}]
    for rule in config.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule: rule['inboundTag'] = [tag if t == old_tag else t for t in rule['inboundTag']]
    return config


def snapshot(api):
    if exists('before'): return read('before')
    before = {'nodes': api('GET', '/api/nodes/'), 'hosts': api('GET', '/api/hosts/'),
        'profiles': api('GET', '/api/config-profiles/')['configProfiles'],
        'normal': api('GET', '/api/config-profiles/' + NORMAL_PROFILE),
        'squads': api('GET', '/api/internal-squads/')['internalSquads']}
    save('before', before)
    save('before-checksum', {'sha256': hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()})
    return before


def stage(api, n):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    before = snapshot(api)
    assert not exists(n['id'] + '-created'), 'Intent exists: reconcile API instead of repeat POST'
    nodes, hosts = api('GET', '/api/nodes/'), api('GET', '/api/hosts/')
    profiles = api('GET', '/api/config-profiles/')['configProfiles']
    name = 'HAM-' + n['id'].upper() + '-SELFSTEAL'
    assert not any(x['address'] == n['ip'] or x['name'] == name for x in nodes)
    assert not any(h['address'] in (n['ip'], n['domain']) or h['remark'] == n['name'] for h in hosts)
    assert not any(p['name'] == name for p in profiles)
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    selected = [s for s in squads if NORMAL_INBOUND in ids(s)]
    baseline = {s['uuid'] for s in before['squads'] if NORMAL_INBOUND in ids(s)}
    assert selected and {s['uuid'] for s in selected} == baseline, 'Normal-server entitlements changed'
    private = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    config = candidate(before['normal']['config'], n, base64.urlsafe_b64encode(private).decode().rstrip('='))
    save(n['id'] + '-config', config)
    test = subprocess.run([XRAY, 'run', '-test', '-c', str(STATE / (n['id'] + '-config.json'))],
        cwd=str(Path(XRAY).parent), capture_output=True, text=True)
    save(n['id'] + '-xray-test', {'passed': test.returncode == 0, 'output': test.stdout + test.stderr})
    assert test.returncode == 0, 'Xray configuration test failed'
    created = {'timestamp': time.time(), 'squads': [s['uuid'] for s in selected], 'name': name, 'hosts': []}
    save(n['id'] + '-created', created)
    profile = api('POST', '/api/config-profiles/', {'name': name, 'config': config})
    created['profile'] = profile['uuid']; created['inbound'] = profile['inbounds'][0]['uuid']
    save(n['id'] + '-created', created)
    assert len(profile['inbounds']) == 1 and profile['config'] == config
    node = api('POST', '/api/nodes/', {'name': name, 'address': n['ip'], 'port': 2222,
        'countryCode': n['country'], 'isTrafficTrackingActive': True,
        'configProfile': {'activeConfigProfileUuid': created['profile'], 'activeInbounds': [created['inbound']]},
        'note': 'Own HTTPS target and certificate: ' + n['domain']})
    created['node'] = node['uuid']; save(n['id'] + '-created', created)
    used = [int(m.group(1)) for h in hosts if (m := re.match(r'^ABP-(\d+)-', h['remark']))]
    hidden = 'ABP-' + str(max(used, default=0) + 1) + '-' + n['country'] + '-HIDDEN'
    for remark, is_hidden in [(n['name'], False), (hidden, True)]:
        save(n['id'] + '-host-intent', {'remark': remark, 'isHidden': is_hidden})
        host = api('POST', '/api/hosts/', {'remark': remark, 'address': n['domain'], 'port': 443,
            'host': n['domain'], 'sni': n['domain'], 'fingerprint': 'firefox', 'isHidden': is_hidden,
            'isDisabled': True, 'nodes': [created['node']], 'excludedInternalSquads': [],
            'inbound': {'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['inbound']}})
        created['hosts'].append(host['uuid']); save(n['id'] + '-created', created)
    for squad in selected:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        assert set(ids(squad)) <= set(ids(current)), 'Concurrent entitlement removal'
        intended = list(dict.fromkeys(ids(current) + [created['inbound']]))
        result = api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': intended})
        assert set(ids(result)) == set(intended)
    return {'id': n['id'], 'staged': True, 'hosts_disabled': len(created['hosts']), 'squads': [s['name'] for s in selected]}


def create_test(api):
    assert not exists('test-user'), 'Reconcile previous intent first'
    before = read('before')
    squad = next(s for s in before['squads'] if s['name'] == 'BASE' and NORMAL_INBOUND in ids(s))
    identifier = str(uuid.uuid4())
    body = {'uuid': identifier, 'username': 'eu_selfsteal_probe_' + identifier[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(),
        'trafficLimitBytes': 2147483648, 'trafficLimitStrategy': 'NO_RESET', 'tag': 'EU_SS_PROBE',
        'description': 'Temporary four-node self-steal deployment check', 'activeInternalSquads': [squad['uuid']]}
    save('test-user', body); user = api('POST', '/api/users/', body)
    assert user['uuid'] == identifier
    return {'temporary_user_created': True, 'expires_in_hours': 3}


def probe_module(n):
    path = ROOT.parent / 'selfsteal-ru214/panel.py'
    spec = importlib.util.spec_from_file_location('probe_support', path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    mod.STATE, mod.IP, mod.XRAY = STATE, n['ip'], XRAY
    return mod


def probe(api, n):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    created = read(n['id'] + '-created')
    assert api('GET', '/api/nodes/' + created['node'])['isConnected']
    reality = read(n['id'] + '-config')['inbounds'][0]['streamSettings']['realitySettings']
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['privateKey'] + '='))
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    tests = []
    for address, fingerprint in [(n['ip'], 'firefox'), (n['domain'], 'chrome')]:
        outbound = {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
            'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                'serverName': n['domain'], 'fingerprint': fingerprint, 'publicKey': public, 'shortId': reality['shortIds'][0]}}}
        tests.append({'address': address, 'fingerprint': fingerprint, **probe_module(n).test_outbound(outbound)})
    proof = {'id': n['id'], 'timestamp': time.time(), 'all_passed': all(x['passed'] for x in tests), 'tests': tests}
    save(n['id'] + '-probe', proof); assert proof['all_passed'], 'Keep hosts disabled: probe failed'
    return proof


def verify(api):
    before = read('before')
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    for n in before['nodes']:
        now = nodes[n['uuid']]
        for k in ('name', 'address', 'port', 'isDisabled'): assert n[k] == now[k], 'Unrelated node changed'
        assert binding(n) == binding(now), 'Unrelated binding changed'
    for h in before['hosts']:
        assert {k:v for k,v in h.items() if k != 'viewPosition'} == {k:v for k,v in hosts[h['uuid']].items() if k != 'viewPosition'}, 'Unrelated host changed'
    assert api('GET', '/api/config-profiles/' + NORMAL_PROFILE)['config'] == before['normal']['config']
    created = [read(n['id'] + '-created') for n in NODES if exists(n['id'] + '-created')]
    for s in before['squads']:
        required = set(ids(s)) | {c['inbound'] for c in created if s['uuid'] in c['squads']}
        assert required <= set(ids(api('GET', '/api/internal-squads/' + s['uuid']))), 'Entitlement removed'
    for c in created: assert nodes[c['node']]['isConnected'] and not nodes[c['node']]['isDisabled']
    return {'existing_nodes_preserved': len(before['nodes']), 'existing_hosts_preserved': len(before['hosts']),
            'new_nodes_connected': len(created), 'original_normal_profile_preserved': True}


def publish(api, n):
    proof = read(n['id'] + '-probe'); assert proof['all_passed'] and time.time() - proof['timestamp'] < 900
    verify(api); c = read(n['id'] + '-created')
    for identifier in c['hosts']:
        h = api('GET', '/api/hosts/' + identifier)
        assert h['address'] == n['domain'] and h['nodes'] == [c['node']]
        api('PATCH', '/api/hosts/', {'uuid': identifier, 'isDisabled': False})
        assert not api('GET', '/api/hosts/' + identifier)['isDisabled']
    save(n['id'] + '-published', {'timestamp': time.time()})
    return {'id': n['id'], 'published_visible_and_auto_host': True}


def subscription(api, n):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/3.11.0',
        'X-Hwid': 'selfsteal-eu-20260917-probe', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=30) as response:
        configs = json.load(response); assert response.status == 200
    matching = [c for c in configs if c.get('remarks') == n['name']]
    assert len(matching) == 1
    def targets(c):
        return [o for o in c.get('outbounds', []) if o.get('protocol') == 'vless' and
                any(s.get('address') == n['domain'] for s in o.get('settings', {}).get('vnext', []))]
    direct = targets(matching[0]); assert len(direct) == 1
    assert direct[0]['streamSettings']['security'] == 'reality'
    assert direct[0]['streamSettings']['realitySettings']['serverName'] == n['domain']
    automatic = [c for c in configs if 'Автовыбор Серверов' in c.get('remarks', '')]
    assert len(automatic) == 1 and targets(automatic[0]), 'New node absent from normal auto-selection'
    proof = {'id': n['id'], 'timestamp': time.time(), 'configs': len(configs),
        'visible_host_count': len(matching), 'auto_candidates': len(targets(automatic[0])),
        **probe_module(n).test_outbound(direct[0])}
    save(n['id'] + '-subscription', proof); assert proof['passed']
    return proof


def rollback(api, n):
    c = read(n['id'] + '-created')
    for identifier in c.get('hosts', []):
        host = api('GET', '/api/hosts/' + identifier)
        assert host['nodes'] == [c['node']] and host['address'] == n['domain'], 'Later unrelated edit'
        api('PATCH', '/api/hosts/', {'uuid': identifier, 'isDisabled': True})
    if 'inbound' in c:
        for sid in c['squads']:
            squad = api('GET', '/api/internal-squads/' + sid)
            remaining = [i for i in ids(squad) if i != c['inbound']]
            if remaining != ids(squad): api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': remaining})
    save(n['id'] + '-rollback', {'timestamp': time.time()})
    return {'id': n['id'], 'own_hosts_disabled': True, 'own_entitlements_detached': True}


def cleanup(api, query):
    intent = read('test-user'); user = api('GET', '/api/users/' + intent['uuid'])
    assert all(user[k] == intent[k] for k in ('username', 'tag', 'description'))
    api('DELETE', '/api/users/' + intent['uuid'])
    result = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(intent['uuid'])) + "'")
    assert result['remaining'] == 0
    save('test-cleanup', {'verified_absent': True, 'timestamp': time.time()})
    return {'temporary_account_deleted': True, 'verified_absent': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['stage', 'create-test', 'probe', 'publish', 'subscription', 'verify', 'rollback', 'cleanup'])
    parser.add_argument('--id', choices=[n['id'] for n in NODES])
    args = parser.parse_args(); api, query = create_client()
    if args.action == 'cleanup': result = cleanup(api, query)
    elif args.action == 'create-test': result = create_test(api)
    elif args.action == 'verify': result = verify(api)
    else:
        assert args.id, 'Node ID required'
        result = globals()[args.action](api, next(n for n in NODES if n['id'] == args.id))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__': main()
