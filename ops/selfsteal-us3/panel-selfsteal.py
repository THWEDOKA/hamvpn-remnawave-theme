"""Scoped, backed-up REALITY profile transition for one existing node."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid as uuidlib

from panel_api import create_client

NODE = '22ac9320-4762-461d-b877-a9f33b58d492'
OLD_PROFILE = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
OLD_INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
HOSTS = ('a2302256-68a3-4e3e-8213-5817b0177712', '2a69e425-fb50-4bea-aeec-868735309ff4')
NAME = 'US3-SELFSTEAL'
TAG = 'vless-reality-us3-selfsteal'
DOMAIN = 'us3.torcalc.ru'
IP = '162.141.185.216'
STATE = Path('/root/selfsteal-us3-panel')
XRAY = '/root/selfsteal-us3-test/xray'
TEST_ACCOUNT = Path('/root/selfsteal-us3-test/probe-account.json')


def clone_config(config):
    result = copy.deepcopy(config)
    assert len(result['inbounds']) == 1
    inbound = result['inbounds'][0]
    assert inbound['tag'] == 'vless-reality-shared'
    assert inbound['port'] == 443 and inbound['protocol'] == 'vless'
    stream = inbound['streamSettings']
    assert stream['network'] == 'raw' and stream['security'] == 'reality'
    inbound['tag'] = TAG
    reality = stream['realitySettings']
    assert reality.get('target') == 'google.com:443' and 'dest' not in reality
    reality['target'] = '127.0.0.1:8443'
    reality['serverNames'] = list(dict.fromkeys([DOMAIN, *reality['serverNames']]))
    for rule in result.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            rule['inboundTag'] = [TAG if tag == 'vless-reality-shared' else tag for tag in rule['inboundTag']]
    return result


def ids(squad):
    return [i['uuid'] for i in squad['inbounds']]


def preserved_squad_access(original, current, pilot_id):
    expected = {*ids(original), pilot_id}
    actual = set(ids(current))
    assert expected <= actual, 'Original or pilot squad access removed'
    return len(actual - expected)


def node_binding(node):
    p = node['configProfile']
    return {'activeConfigProfileUuid': p['activeConfigProfileUuid'],
            'activeInbounds': [i['uuid'] for i in p['activeInbounds']]}


def save(name, data):
    path = STATE / name
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.chmod(0o600)
    temp.replace(path)


def read(name):
    return json.loads((STATE / name).read_text(encoding='utf-8'))


def stage(api):
    assert not STATE.exists(), 'Existing state; inspect before retry'
    profile = api('GET', f'/api/config-profiles/{OLD_PROFILE}')
    node = api('GET', f'/api/nodes/{NODE}')
    hosts = [api('GET', f'/api/hosts/{uuid}') for uuid in HOSTS]
    assert node['address'] == IP and node['isConnected'] and not node['isDisabled']
    assert node_binding(node) == {'activeConfigProfileUuid': OLD_PROFILE, 'activeInbounds': [OLD_INBOUND]}
    assert len(profile['nodes']) == 15
    for host in hosts:
        assert host['nodes'] == [NODE] and host['address'] == IP and host['port'] == 443
        assert host['inbound']['configProfileInboundUuid'] == OLD_INBOUND and not host['isDisabled']
    profiles = api('GET', '/api/config-profiles/')['configProfiles']
    assert not any(p['name'] == NAME for p in profiles), 'Profile name already exists'
    squads = [s for s in api('GET', '/api/internal-squads/')['internalSquads'] if OLD_INBOUND in ids(s)]
    assert len(squads) == 4
    config = clone_config(profile['config'])
    STATE.mkdir(mode=0o700)
    save('snapshot.json', {'profile': profile, 'node': node, 'hosts': hosts, 'squads': squads})
    save('snapshot-sha256.json', {'sha256': hashlib.sha256((STATE / 'snapshot.json').read_bytes()).hexdigest()})
    # Backup exists before the first API mutation. Do not repeat an uncertain POST.
    created = api('POST', '/api/config-profiles/', {'name': NAME, 'config': config})
    save('created-profile.json', created)
    assert created['config'] == config and len(created['inbounds']) == 1
    new_id = created['inbounds'][0]['uuid']
    for squad in squads:
        current = api('GET', f"/api/internal-squads/{squad['uuid']}")
        assert ids(current) == ids(squad), 'Concurrent squad change; inspect first'
        updated = api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': [*ids(current), new_id]})
        assert set(ids(updated)) == {*ids(current), new_id}
    save('stage.json', {'profile': created['uuid'], 'inbound': new_id, 'phase': 'staged'})
    return {'phase': 'staged', 'profile': created['uuid'], 'inbound': new_id, 'squads': len(squads)}


def switch(api):
    state = read('stage.json')
    node = api('GET', f'/api/nodes/{NODE}')
    assert node_binding(node) == node_binding(read('snapshot.json')['node'])
    for squad in read('snapshot.json')['squads']:
        assert state['inbound'] in ids(api('GET', f"/api/internal-squads/{squad['uuid']}"))
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {
        'activeConfigProfileUuid': state['profile'], 'activeInbounds': [state['inbound']]}})
    state['phase'] = 'switched'
    save('stage.json', state)
    return {'phase': 'switched', 'node': NODE}


def publish(api):
    state = read('stage.json')
    proof = read('probe-after.json')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 600
    assert api('GET', f'/api/nodes/{NODE}')['configProfile']['activeConfigProfileUuid'] == state['profile']
    for original in read('snapshot.json')['hosts']:
        current = api('GET', f"/api/hosts/{original['uuid']}")
        for key in ('inbound', 'address', 'sni', 'host', 'nodes', 'isDisabled', 'isHidden'):
            assert current[key] == original[key], 'Concurrent host change; inspect first'
        body = {'uuid': original['uuid'], 'address': DOMAIN, 'sni': DOMAIN,
                'host': DOMAIN, 'isDisabled': original['isDisabled'],
                'inbound': {'configProfileUuid': state['profile'], 'configProfileInboundUuid': state['inbound']}}
        updated = api('PATCH', '/api/hosts/', body)
        assert all(updated[k] == v for k, v in body.items())
    state['phase'] = 'published'
    save('stage.json', state)
    return {'phase': 'published', 'hosts_changed': len(HOSTS), 'hostname': DOMAIN}


def verify(api):
    state, backup = read('stage.json'), read('snapshot.json')
    original = api('GET', f'/api/config-profiles/{OLD_PROFILE}')
    assert original['config'] == backup['profile']['config'], 'Shared profile changed'
    assert {n['uuid'] for n in original['nodes']} == {n['uuid'] for n in backup['profile']['nodes']} - {NODE}
    new = api('GET', f"/api/config-profiles/{state['profile']}")
    assert new['config'] == clone_config(backup['profile']['config'])
    assert [n['uuid'] for n in new['nodes']] == [NODE]
    concurrent_additions = {}
    for squad in backup['squads']:
        current = api('GET', f"/api/internal-squads/{squad['uuid']}")
        extra = preserved_squad_access(squad, current, state['inbound'])
        if extra:
            concurrent_additions[squad['name']] = extra
    node = api('GET', f'/api/nodes/{NODE}')
    assert node['isConnected'] and not node['isDisabled']
    for uuid in HOSTS:
        host = api('GET', f'/api/hosts/{uuid}')
        assert host['address'] == host['sni'] == host['host'] == DOMAIN
        assert host['inbound']['configProfileInboundUuid'] == state['inbound']
    return {'verified': True, 'other_nodes_preserved': 14, 'connected': node['isConnected'],
            'users_online': node.get('usersOnline'), 'xray_uptime': node.get('xrayUptime'),
            'concurrent_squad_additions_preserved': concurrent_additions}


def rollback(api):
    backup = read('snapshot.json')
    created = read('created-profile.json')
    profile_id, inbound_id = created['uuid'], created['inbounds'][0]['uuid']
    node = api('GET', f'/api/nodes/{NODE}')
    assert node['configProfile']['activeConfigProfileUuid'] in (OLD_PROFILE, profile_id)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': node_binding(backup['node'])})
    for original in backup['hosts']:
        current = api('GET', f"/api/hosts/{original['uuid']}")
        assert current['inbound']['configProfileUuid'] in (OLD_PROFILE, profile_id)
        body = {k: original[k] for k in ('uuid', 'inbound', 'address', 'sni', 'host', 'isDisabled')}
        api('PATCH', '/api/hosts/', body)
    # Preserve every concurrent squad addition except this pilot's own inbound.
    for squad in backup['squads']:
        current = api('GET', f"/api/internal-squads/{squad['uuid']}")
        if inbound_id in ids(current):
            api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': [i for i in ids(current) if i != inbound_id]})
    # Keep the inactive profile and root-only backup for audit/recovery; no deletes.
    save('rollback.json', {'timestamp': time.time(), 'restored': True})
    return {'restored': True, 'inactive_profile_retained': profile_id}


def create_test(api, query):
    assert not TEST_ACCOUNT.exists(), 'Existing test intent; inspect before retry'
    user_id = str(uuidlib.uuid4())
    body = {'uuid': user_id, 'username': 'ss_us3_probe_' + user_id[:8],
            'expireAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            'trafficLimitBytes': 1024 * 1024 * 1024, 'trafficLimitStrategy': 'NO_RESET',
            'tag': 'SELFSTEAL_PROBE', 'description': 'Temporary USA-3 deployment probe; remove after verification',
            'activeInternalSquads': ['fbbac611-42b0-4d4a-8be4-8f2faf555f5d']}
    TEST_ACCOUNT.write_text(json.dumps(body))
    TEST_ACCOUNT.chmod(0o600)
    created = api('POST', '/api/users/', body)
    assert created['uuid'] == user_id and created['username'] == body['username']
    return {'created_test_account': True, 'expires_in_minutes': 60, 'traffic_limit_gib': 1}


def cleanup_test(api, query):
    intent = json.loads(TEST_ACCOUNT.read_text())
    current = api('GET', f"/api/users/{intent['uuid']}")
    assert current['uuid'] == intent['uuid'] and current['username'] == intent['username']
    assert current['tag'] == 'SELFSTEAL_PROBE' and current['description'] == intent['description']
    api('DELETE', f"/api/users/{intent['uuid']}")
    remaining = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + intent['uuid'] + "'")
    assert remaining['remaining'] == 0
    return {'temporary_test_account_deleted': True, 'verified_absent': True}


def probe(api, query, after):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    profile = api('GET', f'/api/config-profiles/{OLD_PROFILE}')
    reality = profile['config']['inbounds'][0]['streamSettings']['realitySettings']
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['privateKey'] + '='))
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
    intent = json.loads(TEST_ACCOUNT.read_text())
    user = api('GET', f"/api/users/{intent['uuid']}")
    assert user['username'] == intent['username'] and user['status'] == 'ACTIVE'
    scenarios = [('cached', IP, 'global.hambot.ru', 'qq')]
    if after:
        scenarios += [('new-qq', DOMAIN, DOMAIN, 'qq'), ('new-chrome', DOMAIN, DOMAIN, 'chrome')]
    results = []
    for label, address, sni, fingerprint in scenarios:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        config = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
                  'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
                  'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
                  'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
                  'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                  'serverName': sni, 'fingerprint': fingerprint, 'publicKey': public, 'shortId': reality['shortIds'][0]}}}]}
        with tempfile.TemporaryDirectory(prefix='probe-', dir='/root/selfsteal-us3-test') as directory:
            cfg = Path(directory) / 'client.json'
            cfg.write_text(json.dumps(config))
            cfg.chmod(0o600)
            proc = subprocess.Popen([XRAY, 'run', '-c', str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(40):
                    assert proc.poll() is None, 'Probe core failed to start'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                curl = ['curl', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{port}', '-fsS', '--connect-timeout', '10', '--max-time', '20']
                response = subprocess.run([*curl, '-o', '/dev/null', '-w', '%{http_code}', 'https://www.gstatic.com/generate_204'], text=True, capture_output=True)
                exit_ip = subprocess.run([*curl, 'https://api.ipify.org'], text=True, capture_output=True)
                passed = response.returncode == 0 and response.stdout == '204' and exit_ip.returncode == 0 and exit_ip.stdout.strip() == IP
                results.append({'scenario': label, 'sni': sni, 'fingerprint': fingerprint,
                                'http_status': response.stdout, 'exit_ip': exit_ip.stdout.strip() if exit_ip.returncode == 0 else None,
                                'passed': passed, 'curl_codes': [response.returncode, exit_ip.returncode]})
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    result = {'timestamp': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    if after:
        save('probe-after.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['stage', 'switch', 'publish', 'verify', 'rollback', 'probe-before', 'probe-after', 'create-test', 'cleanup-test'])
    args = parser.parse_args()
    assert os.geteuid() == 0
    os.umask(0o077)
    api, query = create_client()
    if args.action.startswith('probe-'):
        result = probe(api, query, args.action == 'probe-after')
    elif args.action == 'create-test':
        result = create_test(api, query)
    elif args.action == 'cleanup-test':
        result = cleanup_test(api, query)
    else:
        result = globals()[args.action](api)
    print(json.dumps(result, ensure_ascii=False))
    if result.get('all_passed') is False:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
