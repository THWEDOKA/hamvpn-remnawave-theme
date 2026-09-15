"""Scoped additive rollout. Run on the HAM panel, never print raw API records."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'selfsteal-us3'))
from panel_api import create_client

ROOT = Path(__file__).parent
STATE = Path('/root/hamvpn-tls245-panel')
IP = '196.251.107.245'
DOMAIN = 'tls245.torcalc.ru'
NAME = 'VLESS TLS — 245'
PROFILE_NAME = 'TLS245-VLESS'
SQUADS = {'WHITE', 'BASE', 'OLD', 'site'}
NORMAL_INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
XRAY = '/root/selfsteal-us3-test/xray'


def save(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    path = STATE / (name + '.json')
    path.write_text(json.dumps(value, ensure_ascii=False))
    path.chmod(0o600)


def read(name):
    return json.loads((STATE / (name + '.json')).read_text())


def ids(squad):
    return [i['uuid'] for i in squad['inbounds']]


def stage(api):
    assert not (STATE / 'created.json').exists(), 'Deployment intent already exists; inspect before retry'
    nodes = api('GET', '/api/nodes/')
    hosts = api('GET', '/api/hosts/')
    profiles = api('GET', '/api/config-profiles/')['configProfiles']
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    assert not any(n['address'] == IP or n['name'] == NAME for n in nodes)
    assert not any(h['address'] in (IP, DOMAIN) or h['remark'] == NAME for h in hosts)
    assert not any(p['name'] == PROFILE_NAME for p in profiles)
    selected = [s for s in squads if NORMAL_INBOUND in ids(s)]
    assert {s['name'] for s in selected} == SQUADS, 'Entitlements changed; stop'
    save('before', {'nodes': nodes, 'hosts': hosts, 'profiles': profiles, 'squads': squads})
    created = {'timestamp': time.time(), 'squads': [s['uuid'] for s in selected]}
    save('created', created)
    try:
        profile = api('POST', '/api/config-profiles/', {'name': PROFILE_NAME,
            'config': json.loads((ROOT / 'config.json').read_text())})
        created['profile'] = profile['uuid']
        save('created', created)
        inbound, = profile['inbounds']
        assert inbound['tag'] == 'vless-tls245' and inbound['security'] == 'tls'
        created['inbound'] = inbound['uuid']
        save('created', created)
        node = api('POST', '/api/nodes/', {'name': NAME, 'address': IP, 'port': 2222,
            'countryCode': 'DE', 'isTrafficTrackingActive': True,
            'configProfile': {'activeConfigProfileUuid': profile['uuid'], 'activeInbounds': [inbound['uuid']]},
            'note': 'Ordinary VLESS TCP TLS; tls245.torcalc.ru; no self-steal'})
        created['node'] = node['uuid']
        save('created', created)
        host = api('POST', '/api/hosts/', {'remark': NAME, 'address': DOMAIN, 'port': 443,
            'sni': DOMAIN, 'fingerprint': 'chrome', 'alpn': 'h2,http/1.1',
            'isDisabled': True, 'nodes': [node['uuid']], 'excludedInternalSquads': [],
            'inbound': {'configProfileUuid': profile['uuid'], 'configProfileInboundUuid': inbound['uuid']}})
        created['host'] = host['uuid']
        save('created', created)
        for squad in selected:
            current = api('GET', '/api/internal-squads/' + squad['uuid'])
            assert set(ids(current)) == set(ids(squad)), 'Concurrent squad edit; stop'
            api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'],
                'inbounds': ids(current) + [inbound['uuid']]})
        return {'staged': True, 'host_disabled': True, **created}
    except Exception:
        rollback(api)
        raise


def verify_preserved(api):
    before, created = read('before'), read('created')
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    profiles = {p['uuid']: p for p in api('GET', '/api/config-profiles/')['configProfiles']}
    for original in before['nodes']:
        current = nodes[original['uuid']]
        for key in ('name', 'address', 'port', 'isDisabled', 'configProfile'):
            assert original[key] == current[key], 'Existing node configuration changed'
    for original in before['hosts']:
        assert original == hosts[original['uuid']], 'Existing host changed'
    for original in before['profiles']:
        assert original == profiles[original['uuid']], 'Existing profile changed'
    for squad in before['squads']:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        expected = set(ids(squad))
        if squad['uuid'] in created['squads']:
            expected.add(created['inbound'])
        assert set(ids(current)) == expected, 'Unexpected squad change'
    node = nodes[created['node']]
    assert node['isConnected'] and not node['isDisabled'], 'New node not healthy'
    return {'existing_nodes_preserved': len(before['nodes']),
        'existing_hosts_preserved': len(before['hosts']),
        'existing_profiles_preserved': len(before['profiles']), 'new_node_connected': True}


def create_test(api):
    assert not (STATE / 'test-user.json').exists()
    user_id = str(uuid.uuid4())
    body = {'uuid': user_id, 'username': 'tls245_probe_' + user_id[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        'trafficLimitBytes': 1073741824, 'trafficLimitStrategy': 'NO_RESET',
        'tag': 'TLS245_PROBE', 'description': 'Temporary TLS245 deployment verification',
        'activeInternalSquads': ['fbbac611-42b0-4d4a-8be4-8f2faf555f5d']}
    save('test-user', body)
    user = api('POST', '/api/users/', body)
    assert user['uuid'] == user_id
    return {'temporary_test_created': True, 'expires_in_minutes': 60}


def probe(api):
    intent = read('test-user')
    user = api('GET', '/api/users/' + intent['uuid'])
    assert user['username'] == intent['username'] and user['status'] == 'ACTIVE'
    results = []
    for address in (IP, DOMAIN):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        config = {'log': {'loglevel': 'warning'}, 'inbounds': [{
            'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [{
            'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
                'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                'serverName': DOMAIN, 'fingerprint': 'chrome', 'alpn': ['h2', 'http/1.1'],
                'allowInsecure': False}}}]}
        with tempfile.TemporaryDirectory(prefix='probe-', dir=STATE) as directory:
            path = Path(directory) / 'client.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            proc = subprocess.Popen([XRAY, 'run', '-c', str(path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(40):
                    assert proc.poll() is None, 'Probe core failed'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                curl = ['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                    '-fsS', '--connect-timeout', '10', '--max-time', '20']
                response = subprocess.run(curl + ['-o', '/dev/null', '-w', '%{http_code}',
                    'https://www.gstatic.com/generate_204'], capture_output=True, text=True)
                egress = subprocess.run(curl + ['https://api.ipify.org'], capture_output=True, text=True)
                ok = response.returncode == 0 and response.stdout == '204' and egress.returncode == 0 and egress.stdout.strip() == IP
                results.append({'address': address, 'http_status': response.stdout,
                    'exit_ip': egress.stdout.strip() if egress.returncode == 0 else None,
                    'passed': ok, 'curl_codes': [response.returncode, egress.returncode]})
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
    result = {'timestamp': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    save('probe', result)
    assert result['all_passed'], 'Authenticated VPN probe failed; host remains unpublished'
    return result


def publish(api):
    proof = read('probe')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 600
    preserved = verify_preserved(api)
    created = read('created')
    host = api('GET', '/api/hosts/' + created['host'])
    assert host['address'] == DOMAIN and host['remark'] == NAME
    api('PATCH', '/api/hosts/', {'uuid': created['host'], 'isDisabled': False})
    assert not api('GET', '/api/hosts/' + created['host'])['isDisabled']
    save('published', {'timestamp': time.time(), **preserved})
    return {'published': True, **preserved}


def cleanup(api, query):
    intent = read('test-user')
    user = api('GET', '/api/users/' + intent['uuid'])
    assert user['username'] == intent['username'] and user['tag'] == 'TLS245_PROBE'
    api('DELETE', '/api/users/' + intent['uuid'])
    result = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(intent['uuid'])) + "'")
    assert result['remaining'] == 0
    save('test-cleanup', {'timestamp': time.time(), 'deleted': True})
    return {'temporary_account_deleted': True, 'verified_absent': True}


def rollback(api):
    created = read('created')
    if created.get('host'):
        api('PATCH', '/api/hosts/', {'uuid': created['host'], 'isDisabled': True})
    if created.get('inbound'):
        for squad_uuid in created['squads']:
            squad = api('GET', '/api/internal-squads/' + squad_uuid)
            if created['inbound'] in ids(squad):
                api('PATCH', '/api/internal-squads/', {'uuid': squad_uuid,
                    'inbounds': [i for i in ids(squad) if i != created['inbound']]})
    save('rollback', {'timestamp': time.time(), 'new_host_disabled': True})
    return {'new_host_disabled': True, 'only_new_inbound_detached': True,
        'inactive_artifacts_retained_for_audit': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['stage', 'verify', 'create-test', 'probe', 'publish', 'cleanup-test', 'rollback'])
    action = parser.parse_args().action
    api, query = create_client()
    actions = {'stage': stage, 'verify': verify_preserved, 'create-test': create_test,
        'probe': probe, 'publish': publish, 'rollback': rollback}
    result = cleanup(api, query) if action == 'cleanup-test' else actions[action](api)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
