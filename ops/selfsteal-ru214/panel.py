"""Scope-limited migration of the existing RU214 REALITY node; secrets stay on panel."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
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

IP = '161.104.90.214'
DOMAIN = 'ru214.torcalc.ru'
NODE = '9b15b13b-7107-459e-a5c6-7ed870c190b3'
HOST = '7de41248-f207-49c3-b9f6-b239004831df'
OLD_PROFILE = 'f919bbcd-495a-456b-80e7-7674ba322d1e'
OLD_INBOUND = 'fc95b208-cb8b-43f0-9d0f-9e5dfc8b6566'
OLD_TAG = 'VLESS-RU-COMPAT'
TAG = 'vless-ru214-selfsteal'
NAME = 'RU214-SELFSTEAL'
STATE = Path('/root/selfsteal-ru214-panel')
XRAY = '/root/selfsteal-us3-test/xray'
TIMER = 'selfsteal-ru214-rollback'
HOST_FIELDS = ('inbound', 'address', 'sni', 'host', 'nodes', 'isDisabled', 'isHidden', 'fingerprint')


def save(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    path = STATE / (name + '.json')
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(path)


def read(name):
    return json.loads((STATE / (name + '.json')).read_text(encoding='utf-8'))


def ids(squad):
    return [i['uuid'] for i in squad['inbounds']]


def binding(node):
    value = node['configProfile']
    return {'activeConfigProfileUuid': value['activeConfigProfileUuid'],
            'activeInbounds': [i['uuid'] for i in value['activeInbounds']]}


def candidate(original):
    result = copy.deepcopy(original)
    assert len(result['inbounds']) == 1
    inbound = result['inbounds'][0]
    assert inbound['tag'] == OLD_TAG and inbound['port'] == 443 and inbound['protocol'] == 'vless'
    stream = inbound['streamSettings']
    assert stream['security'] == 'reality' and stream['network'] in ('raw', 'tcp')
    reality = stream['realitySettings']
    assert reality.get('target') == 'google.com:443' and 'dest' not in reality
    inbound['tag'] = TAG
    reality['target'] = '127.0.0.1:8443'
    reality['serverNames'] = list(dict.fromkeys([DOMAIN, *reality['serverNames']]))
    for rule in result.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            rule['inboundTag'] = [TAG if tag == OLD_TAG else tag for tag in rule['inboundTag']]
    return result


def stage(api):
    assert not (STATE / 'before.json').exists(), 'Existing intent; inspect instead of retrying'
    nodes, hosts = api('GET', '/api/nodes/'), api('GET', '/api/hosts/')
    node = next(n for n in nodes if n['uuid'] == NODE)
    assert node['address'] == IP and node['isConnected'] and not node['isDisabled']
    assert binding(node) == {'activeConfigProfileUuid': OLD_PROFILE, 'activeInbounds': [OLD_INBOUND]}
    selected_hosts = [h for h in hosts if NODE in h.get('nodes', []) or h['address'] in (IP, DOMAIN)]
    assert len(selected_hosts) == 1 and selected_hosts[0]['uuid'] == HOST
    host = selected_hosts[0]
    assert host['nodes'] == [NODE] and not host['isDisabled'] and host['address'] == IP
    assert host['inbound'] == {'configProfileUuid': OLD_PROFILE, 'configProfileInboundUuid': OLD_INBOUND}
    profiles = api('GET', '/api/config-profiles/')['configProfiles']
    assert not any(p['name'] == NAME for p in profiles)
    assert not any(i['tag'] == TAG for p in profiles for i in p['inbounds'])
    profile = api('GET', '/api/config-profiles/' + OLD_PROFILE)
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    selected = [s for s in squads if OLD_INBOUND in ids(s)]
    assert selected
    save('before', {'node': node, 'host': host, 'profile': profile, 'nodes': nodes,
                   'hosts': hosts, 'squads': squads, 'selected_squads': [s['uuid'] for s in selected]})
    save('backup-checksum', {'sha256': hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()})
    config = candidate(profile['config'])
    save('candidate', config)
    # Persisted intent precedes POST; never repeat POST blindly after uncertainty.
    save('create-intent', {'name': NAME, 'timestamp': time.time()})
    new = api('POST', '/api/config-profiles/', {'name': NAME, 'config': config})
    save('created', {'profile': new['uuid'], 'inbound': new['inbounds'][0]['uuid']})
    assert len(new['inbounds']) == 1 and new['config'] == config
    for squad in selected:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        assert set(ids(squad)) <= set(ids(current)), 'Existing squad access removed concurrently'
        proposed = list(dict.fromkeys(ids(current) + [new['inbounds'][0]['uuid']]))
        updated = api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': proposed})
        assert set(ids(updated)) == set(proposed)
    return {'staged': True, 'profile': new['uuid'], 'inbound': new['inbounds'][0]['uuid'],
            'squads': [s['name'] for s in selected], 'active_node_unchanged': True}


def create_test(api):
    assert not (STATE / 'test-user.json').exists()
    before = read('before')
    squad = next(s for s in before['squads'] if s['uuid'] in before['selected_squads'] and s['name'] == 'BASE')
    identifier = str(uuid.uuid4())
    body = {'uuid': identifier, 'username': 'ssru214_probe_' + identifier[:8],
            'expireAt': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            'trafficLimitBytes': 1073741824, 'trafficLimitStrategy': 'NO_RESET',
            'tag': 'RU214_PROBE', 'description': 'Temporary RU214 self-steal deployment probe',
            'activeInternalSquads': [squad['uuid']]}
    save('test-user', body)
    user = api('POST', '/api/users/', body)
    assert user['uuid'] == identifier
    return {'temporary_account_created': True, 'expires_in_minutes': 120}


def test_outbound(outbound):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
        'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [outbound]}
    with tempfile.TemporaryDirectory(prefix='probe-', dir=STATE) as directory:
        path = Path(directory) / 'client.json'
        path.write_text(json.dumps(config)); path.chmod(0o600)
        proc = subprocess.Popen([XRAY, 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                assert proc.poll() is None, 'Probe failed to start'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            curl = ['curl', '-4', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                    '-fsS', '--connect-timeout', '8', '--max-time', '15']
            response = subprocess.run(curl + ['-o', '/dev/null', '-w', '%{http_code}',
                'https://www.gstatic.com/generate_204'], capture_output=True, text=True)
            egress = subprocess.run(curl + ['https://ifconfig.me/ip'], capture_output=True, text=True)
            return {'passed': response.returncode == 0 and response.stdout == '204' and
                    egress.returncode == 0 and egress.stdout.strip() == IP,
                    'http_status': response.stdout, 'exit_ip': egress.stdout.strip() if egress.returncode == 0 else None,
                    'curl_codes': [response.returncode, egress.returncode]}
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)


def probe(api, after):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    before = read('before')
    reality = before['profile']['config']['inbounds'][0]['streamSettings']['realitySettings']
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['privateKey'] + '='))
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    scenarios = [('cached-firefox', IP, before['host']['sni'], before['host']['fingerprint'])]
    if after: scenarios += [('new-firefox', DOMAIN, DOMAIN, 'firefox'), ('new-chrome', DOMAIN, DOMAIN, 'chrome')]
    results = []
    for label, address, sni, fingerprint in scenarios:
        outbound = {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
            'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                'serverName': sni, 'fingerprint': fingerprint, 'publicKey': public, 'shortId': reality['shortIds'][0]}}}
        results.append({'scenario': label, **test_outbound(outbound)})
        if not results[-1]['passed']: break
    proof = {'timestamp': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    save('probe-after' if after else 'probe-before', proof)
    if not proof['all_passed']:
        if after: rollback(api)
        print(json.dumps(proof))
        raise RuntimeError('VPN probe failed; previous binding restored if switched')
    return proof


def switch(api):
    before, created = read('before'), read('created')
    proof, validation = read('probe-before'), read('xray-test')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 1800
    assert validation['passed'] and validation['sha256'] == hashlib.sha256((STATE / 'candidate.json').read_bytes()).hexdigest()
    subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer'], check=True)
    assert binding(api('GET', '/api/nodes/' + NODE)) == binding(before['node'])
    assert api('GET', '/api/config-profiles/' + OLD_PROFILE)['config'] == before['profile']['config']
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {
        'activeConfigProfileUuid': created['profile'], 'activeInbounds': [created['inbound']]}})
    save('switched', {'timestamp': time.time()})
    return {'switched_only_ru214': True, 'rollback_armed': True}


def publish(api):
    proof, before, created = read('probe-after'), read('before'), read('created')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 600
    host = api('GET', '/api/hosts/' + HOST)
    assert all(host[k] == before['host'][k] for k in HOST_FIELDS)
    api('PATCH', '/api/hosts/', {'uuid': HOST, 'address': DOMAIN, 'sni': DOMAIN, 'host': DOMAIN,
        'isDisabled': before['host']['isDisabled'], 'inbound': {
            'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['inbound']}})
    save('published', {'timestamp': time.time()})
    return {'published': True, 'name_preserved': before['host']['remark']}


def reviewed_host(original, changes):
    """Allow only exact independently reviewed concurrent IP changes, never a wildcard."""
    expected = copy.deepcopy(original)
    if original['uuid'] in changes:
        change = changes[original['uuid']]
        assert original['uuid'] != HOST and set(change) == {'before', 'after'}
        assert original['address'] == change['before'] and change['before'] != change['after']
        for value in change.values():
            assert str(ipaddress.IPv4Address(value)) == value
        expected['address'] = change['after']
    return expected


def verify(api):
    before, created = read('before'), read('created')
    concurrent = {}
    if (STATE / 'reviewed-concurrent-addresses.json').exists():
        review = read('reviewed-concurrent-addresses')
        assert review['snapshot_sha256'] == hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()
        assert review['reviewed'] is True
        concurrent = review['hosts']
        assert set(concurrent) <= {h['uuid'] for h in before['hosts']} - {HOST}
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    assert nodes[NODE]['isConnected'] and not nodes[NODE]['isDisabled']
    assert binding(nodes[NODE]) == {'activeConfigProfileUuid': created['profile'], 'activeInbounds': [created['inbound']]}
    for node in before['nodes']:
        if node['uuid'] != NODE:
            assert binding(node) == binding(nodes[node['uuid']]), 'Unrelated node binding changed'
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    reordered = 0
    for host in before['hosts']:
        if host['uuid'] == HOST: continue
        current = hosts[host['uuid']]
        expected_host = reviewed_host(host, concurrent)
        assert {k: v for k, v in expected_host.items() if k != 'viewPosition'} == {k: v for k, v in current.items() if k != 'viewPosition'}, 'Unreviewed unrelated host change'
        reordered += host.get('viewPosition') != current.get('viewPosition')
    expected = copy.deepcopy(before['host'])
    expected.update(address=DOMAIN, sni=DOMAIN, host=DOMAIN, inbound={
        'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['inbound']})
    assert {k: v for k, v in hosts[HOST].items() if k != 'viewPosition'} == {k: v for k, v in expected.items() if k != 'viewPosition'}
    assert api('GET', '/api/config-profiles/' + OLD_PROFILE)['config'] == before['profile']['config']
    extras = {}
    for squad in before['squads']:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        expected_ids = set(ids(squad))
        if squad['uuid'] in before['selected_squads']: expected_ids.add(created['inbound'])
        assert expected_ids <= set(ids(current)), 'Existing entitlement removed'
        if set(ids(current)) - expected_ids: extras[squad['name']] = len(set(ids(current)) - expected_ids)
    return {'connected': True, 'users_online': nodes[NODE].get('usersOnline'),
            'other_node_bindings_preserved': len(before['nodes']) - 1,
            'other_hosts_preserved': len(before['hosts']) - 1, 'old_profile_preserved': True,
            'concurrent_squad_additions_preserved': extras,
            'reviewed_concurrent_address_changes_preserved': len(concurrent),
            'concurrent_host_reorders_preserved': reordered,
            'concurrent_new_hosts_preserved': len(set(hosts) - {h['uuid'] for h in before['hosts']})}


def subscription(api):
    import urllib.request
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    request = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/3.11.0',
        'X-Hwid': 'selfsteal-ru214-deployment-probe', 'X-Device-Os': 'iOS',
        'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(request, timeout=20) as response:
        configs = json.load(response); assert response.status == 200
    matches = [c for c in configs if c.get('remarks') == read('before')['host']['remark']]
    assert len(matches) == 1
    outbounds = [o for o in matches[0]['outbounds'] if o.get('protocol') == 'vless' and
        any(s.get('address') == DOMAIN for s in o.get('settings', {}).get('vnext', []))]
    assert len(outbounds) == 1
    outbound = outbounds[0]
    assert outbound['streamSettings']['security'] == 'reality'
    assert outbound['streamSettings']['realitySettings']['serverName'] == DOMAIN
    result = test_outbound(outbound)
    assert result['passed']
    result.update(public_subscription_http=200, single_host_count=1, configs=len(configs),
                  security='reality', timestamp=time.time())
    save('subscription-proof', result)
    return result


def rollback(api):
    before, created = read('before'), read('created')
    node, host = api('GET', '/api/nodes/' + NODE), api('GET', '/api/hosts/' + HOST)
    expected = {'activeConfigProfileUuid': created['profile'], 'activeInbounds': [created['inbound']]}
    assert binding(node) in (binding(before['node']), expected), 'Later unrelated binding; stop'
    assert host['inbound']['configProfileUuid'] in (OLD_PROFILE, created['profile']), 'Later unrelated host; stop'
    for key in ('address', 'sni', 'host'):
        assert host[key] in (before['host'][key], DOMAIN), 'Later unrelated host field; stop'
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': binding(before['node'])})
    api('PATCH', '/api/hosts/', {k: before['host'][k] for k in ('uuid', 'inbound', 'address', 'sni', 'host', 'isDisabled')})
    for sid in before['selected_squads']:
        squad = api('GET', '/api/internal-squads/' + sid)
        remaining = [i for i in ids(squad) if i != created['inbound']]
        if remaining != ids(squad): api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': remaining})
    assert binding(api('GET', '/api/nodes/' + NODE)) == binding(before['node'])
    save('rollback', {'timestamp': time.time(), 'restored': True})
    return {'old_binding_restored': True, 'inactive_profile_retained': True}


def cleanup(api, query):
    intent = read('test-user')
    user = api('GET', '/api/users/' + intent['uuid'])
    assert all(user[k] == intent[k] for k in ('username', 'tag', 'description'))
    api('DELETE', '/api/users/' + intent['uuid'])
    count = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(intent['uuid'])) + "'")
    assert count['remaining'] == 0
    save('test-cleanup', {'timestamp': time.time(), 'verified_absent': True})
    return {'own_temporary_account_deleted': True, 'verified_absent': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['stage', 'create-test', 'probe-before', 'probe-after',
        'switch', 'publish', 'verify', 'subscription', 'rollback', 'cleanup-test'])
    action = parser.parse_args().action
    api, query = create_client()
    if action.startswith('probe-'): result = probe(api, action == 'probe-after')
    elif action == 'cleanup-test': result = cleanup(api, query)
    else: result = globals()[action.replace('-', '_')](api)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__': main()
