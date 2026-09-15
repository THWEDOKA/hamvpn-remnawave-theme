"""Scoped TLS-to-REALITY migration with a cached-TLS compatibility target."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'vless-tls245'))
import panel_deploy as common

STATE = Path('/root/selfsteal-tls245-panel')
common.STATE = STATE
IP, DOMAIN = common.IP, common.DOMAIN
NODE = 'dd62f99f-0464-413f-915e-05bb075098bd'
OLD_PROFILE = 'd67d1f67-62bc-4133-9183-5e9cfecc189c'
OLD_INBOUND = '1957094e-0d78-4c48-9004-a11f2518a5d5'
HOST = 'f9e8c4e3-24f4-4771-8e09-69d366c8f5b6'
PROFILE_NAME = 'TLS245-SELFSTEAL'
TAGS = ['tls245-selfsteal', 'tls245-legacy-compat']
TIMER = 'selfsteal-tls245-rollback'
save, read, ids = common.save, common.read, common.ids


def connection_fields(host):
    # A concurrent host insertion/reorder changes positions, not connections.
    return {k: v for k, v in host.items() if k != 'viewPosition'}


def binding(node):
    return {'activeConfigProfileUuid': node['configProfile']['activeConfigProfileUuid'],
        'activeInbounds': [i['uuid'] for i in node['configProfile']['activeInbounds']]}


def candidate(original, private_key, short_id):
    config = copy.deepcopy(original)
    assert len(config['inbounds']) == 1
    old = config['inbounds'][0]
    assert old['protocol'] == 'vless' and old['port'] == 443
    assert old['streamSettings']['security'] == 'tls'
    assert old['streamSettings']['network'] in ('raw', 'tcp')
    legacy = copy.deepcopy(old)
    legacy.update(tag=TAGS[1], listen='127.0.0.1', port=8443)
    legacy['settings']['fallbacks'] = [
        {'dest': '127.0.0.1:8080'}, {'alpn': 'h2', 'dest': '127.0.0.1:8081'}]
    main = copy.deepcopy(old)
    main['tag'] = TAGS[0]
    main['settings'].pop('fallbacks', None)
    main['streamSettings'].pop('tlsSettings')
    main['streamSettings'].update(security='reality', realitySettings={
        'show': False, 'xver': 0, 'target': '127.0.0.1:8443',
        'serverNames': [DOMAIN], 'privateKey': private_key, 'shortIds': [short_id]})
    config['inbounds'] = [main, legacy]
    for rule in config.get('routing', {}).get('rules', []):
        if old['tag'] in rule.get('inboundTag', []):
            rule['inboundTag'] = [t for t in rule['inboundTag'] if t != old['tag']] + TAGS
    return config


def prepare(api):
    assert not (STATE / 'before.json').exists(), 'Existing migration intent; inspect instead of retrying'
    nodes = api('GET', '/api/nodes/')
    node = next(n for n in nodes if n['uuid'] == NODE)
    assert node['address'] == IP and node['isConnected'] and not node['isDisabled']
    assert binding(node) == {'activeConfigProfileUuid': OLD_PROFILE, 'activeInbounds': [OLD_INBOUND]}
    hosts = api('GET', '/api/hosts/')
    targets = [h for h in hosts if h['inbound'].get('configProfileUuid') == OLD_PROFILE or NODE in h.get('nodes', [])]
    assert len(targets) == 1 and targets[0]['uuid'] == HOST
    assert targets[0]['nodes'] == [NODE] and not targets[0]['isDisabled']
    profiles = api('GET', '/api/config-profiles/')['configProfiles']
    assert not any(p['name'] == PROFILE_NAME for p in profiles)
    profile = api('GET', '/api/config-profiles/' + OLD_PROFILE)
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    selected = [s for s in squads if OLD_INBOUND in ids(s)]
    assert selected
    for p in profiles:
        assert not any(i['tag'] in TAGS for i in p.get('inbounds', []))
    before = {'nodes': nodes, 'node': node, 'hosts': hosts, 'host': targets[0],
        'profile': profile, 'profiles': profiles, 'squads': squads,
        'selected_squads': [s['uuid'] for s in selected]}
    save('before', before)
    save('backup-checksum', {'sha256': hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()})
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
    key = X25519PrivateKey.generate()
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
    private = encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    public = encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    config = candidate(profile['config'], private, secrets.token_hex(8))
    save('candidate', config)
    save('key-public', {'publicKey': public})
    new = api('POST', '/api/config-profiles/', {'name': PROFILE_NAME, 'config': config})
    state = {'profile': new['uuid'], 'inbounds': {i['tag']: i['uuid'] for i in new['inbounds']}}
    save('created', state)
    assert set(state['inbounds']) == set(TAGS)
    for squad in selected:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        assert set(ids(current)) == set(ids(squad)), 'Concurrent entitlement edit'
        api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'],
            'inbounds': ids(current) + list(state['inbounds'].values())})
    return {'prepared': True, 'profile': new['uuid'], 'squads': [s['name'] for s in selected],
        'host_name_preserved': targets[0]['remark'], 'active_node_unchanged': True}


def create_test(api):
    assert not (STATE / 'test-user.json').exists()
    before = read('before')
    selected = [s for s in before['squads'] if s['uuid'] in before['selected_squads']]
    squad = next((s for s in selected if s['name'] == 'BASE'), selected[0])
    user_id = str(uuid.uuid4())
    body = {'uuid': user_id, 'username': 'ss245_probe_' + user_id[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        'trafficLimitBytes': 1073741824, 'trafficLimitStrategy': 'NO_RESET',
        'tag': 'TLS245_PROBE', 'description': 'Temporary self-steal TLS245 migration probe',
        'activeInternalSquads': [squad['uuid']]}
    save('test-user', body)
    user = api('POST', '/api/users/', body)
    assert user['uuid'] == user_id
    return {'temporary_account_created': True, 'expires_in_minutes': 120}


def test_outbound(outbound):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    config = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1',
        'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
        'outbounds': [outbound]}
    with tempfile.TemporaryDirectory(prefix='probe-', dir=STATE) as directory:
        path = Path(directory) / 'client.json'
        path.write_text(json.dumps(config)); path.chmod(0o600)
        proc = subprocess.Popen([common.XRAY, 'run', '-c', str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                assert proc.poll() is None, 'Probe process failed'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            curl = ['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                '-fsS', '--connect-timeout', '8', '--max-time', '15']
            response = subprocess.run(curl + ['-o', '/dev/null', '-w', '%{http_code}',
                'https://www.gstatic.com/generate_204'], capture_output=True, text=True)
            egress = subprocess.run(curl + ['https://api.ipify.org'], capture_output=True, text=True)
            return {'passed': response.returncode == 0 and response.stdout == '204' and
                egress.returncode == 0 and egress.stdout.strip() == IP,
                'http_status': response.stdout, 'exit_ip': egress.stdout.strip() if egress.returncode == 0 else None,
                'curl_codes': [response.returncode, egress.returncode]}
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)


def probe(api, after):
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    scenarios = [('cached-tls-ip', IP, 'tls', 'chrome'), ('cached-tls-domain', DOMAIN, 'tls', 'chrome')]
    if after:
        scenarios += [('reality-chrome', DOMAIN, 'reality', 'chrome'), ('reality-firefox', IP, 'reality', 'firefox')]
    results = []
    for label, address, security, fingerprint in scenarios:
        stream = {'network': 'raw', 'security': security}
        if security == 'tls':
            stream['tlsSettings'] = {'serverName': DOMAIN, 'fingerprint': fingerprint,
                'alpn': ['h2', 'http/1.1'], 'allowInsecure': False}
        else:
            reality = read('candidate')['inbounds'][0]['streamSettings']['realitySettings']
            stream['realitySettings'] = {'serverName': DOMAIN, 'fingerprint': fingerprint,
                'publicKey': read('key-public')['publicKey'], 'shortId': reality['shortIds'][0]}
        outbound = {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
            'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': stream}
        result = test_outbound(outbound)
        results.append({'scenario': label, **result})
        if not result['passed']: break
    proof = {'timestamp': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    save('probe-after' if after else 'probe-before', proof)
    if not proof['all_passed']:
        if after: rollback(api)
        raise RuntimeError('VPN probe failed; previous binding restored if switched')
    return proof


def switch(api):
    before, created = read('before'), read('created')
    proof = read('probe-before')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 1800
    validation = read('xray-test')
    assert validation['passed'] and validation['sha256'] == hashlib.sha256((STATE / 'candidate.json').read_bytes()).hexdigest()
    subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer'], check=True)
    current = api('GET', '/api/nodes/' + NODE)
    assert binding(current) == binding(before['node'])
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {
        'activeConfigProfileUuid': created['profile'], 'activeInbounds': list(created['inbounds'].values())}})
    save('switched', {'timestamp': time.time()})
    return {'switched_only_target_node': True, 'rollback_timer_armed': True}


def publish(api):
    proof = read('probe-after')
    assert proof['all_passed'] and time.time() - proof['timestamp'] < 600
    before, created = read('before'), read('created')
    host = api('GET', '/api/hosts/' + HOST)
    assert host['inbound'] == before['host']['inbound'] and host['remark'] == before['host']['remark']
    api('PATCH', '/api/hosts/', {'uuid': HOST, 'inbound': {'configProfileUuid': created['profile'],
        'configProfileInboundUuid': created['inbounds'][TAGS[0]]}, 'address': DOMAIN,
        'sni': DOMAIN, 'host': DOMAIN, 'isDisabled': before['host']['isDisabled']})
    save('published', {'timestamp': time.time()})
    return {'published': True, 'name_preserved': before['host']['remark']}


def verify(api):
    before, created = read('before'), read('created')
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    assert nodes[NODE]['isConnected'] and not nodes[NODE]['isDisabled']
    assert nodes[NODE]['configProfile']['activeConfigProfileUuid'] == created['profile']
    assert set(binding(nodes[NODE])['activeInbounds']) == set(created['inbounds'].values())
    for n in before['nodes']:
        if n['uuid'] == NODE: continue
        for k in ('name', 'address', 'port', 'isDisabled', 'configProfile'):
            assert n[k] == nodes[n['uuid']][k], 'Unrelated node changed'
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    reordered = []
    for h in before['hosts']:
        if h.get('viewPosition') != hosts[h['uuid']].get('viewPosition'):
            reordered.append(h['uuid'])
        if h['uuid'] != HOST:
            assert connection_fields(h) == connection_fields(hosts[h['uuid']]), 'Unrelated host connection changed'
    expected = copy.deepcopy(before['host'])
    expected.update(address=DOMAIN, sni=DOMAIN, host=DOMAIN,
        inbound={'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['inbounds'][TAGS[0]]})
    assert connection_fields(hosts[HOST]) == connection_fields(expected)
    assert api('GET', '/api/config-profiles/' + OLD_PROFILE)['config'] == before['profile']['config']
    concurrent_additions = {}
    for squad in before['squads']:
        current = api('GET', '/api/internal-squads/' + squad['uuid'])
        expected_ids = set(ids(squad))
        if squad['uuid'] in before['selected_squads']: expected_ids.update(created['inbounds'].values())
        assert expected_ids <= set(ids(current)), 'Required squad access removed'
        extra = set(ids(current)) - expected_ids
        if extra: concurrent_additions[squad['name']] = sorted(extra)
    return {'target_connected': True, 'other_nodes_preserved': len(before['nodes'])-1,
        'other_host_connections_preserved': len(before['hosts'])-1, 'old_profile_preserved': True,
        'concurrent_host_positions_preserved': len(reordered),
        'concurrent_new_hosts_preserved': len(set(hosts) - {h['uuid'] for h in before['hosts']}),
        'concurrent_squad_additions_preserved': concurrent_additions}


def subscription(api):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/3.11.0',
        'X-Hwid': 'selfsteal-tls245-deployment-probe', 'X-Device-Os': 'iOS',
        'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=20) as response:
        configs = json.load(response); assert response.status == 200
    matches = [c for c in configs if c.get('remarks') == read('before')['host']['remark']]
    assert len(matches) == 1
    outbounds = [o for o in matches[0]['outbounds'] if o.get('protocol') == 'vless' and
        any(s.get('address') == DOMAIN for s in o.get('settings', {}).get('vnext', []))]
    assert len(outbounds) == 1
    out = outbounds[0]
    assert out['streamSettings']['security'] == 'reality'
    assert out['streamSettings']['realitySettings']['serverName'] == DOMAIN
    result = test_outbound(out)
    assert result['passed']
    result.update(public_subscription_http=200, host_count=1, security='reality',
        configs=len(configs), timestamp=time.time())
    save('subscription-proof', result)
    return result


def rollback(api):
    before, created = read('before'), read('created')
    current = api('GET', '/api/nodes/' + NODE)
    assert current['configProfile']['activeConfigProfileUuid'] in (OLD_PROFILE, created['profile']), 'Unrelated later node binding'
    host = api('GET', '/api/hosts/' + HOST)
    assert host['inbound']['configProfileUuid'] in (OLD_PROFILE, created['profile']), 'Unrelated later host binding'
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': binding(before['node'])})
    original = before['host']
    api('PATCH', '/api/hosts/', {k: original[k] for k in ('uuid', 'inbound', 'address', 'sni', 'host', 'isDisabled')})
    for sid in before['selected_squads']:
        squad = api('GET', '/api/internal-squads/' + sid)
        remaining = [i for i in ids(squad) if i not in created['inbounds'].values()]
        if remaining != ids(squad): api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': remaining})
    save('rollback', {'timestamp': time.time(), 'old_tls_restored': True})
    return {'old_tls_restored': True, 'inactive_clone_retained': True}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['prepare','create-test','probe-before','probe-after',
        'switch','publish','verify','subscription','cleanup-test','rollback'])
    action = p.parse_args().action
    api, query = common.create_client()
    if action.startswith('probe-'): result = probe(api, action == 'probe-after')
    elif action == 'cleanup-test': result = common.cleanup(api, query)
    else: result = globals()[action.replace('-', '_')](api)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__': main()
