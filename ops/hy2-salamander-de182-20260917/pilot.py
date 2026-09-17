"""One additive HY2/Salamander UDP8443 pilot. Runtime secrets stay on owned hosts."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-hy2-salamander-de182-20260917')
IP, DOMAIN, PORT = '217.60.68.182', 'de182.torcalc.ru', 8443
NODE, PROFILE = '2c0f93bf-ec0a-4dff-b0f1-b57badd920e1', '597b8c2d-65a6-40a5-bb97-2fb633157812'
TAG = 'ham-de182-hy2-salamander'
NAME = '🇩🇪 Германия — 3 · HY2 Salamander'
OLD_TAGS = ['ham-de182-vless-tls', 'ham-de182-hy2', 'ham-de182-xhttp-pilot']
TIMER = 'ham-hy2-salamander-de182-rollback'
XRAY = '/root/selfsteal-us3-test/xray'
sys.path.insert(0, str(ROOT.parent / 'selfsteal-us3'))
from panel_api import create_client


def save(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    p = STATE / (name + '.json'); temporary = p.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=True), encoding='utf-8')
    temporary.chmod(0o600); temporary.replace(p)


def read(name): return json.loads((STATE / (name + '.json')).read_text())
def exists(name): return (STATE / (name + '.json')).exists()
def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
def ids(s): return [i['uuid'] for i in s['inbounds']]


def binding(n):
    p = n.get('configProfile')
    return None if p is None else {'activeConfigProfileUuid': p['activeConfigProfileUuid'],
        'activeInbounds': [i['uuid'] for i in p['activeInbounds']]}


def mask(password):
    assert len(password) >= 32
    return {'udp': [{'type': 'salamander', 'settings': {'password': password}}]}


def candidate(original, password):
    assert [i['tag'] for i in original['inbounds']] == OLD_TAGS, 'Unexpected existing profile'
    assert all(i['port'] != PORT for i in original['inbounds'])
    result = copy.deepcopy(original)
    inbound = copy.deepcopy(next(i for i in original['inbounds'] if i['tag'] == OLD_TAGS[1]))
    assert inbound['protocol'] == 'hysteria' and inbound['streamSettings']['security'] == 'tls'
    assert inbound['settings']['clients'] == [] and inbound['settings']['version'] == 2
    inbound.update(tag=TAG, port=PORT)
    stream = inbound['streamSettings']
    assert stream['network'] == 'hysteria' and stream['hysteriaSettings']['version'] == 2
    assert 'udp' not in stream.get('finalmask', {})
    stream.setdefault('finalmask', {}).update(mask(password))
    result['inbounds'].append(inbound)
    return result


def host_body(inbound, password):
    return {'remark': NAME, 'address': DOMAIN, 'port': PORT, 'sni': DOMAIN, 'host': DOMAIN,
        'alpn': 'h3', 'securityLayer': 'DEFAULT', 'isDisabled': True, 'isHidden': False,
        'tags': [], 'nodes': [NODE], 'excludedInternalSquads': [], 'finalMask': mask(password),
        'inbound': {'configProfileUuid': PROFILE, 'configProfileInboundUuid': inbound}}


def snapshot(api):
    assert not exists('before'), 'Existing intent: reconcile rather than repeat'
    nodes, hosts = api('GET', '/api/nodes/'), api('GET', '/api/hosts/')
    node = next(n for n in nodes if n['uuid'] == NODE)
    assert node['address'] == IP and node['isConnected'] and not node['isDisabled']
    assert [n['uuid'] for n in nodes if (binding(n) or {}).get('activeConfigProfileUuid') == PROFILE] == [NODE]
    profile = api('GET', '/api/config-profiles/' + PROFILE)
    assert [i['tag'] for i in profile['inbounds']] == OLD_TAGS
    assert set(binding(node)['activeInbounds']) == set(ids(profile))
    assert not any(h['remark'] == NAME or (h['address'] in (IP, DOMAIN) and h['port'] == PORT) for h in hosts)
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    old_hy2 = next(i['uuid'] for i in profile['inbounds'] if i['tag'] == OLD_TAGS[1])
    selected = [s['uuid'] for s in squads if old_hy2 in ids(s)]
    assert selected
    save('before', {'nodes': nodes, 'hosts': hosts, 'profile': profile, 'squads': squads,
        'binding': binding(node), 'selected_squads': selected})
    password = secrets.token_urlsafe(32)
    save('obfs-secret', {'password': password})
    save('candidate', candidate(profile['config'], password))
    return {'backed_up': True, 'target': IP, 'udp_port': PORT, 'old_inbounds': 3, 'secret_generated_privately': True}


def node_test():
    assert IP + '/' in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    assert not subprocess.check_output(['ss', '-H', '-lnu', 'sport = :' + str(PORT)], text=True).strip()
    config = json.load(sys.stdin)
    assert config['inbounds'][-1]['tag'] == TAG and config['inbounds'][-1]['port'] == PORT
    assert [i['tag'] for i in config['inbounds'][:-1]] == OLD_TAGS
    save('node-candidate', config)
    paths = ['/opt/remnanode/docker-compose.yml', '/etc/nginx/conf.d/hamvpn-fallback.conf',
        '/etc/letsencrypt/renewal/de182.torcalc.ru.conf',
        '/etc/letsencrypt/renewal-hooks/deploy/hamvpn-selfsteal-nginx',
        '/usr/local/sbin/hamvpn-selfsteal-firewall']
    baseline = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}
    if exists('node-baseline'):
        assert read('node-baseline') == baseline, 'Concurrent node configuration edit'
    else:
        save('node-baseline', baseline)
    proc = subprocess.run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
        input=json.dumps(config), text=True, capture_output=True)
    save('installed-xray-output', {'stdout': proc.stdout, 'stderr': proc.stderr})
    proof = {'passed': proc.returncode == 0, 'sha256': digest(config), 'udp_port_free': True, 'time': time.time()}
    save('installed-test', proof)
    assert proof['passed'], 'Installed Xray rejected candidate; private output retained on node'
    return proof


def accept_test():
    proof = json.load(sys.stdin)
    assert proof['passed'] and proof['udp_port_free'] and proof['sha256'] == digest(read('candidate'))
    assert time.time() - proof['time'] < 1800
    save('installed-test', proof)
    return {'installed_binary_validation_accepted': True}


def create_test(api):
    assert not exists('test-user')
    b = read('before'); s = next(s for s in b['squads'] if s['name'] == 'BASE' and s['uuid'] in b['selected_squads'])
    identifier = str(uuid.uuid4())
    body = {'uuid': identifier, 'username': 'hy2_salamander_probe_' + identifier[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        'trafficLimitBytes': 268435456, 'trafficLimitStrategy': 'NO_RESET', 'tag': 'HY2_SAL_PROBE',
        'description': 'Temporary DE182 HY2 Salamander pilot check', 'activeInternalSquads': [s['uuid']]}
    save('test-user', body); assert api('POST', '/api/users/', body)['uuid'] == identifier
    return {'temporary_user_created': True, 'expires_in_hours': 2}


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT.parent / relative)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def outbound(user, protocol):
    existing = module('old_xhttp_common', 'xhttp-de182-20260917/common.py')
    result = existing.outbound(user, 'hysteria' if protocol == 'salamander' else protocol)
    if protocol == 'salamander':
        result['settings']['port'] = PORT
        result['streamSettings']['finalmask'] = mask(read('obfs-secret')['password'])
    return result


def test_outbound(out):
    support = module('probe_support', 'selfsteal-ru214/panel.py')
    support.STATE, support.IP, support.XRAY = STATE, IP, XRAY
    return support.test_outbound(out)


def probes(api, after):
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    names = ['vless', 'hysteria', 'xhttp'] + (['salamander'] if after else [])
    tests = [{'protocol': n, **test_outbound(outbound(user, n))} for n in names]
    proof = {'time': time.time(), 'all_passed': all(t['passed'] for t in tests), 'tests': tests}
    save('after-probes' if after else 'before-probes', proof)
    assert proof['all_passed'], 'Probe failed: retain rollback, do not publish'
    return proof


def apply(api):
    b = read('before'); validation = read('installed-test')
    assert validation['passed'] and validation['sha256'] == digest(read('candidate'))
    assert read('before-probes')['all_passed'] and time.time() - read('before-probes')['time'] < 1800
    assert not exists('created')
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == b['profile']['config']
    assert binding(api('GET', '/api/nodes/' + NODE)) == b['binding']
    save('created', {'time': time.time()})
    subprocess.run(['systemd-run', '--unit', TIMER, '--on-active=25m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'rollback'], check=True, capture_output=True)
    p = api('PATCH', '/api/config-profiles/', {'uuid': PROFILE, 'config': read('candidate')})
    assert p['config'] == read('candidate')
    mapping = {i['tag']: i['uuid'] for i in p['inbounds']}
    for old in b['profile']['inbounds']: assert mapping[old['tag']] == old['uuid']
    c = {'inbound': mapping[TAG]}; save('created', c)
    for sid in b['selected_squads']:
        current = api('GET', '/api/internal-squads/' + sid)
        updated = list(dict.fromkeys(ids(current) + [c['inbound']]))
        assert set(ids(api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': updated}))) == set(updated)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {'activeConfigProfileUuid': PROFILE,
        'activeInbounds': b['binding']['activeInbounds'] + [c['inbound']]}})
    body = host_body(c['inbound'], read('obfs-secret')['password']); save('host-intent', body)
    c['host'] = api('POST', '/api/hosts/', body)['uuid']; save('created', c)
    return {'inbound_added': True, 'old_inbounds_preserved': 3, 'host_disabled': True, 'rollback_armed': True}


def verify(api):
    b, c = read('before'), read('created')
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    for old in b['nodes']:
        now = nodes[old['uuid']]
        for key in ('name', 'address', 'isDisabled'): assert old[key] == now[key], 'Unrelated node edit'
        expected = binding(old)
        if old['uuid'] == NODE: expected['activeInbounds'].append(c['inbound'])
        assert binding(now) == expected, 'Unrelated binding edit'
    assert nodes[NODE]['isConnected']
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    strip = lambda h: {k: v for k, v in h.items() if k != 'viewPosition'}
    for old in b['hosts']: assert strip(old) == strip(hosts[old['uuid']]), 'Existing host edit'
    for old in b['squads']:
        expected = set(ids(old)) | ({c['inbound']} if old['uuid'] in b['selected_squads'] else set())
        assert set(ids(api('GET', '/api/internal-squads/' + old['uuid']))) == expected
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == read('candidate')
    h = hosts[c['host']]
    assert h['tags'] == [] and not h['isHidden'] and h['nodes'] == [NODE]
    assert h['finalMask'] == mask(read('obfs-secret')['password']) and h['port'] == PORT
    return {'node_connected': True, 'existing_nodes_preserved': len(b['nodes']),
        'existing_hosts_preserved': len(b['hosts']), 'outside_auto_pool': True}


def publish(api):
    assert read('after-probes')['all_passed'] and time.time() - read('after-probes')['time'] < 900
    verify(api); api('PATCH', '/api/hosts/', {'uuid': read('created')['host'], 'isDisabled': False})
    return {'published': NAME, 'udp_port': PORT, 'obfuscation': 'salamander'}


def subscription(api):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/5.7.0',
        'X-Hwid': 'hamvpn-hy2-salamander-de182', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=30) as r: configs = json.load(r)
    target = lambda o: o.get('protocol') == 'hysteria' and o.get('settings', {}).get('address') == DOMAIN and o.get('settings', {}).get('port') == PORT
    config, = [c for c in configs if c.get('remarks') == NAME]
    out, = [o for o in config['outbounds'] if target(o)]
    for c in configs:
        if c.get('remarks') == '⚡ Автовыбор Серверов': assert not any(target(o) for o in c['outbounds'])
    stream = out['streamSettings']; assert stream['security'] == 'tls'
    assert stream['tlsSettings']['serverName'] == DOMAIN and not stream['tlsSettings'].get('allowInsecure', False)
    assert stream['finalmask']['udp'] == mask(read('obfs-secret')['password'])['udp']
    result = test_outbound(out)
    proof = {'time': time.time(), 'public_subscription_http': 200, 'host_count': 1, 'port': PORT,
        'salamander_matches_server': True, 'certificate_verification': True, **result}
    save('subscription-proof', proof); assert proof['passed'], 'Actual subscription failed'
    return proof


def negative_test(api):
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    out = outbound(user, 'salamander'); out['streamSettings'].pop('finalmask')
    result = test_outbound(out)
    assert not result['passed'] and result['curl_codes'][0] != 0
    proof = {'time': time.time(), 'same_valid_user_without_mask_rejected': True, 'curl_codes': result['curl_codes']}
    save('negative-test', proof)
    return proof


def cleanup(api, query):
    intent = read('test-user'); user = api('GET', '/api/users/' + intent['uuid'])
    assert all(user[k] == intent[k] for k in ('username', 'tag', 'description'))
    api('DELETE', '/api/users/' + intent['uuid'])
    result = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(intent['uuid'])) + "'")
    assert result['remaining'] == 0
    save('test-cleanup', {'verified_absent': True, 'time': time.time()})
    return {'temporary_user_deleted': True, 'verified_absent': True}


def node_verify():
    baseline = read('node-baseline')
    assert {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in baseline} == baseline
    for protocol, port in [('u', PORT), ('u', 443), ('t', 443), ('t', 10080)]:
        assert subprocess.check_output(['ss', '-H', '-ln' + protocol, 'sport = :' + str(port)], text=True).strip()
    for service in ('nginx', 'certbot.timer', 'hamvpn-selfsteal-firewall.service'):
        assert subprocess.check_output(['systemctl', 'is-active', service], text=True).strip() == 'active'
    proof = {'time': time.time(), 'listeners_present': True, 'nginx_compose_firewall_renewal_preserved': True}
    save('node-verified', proof)
    return proof


def finish(api):
    assert read('subscription-proof')['passed'] and read('negative-test')['same_valid_user_without_mask_rejected']
    assert read('test-cleanup')['verified_absent']
    proof = verify(api)
    assert not api('GET', '/api/hosts/' + read('created')['host'])['isDisabled']
    subprocess.run(['systemctl', 'stop', TIMER + '.timer'], check=True)
    assert subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer']).returncode != 0
    proof.update(time=time.time(), rollback_disarmed=True, russian_network_unverified=True)
    save('finished', proof)
    return proof


def rollback(api):
    b = read('before'); p = api('GET', '/api/config-profiles/' + PROFILE)
    assert p['config'] in (b['profile']['config'], read('candidate')), 'Concurrent profile edit'
    new = next((i['uuid'] for i in p['inbounds'] if i['tag'] == TAG), None)
    if new:
        n = api('GET', '/api/nodes/' + NODE)
        assert binding(n)['activeConfigProfileUuid'] == PROFILE
        assert set(binding(n)['activeInbounds']) <= set(b['binding']['activeInbounds'] + [new])
        for h in api('GET', '/api/hosts/'):
            if h['inbound']['configProfileInboundUuid'] == new:
                assert h['remark'] == NAME and h['nodes'] == [NODE]
                api('PATCH', '/api/hosts/', {'uuid': h['uuid'], 'isDisabled': True})
        api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': b['binding']})
        for sid in b['selected_squads']:
            s = api('GET', '/api/internal-squads/' + sid)
            api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': [i for i in ids(s) if i != new]})
        api('PATCH', '/api/config-profiles/', {'uuid': PROFILE, 'config': b['profile']['config']})
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == b['profile']['config']
    save('rollback', {'time': time.time(), 'restored': True})
    return {'original_three_inbounds_restored': True, 'pilot_disabled': True}


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['snapshot', 'node-test', 'accept-test',
        'create-test', 'before-probes', 'apply', 'after-probes', 'verify', 'publish', 'subscription',
        'negative-test', 'cleanup', 'node-verify', 'finish', 'rollback'])
    action = p.parse_args().action
    if action in ('node-test', 'node-verify', 'accept-test'): result = globals()[action.replace('-', '_')]()
    else:
        api, query = create_client()
        if action == 'cleanup': result = cleanup(api, query)
        elif action.endswith('-probes'): result = probes(api, after=action == 'after-probes')
        else: result = globals()[action.replace('-', '_')](api)
    print(json.dumps(result, ensure_ascii=False))
