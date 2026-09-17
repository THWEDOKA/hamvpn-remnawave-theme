"""Explicit owner addition of three existing Timeweb nodes to normal auto selection."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
from common import ROOT, STATE, XRAY, save, read, exists, binding

sys.path.insert(0, str(ROOT.parent / 'selfsteal-us3'))
from panel_api import create_client

TARGETS = [
    {'name': 'Netherlands-HAM-TMWEB-1', 'node': 'a4029bb7-a591-450a-913d-6f204d965629',
     'ip': '83.217.194.44', 'remark': 'ABP-TMWEB-NL1-HIDDEN'},
    {'name': 'HAM-GERMANY-TMWEB-1', 'node': 'd6cd9021-7bcf-4917-9edd-4a637a724dcb',
     'ip': '89.19.211.249', 'remark': 'ABP-TMWEB-DE1-HIDDEN'},
    {'name': 'HAM-NL-TMWEB-2', 'node': '881da512-c0a0-488f-ab43-4f45356c54c6',
     'ip': '201.51.22.125', 'remark': 'ABP-TMWEB-NL2-HIDDEN'},
]
PROFILE = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
SOURCE_HOST = '104c5bf6-eb27-46fc-9d6c-13203c5cdf74'
TEMPLATE = '61db91b0-d5db-4493-beeb-a598e8cf8e7b'
TIMER = 'ham-timeweb-auto-rollback'


def body(target):
    return {'remark': target['remark'], 'address': target['ip'], 'port': 443,
        'fingerprint': 'firefox', 'securityLayer': 'DEFAULT', 'isHidden': True,
        'isDisabled': True, 'tags': ['AUTO_BASE_POOL'], 'nodes': [target['node']],
        'excludedInternalSquads': [],
        'inbound': {'configProfileUuid': PROFILE, 'configProfileInboundUuid': INBOUND}}


def subscription(api):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/5.7.0',
        'X-Hwid': 'hamvpn-xhttp-de182-pilot', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=30) as r: return json.load(r)


def target_outbounds(config, ip):
    return [o for o in config.get('outbounds', []) if o.get('protocol') == 'vless'
        and any(v.get('address') == ip for v in o.get('settings', {}).get('vnext', []))]


def probe(value, ip):
    spec = importlib.util.spec_from_file_location('timeweb_probe', ROOT.parent / 'selfsteal-ru214/panel.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    mod.STATE, mod.IP, mod.XRAY = STATE, ip, XRAY
    return mod.test_outbound(value)


def prepare(api):
    assert not exists('auto-before'), 'Existing intent: inspect instead of repeating'
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    hosts = api('GET', '/api/hosts/')
    template = api('GET', '/api/subscription-templates/' + TEMPLATE)
    assert template['templateJson']['remnawave']['injectHosts'] == [
        {'selector': {'type': 'tagRegex', 'pattern': '^AUTO_BASE_POOL$'}, 'tagPrefix': 'basepool', 'selectFrom': 'ALL'}]
    source = next(h for h in hosts if h['uuid'] == SOURCE_HOST)
    assert source['address'] == '89.19.211.249' and source['port'] == 443
    assert source['sni'] is None and source['host'] is None and source['alpn'] is None
    assert source['securityLayer'] == 'DEFAULT' and source['fingerprint'] == 'firefox'
    for target in TARGETS:
        n = nodes[target['node']]
        assert n['name'] == target['name'] and n['address'] == target['ip']
        assert n['isConnected'] and not n['isDisabled']
        assert binding(n) == {'activeConfigProfileUuid': PROFILE, 'activeInbounds': [INBOUND]}
        assert not any(h['remark'] == target['remark'] or ('AUTO_BASE_POOL' in h['tags'] and
            (h['address'] == target['ip'] or target['node'] in h['nodes'])) for h in hosts), 'Existing auto entry: do not duplicate'
    save('auto-before', {'nodes': [nodes[t['node']] for t in TARGETS], 'hosts': hosts,
        'template': template, 'profile': api('GET', '/api/config-profiles/' + PROFILE)})
    configs = subscription(api)
    visible = next(c for c in configs if c.get('remarks') == source['remark'])
    original, = target_outbounds(visible, source['address'])
    assert original['streamSettings']['security'] == 'reality'
    results = []
    for target in TARGETS:
        out = copy.deepcopy(original)
        out['settings']['vnext'][0]['address'] = target['ip']
        results.append({'name': target['name'], **probe(out, target['ip'])})
    proof = {'time': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    save('auto-before-probes', proof)
    assert proof['all_passed'], 'Do not add a non-working node to auto selection'
    return proof


def apply(api):
    assert read('auto-before-probes')['all_passed'] and time.time() - read('auto-before-probes')['time'] < 900
    assert not exists('auto-created')
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == read('auto-before')['profile']['config']
    c = {'hosts': []}; save('auto-created', c)
    subprocess.run(['systemd-run', '--unit', TIMER, '--on-active=15m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'rollback'], check=True, capture_output=True)
    for target in TARGETS:
        intent = body(target); save('auto-host-intent', intent)
        result = api('POST', '/api/hosts/', intent)
        c['hosts'].append({'uuid': result['uuid'], **target}); save('auto-created', c)
    for host in c['hosts']: api('PATCH', '/api/hosts/', {'uuid': host['uuid'], 'isDisabled': False})
    return {'added_hidden_hosts': 3, 'node_configs_unchanged': True, 'rollback_armed': True}


def verify(api):
    before = read('auto-before')
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == before['profile']['config']
    assert api('GET', '/api/subscription-templates/' + TEMPLATE)['templateJson'] == before['template']['templateJson']
    for n in before['nodes']:
        now = api('GET', '/api/nodes/' + n['uuid'])
        assert binding(n) == binding(now) and now['isConnected'] and not now['isDisabled']
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    strip = lambda h: {k: v for k, v in h.items() if k != 'viewPosition'}
    for old in before['hosts']: assert strip(old) == strip(hosts[old['uuid']]), 'Existing host changed'
    for h in read('auto-created')['hosts']:
        now = hosts[h['uuid']]
        assert now['isHidden'] and not now['isDisabled'] and now['tags'] == ['AUTO_BASE_POOL']
        assert now['address'] == h['ip'] and now['nodes'] == [h['node']]
    configs = subscription(api)
    auto, = [c for c in configs if c.get('remarks') == '⚡ Автовыбор Серверов']
    assert all(not any(c.get('remarks') == t['remark'] for c in configs) for t in TARGETS)
    balancers = auto['routing']['balancers']
    selectors = [s for b in balancers for s in b['selector']]
    tests = []
    for target in TARGETS:
        out, = target_outbounds(auto, target['ip'])
        assert any(out['tag'].startswith(selector) for selector in selectors)
        assert out['streamSettings']['security'] == 'reality'
        tests.append({'name': target['name'], 'candidate_count': 1, **probe(out, target['ip'])})
    proof = {'time': time.time(), 'all_passed': all(t['passed'] for t in tests), 'tests': tests,
        'shared_profile_and_template_unchanged': True, 'old_hosts_preserved': len(before['hosts'])}
    save('auto-verified', proof); assert proof['all_passed'], 'Actual auto-selection outbounds failed'
    return proof


def finish(api):
    assert read('auto-verified')['all_passed'] and time.time() - read('auto-verified')['time'] < 900
    subprocess.run(['systemctl', 'stop', TIMER + '.timer'], check=True)
    assert subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer']).returncode != 0
    save('auto-finished', {'time': time.time(), 'rollback_disarmed': True})
    return {'normal_auto_selection_added': [t['name'] for t in TARGETS], 'rollback_disarmed': True}


def rollback(api):
    # Includes a POST whose response may have been lost, but only the exact
    # previously absent operation-owned name/address/node/inbound combination.
    before_ids = {h['uuid'] for h in read('auto-before')['hosts']}
    disabled = 0
    for h in api('GET', '/api/hosts/'):
        for target in TARGETS:
            if h['remark'] != target['remark']: continue
            assert h['uuid'] not in before_ids and h['address'] == target['ip']
            assert h['nodes'] == [target['node']] and h['inbound']['configProfileInboundUuid'] == INBOUND
            api('PATCH', '/api/hosts/', {'uuid': h['uuid'], 'isDisabled': True})
            disabled += 1
    save('auto-rollback', {'time': time.time(), 'disabled_owned_hosts': disabled})
    return {'disabled_owned_hosts': disabled}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['prepare', 'apply', 'verify', 'finish', 'rollback'])
    args = parser.parse_args(); api, _ = create_client()
    print(json.dumps(globals()[args.action](api), ensure_ascii=False))
