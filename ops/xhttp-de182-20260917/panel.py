"""Add an isolated test host/inbound, preserving the target's existing two protocols."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid
from common import *

sys.path.insert(0, str(ROOT.parent / 'selfsteal-us3'))
from panel_api import create_client
TIMER = 'ham-xhttp-de182-panel-rollback'


def test_outbound(value):
    spec = importlib.util.spec_from_file_location('pilot_probe', ROOT.parent / 'selfsteal-ru214/panel.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    mod.STATE, mod.IP, mod.XRAY = STATE, IP, XRAY
    return mod.test_outbound(value)


def snapshot(api):
    assert not exists('before'), 'Existing pilot: reconcile instead of repeating'
    nodes, hosts = api('GET', '/api/nodes/'), api('GET', '/api/hosts/')
    node = next(n for n in nodes if n['uuid'] == NODE)
    assert node['address'] == IP and node['isConnected'] and not node['isDisabled']
    assert binding(node) == {'activeConfigProfileUuid': PROFILE, 'activeInbounds': OLD_IDS}
    assert [n['uuid'] for n in nodes if (binding(n) or {}).get('activeConfigProfileUuid') == PROFILE] == [NODE]
    assert not any(h['remark'] == NAME for h in hosts)
    profile = api('GET', '/api/config-profiles/' + PROFILE)
    config = candidate(profile['config'])
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    selected = [s['uuid'] for s in squads if OLD_IDS[0] in ids(s)]
    assert selected
    save('before', {'nodes': nodes, 'hosts': hosts, 'profile': profile, 'squads': squads, 'selected_squads': selected})
    save('candidate', config)
    return {'snapshot_saved': True, 'one_node_profile': True, 'squads': len(selected)}


def create_test(api):
    assert not exists('test-user')
    before = read('before')
    selected = [s for s in before['squads'] if s['uuid'] in before['selected_squads']]
    squad = next(s for s in selected if s['name'] == 'BASE')
    identifier = str(uuid.uuid4())
    body = {'uuid': identifier, 'username': 'xhttp_de182_probe_' + identifier[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        'trafficLimitBytes': 268435456, 'trafficLimitStrategy': 'NO_RESET', 'tag': 'XHTTP_PILOT',
        'description': 'Temporary DE182 XHTTP pilot verification', 'activeInternalSquads': [squad['uuid']]}
    save('test-user', body)
    assert api('POST', '/api/users/', body)['uuid'] == identifier
    return {'temporary_user_created': True, 'expires_in_hours': 2}


def probes(api, after=False):
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    protocols = ['vless', 'hysteria'] + (['xhttp'] if after else [])
    tests = [{'protocol': p, **test_outbound(outbound(user, p))} for p in protocols]
    proof = {'time': time.time(), 'all_passed': all(r['passed'] for r in tests), 'tests': tests}
    save('after-probes' if after else 'before-probes', proof)
    assert proof['all_passed'], 'Probe failed: do not publish/disarm rollback'
    return proof


def apply(api):
    before = read('before')
    assert read('before-probes')['all_passed'] and time.time() - read('before-probes')['time'] < 1800
    assert not exists('created')
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == before['profile']['config']
    assert binding(api('GET', '/api/nodes/' + NODE)) == {'activeConfigProfileUuid': PROFILE, 'activeInbounds': OLD_IDS}
    save('created', {'time': time.time()})
    subprocess.run(['systemd-run', '--unit', TIMER, '--on-active=25m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'rollback'], check=True, capture_output=True)
    result = api('PATCH', '/api/config-profiles/', {'uuid': PROFILE, 'config': read('candidate')})
    assert result['config'] == read('candidate')
    mapping = {i['tag']: i['uuid'] for i in result['inbounds']}
    for i in before['profile']['inbounds']: assert mapping[i['tag']] == i['uuid'], 'Old inbound UUID changed'
    c = {'time': time.time(), 'inbound': mapping[TAG]}; save('created', c)
    for sid in before['selected_squads']:
        current = api('GET', '/api/internal-squads/' + sid)
        updated = list(dict.fromkeys(ids(current) + [c['inbound']]))
        assert set(ids(api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': updated}))) == set(updated)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {'activeConfigProfileUuid': PROFILE,
        'activeInbounds': OLD_IDS + [c['inbound']]}})
    body = host_body(c['inbound']); save('host-intent', body)
    c['host'] = api('POST', '/api/hosts/', body)['uuid']; save('created', c)
    return {'inbound_added': True, 'existing_inbounds_preserved': True, 'test_host_disabled': True, 'rollback_armed': True}


def verify(api):
    before, c = read('before'), read('created')
    nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    for old in before['nodes']:
        now = nodes[old['uuid']]
        for key in ('address', 'name', 'isDisabled'): assert now[key] == old[key], 'Unrelated node change'
        expected = binding(old)
        if old['uuid'] == NODE: expected['activeInbounds'] = OLD_IDS + [c['inbound']]
        assert binding(now) == expected, 'Unrelated node binding change'
    assert nodes[NODE]['isConnected']
    hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    strip = lambda h: {k: v for k, v in h.items() if k != 'viewPosition'}
    for old in before['hosts']: assert strip(old) == strip(hosts[old['uuid']]), 'Existing host changed'
    for s in before['squads']:
        expected = set(ids(s)) | ({c['inbound']} if s['uuid'] in before['selected_squads'] else set())
        assert set(ids(api('GET', '/api/internal-squads/' + s['uuid']))) == expected, 'Unexpected squad change'
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == read('candidate')
    host = hosts[c['host']]
    assert not host['isHidden'] and host['tags'] == [] and host['nodes'] == [NODE]
    return {'node_connected': True, 'existing_nodes_preserved': len(before['nodes']),
        'existing_hosts_preserved': len(before['hosts']), 'pilot_outside_auto_pool': True}


def publish(api):
    assert read('after-probes')['all_passed'] and time.time() - read('after-probes')['time'] < 900
    verify(api)
    c = read('created')
    api('PATCH', '/api/hosts/', {'uuid': c['host'], 'isDisabled': False})
    return {'published': NAME, 'auto_pool_unchanged': True}


def subscription(api):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    request = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/5.7.0',
        'X-Hwid': 'hamvpn-xhttp-de182-pilot', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(request, timeout=30) as response: configs = json.load(response)
    matching = [v for v in configs if v.get('remarks') == NAME]
    assert len(matching) == 1
    def targets(config):
        return [o for o in config.get('outbounds', []) if o.get('protocol') == 'vless'
            and o.get('streamSettings', {}).get('network') == 'xhttp'
            and any(v.get('address') == DOMAIN for v in o.get('settings', {}).get('vnext', []))]
    out, = targets(matching[0])
    for config in configs:
        if config.get('remarks') == '⚡ Автовыбор Серверов': assert not targets(config)
    server, = out['settings']['vnext']; stream = out['streamSettings']
    assert server['port'] == 443 and not server['users'][0].get('flow')
    assert stream['security'] == 'tls' and stream['tlsSettings']['serverName'] == DOMAIN
    assert not stream['tlsSettings'].get('allowInsecure', False)
    assert stream['xhttpSettings']['path'] == PATH and stream['xhttpSettings']['mode'] == 'packet-up'
    result = test_outbound(out)
    proof = {'time': time.time(), 'public_subscription_http': 200, 'host_count': 1,
        'network': 'xhttp', 'security': 'tls', 'mode': 'packet-up', 'auto_pool_unchanged': True, **result}
    save('subscription-proof', proof); assert proof['passed'], 'Actual subscription failed'
    return proof


def cleanup(api, query):
    intent = read('test-user'); user = api('GET', '/api/users/' + intent['uuid'])
    assert all(user[k] == intent[k] for k in ('username', 'tag', 'description'))
    api('DELETE', '/api/users/' + intent['uuid'])
    result = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(intent['uuid'])) + "'")
    assert result['remaining'] == 0
    save('test-cleanup', {'time': time.time(), 'verified_absent': True})
    return {'temporary_user_deleted': True, 'verified_absent': True}


def finish(api):
    assert read('subscription-proof')['passed'] and read('test-cleanup')['verified_absent']
    proof = verify(api)
    assert not api('GET', '/api/hosts/' + read('created')['host'])['isDisabled']
    subprocess.run(['systemctl', 'stop', TIMER + '.timer'], check=True)
    assert subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer']).returncode != 0
    proof.update(time=time.time(), rollback_disarmed=True, russian_network_unverified=True)
    save('finished', proof)
    return proof


def rollback(api):
    before = read('before')
    profile = api('GET', '/api/config-profiles/' + PROFILE)
    assert profile['config'] in (before['profile']['config'], read('candidate')), 'Concurrent profile change'
    new = next((i['uuid'] for i in profile['inbounds'] if i['tag'] == TAG), None)
    if new:
        node = api('GET', '/api/nodes/' + NODE)
        assert binding(node)['activeConfigProfileUuid'] == PROFILE
        assert set(binding(node)['activeInbounds']) <= set(OLD_IDS + [new])
        for host in api('GET', '/api/hosts/'):
            if host['inbound']['configProfileInboundUuid'] == new:
                assert host['remark'] == NAME and host['nodes'] == [NODE]
                api('PATCH', '/api/hosts/', {'uuid': host['uuid'], 'isDisabled': True})
        api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {'activeConfigProfileUuid': PROFILE, 'activeInbounds': OLD_IDS}})
        for sid in before['selected_squads']:
            current = api('GET', '/api/internal-squads/' + sid)
            api('PATCH', '/api/internal-squads/', {'uuid': sid, 'inbounds': [i for i in ids(current) if i != new]})
        api('PATCH', '/api/config-profiles/', {'uuid': PROFILE, 'config': before['profile']['config']})
    assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == before['profile']['config']
    save('rollback', {'time': time.time(), 'restored': True})
    return {'original_profile_restored': True, 'pilot_disabled': True}


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['snapshot', 'create-test', 'before-probes',
        'apply', 'after-probes', 'verify', 'publish', 'subscription', 'cleanup', 'finish', 'rollback'])
    action = p.parse_args().action
    api, query = create_client()
    if action == 'cleanup': result = cleanup(api, query)
    elif action.endswith('-probes'): result = probes(api, after=action == 'after-probes')
    else: result = globals()[action.replace('-', '_')](api)
    print(json.dumps(result, ensure_ascii=False))
