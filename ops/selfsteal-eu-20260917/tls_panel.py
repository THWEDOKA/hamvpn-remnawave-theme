"""Owner-requested replacement: plain VLESS TLS fallback + Hysteria2 UDP."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request
import panel

ROOT, STATE, NODES = panel.ROOT, panel.STATE, panel.NODES
save, read, exists, ids = panel.save, panel.read, panel.exists, panel.ids


def stage(api, n):
    old = read(n['id'] + '-created')
    assert not exists(n['id'] + '-tls-created'), 'Intent exists: reconcile, do not repeat'
    before = {'node': api('GET', '/api/nodes/' + old['node']),
        'hosts': [api('GET', '/api/hosts/' + h) for h in old['hosts']],
        'squads': [api('GET', '/api/internal-squads/' + s) for s in old['squads']]}
    assert all(h['isDisabled'] for h in before['hosts'])
    assert before['node']['configProfile']['activeConfigProfileUuid'] == old['profile']
    save(n['id'] + '-tls-before', before)
    name = 'HAM-' + n['id'].upper() + '-TLS-HY2'
    assert not any(p['name'] == name for p in api('GET', '/api/config-profiles/')['configProfiles'])
    config = json.loads((ROOT / n['id'] / 'tls-hy2-config.json').read_text())
    created = {'name': name, 'node': old['node'], 'squads': old['squads'], 'hosts': []}
    save(n['id'] + '-tls-created', created)
    p = api('POST', '/api/config-profiles/', {'name': name, 'config': config})
    created['profile'] = p['uuid']
    created['inbounds'] = {i['tag']: i['uuid'] for i in p['inbounds']}
    save(n['id'] + '-tls-created', created)
    assert len(p['inbounds']) == 2 and p['config'] == config
    for s in before['squads']:
        current = api('GET', '/api/internal-squads/' + s['uuid'])
        assert set(ids(s)) <= set(ids(current))
        new_ids = list(dict.fromkeys(ids(current) + list(created['inbounds'].values())))
        result = api('PATCH', '/api/internal-squads/', {'uuid': s['uuid'], 'inbounds': new_ids})
        assert set(ids(result)) == set(new_ids)
    for original in before['hosts']:
        body = {'uuid': original['uuid'], 'inbound': {'configProfileUuid': p['uuid'],
            'configProfileInboundUuid': created['inbounds']['ham-' + n['id'] + '-vless-tls']},
            'securityLayer': 'DEFAULT', 'alpn': 'h2,http/1.1',
            'tags': list(dict.fromkeys(original.get('tags', []) + (['AUTO_BASE_POOL'] if original['isHidden'] else [])))}
        api('PATCH', '/api/hosts/', body)
        created['hosts'].append(original['uuid']); save(n['id'] + '-tls-created', created)
    for hidden in (False, True):
        body = {'remark': 'ABP-' + n['id'].upper() + '-HY2-HIDDEN' if hidden else n['name'] + ' · Hysteria2',
            'address': n['domain'], 'port': 443, 'host': n['domain'], 'sni': n['domain'],
            'alpn': 'h3', 'isHidden': hidden, 'isDisabled': True, 'nodes': [old['node']],
            'tags': ['AUTO_BASE_POOL'] if hidden else [], 'excludedInternalSquads': [],
            'inbound': {'configProfileUuid': p['uuid'], 'configProfileInboundUuid': created['inbounds']['ham-' + n['id'] + '-hy2']}}
        save(n['id'] + '-tls-host-intent', body)
        host = api('POST', '/api/hosts/', body)
        created['hosts'].append(host['uuid']); save(n['id'] + '-tls-created', created)
    return {'id': n['id'], 'tls_hy2_staged': True, 'four_hosts_disabled': True}


def switch(api, n):
    c = read(n['id'] + '-tls-created'); old = read(n['id'] + '-created')
    node = api('GET', '/api/nodes/' + c['node'])
    assert node['configProfile']['activeConfigProfileUuid'] == old['profile']
    timer = 'ham-eu-tls-' + n['id'] + '-rollback'
    subprocess.run(['systemd-run', '--unit', timer, '--on-active=15m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'rollback', '--id', n['id']], check=True, capture_output=True)
    api('PATCH', '/api/nodes/', {'uuid': c['node'], 'configProfile': {'activeConfigProfileUuid': c['profile'],
        'activeInbounds': list(c['inbounds'].values())}})
    save(n['id'] + '-tls-switched', {'timestamp': time.time(), 'rollback_timer': timer})
    return {'id': n['id'], 'switched': True, 'rollback_timer_armed': True}


def outbound(n, user, protocol):
    tls = {'serverName': n['domain'], 'allowInsecure': False}
    if protocol == 'vless':
        return {'protocol': 'vless', 'settings': {'vnext': [{'address': n['domain'], 'port': 443,
            'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                **tls, 'fingerprint': 'firefox', 'alpn': ['h2', 'http/1.1']}}}
    return {'protocol': 'hysteria', 'settings': {'address': n['domain'], 'port': 443, 'version': 2},
        'streamSettings': {'network': 'hysteria', 'hysteriaSettings': {'version': 2, 'auth': user['vlessUuid']},
            'security': 'tls', 'tlsSettings': {**tls, 'alpn': ['h3']}}}


def probe(api, n):
    user = api('GET', '/api/users/' + read('test-user')['uuid'])
    results = [{'protocol': protocol, **panel.probe_module(n).test_outbound(outbound(n, user, protocol))}
        for protocol in ('vless', 'hysteria')]
    proof = {'id': n['id'], 'timestamp': time.time(), 'all_passed': all(r['passed'] for r in results), 'tests': results}
    save(n['id'] + '-tls-probe', proof)
    if not proof['all_passed']:
        rollback(api, n)
        raise RuntimeError('TLS/HY2 probe failed; original binding restored and hosts disabled')
    return proof


def publish(api, n):
    proof = read(n['id'] + '-tls-probe'); assert proof['all_passed'] and time.time() - proof['timestamp'] < 900
    panel.verify(api)
    c = read(n['id'] + '-tls-created')
    node = api('GET', '/api/nodes/' + c['node'])
    assert node['isConnected'] and node['configProfile']['activeConfigProfileUuid'] == c['profile']
    for hid in c['hosts']:
        h = api('GET', '/api/hosts/' + hid)
        assert h['inbound']['configProfileUuid'] == c['profile'] and h['nodes'] == [c['node']]
        api('PATCH', '/api/hosts/', {'uuid': hid, 'isDisabled': False})
    return {'id': n['id'], 'vless_tls_and_hy2_published': True}


def subscription(api, n):
    sub = api('GET', '/api/subscriptions/by-uuid/' + read('test-user')['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/3.11.0',
        'X-Hwid': 'selfsteal-eu-20260917-probe', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=30) as r: configs = json.load(r)
    results = []
    auto = [c for c in configs if c.get('remarks') == '⚡ Автовыбор Серверов']; assert len(auto) == 1
    for protocol, name in [('vless', n['name']), ('hysteria', n['name'] + ' · Hysteria2')]:
        matching = [c for c in configs if c.get('remarks') == name]; assert len(matching) == 1
        def targets(c):
            return [o for o in c.get('outbounds', []) if o.get('protocol') == protocol and
                (o.get('settings', {}).get('address') == n['domain'] or
                 any(s.get('address') == n['domain'] for s in o.get('settings', {}).get('vnext', [])))]
        direct = targets(matching[0]); assert len(direct) == 1 and len(targets(auto[0])) == 1
        assert direct[0]['streamSettings']['security'] == 'tls'
        result = panel.probe_module(n).test_outbound(direct[0])
        results.append({'protocol': protocol, 'auto_pool_member': True, **result})
    proof = {'id': n['id'], 'timestamp': time.time(), 'configs': len(configs),
        'tests': results, 'all_passed': all(r['passed'] for r in results)}
    save(n['id'] + '-tls-subscription', proof)
    if not proof['all_passed']:
        rollback(api, n); raise RuntimeError('Public subscription probe failed; reverted')
    return proof


def rollback(api, n):
    c = read(n['id'] + '-tls-created'); before = read(n['id'] + '-tls-before')
    current = api('GET', '/api/nodes/' + c['node'])
    allowed = (c['profile'], before['node']['configProfile']['activeConfigProfileUuid'])
    assert current['configProfile']['activeConfigProfileUuid'] in allowed, 'Later unrelated binding'
    for hid in c['hosts']:
        host = api('GET', '/api/hosts/' + hid)
        assert host['nodes'] == [c['node']] and host['address'] == n['domain']
        api('PATCH', '/api/hosts/', {'uuid': hid, 'isDisabled': True})
    b = before['node']['configProfile']
    api('PATCH', '/api/nodes/', {'uuid': c['node'], 'configProfile': {'activeConfigProfileUuid': b['activeConfigProfileUuid'],
        'activeInbounds': [i['uuid'] for i in b['activeInbounds']]}})
    for h in before['hosts']:
        api('PATCH', '/api/hosts/', {k: h[k] for k in ('uuid', 'inbound', 'tags', 'alpn', 'securityLayer', 'isDisabled')})
    save(n['id'] + '-tls-rollback', {'timestamp': time.time(), 'restored': True})
    return {'id': n['id'], 'old_binding_restored': True, 'new_hosts_disabled': True}


def finish(api, n):
    assert read(n['id'] + '-tls-subscription')['all_passed']
    c = read(n['id'] + '-tls-created')
    node = api('GET', '/api/nodes/' + c['node'])
    assert node['isConnected'] and node['configProfile']['activeConfigProfileUuid'] == c['profile']
    for hid in c['hosts']: assert not api('GET', '/api/hosts/' + hid)['isDisabled']
    timer = 'ham-eu-tls-' + n['id'] + '-rollback.timer'
    subprocess.run(['systemctl', 'stop', timer], check=True)
    assert subprocess.run(['systemctl', 'is-active', '--quiet', timer]).returncode != 0
    save(n['id'] + '-tls-finished', {'timestamp': time.time(), 'connected': True, 'rollback_disarmed': True})
    return {'id': n['id'], 'connected': True, 'rollback_disarmed': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['stage', 'switch', 'probe', 'publish', 'subscription', 'rollback', 'finish'])
    parser.add_argument('--id', required=True, choices=[n['id'] for n in NODES]); args = parser.parse_args()
    api, _ = panel.create_client(); n = next(n for n in NODES if n['id'] == args.id)
    print(json.dumps(globals()[args.action](api, n), ensure_ascii=False))


if __name__ == '__main__': main()
