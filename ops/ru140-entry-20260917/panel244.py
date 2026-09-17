"""Guarded PITER migration with four independent reverse-SSH exit channels."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import panel as prior
from common import binding, ids
from entry244_common import *

TIMER = 'ham-entry244-panel-rollback'
HOST_FIELDS = prior.HOST_FIELDS
LEGACY_EGRESS = '193.233.222.244'
SOURCE_PROFILE = '75174e4f-1572-493d-a30c-96651ab0e70d'


def candidate(before, service_user):
    config = copy.deepcopy(before['profiles'][OLD_PROFILE]['config'])
    assert len(config['inbounds']) == 1
    legacy = config['inbounds'][0]
    previous_tag = legacy['tag']
    legacy.update(tag=LEGACY_TAG, listen='127.0.0.1', port=15443)
    for rule in config.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            rule['inboundTag'] = [LEGACY_TAG if t == previous_tag else t for t in rule['inboundTag']]
    additional = prior.candidate(before['profiles'], service_user)
    new_rules = []
    for n, inbound in zip(NODES, additional['inbounds']):
        tag = 'vless-entry244-' + n['id']
        inbound['tag'] = tag
        inbound['streamSettings']['realitySettings']['target'] = '127.0.0.1:9443'
        sources = [i for i in before['profiles'][SOURCE_PROFILE]['config']['inbounds']
                   if i['tag'] == 'vless-entry208-' + n['id']]
        assert len(sources) == 1, 'Ambiguous source frontend'
        source = sources[0]['streamSettings']['realitySettings']
        for key in ('privateKey', 'shortIds', 'serverNames'):
            inbound['streamSettings']['realitySettings'][key] = copy.deepcopy(source[key])
        config['inbounds'].append(inbound)
        config['outbounds'].append(prior.upstream(n, before['profiles'], service_user, True))
        new_rules.append({'type': 'field', 'inboundTag': [tag], 'outboundTag': 'exit-' + n['id']})
    # Apply the existing blocking policy before entry-specific routes. Crucially,
    # legacy geoip:ru/geosite:ru DIRECT rules must never precede the four routes.
    blocking = [copy.deepcopy(r) for r in config['routing']['rules'] if r.get('outboundTag') == 'BLOCK']
    config['routing']['rules'] = blocking + new_rules + config['routing']['rules']
    return config


def user(api):
    intent = prior.read('test-user')
    value = api('GET', '/api/users/' + intent['uuid'])
    assert all(value[k] == intent[k] for k in ('username', 'tag', 'description'))
    assert value['status'] == 'ACTIVE'
    return value


def snapshot(api):
    assert not exists('before')
    nodes = api('GET', '/api/nodes/')
    node = next(n for n in nodes if n['uuid'] == NODE)
    assert node['address'] == ENTRY and node['isConnected'] and not node['isDisabled']
    assert binding(node) == {'profile': OLD_PROFILE, 'inbounds': [OLD_INBOUND]}
    for foreign in NODES:
        current = next(n for n in nodes if n['uuid'] == foreign['node'])
        assert current['address'] == foreign['ip'] and current['isConnected'] and not current['isDisabled']
        assert binding(current)['profile'] == foreign['profile'] and foreign['inbound'] in binding(current)['inbounds']
    assert not any(p['name'] == NAME for p in api('GET', '/api/config-profiles/')['configProfiles'])
    hosts = api('GET', '/api/hosts/')
    for h in hosts:
        if h['uuid'] in prior.EXTRA_HOSTS: assert h['isDisabled']
        if h['uuid'] in OLD_HOSTS:
            assert h['nodes'] == [NODE] and h['inbound']['configProfileInboundUuid'] == OLD_INBOUND
    before = {'nodes': nodes, 'hosts': hosts, 'squads': api('GET', '/api/internal-squads/')['internalSquads'],
              'profiles': {p: api('GET', '/api/config-profiles/' + p) for p in {OLD_PROFILE, SOURCE_PROFILE, *[n['profile'] for n in NODES]}}}
    indexed = {h['uuid']: h for h in hosts}
    assert OLD_HOSTS | TARGET_HOSTS <= indexed.keys()
    for n in NODES:
        source_id = next(i['uuid'] for i in before['profiles'][SOURCE_PROFILE]['inbounds']
                         if i['tag'] == 'vless-entry208-' + n['id'])
        for identifier in n['hosts']:
            host = indexed[identifier]
            assert host['nodes'] == ['22ac9320-4762-461d-b877-a9f33b58d492']
            assert host['inbound'] == {'configProfileUuid': SOURCE_PROFILE, 'configProfileInboundUuid': source_id}
            assert host['address'] == host['sni'] == n['domain'] and host['port'] == 443 and not host['isDisabled']
    save('before', before)
    save('before-checksum', {'sha256': hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()})
    service = api('GET', '/api/users/' + prior.read('backend-user')['uuid'])
    assert service['username'] == 'ham_entry140_backend' and service['status'] == 'ACTIVE'
    save('candidate', candidate(before, service))
    return {'snapshot_verified': True, 'legacy_preserved': True, 'published_frontend_keys_preserved': True}


def test_one(outbound, expected):
    previous = prior.STATE
    prior.STATE = STATE
    try:
        return prior.test_outbound(outbound, {'ip': expected})
    finally:
        prior.STATE = previous


def reality_client(inbound, u, address, sni, fingerprint):
    r = inbound['streamSettings']['realitySettings']
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
            'users': [{'id': u['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
            'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                'serverName': sni, 'fingerprint': fingerprint, 'publicKey': prior.public_key(r['privateKey']),
                'shortId': r['shortIds'][0]}}}


def clients(api, old=False):
    u = user(api); before = read('before'); values = []
    for n in NODES:
        if old:
            values.append({'id': n['id'], 'ip': n['ip'], 'outbound': prior.upstream(n, before['profiles'], u, False)})
        else:
            inbound = next(i for i in read('candidate')['inbounds'] if i['tag'] == 'vless-entry244-' + n['id'])
            for fp in ('chrome', 'firefox'):
                outbound = reality_client(inbound, u, ENTRY, n['domain'], fp)
                outbound['settings']['vnext'][0]['port'] = frontend_port(n)
                values.append({'id': n['id'] + '-' + fp, 'ip': n['ip'], 'outbound': outbound})
    legacy = before['profiles'][OLD_PROFILE]['config']['inbounds'][0]
    for fp, sni in [('chrome', 'google.com'), ('firefox', 'google.com')]:
        values.append({'id': 'legacy-' + fp, 'ip': LEGACY_EGRESS, 'outbound': reality_client(legacy, u, ENTRY, sni, fp)})
    return values


def probes(api, old=False):
    tests = []
    for item in clients(api, old):
        result = {'id': item['id'], **test_one(item['outbound'], item['ip'])}
        tests.append(result); print(json.dumps(result), flush=True)
    proof = {'timestamp': time.time(), 'all_passed': all(t['passed'] for t in tests), 'tests': tests}
    save('old-probes' if old else 'new-probes', proof)
    assert proof['all_passed'], 'External authenticated probe failed; do not publish'
    return {'all_passed': True, 'tests': len(tests)}


def additions(squad, created):
    if squad['uuid'] == prior.read('backend-squad')['uuid']: return []
    result = []
    if OLD_INBOUND in ids(squad): result.append(created['legacy'])
    source_metadata = read('before')['profiles'][SOURCE_PROFILE]['inbounds']
    for n in NODES:
        source_id = next(i['uuid'] for i in source_metadata if i['tag'] == 'vless-entry208-' + n['id'])
        if source_id in ids(squad): result.append(created['inbounds'][n['id']])
    return result


def stage(api):
    assert not exists('create-intent') and read('installed-test')['installed_xray_test_passed']
    assert read('old-probes')['all_passed']
    config = read('candidate')
    assert read('installed-test')['sha256'] == hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    save('create-intent', {'name': NAME, 'timestamp': time.time()})
    profile = api('POST', '/api/config-profiles/', {'name': NAME, 'config': config})
    assert profile['config'] == config
    created = {'profile': profile['uuid'],
               'legacy': next(i['uuid'] for i in profile['inbounds'] if i['tag'] == LEGACY_TAG),
               'inbounds': {n['id']: next(i['uuid'] for i in profile['inbounds'] if i['tag'] == 'vless-entry244-' + n['id']) for n in NODES}}
    save('created', created)
    for old in read('before')['squads']:
        extra = additions(old, created)
        if not extra: continue
        current = api('GET', '/api/internal-squads/' + old['uuid'])
        assert set(ids(old)) <= set(ids(current))
        desired = list(dict.fromkeys(ids(current) + extra))
        changed = api('PATCH', '/api/internal-squads/', {'uuid': old['uuid'], 'inbounds': desired})
        assert set(ids(changed)) == set(desired)
    return {'isolated_profile_ready': True, 'existing_node_not_switched': True}


def legacy_host(host):
    created = read('created')
    return {'inbound': {'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['legacy']}}


def frontend_port(node):
    inbound = next(i for i in read('candidate')['inbounds'] if i['tag'] == 'vless-entry244-' + node['id'])
    return inbound['port'] if inbound['listen'] == ENTRY else 443


def frontend_address(node):
    return ENTRY if frontend_port(node) != 443 else node['domain']


def target_host(host):
    n = next(n for n in NODES if host['uuid'] in n['hosts']); created = read('created')
    return {'inbound': {'configProfileUuid': created['profile'], 'configProfileInboundUuid': created['inbounds'][n['id']]},
            'address': frontend_address(n), 'sni': n['domain'], 'host': n['domain'], 'port': frontend_port(n), 'nodes': [NODE],
            'securityLayer': 'DEFAULT', 'fingerprint': host.get('fingerprint') or 'chrome', 'alpn': None, 'isDisabled': False}


def activate(api):
    assert not exists('activate-intent')
    if exists('direct-prepared'):
        assert exists('direct-staged') and read('installed-test')['installed_xray_test_passed']
        assert read('installed-test')['sha256'] == hashlib.sha256(json.dumps(read('candidate'), sort_keys=True).encode()).hexdigest()
        ready = read('direct-entry-ready')
        assert ready['direct_entry_verified'] and ready['sha256'] == read('installed-test')['sha256']
        assert 0 <= time.time() - ready['timestamp'] < 300
    before = read('before'); created = read('created')
    current = api('GET', '/api/nodes/' + NODE)
    original = next(n for n in before['nodes'] if n['uuid'] == NODE)
    assert current['isConnected'] and not current['isDisabled']
    assert all(current[k] == original[k] for k in ('name', 'address', 'port', 'isDisabled'))
    assert binding(current) == {'profile': OLD_PROFILE, 'inbounds': [OLD_INBOUND]}
    save('activate-intent', {'timestamp': time.time()})
    subprocess.run(['systemd-run', '--unit=' + TIMER, '--on-active=31m', 'python3', str(ROOT / 'panel244.py'), 'rollback'], check=True, capture_output=True)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {'activeConfigProfileUuid': created['profile'],
        'activeInbounds': [created['legacy'], *created['inbounds'].values()]}})
    for host in before['hosts']:
        if host['uuid'] in OLD_HOSTS:
            current = next(h for h in api('GET', '/api/hosts/') if h['uuid'] == host['uuid'])
            assert prior.stable_host(current) == prior.stable_host(host)
            api('PATCH', '/api/hosts/', {'uuid': host['uuid'], **legacy_host(host)})
    save('activated', {'timestamp': time.time()})
    return {'node_profile_switched': True, 'legacy_host_binding_updated_only': True}


def verify(api, published=False):
    before = read('before'); created = read('created')
    assert hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest() == read('before-checksum')['sha256']
    verification = read('verification-baseline') if exists('verification-baseline') else before
    concurrent = exists('verification-baseline')
    protected_nodes = {NODE, '22ac9320-4762-461d-b877-a9f33b58d492', *[n['node'] for n in NODES]}
    external_changes = []
    now_nodes = {n['uuid']: n for n in api('GET', '/api/nodes/')}
    if not concurrent: assert set(now_nodes) == {n['uuid'] for n in verification['nodes']}
    for old in verification['nodes']:
        if concurrent and old['uuid'] not in protected_nodes:
            current = now_nodes.get(old['uuid'])
            if current is None or binding(current) != binding(old) or any(current[k] != old[k] for k in ('name','address','port','isDisabled')):
                external_changes.append({'kind':'node','uuid':old['uuid']})
            continue
        current = now_nodes[old['uuid']]
        wanted = binding(old)
        if old['uuid'] == NODE:
            wanted = {'profile': created['profile'], 'inbounds': [created['legacy'], *created['inbounds'].values()]}
            assert current['isConnected']
        actual = binding(current)
        assert actual['profile'] == wanted['profile'] and set(actual['inbounds']) == set(wanted['inbounds'])
        node_fields = ('address', 'port', 'isDisabled') if concurrent else ('name', 'address', 'port', 'isDisabled')
        assert all(current[k] == old[k] for k in node_fields)
    now_hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    if not concurrent: assert set(now_hosts) == {h['uuid'] for h in verification['hosts']}
    for old in verification['hosts']:
        if concurrent and old['uuid'] not in OLD_HOSTS | TARGET_HOSTS:
            current = now_hosts.get(old['uuid'])
            if current is None or prior.stable_host(current) != prior.stable_host(old):
                external_changes.append({'kind':'host','uuid':old['uuid']})
            continue
        wanted = copy.deepcopy(old)
        if old['uuid'] in OLD_HOSTS: wanted.update(legacy_host(old))
        if published and old['uuid'] in TARGET_HOSTS: wanted.update(target_host(old))
        if concurrent and old['uuid'] in OLD_HOSTS:
            # We changed only TEST's inbound binding. Preserve later operator
            # naming/visibility choices; all wire fields remain guarded.
            for key in ('remark','isDisabled'): wanted[key] = now_hosts[old['uuid']][key]
        assert prior.stable_host(wanted) == prior.stable_host(now_hosts[old['uuid']]), 'Host changed: ' + old['uuid']
    for pid, profile in before['profiles'].items():
        assert api('GET', '/api/config-profiles/' + pid)['config'] == profile['config']
    assert api('GET', '/api/config-profiles/' + created['profile'])['config'] == read('candidate')
    for old in before['squads']:
        current = api('GET', '/api/internal-squads/' + old['uuid'])
        assert set(ids(old) + additions(old, created)) <= set(ids(current))
    if concurrent:
        save('concurrent-verification', {'timestamp':time.time(),'unrelated_edits_not_overwritten':external_changes,
            'new_nodes':list(set(now_nodes)-{n['uuid'] for n in verification['nodes']}),
            'new_hosts':list(set(now_hosts)-{h['uuid'] for h in verification['hosts']})})
    return {'entry_connected': True, 'legacy_keys_and_settings_preserved': True,
            'unrelated_nodes_hosts_and_profiles_unchanged': not external_changes
                and set(now_nodes)=={n['uuid'] for n in verification['nodes']}
                and set(now_hosts)=={h['uuid'] for h in verification['hosts']},
            'scoped_changes_verified':True, 'shared_and_foreign_profiles_unchanged':True,
            'concurrent_unrelated_edits_preserved':concurrent, 'old_rights_preserved': True}


def publish(api):
    assert not exists('publish-intent')
    proof = read('new-probes')
    assert proof['all_passed'] and 0 <= time.time() - proof['timestamp'] < 1800
    verify(api)
    save('publish-intent', {'timestamp': time.time()})
    for host in read('before')['hosts']:
        if host['uuid'] in TARGET_HOSTS:
            current = next(h for h in api('GET', '/api/hosts/') if h['uuid'] == host['uuid'])
            assert prior.stable_host(current) == prior.stable_host(host)
            api('PATCH', '/api/hosts/', {'uuid': host['uuid'], **target_host(host)})
    result = verify(api, True)
    save('published', {'timestamp': time.time(), **result})
    return result


def rollback(api):
    # On explicit rollback, stop node244's nginx router first. The paired node
    # timer does so one minute before this unattended timer fires.
    before = read('before'); created = read('created')
    current = api('GET', '/api/nodes/' + NODE)
    old_binding = {'profile': OLD_PROFILE, 'inbounds': [OLD_INBOUND]}
    new_binding = {'profile': created['profile'], 'inbounds': [created['legacy'], *created['inbounds'].values()]}
    actual = binding(current)
    assert any(actual['profile'] == b['profile'] and set(actual['inbounds']) == set(b['inbounds'])
               for b in (old_binding, new_binding)), 'Later node binding; rollback refused'
    original = next(n for n in before['nodes'] if n['uuid'] == NODE)
    assert all(current[k] == original[k] for k in ('name', 'address', 'port', 'isDisabled'))
    pending = []
    indexed = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    for old in before['hosts']:
        if old['uuid'] not in OLD_HOSTS | TARGET_HOSTS: continue
        fields = legacy_host(old) if old['uuid'] in OLD_HOSTS else target_host(old)
        current = indexed[old['uuid']]
        allowed = copy.deepcopy(old); allowed.update(fields)
        original_allowed = copy.deepcopy(old)
        if host_is_legacy := old['uuid'] in OLD_HOSTS:
            for key in ('remark','isDisabled'):
                allowed[key] = original_allowed[key] = current[key]
        assert prior.stable_host(current) in (prior.stable_host(original_allowed), prior.stable_host(allowed)), 'Later host edit; rollback refused'
        if prior.stable_host(current) != prior.stable_host(old):
            pending.append({'uuid': old['uuid'], **{k: old[k] for k in fields}})
    if any(exists('dns-' + n['id']) for n in NODES):
        import dns244
        dns244.rollback()
    for body in pending:
        api('PATCH', '/api/hosts/', body)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': {'activeConfigProfileUuid': OLD_PROFILE, 'activeInbounds': [OLD_INBOUND]}})
    assert binding(api('GET', '/api/nodes/' + NODE)) == {'profile': OLD_PROFILE, 'inbounds': [OLD_INBOUND]}
    save('rollback', {'timestamp': time.time()})
    return {'old_node_and_host_bindings_restored': True}


def subscription(api):
    import prune_hosts
    configs = prune_hosts.subscription(api)
    automatic = next(c for c in configs if c.get('remarks') == '⚡ Автовыбор Серверов')
    tests = []
    for n in NODES:
        remark = next(h['remark'] for h in read('before')['hosts'] if h['uuid'] == n['hosts'][0])
        matches = [c for c in configs if c.get('remarks') == remark]; assert len(matches) == 1
        for label, config in [('visible', matches[0]), ('automatic', automatic)]:
            outputs = [o for o in config['outbounds'] if o.get('protocol') == 'vless' and
                       any(v.get('address') == frontend_address(n) and v.get('port') == frontend_port(n)
                           for v in o.get('settings', {}).get('vnext', []))]
            assert len(outputs) == 1
            outbound = outputs[0]
            assert outbound['streamSettings']['security'] == 'reality'
            assert outbound['streamSettings']['realitySettings']['serverName'] == n['domain']
            assert outbound['settings']['vnext'][0]['port'] == frontend_port(n)
            result = {'id': n['id'], 'source': label, **test_one(outbound, n['ip'])}
            tests.append(result); print(json.dumps(result), flush=True)
    banned = {h['remark'] for h in read('before')['hosts'] if h['uuid'] in prior.EXTRA_HOSTS and not h['isHidden']}
    assert not banned.intersection(c.get('remarks') for c in configs)
    proof = {'timestamp': time.time(), 'all_passed': all(t['passed'] for t in tests), 'tests': tests}
    save('subscription-proof', proof)
    assert proof['all_passed'], 'Published subscription failed; rollback required'
    return {'actual_happ_subscription_verified': True, 'main_and_auto_routes': 8, 'experimental_duplicates_absent': True}


def finish(api):
    assert read('subscription-proof')['all_passed'] and 0 <= time.time() - read('subscription-proof')['timestamp'] < 1800
    assert not exists('rollback'), 'Rollback already occurred'
    result = verify(api, True)
    subprocess.run(['systemctl', 'stop', TIMER + '.timer'], check=True, capture_output=True)
    for suffix in ('.timer', '.service'):
        assert unit_inactive(TIMER + suffix)
    assert not exists('rollback'), 'Rollback raced with finish'
    result = verify(api, True)
    save('finished', {'timestamp': time.time(), **result})
    return {**result, 'panel_rollback_timer_inactive': True}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['snapshot', 'baseline', 'probes', 'stage', 'activate', 'verify', 'publish',
        'rollback', 'subscription', 'finish', 'export-candidate', 'export-backends', 'export-clients', 'accept-test', 'accept-entry'])
    args = parser.parse_args()
    if args.action == 'export-candidate': print(json.dumps(read('candidate'))); return
    if args.action == 'accept-test':
        proof = json.load(sys.stdin)
        assert proof['installed_xray_test_passed']
        assert proof['sha256'] == hashlib.sha256(json.dumps(read('candidate'), sort_keys=True).encode()).hexdigest()
        save('installed-test', proof); print('{"installed_config_test_accepted":true}'); return
    if args.action == 'accept-entry':
        proof = json.load(sys.stdin)
        assert proof['direct_entry_verified'] and proof['nginx_public_router_absent']
        assert proof['sha256'] == hashlib.sha256(json.dumps(read('candidate'), sort_keys=True).encode()).hexdigest()
        assert 0 <= time.time() - proof['timestamp'] < 300
        save('direct-entry-ready', proof); print('{"entry_readiness_accepted":true}'); return
    api, _ = prior.create_client()
    if args.action == 'export-backends':
        config = read('candidate')
        print(json.dumps([{'id': n['id'], 'ip': n['ip'], 'outbound': next(o for o in config['outbounds'] if o['tag'] == 'exit-' + n['id'])} for n in NODES])); return
    if args.action == 'export-clients': print(json.dumps(clients(api))); return
    if args.action == 'baseline': result = probes(api, True)
    elif args.action == 'verify': result = verify(api, exists('published'))
    else: result = globals()[args.action](api)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__': main()
