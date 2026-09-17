"""Reversibly retire only the eight approved four-exit experiment hosts.

Independent of entry140 publication: no DNS, node, profile or routing writes.
Full API/subscription snapshots stay root-only on the panel.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.request

from common import NODES, binding
from panel import EXTRA_HOSTS, create_client, read as entry_read

STATE = Path('/root/hamvpn-four-exit-host-cleanup-20260917')
KEPT = {h for n in NODES for h in n['hosts']}
NODE_IDS = {n['node'] for n in NODES}


def save(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = STATE / (name + '.json')
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(target)


def read(name):
    return json.loads((STATE / (name + '.json')).read_text(encoding='utf-8'))


def normalized(host):
    return {k: v for k, v in host.items() if k != 'viewPosition'}


def assert_scope(hosts):
    selected = {h['uuid'] for h in hosts if NODE_IDS.intersection(h.get('nodes', []))}
    assert selected == KEPT | EXTRA_HOSTS, 'Group changed; review exact identities'
    assert len(KEPT) == len(EXTRA_HOSTS) == 8
    for host in hosts:
        if host['uuid'] in selected:
            assert len(host['nodes']) == 1 and host['nodes'][0] in NODE_IDS
        if host['uuid'] in KEPT:
            assert not host['isDisabled'], 'A retained host is disabled'


def node_state(api):
    return {n['uuid']: {k: n.get(k) for k in ('name', 'address', 'port', 'isDisabled')} |
            {'binding': binding(n)} for n in api('GET', '/api/nodes/')}


def profiles(api):
    return {p: api('GET', '/api/config-profiles/' + p)['config']
            for p in {n['profile'] for n in NODES}}


def subscription(api):
    intent = entry_read('test-user')
    user = api('GET', '/api/users/' + intent['uuid'])
    assert all(user[k] == intent[k] for k in ('username', 'tag', 'description'))
    assert user['status'] == 'ACTIVE'
    sub = api('GET', '/api/subscriptions/by-uuid/' + intent['uuid'])
    request = urllib.request.Request(sub['subscriptionUrl'], headers={
        'User-Agent': 'Happ/5.7.0', 'X-Hwid': 'ham-entry140-deployment-probe',
        'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200
        result = json.load(response)
    assert isinstance(result, list) and all(isinstance(c, dict) for c in result)
    return result


def subscription_proof(before, current):
    wanted = {h['remark'] for h in before['hosts'] if h['uuid'] in KEPT and not h['isHidden']}
    banned = {h['remark'] for h in before['hosts'] if h['uuid'] in EXTRA_HOSTS and not h['isHidden']}
    remarks = [c.get('remarks') for c in current]
    assert len(wanted) == 4 and all(remarks.count(name) == 1 for name in wanted)
    assert not banned.intersection(remarks), 'An experimental host remains published'
    old_configs = {c['remarks']: c for c in before['subscription']}
    new_configs = {c['remarks']: c for c in current}
    assert set(new_configs) == set(old_configs) - banned, 'Unexpected subscription membership change'
    for name in new_configs:
        if name != '⚡ Автовыбор Серверов':
            assert new_configs[name] == old_configs[name], 'Unrelated subscription config changed'
    old_auto = old_configs['⚡ Автовыбор Серверов']
    new_auto = new_configs['⚡ Автовыбор Серверов']
    def vless(config):
        # The template regenerates ordinal basepool-N tags after removing entries.
        # Compare connection settings, not their presentation/index-derived tag.
        return [{k: v for k, v in o.items() if k != 'tag'}
                for o in config['outbounds'] if o.get('protocol') == 'vless']
    assert vless(new_auto) == vless(old_auto), 'Existing VLESS auto pool changed'
    addresses = {h['address'] for h in before['hosts'] if h['uuid'] in EXTRA_HOSTS}
    for outbound in new_auto['outbounds']:
        if outbound.get('protocol') in ('hysteria', 'hysteria2'):
            assert not any(s.get('address') in addresses for s in outbound.get('settings', {}).get('servers', []))
    return {'four_visible_hosts': True, 'other_visible_configs_unchanged': True,
            'vless_auto_pool_unchanged': True, 'experimental_visible_hosts_absent': True,
            'subscription_configs': len(current)}


def snapshot(api):
    assert not (STATE / 'before.json').exists(), 'Snapshot exists; inspect before retrying'
    hosts = api('GET', '/api/hosts/')
    assert_scope(hosts)
    data = {'hosts': hosts, 'nodes': node_state(api), 'profiles': profiles(api),
            'subscription': subscription(api), 'timestamp': time.time()}
    save('before', data)
    save('checksum', {'sha256': hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()})
    return {'snapshot_verified': True, 'retire': len(EXTRA_HOSTS), 'retain_visible': 4, 'retain_auto': 4}


def verify(api, retired=True):
    before = read('before')
    assert hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest() == read('checksum')['sha256']
    current = api('GET', '/api/hosts/')
    assert_scope(current)
    indexed = {h['uuid']: h for h in current}
    assert set(indexed) == {h['uuid'] for h in before['hosts']}
    for old in before['hosts']:
        expected = normalized(old)
        if retired and old['uuid'] in EXTRA_HOSTS:
            expected['isDisabled'] = True
        assert normalized(indexed[old['uuid']]) == expected, 'Unexpected host mutation'
    assert node_state(api) == before['nodes'], 'Node state changed'
    assert profiles(api) == before['profiles'], 'Exit profile changed'
    result = {'only_eight_flags_changed': retired, 'nodes_and_profiles_unchanged': True}
    if retired:
        result.update(subscription_proof(before, subscription(api)))
    save('verification', {'timestamp': time.time(), **result})
    return result


def rollback(api):
    before = read('before')
    for old in before['hosts']:
        if old['uuid'] not in EXTRA_HOSTS:
            continue
        current = next(h for h in api('GET', '/api/hosts/') if h['uuid'] == old['uuid'])
        expected = normalized(old)
        expected['isDisabled'] = current['isDisabled']
        assert normalized(current) == expected, 'Later edit detected; guarded rollback refused'
        if current['isDisabled'] != old['isDisabled']:
            api('PATCH', '/api/hosts/', {'uuid': old['uuid'], 'isDisabled': old['isDisabled']})
    result = verify(api, retired=False)
    save('rollback', result)
    return {'host_flags_restored': True}


def apply(api):
    assert not (STATE / 'intent.json').exists(), 'Intent exists; inspect before retrying'
    verify(api, retired=False)
    save('intent', {'timestamp': time.time(), 'hosts': sorted(EXTRA_HOSTS)})
    try:
        for identifier in sorted(EXTRA_HOSTS):
            old = next(h for h in read('before')['hosts'] if h['uuid'] == identifier)
            current = next(h for h in api('GET', '/api/hosts/') if h['uuid'] == identifier)
            assert normalized(current) == normalized(old), 'Concurrent host edit'
            api('PATCH', '/api/hosts/', {'uuid': identifier, 'isDisabled': True})
        result = verify(api)
        save('finished', result)
        return result
    except Exception:
        rollback(api)
        raise


def retry(api):
    assert (STATE / 'rollback.json').exists() and not (STATE / 'finished.json').exists()
    verify(api, retired=False)
    assert not (STATE / 'first-attempt.json').exists(), 'Retry already attempted; inspect state'
    (STATE / 'intent.json').rename(STATE / 'first-attempt.json')
    return apply(api)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['snapshot', 'apply', 'verify', 'rollback', 'retry'])
    args = parser.parse_args()
    api, _ = create_client()
    print(json.dumps(globals()[args.action](api), ensure_ascii=False))


if __name__ == '__main__':
    main()
