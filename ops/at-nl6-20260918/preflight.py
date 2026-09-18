"""AT/NL6 preflight; main owns execution/publication, no VPN installation.

snapshot/inspect are API-read-only. account/cleanup may mutate ONLY a new
intent-owned 3-hour/512-MiB probe. No profiles, hosts, squads, DNS or SSH writes.
Every lifecycle call requires entry_id; both entries are always inventoried.
Optional --run-id uses preflight/<entry>/runs/<slug>, never the closed default
store. Slugs are 1-48 lowercase ASCII letters/digits with single internal
hyphens and a leading letter. Omit it to preserve the legacy lifecycle.
Old six-route state/identity is NEVER read or reused. account returns private
data to callers in RAM; CLI outputs only whitelisted counters/booleans.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('at_nl6_published_pure_helpers',
    ROOT.parent/'cloud140-six-20260918'/'preflight.py')
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
require, digest, indexed = shared.require, shared.digest, shared.indexed
binding, active, remaining, owned, timestamp = shared.binding, shared.active, shared.remaining, shared.owned, shared.timestamp

SCOPE = 'at-nl6-20260918'
STATE = Path('/root/hamvpn-at-nl6-20260918/preflight')
LIMIT = 512 * 1024 * 1024
TAG = 'AT_NL6_PROBE'
DESCRIPTION = 'Temporary AT NL6 explicit-entry diagnostics'
CUSTOMER_NAMES = frozenset(('WHITE', 'BASE', 'OLD', 'site'))
ENTRIES = {
    'cloud': dict(uuid='f67527b4-9685-41a3-8bd1-c1538724b4a1', address='176.108.245.140'),
    # UUID confirmed from the live panel API, not inferred from a name.
    'aeza': dict(uuid='560e38b3-6ee8-4f10-861e-e2f1eddd4caa', address='193.233.222.244'),
}
TARGETS = {
    'at': dict(node='7f9b7a9d-fee8-4f64-ac6e-dceb59afe715', ip='147.45.71.38',
               host='8a734066-a484-4b17-b1ac-c02f52f62c06', auto='17323e32-fb2c-4e4c-896d-07313101248a'),
    'nl6': dict(node='c7eefe81-cc9a-485a-a441-410e06182b76', ip='31.76.9.211',
                host='0ed1ddaf-0cca-4998-89c6-600bc54cb94d', auto='565be158-e2c5-4f62-9b9c-c9f6d44738c0'),
}


def entry(entry_id):
    require(entry_id in ENTRIES, 'Explicit entry_id cloud|aeza required')
    return deepcopy(ENTRIES[entry_id])


def route_ids(values):
    require(isinstance(values, (list, tuple)) and values and len(values) == len(set(values))
            and set(values) <= set(TARGETS), 'Explicit nonempty AT/NL6 route subset required')
    return sorted(values)


def run_fields(run_id):
    require(run_id is None or (isinstance(run_id, str) and 1 <= len(run_id) <= 48 and
            re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', run_id) is not None),
            'Invalid run_id: expected a bounded lowercase slug')
    # Absence, not null, preserves hashes and markers of existing lifecycles.
    return {} if run_id is None else dict(run_id=run_id)


def check_run(value, store):
    require({k: value[k] for k in ('run_id',) if k in value} ==
            run_fields(getattr(store, 'run_id', None)), 'Foreign run lifecycle')


class Store(shared.Store):
    def __init__(self, entry_id, path=None, *, run_id=None):
        entry(entry_id)
        run_fields(run_id)
        require(path is None or run_id is None, 'Explicit run cannot override AT/NL6 state root')
        # Reuse ONLY storage implementation; never its old default directory.
        selected = Path(path) if path is not None else STATE/entry_id
        if run_id is not None: selected = selected/'runs'/run_id
        super().__init__(selected)
        require('cloud140-six-20260918' not in self.path.as_posix(), 'Old closed namespace prohibited')
        self.entry_id, self.run_id = entry_id, run_id


def excluded(host):
    values = host.get('excludedInternalSquads', [])
    require(isinstance(values, list), 'Invalid host exclusions')
    ids = [v.get('uuid', v.get('squadUuid')) if isinstance(v, dict) else v for v in values]
    require(all(isinstance(v, str) and v for v in ids) and len(ids) == len(set(ids)), 'Ambiguous host exclusions')
    return set(ids)


def customer_rights(hosts, squads):
    customers = [s for s in squads if s['name'] in CUSTOMER_NAMES]
    require(len(customers) == len(CUSTOMER_NAMES) and {s['name'] for s in customers} == CUSTOMER_NAMES,
            'Customer squad inventory ambiguous')
    result = {}
    for host in hosts:
        iid = binding(host)[1]
        result[host['uuid']] = sorted(s['uuid'] for s in customers
            if iid in indexed(s['inbounds']) and s['uuid'] not in excluded(host))
        require(result[host['uuid']], 'Selected host lacks effective customer rights')
    return result


def collect(api, entry_id):
    entry(entry_id)
    nodes, hosts = indexed(api('GET', '/api/nodes/')), indexed(api('GET', '/api/hosts/'))
    squads = list(indexed(api('GET', '/api/internal-squads/')['internalSquads']).values())
    roots = {e['uuid']: e['address'] for e in ENTRIES.values()}
    roots.update({t['node']: t['ip'] for t in TARGETS.values()})
    pids = set(); selected = []
    for uid, address in roots.items():
        require(nodes[uid]['address'] == address, 'Node identity/address drift')
        pid, aids = active(nodes[uid]); require(pid and aids, 'Target has no configured active inbound')
        pids.add(pid)
    for target in TARGETS.values():
        pid, aids = active(nodes[target['node']])
        for key, hidden in [('host', False), ('auto', True)]:
            h = hosts[target[key]]
            require(h['nodes'] == [target['node']] and h['isHidden'] is hidden and not h['isDisabled'],
                    'Selected main/auto identity changed')
            hp, hi = binding(h)
            require(hp == pid and hi in aids, 'Selected host not on its active exit inbound')
            selected.append(h); pids.add(hp)
    profiles = {pid: api('GET', '/api/config-profiles/'+pid) for pid in sorted(pids)}
    inbound_ids = set()
    for pid, profile in profiles.items():
        require(profile['uuid'] == pid and isinstance(profile['config'], dict), 'Invalid profile')
        metadata = indexed(profile['inbounds'])
        tags = [i['tag'] for i in profile['config']['inbounds']]
        require(len(tags) == len(set(tags)) and all(i['tag'] in tags for i in metadata.values()), 'Inbound metadata/raw mismatch')
        inbound_ids.update(metadata)
    for uid in roots:
        pid, aids = active(nodes[uid])
        require(aids <= set(indexed(profiles[pid]['inbounds'])), 'Active inbound missing from profile')
    consumers = {pid: sorted(n['uuid'] for n in nodes.values()
                  if (n.get('configProfile') or {}).get('activeConfigProfileUuid') == pid) for pid in profiles}
    relevant_nodes = set(roots) | {uid for ids in consumers.values() for uid in ids}
    relevant_hosts = [h for h in hosts.values() if set(h.get('nodes', [])) & relevant_nodes or
                      (h.get('inbound') or {}).get('configProfileUuid') in profiles or
                      (h.get('inbound') or {}).get('configProfileInboundUuid') in inbound_ids]
    relevant_squads = [s for s in squads if s['name'] in CUSTOMER_NAMES or set(indexed(s['inbounds'])) & inbound_ids]
    return dict(scope=SCOPE, entry_id=entry_id, entries=deepcopy(ENTRIES), targets=deepcopy(TARGETS),
                timestamp=time.time(), nodes=[nodes[n] for n in sorted(relevant_nodes)], hosts=relevant_hosts,
                squads=relevant_squads, profiles=profiles, profile_consumers=consumers,
                customer_rights=customer_rights(selected, squads))


def baseline(store, entry_id):
    entry(entry_id)
    require(getattr(store, 'entry_id', None) == entry_id, 'Foreign store entry namespace')
    value = store.get('before')
    check_run(value, store)
    require(value['scope'] == SCOPE and value['entry_id'] == entry_id and
            value['entries'] == ENTRIES and value['targets'] == TARGETS, 'Foreign snapshot scope/targets/entry')
    return value


def summary(value):
    # NEVER serialize raw node.configProfile or squad.inbounds: nested metadata
    # may contain rawInbound/privateKey. Enumerated IDs/counts/booleans only.
    nodes = indexed(value['nodes'])
    health = {key: bool(nodes[e['uuid']]['isConnected'] and not nodes[e['uuid']]['isDisabled'])
              for key, e in ENTRIES.items()}
    health.update({key: bool(nodes[t['node']]['isConnected'] and not nodes[t['node']]['isDisabled'])
                   for key, t in TARGETS.items()})
    return dict(snapshot_verified=True, scope=SCOPE, entry_id=value['entry_id'], sha256=digest(value),
                **run_fields(value.get('run_id')),
                inventoried_entries=2, selected_exits=2, selected_hosts=4, profiles=len(value['profiles']),
                preserved_nodes=len(value['nodes']), preserved_hosts=len(value['hosts']),
                shared_profiles=sum(len(ids) > 1 for ids in value['profile_consumers'].values()), panel_connected=health,
                runtime_connectivity_tested=False, installation_authorized=False)


def snapshot(api, store, entry_id):
    entry(entry_id)
    require(getattr(store, 'entry_id', None) == entry_id, 'Foreign store namespace')
    identity = run_fields(getattr(store, 'run_id', None))
    require(not store.exists('before'), 'Immutable snapshot exists; do not overwrite')
    store.put('before', dict(collect(api, entry_id), **identity))
    return summary(baseline(store, entry_id))


def live_rights(api, before, routes):
    ids = [TARGETS[r][key] for r in route_ids(routes) for key in ('host', 'auto')]
    old = indexed(before['hosts'])
    hosts = [api('GET', '/api/hosts/'+hid) for hid in ids]
    for h in hosts:
        prior = old[h['uuid']]
        require(all(h[k] == prior[k] for k in ('nodes', 'inbound', 'isHidden', 'isDisabled')) and
                excluded(h) == excluded(prior), 'Selected host binding/exclusion drift')
    rights = customer_rights(hosts, api('GET', '/api/internal-squads/')['internalSquads'])
    require(rights == {hid: before['customer_rights'][hid] for hid in ids}, 'Selected effective rights drift')
    return sorted({sid for values in rights.values() for sid in values})


def read_intent(store, entry_id):
    before = baseline(store, entry_id); value = store.get('test-intent')
    check_run(value, store)
    require(value['scope'] == SCOPE and value['entry_id'] == entry_id and value['snapshot_sha256'] == digest(before), 'Foreign probe intent')
    routes = route_ids(value['routes']); body = value['body']
    expected = sorted({s for r in routes for key in ('host', 'auto') for s in before['customer_rights'][TARGETS[r][key]]})
    require(body['tag'] == TAG and body['description'] == DESCRIPTION and
            body['username'] == 'atnl6_'+str(uuid.UUID(body['uuid'])).replace('-', '')[:24] and
            body['trafficLimitBytes'] == LIMIT and body['trafficLimitStrategy'] == 'NO_RESET' and
            sorted(body['activeInternalSquads']) == expected and
            abs(timestamp(body['expireAt']) - value['created_at'] - 10800) < 1, 'Invalid independent probe identity')
    return body, routes


def probe_user(api, store, entry_id):
    require(not store.exists('test-cleanup') and not store.exists('test-cleanup-intent'), 'Probe lifecycle closed')
    body, _ = read_intent(store, entry_id)
    if store.exists('test-created'):
        require(store.get('test-created') == marker(body, entry_id, getattr(store, 'run_id', None)),
                'Foreign created marker')
    return owned(api('GET', '/api/users/'+body['uuid']), body, usable=True)


def marker(body, entry_id, run_id=None):
    return dict(scope=SCOPE, entry_id=entry_id, uuid=body['uuid'], **run_fields(run_id))


def account(api, query, store, entry_id, routes):
    routes = route_ids(routes)
    require(not store.exists('test-cleanup') and not store.exists('test-cleanup-intent'), 'Probe lifecycle closed')
    before = baseline(store, entry_id)
    identity = run_fields(getattr(store, 'run_id', None))
    rights = live_rights(api, before, routes)
    if store.exists('test-intent'):
        body, old_routes = read_intent(store, entry_id)
        require(routes == old_routes, 'Probe route scope cannot expand')
        require(remaining(query, body['uuid']) == 1, 'Uncertain create; never repeat POST')
    else:
        require(not store.exists('test-created'), 'Created marker without probe intent')
        identifier = str(uuid.uuid4())
        require(remaining(query, identifier) == 0, 'Identity already exists')
        now = datetime.now(timezone.utc)
        body = dict(uuid=identifier, username='atnl6_'+identifier.replace('-', '')[:24], tag=TAG,
                    description=DESCRIPTION, expireAt=(now+timedelta(hours=3)).isoformat(),
                    trafficLimitBytes=LIMIT, trafficLimitStrategy='NO_RESET', activeInternalSquads=rights)
        store.put('test-intent', dict(scope=SCOPE, entry_id=entry_id, routes=routes, snapshot_sha256=digest(before),
                                     created_at=now.timestamp(), body=body, **identity))
        try: api('POST', '/api/users/', body)
        except Exception: pass  # Always resolve by readback, never echo response.
        require(remaining(query, identifier) == 1, 'Create not confirmed; intent retained without retry')
    user = probe_user(api, store, entry_id)
    expected = marker(body, entry_id, getattr(store, 'run_id', None))
    if store.exists('test-created'):
        require(store.get('test-created') == expected, 'Foreign created marker')
    else: store.put('test-created', expected)
    return user  # SECRET RAM result; CLI does not print it.


def cleanup(api, query, store, entry_id):
    body, _ = read_intent(store, entry_id)
    expected = marker(body, entry_id, getattr(store, 'run_id', None))
    for name in ('test-created', 'test-cleanup-intent'):
        if store.exists(name): require(store.get(name) == expected, 'Foreign lifecycle marker')
    if store.exists('test-cleanup'):
        require(store.get('test-cleanup') == dict(**expected, absence_verified=True) and
                remaining(query, body['uuid']) == 0, 'Probe absence/cleanup marker changed')
        return dict(disposable_user_deleted=True, absence_verified=True)
    present = remaining(query, body['uuid'])
    if present: owned(api('GET', '/api/users/'+body['uuid']), body)
    if not store.exists('test-cleanup-intent'): store.put('test-cleanup-intent', expected)
    if present:
        try: api('DELETE', '/api/users/'+body['uuid'])
        except Exception: pass
    require(remaining(query, body['uuid']) == 0, 'Exact probe deletion not confirmed')
    store.put('test-cleanup', dict(**expected, absence_verified=True))
    return dict(disposable_user_deleted=True, absence_verified=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('snapshot', 'inspect', 'account', 'cleanup'))
    parser.add_argument('--entry-id', required=True, choices=tuple(ENTRIES))
    parser.add_argument('--run-id', help='Fresh AT/NL6 lifecycle slug; omit to use the existing default store')
    parser.add_argument('--routes', nargs='+', choices=tuple(TARGETS))
    args = parser.parse_args()
    try:
        require((args.routes is not None) == (args.action == 'account'), 'Explicit route subset required only for account')
        os.umask(0o077)
        store = Store(args.entry_id, run_id=args.run_id); store.secure()
        import fcntl
        fd = os.open(store.path/'operation.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1, 'Unsafe operation lock')
            fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.action == 'inspect': result = summary(baseline(store, args.entry_id))
            else:
                api, query = shared.load_file('at_nl6_api_adapter', ROOT.parent/'selfsteal-us3'/'panel_api.py').create_client()
                if args.action == 'snapshot': result = snapshot(api, store, args.entry_id)
                elif args.action == 'cleanup': result = cleanup(api, query, store, args.entry_id)
                else:
                    account(api, query, store, args.entry_id, args.routes)
                    result = dict(disposable_probe_ready=True, entry_id=args.entry_id, routes=route_ids(args.routes),
                                  traffic_limit_bytes=LIMIT, lifetime_seconds=10800)
            print(json.dumps(dict(result, **run_fields(args.run_id))))
    except Exception:
        print(json.dumps(dict(error='PreflightFailed', message='Inspect protected scoped state; no automatic retry or secret output')), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__': sys.exit(main())
