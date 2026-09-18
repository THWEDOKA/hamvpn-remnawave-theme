"""Synthetic fixtures only. No panel calls, credentials or runtime changes."""
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

_spec = importlib.util.spec_from_file_location('at_nl6_tested_preflight', Path(__file__).with_name('preflight.py'))
p = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(p)
SECRET = 'SYNTHETIC-PRIVATE-MARKER'


class MemoryStore:
    def __init__(self, entry_id='cloud'): self.entry_id, self.data = entry_id, {}
    def exists(self, name): return name in self.data
    def get(self, name): return deepcopy(self.data[name])
    def put(self, name, value):
        if name in self.data: raise FileExistsError(name)
        self.data[name] = deepcopy(value)


class Fixture:
    def __init__(self, entry_id='cloud'):
        self.entry_id = entry_id; self.store = MemoryStore(entry_id)
        self.nodes, self.hosts, self.profiles, self.users, self.calls, self.sql = {}, {}, {}, {}, [], []
        self.squads = [dict(uuid=str(uuid.uuid4()), name=name, inbounds=[]) for name in sorted(p.CUSTOMER_NAMES)]
        self.squads.append(dict(uuid=str(uuid.uuid4()), name='BACKEND_SERVICE', inbounds=[]))
        for key, e in p.ENTRIES.items(): self.node(e['uuid'], e['address'], key+'-profile')
        for key, t in p.TARGETS.items():
            self.node(t['node'], t['ip'], key+'-profile')
            for field in ('host', 'auto'):
                self.hosts[t[field]] = dict(uuid=t[field], nodes=[t['node']], address=t['ip'], port=443,
                    inbound=dict(configProfileUuid=key+'-profile', configProfileInboundUuid=key+'-profile-in'),
                    remark='display '+key, isHidden=field == 'auto', isDisabled=False,
                    excludedInternalSquads=[], unknown=SECRET)
        # Shared NL profile also serves a foreign customer node/host.
        self.node('other-consumer', '192.0.2.9', 'nl6-profile')
        self.hosts['other-host'] = dict(uuid='other-host', nodes=['other-consumer'],
            inbound=dict(configProfileUuid='nl6-profile', configProfileInboundUuid='nl6-profile-in'), unknown=SECRET)
        self.nodes['unconfigured'] = dict(uuid='unconfigured', configProfile=None)
        self.node('unrelated', '192.0.2.99', 'unrelated-profile')

    def node(self, uid, address, pid):
        meta = dict(uuid=pid+'-in', tag=pid+'-tag', rawInbound={'privateKey': SECRET})
        if pid not in self.profiles:
            self.profiles[pid] = dict(uuid=pid, inbounds=[meta], config=dict(
                inbounds=[dict(tag=pid+'-tag', protocol='vless', settings={'unknown': SECRET})],
                routing={'preserve': SECRET}), unknown=SECRET)
            for squad in self.squads: squad['inbounds'].append(deepcopy(meta))
        self.nodes[uid] = dict(uuid=uid, address=address, isConnected=True, isDisabled=False,
            configProfile=dict(activeConfigProfileUuid=pid, activeInbounds=[meta]), unknown=SECRET)

    def api(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if method == 'GET':
            if path == '/api/nodes/': data = list(self.nodes.values())
            elif path == '/api/hosts/': data = list(self.hosts.values())
            elif path == '/api/internal-squads/': data = dict(internalSquads=self.squads)
            else:
                kind, key = path.strip('/').split('/')[1:]
                data = {'nodes': self.nodes, 'hosts': self.hosts, 'config-profiles': self.profiles, 'users': self.users}[kind][key]
            return deepcopy(data)
        if method == 'POST' and path == '/api/users/':
            assert self.store.exists('test-intent'), 'POST before immutable intent'
            self.users[body['uuid']] = dict(deepcopy(body), status='ACTIVE', vlessUuid=SECRET)
            return deepcopy(self.users[body['uuid']])
        if method == 'DELETE' and path.startswith('/api/users/'):
            assert self.store.exists('test-cleanup-intent'), 'DELETE before durable intent'
            self.users.pop(path.rsplit('/', 1)[1]); return {}
        raise AssertionError('Out-of-scope mutation')

    def query(self, sql):
        self.sql.append(sql)
        prefix = "SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='"
        assert sql.startswith(prefix) and sql.endswith("'"), 'SQL is not bounded read-only absence check'
        key = str(uuid.UUID(sql[len(prefix):-1]))
        return dict(remaining=int(key in self.users))

    def snapshot(self): return p.snapshot(self.api, self.store, self.entry_id)
    def account(self, routes=('at',)): return p.account(self.api, self.query, self.store, self.entry_id, list(routes))
    def cleanup(self): return p.cleanup(self.api, self.query, self.store, self.entry_id)


class PreflightTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()

    def test_both_entries_and_shared_consumers_preserved_get_only(self):
        original = deepcopy((self.f.nodes, self.f.hosts, self.f.profiles, self.f.squads))
        result = self.f.snapshot(); before = p.baseline(self.f.store, 'cloud')
        self.assertEqual(result['inventoried_entries'], 2); self.assertEqual(result['selected_hosts'], 4)
        self.assertEqual(before['entries'], p.ENTRIES)
        self.assertIn('other-consumer', p.indexed(before['nodes']))
        self.assertIn('other-host', p.indexed(before['hosts']))
        self.assertNotIn('unrelated', p.indexed(before['nodes']))
        self.assertEqual(original, (self.f.nodes, self.f.hosts, self.f.profiles, self.f.squads))
        self.assertTrue(all(c[0] == 'GET' for c in self.f.calls))
        self.assertEqual(before['profiles']['nl6-profile'], self.f.profiles['nl6-profile'])

    def test_summary_never_leaks_nested_raw_metadata(self):
        result = self.f.snapshot()
        self.assertIn(SECRET, json.dumps(self.f.store.data))
        self.assertNotIn(SECRET, json.dumps(result)); self.assertNotIn('privateKey', json.dumps(result))
        self.assertFalse(result['runtime_connectivity_tested']); self.assertFalse(result['installation_authorized'])

    def test_unhealthy_recorded_for_diagnosis_not_faked_connected(self):
        self.f.nodes[p.TARGETS['at']['node']]['isConnected'] = False
        self.assertFalse(self.f.snapshot()['panel_connected']['at'])

    def test_required_explicit_entry_namespace_and_both_inventory(self):
        with self.assertRaises(TypeError): p.collect(self.f.api)
        for invalid in (None, '', 'cloud140', 'entry'):
            with self.assertRaises(RuntimeError): p.collect(self.f.api, invalid)
        f = Fixture('aeza'); f.snapshot()
        self.assertEqual(p.baseline(f.store, 'aeza')['entries'], p.ENTRIES)
        with self.assertRaises(RuntimeError): p.baseline(f.store, 'cloud')

    def test_immutable_second_snapshot_no_api_calls(self):
        self.f.snapshot(); self.f.calls.clear()
        with self.assertRaises(RuntimeError): self.f.snapshot()
        self.assertEqual(self.f.calls, [])

    def test_foreign_scope_targets_or_entry_rejected(self):
        for key, val in [('scope', 'cloud140-six-20260918'), ('entry_id', 'aeza'), ('targets', {}), ('entries', {})]:
            f = Fixture(); f.snapshot(); f.store.data['before'][key] = val
            with self.assertRaises(RuntimeError): f.account()
            self.assertFalse(any(c[0] == 'POST' for c in f.calls))

    def test_wrong_address_or_host_binding_rejected(self):
        self.f.nodes[p.ENTRIES['aeza']['uuid']]['address'] = '192.0.2.1'
        with self.assertRaises(RuntimeError): self.f.snapshot()
        f = Fixture(); f.hosts[p.TARGETS['at']['host']]['nodes'].append('other-consumer')
        with self.assertRaises(RuntimeError): f.snapshot()

    def test_effective_rights_respect_exclusions_and_no_service_rights(self):
        denied = self.f.squads[0]['uuid']; service = self.f.squads[-1]['uuid']
        for key in ('host', 'auto'):
            self.f.hosts[p.TARGETS['at'][key]]['excludedInternalSquads'] = [dict(uuid=denied)]
        self.f.snapshot(); user = self.f.account()
        self.assertNotIn(denied, user['activeInternalSquads']); self.assertNotIn(service, user['activeInternalSquads'])
        self.assertEqual(len(user['activeInternalSquads']), 3)

    def test_empty_effective_rights_fail(self):
        h = self.f.hosts[p.TARGETS['at']['host']]
        h['excludedInternalSquads'] = [s['uuid'] for s in self.f.squads]
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_independent_probe_limits_identity_and_no_closed_scope_reads(self):
        self.f.snapshot(); user = self.f.account()
        body, routes = p.read_intent(self.f.store, 'cloud')
        self.assertEqual(routes, ['at']); self.assertEqual(body['tag'], 'AT_NL6_PROBE')
        self.assertLessEqual(len(body['tag']), 16)
        self.assertTrue(body['username'].startswith('atnl6_'))
        self.assertEqual(body['trafficLimitBytes'], 512*1024*1024)
        self.assertAlmostEqual(p.timestamp(body['expireAt'])-self.f.store.get('test-intent')['created_at'], 10800, places=3)
        self.assertEqual(user['uuid'], body['uuid']); self.f.account()
        self.assertEqual(sum(c[0] == 'POST' for c in self.f.calls), 1)
        with self.assertRaises(RuntimeError): self.f.account(('at', 'nl6'))

    def test_probe_routes_required_and_subset_drives_rights(self):
        self.f.snapshot()
        for routes in ([], ['invalid'], ['at', 'at']):
            with self.assertRaises(RuntimeError): self.f.account(routes)
        self.assertFalse(any(c[0] == 'POST' for c in self.f.calls))

    def test_lost_create_with_persisted_readback_never_reposts(self):
        self.f.snapshot()
        def api(method, path, body=None):
            value = self.f.api(method, path, body)
            if method == 'POST': raise TimeoutError(SECRET)
            return value
        p.account(api, self.f.query, self.f.store, 'cloud', ['at']); self.f.account()
        self.assertEqual(sum(c[0] == 'POST' for c in self.f.calls), 1)

    def test_lost_absent_create_never_blind_retry(self):
        self.f.snapshot(); posts = []
        def api(method, path, body=None):
            if method == 'POST': posts.append(body); raise TimeoutError(SECRET)
            return self.f.api(method, path, body)
        for _ in range(2):
            with self.assertRaises(RuntimeError): p.account(api, self.f.query, self.f.store, 'cloud', ['at'])
        self.assertEqual(len(posts), 1)

    def test_rights_drift_before_create_prevents_post(self):
        self.f.snapshot(); self.f.hosts[p.TARGETS['at']['host']]['excludedInternalSquads'] = [self.f.squads[0]['uuid']]
        with self.assertRaises(RuntimeError): self.f.account()
        self.assertFalse(self.f.store.exists('test-intent'))

    def test_foreign_identity_intent_not_reused(self):
        self.f.snapshot(); self.f.account(); self.f.store.data['test-intent']['scope'] = 'old-scope'
        with self.assertRaises(RuntimeError): self.f.cleanup()
        self.assertFalse(any(c[0] == 'DELETE' for c in self.f.calls))

    def test_cleanup_only_own_identity_idempotent(self):
        self.f.snapshot(); user = self.f.account(); foreign = str(uuid.uuid4())
        self.f.users[foreign] = dict(customer=True)
        self.assertTrue(self.f.cleanup()['absence_verified']); self.assertTrue(self.f.cleanup()['absence_verified'])
        self.assertEqual(self.f.users, {foreign: dict(customer=True)})
        self.assertEqual([c[1] for c in self.f.calls if c[0] == 'DELETE'], ['/api/users/'+user['uuid']])
        with self.assertRaises(RuntimeError): self.f.account()

    def test_cleanup_lost_response_actual_absence(self):
        self.f.snapshot(); self.f.account()
        def api(method, path, body=None):
            value = self.f.api(method, path, body)
            if method == 'DELETE': raise TimeoutError(SECRET)
            return value
        self.assertTrue(p.cleanup(api, self.f.query, self.f.store, 'cloud')['absence_verified'])

    def test_cleanup_ownership_drift_and_foreign_marker_block_delete(self):
        self.f.snapshot(); user = self.f.account(); self.f.users[user['uuid']]['description'] = 'Customer'
        with self.assertRaises(RuntimeError): self.f.cleanup()
        self.assertFalse(any(c[0] == 'DELETE' for c in self.f.calls))
        f = Fixture(); f.snapshot(); user = f.account(); f.users.pop(user['uuid'])
        f.store.data['test-cleanup-intent'] = {'uuid': 'foreign'}
        with self.assertRaises(RuntimeError): f.cleanup()

    def test_failed_delete_not_success_and_reappearance_not_deleted(self):
        self.f.snapshot(); user = self.f.account()
        def api(method, path, body=None):
            if method == 'DELETE': raise TimeoutError(SECRET)
            return self.f.api(method, path, body)
        with self.assertRaises(RuntimeError): p.cleanup(api, self.f.query, self.f.store, 'cloud')
        self.assertFalse(self.f.store.exists('test-cleanup'))
        self.f.cleanup(); self.f.users[user['uuid']] = user
        with self.assertRaises(RuntimeError): self.f.cleanup()

    def test_new_store_path_no_old_defaults_and_pure_import_unchanged(self):
        self.assertEqual(p.Store('cloud').path, p.STATE/'cloud')
        self.assertNotEqual(p.Store('cloud').path, p.shared.Store().path)
        self.assertEqual(p.shared.SCOPE, 'cloud140-six-20260918')
        with self.assertRaises(RuntimeError): p.Store('cloud', p.shared.STATE)
        with self.assertRaises(RuntimeError): p.Store('aeza').file('../foreign')

    def test_cli_requires_entry_before_store_and_suppresses_private_errors(self):
        with patch.object(p.sys, 'argv', ['preflight.py', 'snapshot']), patch.object(p, 'Store') as store, \
                patch.object(p.sys, 'stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit): p.main()
            store.assert_not_called()
        with patch.object(p.sys, 'argv', ['preflight.py', 'snapshot', '--entry-id', 'cloud']), \
                patch.object(p.Store, 'secure', side_effect=RuntimeError(SECRET)), \
                patch.object(p.sys, 'stderr', new_callable=io.StringIO) as err:
            self.assertEqual(p.main(), 1)
        self.assertNotIn(SECRET, err.getvalue())


if __name__ == '__main__': unittest.main()
