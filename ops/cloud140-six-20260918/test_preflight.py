"""Offline fixtures only: no adapter, SSH, remote state, or real credentials."""
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location('six_preflight_under_test', Path(__file__).with_name('preflight.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SECRET = 'FIXTURE_ONLY_PRIVATE_SENTINEL'


class Memory:
    def __init__(self): self.data = {}
    def exists(self, name): return name in self.data
    def get(self, name): return copy.deepcopy(self.data[name])
    def put(self, name, value):
        if name in self.data: raise FileExistsError(name)
        self.data[name] = copy.deepcopy(value)


class Fixture:
    def __init__(self):
        self.nodes, self.hosts, self.profiles, self.users, self.calls, self.sql = {}, {}, {}, {}, [], []
        self.store = Memory()
        self.squads = [dict(uuid=str(uuid.uuid4()), name=name, inbounds=[]) for name in sorted(p.CUSTOMER_NAMES)]
        self.squads.append(dict(uuid=str(uuid.uuid4()), name='HAM-RU140-BACKEND', inbounds=[]))
        self.profile('entry-profile', [('entry-inbound', 'vless')])
        self.node(p.ENTRY_ID, p.ENTRY, 'entry-profile')
        for target in p.TARGETS:
            key = target['id']
            if key in ('pl', 'cz'):
                pid, iid = p.GB_SOURCE
            else:
                pid, iid = (p.GB_ACTIVE if key == 'gb' else key + '-profile'), key + '-inbound'
            pairs = [(iid, 'hysteria' if key in ('at', 'us1', 'gbpower') else 'vless')]
            if key in ('at', 'gbpower'): pairs += [(key + '-legacy', 'vless')]
            if pid not in self.profiles: self.profile(pid, pairs)
            self.node(target['node'], target['ip'], pid)
            hp, hi = p.GB_SOURCE if key == 'gb' else (pid, iid)
            self.host(target['host'], target['node'], target['ip'], hp, hi, False)
            if p.AUTOS[key]: self.host(p.AUTOS[key], target['node'], target['ip'], hp, hi, True)
        gb = next(t for t in p.TARGETS if t['id'] == 'gb')
        self.host(p.GB_BYPASS, gb['node'], '188.225.62.121', p.GB_ACTIVE, 'gb-inbound', False)
        self.hosts[p.GB_BYPASS]['port'] = 9443
        self.node('other-consumer', '192.0.2.42', p.GB_SOURCE[0])
        self.host('other-consumer-host', 'other-consumer', '192.0.2.42', *p.GB_SOURCE, False)
        self.profile('unrelated-profile', [('unrelated-inbound', 'vless')])
        self.node('unrelated-node', '192.0.2.99', 'unrelated-profile')
        self.host('unrelated-host', 'unrelated-node', '192.0.2.99', 'unrelated-profile', 'unrelated-inbound', False)

    def profile(self, pid, pairs):
        metadata, raw = [], []
        for iid, protocol in pairs:
            meta = dict(uuid=iid, tag=iid, rawInbound=dict(privateKey=SECRET))
            metadata.append(meta)
            raw.append(dict(tag=iid, listen='0.0.0.0', port=443 if protocol == 'hysteria' else 10443,
                protocol=protocol, settings=dict(clients=[dict(id=SECRET, flow='xtls-rprx-vision')]),
                streamSettings=dict(network='hysteria' if protocol == 'hysteria' else 'raw',
                    security='tls' if protocol == 'hysteria' else 'reality',
                    realitySettings=dict(privateKey=SECRET, shortIds=['abcd'], serverNames=['example.com']),
                    tlsSettings=dict(serverName='example.com', certificates=[dict(keyFile=SECRET)]))))
            for squad in self.squads:
                if iid != 'gb-inbound' or squad['name'] in ('WHITE', 'site'):
                    squad['inbounds'].append(copy.deepcopy(meta))
        self.profiles[pid] = dict(uuid=pid, name=pid, inbounds=metadata,
            config=dict(inbounds=raw, outbounds=[dict(tag='DIRECT', protocol='freedom')]), unknown=dict(keep=SECRET))

    def node(self, uid, ip, pid):
        self.nodes[uid] = dict(uuid=uid, address=ip, name=uid, isConnected=True, isDisabled=False,
            configProfile=dict(activeConfigProfileUuid=pid, activeInbounds=copy.deepcopy(self.profiles[pid]['inbounds'])),
            unknown=dict(keep=SECRET))

    def host(self, uid, node, address, pid, iid, hidden):
        self.hosts[uid] = dict(uuid=uid, nodes=[node], address=address, port=443, isDisabled=False,
            isHidden=hidden, remark=uid, fingerprint='qq', inbound=dict(configProfileUuid=pid,
            configProfileInboundUuid=iid), unknown=dict(keep=SECRET))

    def api(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET':
            if path == '/api/nodes/': result = list(self.nodes.values())
            elif path == '/api/hosts/': result = list(self.hosts.values())
            elif path == '/api/internal-squads/': result = dict(internalSquads=self.squads)
            else:
                kind, key = path.strip('/').split('/')[1:]
                result = {'nodes': self.nodes, 'hosts': self.hosts, 'config-profiles': self.profiles, 'users': self.users}[kind][key]
            return copy.deepcopy(result)
        if method == 'POST' and path == '/api/users/':
            if not self.store.exists('test-intent'): raise AssertionError('POST before durable intent')
            self.users[body['uuid']] = dict(copy.deepcopy(body), vlessUuid='fixture-technical-vless', status='ACTIVE')
            return copy.deepcopy(self.users[body['uuid']])
        if method == 'DELETE' and path.startswith('/api/users/'):
            if not self.store.exists('test-cleanup-intent'): raise AssertionError('DELETE before durable intent')
            self.users.pop(path.rsplit('/', 1)[1])
            return {}
        raise AssertionError('Out-of-scope API mutation')

    def query(self, sql):
        self.sql.append(sql)
        prefix = "SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='"
        if not sql.startswith(prefix) or not sql.endswith("'"): raise AssertionError('Non-readonly query')
        key = str(uuid.UUID(sql[len(prefix):-1]))
        return dict(remaining=int(key in self.users))

    def snapshot(self): return p.snapshot(self.api, self.store)
    def account(self): return p.account(self.api, self.query, self.store)
    def cleanup(self): return p.cleanup(self.api, self.query, self.store)


class SnapshotTests(unittest.TestCase):
    def setUp(self): self.f = Fixture()

    def test_scoped_get_only_raw_snapshot_whitelisted_result(self):
        result = self.f.snapshot()
        self.assertTrue(all(c[0] == 'GET' for c in self.f.calls))
        self.assertEqual(result['selected_nodes'], 7)
        self.assertEqual(result['selected_hosts'], 11)
        self.assertEqual(result['known_binding_mismatches'], 2)
        before = p.baseline(self.f.store)
        self.assertEqual(result['sha256'], p.digest(before))
        self.assertIn(SECRET, json.dumps(before))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('unrelated-node', p.indexed(before['nodes']))
        self.assertNotIn('unrelated-host', p.indexed(before['hosts']))
        self.assertIn('other-consumer', p.indexed(before['nodes']))
        self.assertIn('other-consumer-host', p.indexed(before['hosts']))
        self.assertEqual(p.indexed(before['hosts'])[p.GB_BYPASS], self.f.hosts[p.GB_BYPASS])

    def test_unconfigured_unrelated_node_is_ignored(self):
        self.f.nodes['unconfigured'] = dict(uuid='unconfigured', configProfile=None)
        self.f.snapshot()
        self.assertNotIn('unconfigured', p.indexed(p.baseline(self.f.store)['nodes']))

    def test_second_snapshot_never_overwrites_or_calls_api(self):
        self.f.snapshot(); old = copy.deepcopy(self.f.store.data); self.f.calls.clear()
        with self.assertRaises(RuntimeError): self.f.snapshot()
        self.assertEqual(old, self.f.store.data); self.assertEqual(self.f.calls, [])

    def test_rights_derive_selected_gb_source_not_actual_inbound(self):
        self.f.snapshot(); before = p.baseline(self.f.store)
        gb = next(r for r in before['routes'] if r['id'] == 'gb')
        self.assertEqual(len(before['customer_rights'][gb['host']]), 4)
        self.assertEqual(len([s for s in before['squads'] if 'gb-inbound' in p.indexed(s['inbounds'])]), 2)
        service = next(s['uuid'] for s in self.f.squads if s['name'] == 'HAM-RU140-BACKEND')
        self.assertNotIn(service, {s for ids in before['customer_rights'].values() for s in ids})

    def test_no_auto_for_gbpower_and_no_synthesized_host(self):
        self.f.snapshot()
        route = next(r for r in p.baseline(self.f.store)['routes'] if r['id'] == 'gbpower')
        self.assertEqual(route['hosts'], [route['host']])

    def test_new_gbpower_auto_requires_review(self):
        target = p.TARGETS[-1]; host = copy.deepcopy(self.f.hosts[target['host']])
        host.update(uuid='new-auto', isHidden=True); self.f.hosts['new-auto'] = host
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_other_binding_mismatch_rejected(self):
        self.f.hosts[p.TARGETS[0]['host']]['inbound']['configProfileUuid'] = p.GB_SOURCE[0]
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_changed_gb_mismatch_not_generically_accepted(self):
        self.f.hosts[p.TARGETS[3]['host']]['inbound']['configProfileInboundUuid'] = 'different'
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_multi_node_selected_host_rejected(self):
        self.f.hosts[p.TARGETS[0]['host']]['nodes'].append('other-consumer')
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_identity_and_health_drift_rejected(self):
        for field, value in [('address', '192.0.2.200'), ('isConnected', False), ('isDisabled', True)]:
            with self.subTest(field=field):
                f = Fixture(); f.nodes[p.TARGETS[0]['node']][field] = value
                with self.assertRaises(RuntimeError): f.snapshot()

    def test_profile_metadata_missing_fails(self):
        self.f.profiles['at-profile']['config']['inbounds'].pop()
        with self.assertRaises(RuntimeError): self.f.snapshot()

    def test_unexpected_api_shape_or_duplicate_fails(self):
        for rows in ({'response': []}, [{'uuid': 'same'}, {'uuid': 'same'}]):
            with self.assertRaises(RuntimeError): p.indexed(rows)

    def test_snapshot_foreign_scope_cannot_be_used(self):
        self.f.snapshot(); self.f.store.data['before']['scope'] = 'other'
        with self.assertRaises(RuntimeError): self.f.account()
        self.assertFalse(any(c[0] == 'POST' for c in self.f.calls))


class AccountTests(unittest.TestCase):
    def setUp(self): self.f = Fixture(); self.f.snapshot()

    def test_shortlived_limited_union_intent_before_post_and_readback(self):
        user = self.f.account(); intent = p.read_intent(self.f.store)
        self.assertEqual(user['trafficLimitBytes'], 536870912)
        self.assertEqual(len(user['activeInternalSquads']), 4)
        self.assertEqual(user['trafficLimitStrategy'], 'NO_RESET')
        self.assertLessEqual(p.timestamp(user['expireAt']) - self.f.store.get('test-intent')['created_at'], 10800)
        self.assertEqual(user['uuid'], intent['uuid'])
        self.assertTrue(self.f.store.exists('test-created'))
        self.assertEqual(self.f.calls[-1][:2], ('GET', '/api/users/' + user['uuid']))
        self.f.account()
        self.assertEqual(sum(c[0] == 'POST' for c in self.f.calls), 1)

    def test_ambiguous_post_readback_recovers_no_repeat(self):
        def api(method, path, body=None):
            result = self.f.api(method, path, body)
            if method == 'POST': raise TimeoutError(SECRET)
            return result
        user = p.account(api, self.f.query, self.f.store)
        self.assertIn(user['uuid'], self.f.users)
        self.f.account()
        self.assertEqual(sum(c[0] == 'POST' for c in self.f.calls), 1)

    def test_ambiguous_post_absent_stops_all_future_post(self):
        posts = []
        def api(method, path, body=None):
            if method == 'POST': posts.append(body); raise TimeoutError(SECRET)
            return self.f.api(method, path, body)
        for _ in range(2):
            with self.assertRaises(RuntimeError): p.account(api, self.f.query, self.f.store)
        self.assertEqual(len(posts), 1)
        self.assertTrue(self.f.store.exists('test-intent'))
        self.assertFalse(self.f.store.exists('test-created'))

    def test_success_reply_without_persistence_not_accepted(self):
        def api(method, path, body=None):
            return body if method == 'POST' else self.f.api(method, path, body)
        with self.assertRaises(RuntimeError): p.account(api, self.f.query, self.f.store)

    def test_rights_and_binding_drift_prevent_post(self):
        self.f.squads[0]['inbounds'] = []
        with self.assertRaises(RuntimeError): self.f.account()
        self.assertFalse(self.f.store.exists('test-intent'))
        f = Fixture(); f.snapshot(); f.hosts[p.TARGETS[0]['host']]['nodes'] = [p.ENTRY_ID]
        with self.assertRaises(RuntimeError): f.account()

    def test_account_identity_tampering_prevents_reuse(self):
        user = self.f.account(); self.f.users[user['uuid']]['description'] = 'customer account'
        with self.assertRaises(RuntimeError): self.f.account()

    def test_expired_account_never_extended(self):
        user = self.f.account()
        with patch.object(p.time, 'time', return_value=p.timestamp(user['expireAt']) + 1), self.assertRaises(RuntimeError):
            self.f.account()
        self.assertEqual(sum(c[0] == 'POST' for c in self.f.calls), 1)

    def test_dict_squad_api_shape_and_millisecond_expiry(self):
        user = self.f.account(); wire = self.f.users[user['uuid']]
        wire['activeInternalSquads'] = [dict(uuid=s, name='fixture') for s in wire['activeInternalSquads']]
        wire['expireAt'] = datetime.fromisoformat(wire['expireAt']).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        self.f.account()

    def test_intent_uuid_sql_injection_rejected(self):
        with self.assertRaises(ValueError): p.remaining(self.f.query, "x' OR true --")
        self.assertEqual(self.f.sql, [])

    def test_cleanup_exact_identity_and_confirm_sql_absence(self):
        user = self.f.account(); foreign = str(uuid.uuid4()); self.f.users[foreign] = {'customer': True}
        self.assertTrue(self.f.cleanup()['absence_verified'])
        self.assertEqual(self.f.users, {foreign: {'customer': True}})
        self.assertEqual([c[1] for c in self.f.calls if c[0] == 'DELETE'], ['/api/users/' + user['uuid']])
        self.assertTrue(self.f.cleanup()['absence_verified'])
        with self.assertRaises(RuntimeError): self.f.account()

    def test_cleanup_lost_response_checks_absence(self):
        self.f.account()
        def api(method, path, body=None):
            result = self.f.api(method, path, body)
            if method == 'DELETE': raise TimeoutError(SECRET)
            return result
        self.assertTrue(p.cleanup(api, self.f.query, self.f.store)['absence_verified'])

    def test_cleanup_failed_delete_never_claims_success(self):
        self.f.account()
        def api(method, path, body=None):
            if method == 'DELETE': raise TimeoutError(SECRET)
            return self.f.api(method, path, body)
        with self.assertRaises(RuntimeError): p.cleanup(api, self.f.query, self.f.store)
        self.assertFalse(self.f.store.exists('test-cleanup'))
        with self.assertRaises(RuntimeError): self.f.account()

    def test_cleanup_ownership_field_mismatches_stop_delete(self):
        for key in ('username', 'tag', 'description', 'trafficLimitBytes', 'trafficLimitStrategy', 'expireAt', 'activeInternalSquads'):
            with self.subTest(key=key):
                f = Fixture(); f.snapshot(); user = f.account()
                f.users[user['uuid']][key] = [] if key == 'activeInternalSquads' else 'not-ours'
                with self.assertRaises((RuntimeError, ValueError)): f.cleanup()
                self.assertFalse(any(c[0] == 'DELETE' for c in f.calls))

    def test_already_absent_ambiguous_create_cleanup_no_delete(self):
        user = self.f.account(); self.f.users.pop(user['uuid'])
        self.assertTrue(self.f.cleanup()['absence_verified'])
        self.assertFalse(any(c[0] == 'DELETE' for c in self.f.calls))

    def test_reappearing_after_cleanup_fails_without_delete(self):
        user = self.f.account(); self.f.cleanup(); self.f.users[user['uuid']] = user
        with self.assertRaises(RuntimeError): self.f.cleanup()
        self.assertEqual(sum(c[0] == 'DELETE' for c in self.f.calls), 1)


class ExportTests(unittest.TestCase):
    def setUp(self): self.f = Fixture(); self.f.snapshot(); self.f.account()

    def test_export_get_only_new_identity_no_private_or_old_clients(self):
        self.f.calls.clear()
        with patch.object(p, 'public_key', return_value='fixture-public-key'):
            value = p.export_baseline(self.f.api, self.f.store)
        self.assertTrue(value['items'])
        self.assertFalse(value['authenticated_test_performed'])
        self.assertNotIn(SECRET, json.dumps(value))
        self.assertNotIn('privateKey', json.dumps(value))
        self.assertTrue(all(c[0] == 'GET' for c in self.f.calls))
        self.assertFalse(any(i['id'].startswith('us1-') for i in value['items']))
        self.assertTrue(any(i['id'] == 'us1' for i in value['unsupported']))
        for item in value['items']:
            self.assertIsNone(item['expected_egress'])
            endpoint = item['outbound']['settings']['vnext'][0]
            self.assertEqual(endpoint['users'][0]['id'], 'fixture-technical-vless')
            self.assertEqual(endpoint['port'], 10443)  # actual inbound, not guessed 443

    def test_export_never_creates_missing_identity(self):
        self.f.store.data.pop('test-intent'); self.f.calls.clear()
        with self.assertRaises(KeyError): p.export_baseline(self.f.api, self.f.store)
        self.assertEqual(self.f.calls, [])

    def test_profile_drift_fails_export(self):
        self.f.profiles['at-profile']['config']['outbounds'].append(dict(protocol='blackhole'))
        with self.assertRaises(RuntimeError): p.export_baseline(self.f.api, self.f.store)

    def test_cli_requires_export_flag_before_adapter_or_store(self):
        with patch.object(p.sys, 'argv', ['preflight.py', 'export-baseline']), \
                patch.object(p, 'Store') as store, patch.object(p.sys, 'stderr', new_callable=io.StringIO) as error:
            self.assertEqual(p.main(), 1)
        store.assert_not_called(); self.assertNotIn(SECRET, error.getvalue())

    def test_cli_refuses_terminal_secret_export(self):
        with patch.object(p.sys, 'argv', ['preflight.py', 'export-baseline', '--secret-stdout']), \
                patch.object(p.sys.stdout, 'isatty', return_value=True), patch.object(p, 'Store') as store, \
                patch.object(p.sys, 'stderr', new_callable=io.StringIO):
            self.assertEqual(p.main(), 1)
        store.assert_not_called()

    def test_cli_errors_never_echo_exception_body(self):
        with patch.object(p.sys, 'argv', ['preflight.py', 'inspect']), \
                patch.object(p.Store, 'secure', side_effect=RuntimeError(SECRET)), \
                patch.object(p.sys, 'stderr', new_callable=io.StringIO) as error:
            self.assertEqual(p.main(), 1)
        self.assertNotIn(SECRET, error.getvalue())


class StorageTests(unittest.TestCase):
    def test_names_cannot_escape_scope(self):
        for name in ('../before', '/before', 'a/b', 'a\\b', 'before.json', '', 'x' * 65):
            with self.assertRaises(RuntimeError): p.Store().file(name)

    def test_canonical_hash_order_independent_sensitive_to_changes(self):
        self.assertEqual(p.digest(dict(a=1, b=2)), p.digest(dict(b=2, a=1)))
        self.assertNotEqual(p.digest(dict(a=1)), p.digest(dict(a=2)))

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Production POSIX/root permission contract')
    def test_secure_real_files_modes_immutable_hash_symlink_and_hardlink(self):
        # /root avoids deliberately rejected world-writable /tmp ancestors.
        with tempfile.TemporaryDirectory(dir='/root', prefix='six-preflight-test-') as temporary:
            store = p.Store(Path(temporary) / 'state')
            store.put('before', dict(private=SECRET))
            path = store.file('before')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o700)
            self.assertEqual(store.get('before'), dict(private=SECRET))
            with self.assertRaises(FileExistsError): store.put('before', dict(other=True))
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): store.get('before')
            path.chmod(0o600)
            record = json.loads(path.read_text()); record['value']['private'] = 'changed'
            path.write_text(json.dumps(record))
            with self.assertRaises(RuntimeError): store.get('before')
            store.file('linked').symlink_to(path)
            with self.assertRaises(OSError): store.get('linked')
            os.link(path, store.file('hardlinked'))
            with self.assertRaises(RuntimeError): store.get('hardlinked')


if __name__ == '__main__':
    unittest.main()
