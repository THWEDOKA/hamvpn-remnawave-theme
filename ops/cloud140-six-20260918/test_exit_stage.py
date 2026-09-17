"""Offline API/rollback failure simulations. No production/network/service I/O."""

import base64
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import exit_stage as c
from test_preflight import Fixture, Memory, SECRET

NOW = 1800000000.0


class Store(Memory):
    def save(self, name, value):
        assert name == 'operation'
        self.data[name] = deepcopy(value)


class Timer:
    def __init__(self):
        self.active, self.running = set(), set()
        self.starts, self.cancels = [], []

    def start(self, route_id):
        c.require(route_id not in self.active, 'Timer exists')
        self.active.add(route_id)
        self.starts.append(route_id)

    def armed(self, route_id):
        c.require(route_id in self.active and route_id not in self.running, 'Timer not armed')

    def cancel(self, route_id):
        self.active.discard(route_id)
        self.running.discard(route_id)
        self.cancels.append(route_id)


class API:
    def __init__(self, fixture, store, timer, route_id):
        self.nodes, self.profiles, self.hosts = fixture.nodes, fixture.profiles, fixture.hosts
        self.squads = {s['uuid']: s for s in fixture.squads}
        self.users = fixture.users
        self.calls, self.writes, self.counter = [], [], 0
        self.store, self.timer, self.route_id = store, timer, route_id
        self.fail_before, self.fail_after, self.ignore = None, None, None

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        if method != 'GET':
            self.writes.append((method, path, deepcopy(body)))
            assert self.store.exists('before') and self.store.exists('plan')
            assert self.route_id in self.timer.active or 'rollback_intent' in self.store.get('operation')
            if self.fail_before == (method, path):
                self.fail_before = None
                raise TimeoutError(SECRET)
            if self.ignore == (method, path):
                return deepcopy(body)
        parts = path.strip('/').split('/')
        resource, identifier = parts[1], parts[2] if len(parts) > 2 else None
        bucket = {'nodes': self.nodes, 'config-profiles': self.profiles, 'hosts': self.hosts,
                  'internal-squads': self.squads, 'users': self.users}[resource]
        if method == 'GET':
            if identifier:
                return deepcopy(bucket[identifier])
            values = deepcopy(list(bucket.values()))
            if resource in ('config-profiles', 'internal-squads'):
                return {{'config-profiles': 'configProfiles', 'internal-squads': 'internalSquads'}[resource]: values}
            return values
        if method == 'POST':
            self.counter += 1
            value = deepcopy(body)
            value.setdefault('uuid', 'owned-' + resource + '-' + str(self.counter))
            record = self.store.get('operation')
            kind = {'config-profiles': 'profile', 'internal-squads': 'squad', 'users': 'user'}[resource]
            assert record['intents'][kind] == body  # Durable BEFORE creation.
            if resource == 'config-profiles':
                value['inbounds'] = [dict(tag=i['tag'], uuid=value['uuid'] + '-in-' + str(n))
                                     for n, i in enumerate(value['config']['inbounds'])]
            elif resource == 'internal-squads':
                value['inbounds'] = [dict(uuid=i) for i in value['inbounds']]
            else:
                value.update(status='ACTIVE', vlessUuid='00000000-0000-4000-8000-' + str(self.counter).zfill(12))
                value['activeInternalSquads'] = [dict(uuid=i) for i in value['activeInternalSquads']]
            bucket[value['uuid']] = value
            result = value
        elif method == 'PATCH':
            value = deepcopy(body)
            if resource == 'nodes':
                value['configProfile']['activeInbounds'] = [dict(uuid=i) for i in value['configProfile']['activeInbounds']]
            if resource == 'internal-squads':
                value['inbounds'] = [dict(uuid=i) for i in value['inbounds']]
            bucket[value['uuid']].update(value)
            result = bucket[value['uuid']]
        else:
            raise AssertionError('Unexpected/destructive mutation')
        if self.fail_after == (method, path):
            self.fail_after = None
            raise TimeoutError(SECRET)
        return deepcopy(result)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.init('at')

    def init(self, route_id):
        self.route_id = route_id
        self.fixture = Fixture()
        self.fixture.snapshot()
        self.baseline = self.fixture.store
        self.store, self.timer = Store(), Timer()
        self.api = API(self.fixture, self.store, self.timer, route_id)
        self.now = NOW
        self.worker = c.Coordinator(self.api, self.store, self.timer, self.baseline, lambda: self.now,
            identity_factory=lambda: dict(privateKey=base64.urlsafe_b64encode(bytes(range(1, 33))).decode().rstrip('='), shortIds=['1234567890abcdef']))

    def inputs(self, route_id=None, mode='reality'):
        route = c.target(route_id or self.route_id)
        runtime = dict(**{k: route[k] for k in ('id', 'node', 'ip')}, timestamp=self.now,
            backend_port=15444, port_free=True, namespace_verified=True, xray_version='26.7.28')
        result = dict(mode=mode, backend_port=15444, expected_egress='51.194.240.214' if route['id'] == 'gbpower' else route['ip'], runtime=runtime)
        if mode == 'reality':
            runtime['firewall_source'] = c.p.ENTRY
            result.update(target='example.com:443', server_names=['example.com'], target_checks=[dict(
                target='example.com:443', server_name='example.com', trusted_tls=True, tls_version='TLSv1.3', alpn='h2')])
        else:
            runtime['loopback_only'] = True
            scoped = {k: runtime[k] for k in ('id', 'node', 'ip', 'timestamp')}
            result.update(direct_failure=dict(**scoped, entry=c.p.ENTRY, authenticated_direct_attempted=True, passed=False),
                tunnel=dict(**scoped, entry=c.p.ENTRY, backend_port=15444, target_address='127.0.0.1',
                    listener_address='127.0.0.1', listener_port=26501, host_key_pinned=True,
                    restricted_identity=True, fixed_target_verified=True, persistent_service_verified=True))
        return result

    def proof(self, kind='installed'):
        route = c.target(self.route_id)
        record = self.store.get('operation')
        result = dict(**{k: route[k] for k in ('id', 'node', 'ip')}, sha256=record['sha256'], timestamp=self.now)
        if kind == 'installed':
            result['tests'] = [dict(kind='installed-xray', version='26.7.28', passed=True, returncode=0)]
        elif kind == 'baseline':
            before, plan = self.store.get('before'), self.store.get('plan')
            result.update(source_sha256=c.checksum(before['profile']['config']), tests=[])
            active = set(c.binding(before['node'])['inbounds'])
            for tag, iid in c.metadata(before['profile']).items():
                if iid in active:
                    result['tests'].append(dict(kind='legacy', test_id=tag + '-external', tag=tag,
                        namespace='external-client', client='xray-26.7.28', wire_sha256=c.checksum(dict(tag=tag, config='fixture-actual-client')),
                        passed=True, authenticated=True, http_code=204, returncodes=[0, 0], exit_ip=plan['inputs']['expected_egress']))
        else:
            before, plan = self.store.get('before'), self.store.get('plan')
            traffic = dict(authenticated=True, http_code=204, returncode=0, exit_ip=plan['inputs']['expected_egress'])
            result.update(entry=c.p.ENTRY, mode=plan['inputs']['mode'], tests=[dict(kind='backend', namespace='entry-xray', **traffic)])
            result['tests'] += deepcopy(record['baseline_proof']['tests'])
        return result

    def prepare(self, mode='reality'):
        self.worker.prepare(self.route_id, self.inputs(mode=mode))
        self.worker.accept_installed(self.route_id, self.proof())
        self.worker.accept_baseline(self.route_id, self.proof('baseline'))
        return self.store.get('operation')

    def stage(self, mode='reality'):
        self.prepare(mode)
        self.worker.stage(self.route_id)
        return self.store.get('operation')

    def apply(self, mode='reality'):
        self.stage(mode)
        self.worker.apply(self.route_id)
        return self.store.get('operation')

    def test_prepare_four_targets_readonly_snapshot_and_exact_legacy_preservation(self):
        for route_id in c.ACTIVE_ROUTES:
            with self.subTest(route_id=route_id):
                self.init(route_id)
                record = self.prepare()
                before, plan = self.store.get('before'), self.store.get('plan')
                self.assertFalse(self.api.writes)
                self.assertFalse(self.timer.starts)
                self.assertEqual(plan['candidate']['outbounds'], before['profile']['config']['outbounds'])
                renamed = c.model.legacy_tag_map(before['profile']['config'], route_id)
                for old, new in zip(before['profile']['config']['inbounds'], plan['candidate']['inbounds']):
                    expected = deepcopy(old); expected['tag'] = renamed[old['tag']]
                    self.assertEqual(new, expected)
                self.assertEqual(record['sha256'], c.checksum(plan['candidate']))
                self.assertLessEqual(len(plan['name']), 30)
                self.assertLessEqual(len(plan['squad_name']), 30)

    def test_withdrawn_gb_us1_are_rejected_before_any_state_or_api_access(self):
        for route_id in ('gb', 'us1'):
            for action in ('prepare', 'stage', 'apply'):
                with self.subTest(route_id=route_id, action=action), self.assertRaises(c.SafetyError):
                    getattr(self.worker, action)(route_id, self.inputs(route_id)) if action == 'prepare' else getattr(self.worker, action)(route_id)
        self.assertFalse(self.api.calls)
        self.assertFalse(self.store.data)

    def test_retirement_of_other_two_does_not_block_selected_route(self):
        for route_id in ('gb', 'us1'):
            route = c.target(route_id)
            self.api.nodes.pop(route['node'])
            for hid in list(self.api.hosts):
                if route['node'] in self.api.hosts[hid]['nodes']:
                    self.api.hosts.pop(hid)
        self.stage()

    def test_no_fixed_shared_consumer_count_or_old_profile_id(self):
        self.init('pl')
        self.api.nodes['unconfigured'] = dict(uuid='unconfigured', configProfile=None)
        self.stage()
        self.assertEqual(self.store.get('before')['profile']['uuid'], c.p.GB_SOURCE[0])
        self.assertFalse(any(m == 'PATCH' and path == '/api/config-profiles/' for m, path, b in self.api.writes))

    def test_runtime_and_target_gates_prevent_all_writes(self):
        changes = [lambda v: v['runtime'].update(port_free=False),
                   lambda v: v['runtime'].update(namespace_verified=False),
                   lambda v: v['runtime'].update(timestamp=self.now + 1),
                   lambda v: v['runtime'].update(timestamp=self.now - 1801),
                   lambda v: v['runtime'].update(timestamp=True),
                   lambda v: v['runtime'].update(timestamp=float('nan')),
                   lambda v: v['runtime'].update(firewall_source='0.0.0.0/0'),
                   lambda v: v['target_checks'][0].update(trusted_tls=False),
                   lambda v: v['target_checks'][0].update(alpn='http/1.1'),
                   lambda v: v.update(expected_egress='127.0.0.1'),
                   lambda v: v.update(identity={'privateKey': SECRET})]
        for change in changes:
            value = self.inputs(); change(value)
            with self.assertRaises((c.SafetyError, ValueError)): self.worker.prepare(self.route_id, value)
        self.assertFalse(self.api.writes)
        self.assertFalse(self.store.data)

    def test_explicit_ssh_requires_failed_actual_direct_and_restricted_tunnel(self):
        value = self.inputs(mode='ssh')
        for part, key, replacement in [('direct_failure', 'authenticated_direct_attempted', False),
            ('direct_failure', 'passed', True), ('tunnel', 'target_address', c.target('at')['ip']),
            ('tunnel', 'listener_address', '0.0.0.0'), ('tunnel', 'host_key_pinned', False),
            ('tunnel', 'fixed_target_verified', False), ('tunnel', 'persistent_service_verified', False)]:
            changed = deepcopy(value); changed[part][key] = replacement
            with self.assertRaises(c.SafetyError): self.worker.prepare(self.route_id, changed)
        self.apply('ssh')
        exported = self.worker.export_backend(self.route_id)
        endpoint = exported['outbound']['settings']['vnext'][0]
        self.assertEqual((endpoint['address'], endpoint['port']), ('127.0.0.1', 26501))
        self.assertNotIn('flow', endpoint['users'][0])
        self.assertEqual(self.store.get('plan')['candidate']['inbounds'][-1]['listen'], '127.0.0.1')

    def test_resume_never_changes_mode_identity_or_inputs(self):
        first = self.worker.prepare(self.route_id, self.inputs())
        second = self.worker.prepare(self.route_id, self.inputs())
        self.assertEqual(first, second)
        with self.assertRaises(c.SafetyError): self.worker.prepare(self.route_id, self.inputs(mode='ssh'))
        self.assertFalse(self.api.writes)

    def test_source_profile_node_and_host_drift_block_prepare(self):
        for kind in ('profile', 'node', 'host'):
            self.init('at')
            if kind == 'profile': self.api.profiles['at-profile']['config']['dns'] = {'servers': ['1.1.1.1']}
            if kind == 'node': self.api.nodes[c.target('at')['node']]['configProfile']['activeInbounds'].pop()
            if kind == 'host': self.api.hosts[c.target('at')['host']]['remark'] = 'edited'
            with self.assertRaises(c.SafetyError): self.prepare()
            self.assertFalse(self.api.writes)

    def test_shared_host_refused_before_clone(self):
        self.fixture.hosts[c.target('at')['host']]['nodes'].append('other-node')
        with self.assertRaises(c.SafetyError): self.prepare()
        self.assertFalse(self.api.writes)

    def test_candidate_tamper_even_rehashed_record_is_rejected(self):
        self.prepare()
        self.store.data['plan']['candidate']['inbounds'][0]['port'] = 1
        self.store.data['operation']['plan_sha256'] = c.checksum(self.store.data['plan'])
        self.store.data['operation']['sha256'] = c.checksum(self.store.data['plan']['candidate'])
        with self.assertRaises(c.SafetyError): self.worker.export_candidate(self.route_id)

    def test_installed_empty_false_wrong_node_hash_version_stale_and_future_rejected(self):
        self.prepare()
        for delta in [dict(tests=[]), dict(timestamp=self.now + 1), dict(timestamp=self.now - 1801),
                      dict(node='other'), dict(sha256='wrong'), dict(ip='127.0.0.1'),
                      dict(tests=[dict(kind='installed-xray', passed=True, returncode=False, version='26.7.28')]),
                      dict(tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.3.27')])]:
            proof = self.proof(); proof.update(delta)
            with self.assertRaises(c.SafetyError): self.worker.accept_installed(self.route_id, proof)
            self.assertNotIn('installed_proof', self.store.get('operation'))
        with self.assertRaises(c.SafetyError): self.worker.stage(self.route_id)
        self.assertFalse(self.api.writes)

    def test_stage_inactive_only_preserves_nodes_hosts_and_original_profiles(self):
        old_nodes, old_hosts, old_profiles = deepcopy(self.api.nodes), deepcopy(self.api.hosts), deepcopy(self.api.profiles)
        sid = next(iter(self.api.squads)); self.api.squads[sid]['inbounds'].append(dict(uuid='concurrent'))
        record = self.stage()
        self.assertEqual(self.timer.starts, [self.route_id])
        self.assertEqual(self.api.nodes, old_nodes)
        self.assertEqual(self.api.hosts, old_hosts)
        for key, value in old_profiles.items(): self.assertEqual(self.api.profiles[key], value)
        self.assertIn('concurrent', c.ids(self.api.squads[sid]['inbounds']))
        self.assertEqual(c.ids(self.api.squads[record['objects']['squad']]['inbounds']), [record['backend']])
        user = self.api.users[record['objects']['user']]
        self.assertEqual(c.ids(user['activeInternalSquads']), [record['objects']['squad']])
        self.assertEqual(user['trafficLimitBytes'], 0)
        self.assertTrue(user['description'].endswith('not a customer'))
        for squad_id, grant in record['rights'].items():
            self.assertNotIn(record['backend'], grant['added'])

    def test_all_service_and_non_customer_legacy_rights_cloned_not_fixed_four(self):
        record = self.stage()
        original_sids = {s['uuid'] for s in self.store.get('before')['squads']
                         if set(c.ids(s['inbounds'])) & set(c.metadata(self.store.get('before')['profile']).values())}
        self.assertEqual(set(record['rights']), original_sids)
        self.assertGreater(len(record['rights']), 4)

    def test_uncertain_profile_and_squad_and_user_post_readback_never_duplicate(self):
        for path in ('/api/config-profiles/', '/api/internal-squads/', '/api/users/'):
            self.init('at'); self.prepare(); self.api.fail_after = ('POST', path)
            self.worker.stage(self.route_id)
            count = len(self.api.writes)
            self.worker.stage(self.route_id)
            self.assertEqual(len(self.api.writes), count)
            self.assertEqual(sum(m == 'POST' and x == path for m, x, _ in self.api.writes), 1)

    def test_uncertain_unapplied_post_never_repeated(self):
        for path in ('/api/config-profiles/', '/api/internal-squads/', '/api/users/'):
            self.init('at'); self.prepare(); self.api.fail_before = ('POST', path)
            with self.assertRaises((c.SafetyError, KeyError)): self.worker.stage(self.route_id)
            count = len(self.api.writes)
            with self.assertRaises((c.SafetyError, KeyError)): self.worker.stage(self.route_id)
            self.assertEqual(len(self.api.writes), count)
            # Inactive partial objects can be safely retained by rollback.
            self.worker.rollback(self.route_id)
            self.assertTrue(self.store.get('operation')['rolled_back'])

    def test_foreign_object_name_and_tag_collision_not_adopted(self):
        self.prepare()
        new = deepcopy(self.api.profiles['at-profile'])
        new.update(uuid='foreign', name=self.store.get('plan')['name'])
        self.api.profiles['foreign'] = new
        with self.assertRaises(c.SafetyError): self.worker.stage(self.route_id)
        self.assertFalse(self.api.writes)
        self.api.profiles['foreign']['name'] = 'not-ours'
        self.api.profiles['foreign']['inbounds'][0]['tag'] = self.store.get('plan')['candidate']['inbounds'][0]['tag']
        with self.assertRaises(c.SafetyError): self.worker.stage(self.route_id)
        self.assertFalse(self.api.writes)

    def test_apply_only_one_node_and_its_legacy_host_bindings_no_wire_changes(self):
        record = self.stage()
        old_nodes, old_hosts = deepcopy(self.api.nodes), deepcopy(self.api.hosts)
        self.worker.apply(self.route_id)
        node_id = c.target(self.route_id)['node']
        self.assertEqual(c.binding(self.api.nodes[node_id]), record['desired_binding'])
        for nid, original in old_nodes.items():
            if nid != node_id: self.assertEqual(self.api.nodes[nid], original)
        for hid, original in old_hosts.items():
            changed = deepcopy(self.api.hosts[hid]); changed['inbound'] = original['inbound']
            self.assertEqual(changed, original)
        self.assertTrue(all(m != 'DELETE' for m, p, b in self.api.writes))

    def test_active_bypass_maps_but_preexisting_mismatched_hosts_remain_unchanged(self):
        # Historical shape regression only. User-withdrawn GB cannot be deployed
        # unless ACTIVE_ROUTES is explicitly patched inside this offline test.
        with patch.object(c, 'ACTIVE_ROUTES', c.ACTIVE_ROUTES | {'gb'}):
            self.init('gb')
            route = c.target('gb')
            main = deepcopy(self.api.hosts[route['host']]); auto = deepcopy(self.api.hosts[c.p.AUTOS['gb']])
            bypass = deepcopy(self.api.hosts[c.p.GB_BYPASS])
            record = self.apply()
            self.assertEqual(self.api.hosts[route['host']], main)
            self.assertEqual(self.api.hosts[c.p.AUTOS['gb']], auto)
            self.assertNotEqual(self.api.hosts[c.p.GB_BYPASS]['inbound'], bypass['inbound'])
            self.assertEqual(set(record['host_intents']), {c.p.GB_BYPASS})

    def test_lost_applied_node_and_host_response_resume_from_readback(self):
        for path in ('/api/nodes/', '/api/hosts/'):
            self.init('at'); self.stage(); self.api.fail_after = ('PATCH', path)
            with self.assertRaises(TimeoutError): self.worker.apply(self.route_id)
            self.worker.apply(self.route_id)
            writes = [b for m, x, b in self.api.writes if m == 'PATCH' and x == path]
            self.assertEqual(len(writes), len({b['uuid'] for b in writes}))

    def test_unapplied_node_or_host_patch_is_never_blindly_retried(self):
        for path in ('/api/nodes/', '/api/hosts/'):
            self.init('at'); self.stage(); self.api.fail_before = ('PATCH', path)
            with self.assertRaises(TimeoutError): self.worker.apply(self.route_id)
            count = len(self.api.writes)
            with self.assertRaises(c.SafetyError): self.worker.apply(self.route_id)
            self.assertEqual(len(self.api.writes), count)
            self.worker.rollback(self.route_id)

    def test_apply_refuses_stale_proof_running_timer_and_leaked_backend_rights(self):
        for case in ('stale', 'running', 'leak'):
            self.init('at'); record = self.stage(); count = len(self.api.writes)
            if case == 'stale': self.now += 1801
            if case == 'running': self.timer.running.add(self.route_id)
            if case == 'leak': self.api.squads[next(iter(self.api.squads))]['inbounds'].append(dict(uuid=record['backend']))
            with self.assertRaises(c.SafetyError): self.worker.apply(self.route_id)
            self.assertEqual(len(self.api.writes), count)

    def test_new_original_rights_must_restage_before_activation(self):
        self.init('pl')
        record = self.stage()
        sid = 'new-customer'; old_iid = next(iter(c.metadata(self.store.get('before')['profile']).values()))
        self.api.squads[sid] = dict(uuid=sid, name='NEW_CUSTOMER', inbounds=[dict(uuid=old_iid)])
        with self.assertRaises(c.SafetyError): self.worker.apply(self.route_id)
        self.worker.stage(self.route_id)
        self.worker.apply(self.route_id)
        self.assertTrue(self.store.get('operation')['rights'][sid]['added'])

    def test_rollback_restores_owned_delta_preserves_concurrent_rights_and_objects(self):
        record = self.apply()
        originals = deepcopy(self.store.get('before'))
        sid = next(iter(record['rights'])); self.api.squads[sid]['inbounds'].append(dict(uuid='concurrent-after'))
        self.worker.rollback(self.route_id)
        self.assertEqual(c.binding(self.api.nodes[c.target(self.route_id)['node']]), c.binding(originals['node']))
        for old in originals['hosts']: self.assertEqual(self.api.hosts[old['uuid']], old)
        self.assertIn('concurrent-after', c.ids(self.api.squads[sid]['inbounds']))
        self.assertIn(record['objects']['profile'], self.api.profiles)
        self.assertIn(record['objects']['user'], self.api.users)
        self.assertIn(record['objects']['squad'], self.api.squads)
        count = len(self.api.writes); self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count)

    def test_two_shared_profile_routes_rollback_independently_in_either_order(self):
        for order in (('pl', 'cz'), ('cz', 'pl')):
            with self.subTest(order=order):
                self.init('pl')
                first = self.apply()
                second_store, second_timer = Store(), Timer()
                second_api = API(self.fixture, second_store, second_timer, 'cz')
                second_api.squads = self.api.squads  # Same actual panel relations.
                second_api.counter = 100
                second = c.Coordinator(second_api, second_store, second_timer, self.baseline, lambda: self.now,
                    identity_factory=lambda: dict(privateKey=base64.urlsafe_b64encode(bytes(range(2, 34))).decode().rstrip('='), shortIds=['abcddcba']))
                second.prepare('cz', self.inputs('cz'))
                route = c.target('cz'); state = second_store.get('operation')
                proof = dict(**{k: route[k] for k in ('id', 'ip', 'node')}, timestamp=self.now,
                    sha256=state['sha256'], tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.7.28')])
                second.accept_installed('cz', proof)
                b = second_store.get('before')
                legacy_proof = deepcopy(proof)
                legacy_proof.update(source_sha256=c.checksum(b['profile']['config']), tests=[dict(
                    kind='legacy', test_id=tag + '-external', tag=tag, namespace='external-client',
                    client='xray-26.7.28', wire_sha256=c.checksum(dict(tag=tag)), passed=True,
                    authenticated=True, http_code=204, returncodes=[0, 0], exit_ip=route['ip'])
                    for tag, iid in c.metadata(b['profile']).items() if iid in c.binding(b['node'])['inbounds']])
                second.accept_baseline('cz', legacy_proof); second.stage('cz'); second.apply('cz')
                workers, stores = {'pl': self.worker, 'cz': second}, {'pl': self.store, 'cz': second_store}
                for index, route_id in enumerate(order):
                    workers[route_id].rollback(route_id)
                    if index == 0:
                        other = order[1]; active = stores[other].get('operation')
                        self.assertEqual(c.binding(self.api.nodes[c.target(other)['node']]), active['desired_binding'])
                        for sid, grant in active['rights'].items():
                            self.assertTrue(set(grant['added']) <= set(c.ids(self.api.squads[sid]['inbounds'])))
                for route_id in ('pl', 'cz'):
                    before = stores[route_id].get('before')
                    self.assertEqual(c.binding(self.api.nodes[c.target(route_id)['node']]), c.binding(before['node']))

    def test_rollback_preflights_host_profile_grants_binding_before_any_write(self):
        for kind in ('host', 'profile', 'grant', 'binding', 'legacy-rights'):
            self.init('at'); record = self.apply()
            if kind == 'host': self.api.hosts[c.target('at')['host']]['port'] = 12345
            if kind == 'profile': self.api.profiles[record['objects']['profile']]['config']['stats'] = {}
            if kind == 'grant':
                self.api.squads['foreign'] = dict(uuid='foreign', name='FOREIGN', inbounds=[dict(uuid=next(iter(record['rights'].values()))['added'][0])])
            if kind == 'binding': self.api.nodes[c.target('at')['node']]['configProfile']['activeInbounds'].append(dict(uuid='foreign'))
            if kind == 'legacy-rights':
                sid = next(iter(record['rights'])); self.api.squads[sid]['inbounds'] = [dict(uuid=v) for v in record['rights'][sid]['added']]
            count = len(self.api.writes)
            with self.assertRaises(c.SafetyError): self.worker.rollback(self.route_id)
            self.assertEqual(len(self.api.writes), count)

    def test_new_live_entry_using_service_identity_prevents_destructive_backend_rollback(self):
        record = self.apply()
        self.api.profiles['entry-profile']['config']['outbounds'].append(dict(protocol='vless', settings=dict(
            vnext=[dict(users=[dict(id=record['service_uuid'])])])))
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_failed_node_restore_never_removes_rights_or_claims_success(self):
        record = self.apply(); self.api.ignore = ('PATCH', '/api/nodes/')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count + 1)
        self.assertNotIn('rolled_back', self.store.get('operation'))
        for sid, grant in record['rights'].items():
            self.assertTrue(set(grant['added']) <= set(c.ids(self.api.squads[sid]['inbounds'])))

    def test_rollback_lost_response_resumes_then_foreign_reactivation_is_refused(self):
        record = self.apply(); self.api.fail_after = ('PATCH', '/api/nodes/')
        with self.assertRaises(TimeoutError): self.worker.rollback(self.route_id)
        self.worker.rollback(self.route_id)
        wanted = record['desired_binding']
        self.api.nodes[c.target(self.route_id)['node']]['configProfile'] = dict(activeConfigProfileUuid=wanted['profile'], activeInbounds=[dict(uuid=i) for i in wanted['inbounds']])
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count)

    def test_closed_rollback_lifecycle_cannot_stage_apply_or_prepare_again(self):
        self.apply(); self.worker.rollback(self.route_id)
        for action in ('stage', 'apply', 'prepare'):
            with self.assertRaises(c.SafetyError):
                getattr(self.worker, action)(self.route_id, self.inputs()) if action == 'prepare' else getattr(self.worker, action)(self.route_id)

    def test_finish_requires_authenticated_backend_and_all_cached_legacy_egress(self):
        self.apply()
        with self.assertRaises(c.SafetyError): self.worker.finish(self.route_id)
        changes = [lambda p: p.update(tests=[]), lambda p: p['tests'].pop(),
            lambda p: p['tests'][0].update(namespace='laptop'),
            lambda p: p['tests'][0].update(exit_ip='1.1.1.1'),
            lambda p: p['tests'][0].update(authenticated=False),
            lambda p: p['tests'][1].update(wire_sha256='f' * 64),
            lambda p: p.update(timestamp=self.now + 1), lambda p: p.update(sha256='wrong')]
        for change in changes:
            proof = self.proof('backend'); change(proof)
            with self.assertRaises(c.SafetyError): self.worker.accept_backend(self.route_id, proof)
        self.assertFalse(self.timer.cancels)
        self.worker.accept_backend(self.route_id, self.proof('backend'))
        result = self.worker.finish(self.route_id)
        self.assertTrue(result['backend_finished'])
        self.assertTrue(result['rollback_timer_and_service_inactive'])
        self.assertFalse(result['frontend_published'])
        self.assertEqual(self.timer.cancels, [self.route_id])
        count = len(self.api.writes)
        self.assertTrue(self.worker.rollback(self.route_id)['rollback_skipped_finished'])
        self.assertEqual(len(self.api.writes), count)
        self.worker.finish(self.route_id)

    def test_mgmt_and_actual_egress_can_differ(self):
        self.init('gbpower'); self.apply()
        proof = self.proof('backend')
        self.assertNotEqual(proof['tests'][0]['exit_ip'], c.target('gbpower')['ip'])
        self.worker.accept_backend(self.route_id, proof)
        self.worker.finish(self.route_id)

    def test_service_tags_match_installed_api_max16_including_gbpower(self):
        self.assertEqual(len('C1406_GBPOWER_SVC'), 17)
        for route_id in c.ACTIVE_ROUTES:
            value = c.service_tag(route_id)
            self.assertRegex(value, r'^[A-Z0-9_]{1,16}$')
            self.assertLessEqual(len(value), 16)
        self.init('gbpower'); record = self.stage()
        self.assertEqual(record['intents']['user']['tag'], 'C146_GBPOWER_SVC')
        self.assertEqual(len(record['intents']['user']['tag']), 16)
        self.assertEqual(self.api.users[record['objects']['user']]['tag'], record['intents']['user']['tag'])

    def test_preexisting_failures_recorded_truthfully_do_not_block_new_working_backend(self):
        self.prepare()
        baseline = self.proof('baseline')
        for row in baseline['tests']:
            row.update(passed=False, authenticated=False, http_code=0, exit_ip=None, returncodes=[28, 28])
        self.worker.accept_baseline(self.route_id, baseline)
        self.worker.stage(self.route_id); self.worker.apply(self.route_id)
        post = self.proof('backend')
        self.worker.accept_backend(self.route_id, post)
        result = self.worker.finish(self.route_id)
        self.assertEqual(result['preexisting_legacy_failures_remaining'], len(baseline['tests']))
        self.assertEqual(result['legacy_cases_passed'], 0)
        self.assertTrue(result['backend_finished'])

    def test_failed_baseline_can_improve_but_partial_success_cannot_regress(self):
        self.prepare()
        baseline = self.proof('baseline')
        baseline['tests'][0].update(passed=False, authenticated=True, http_code=204, exit_ip=None, returncodes=[0, 28])
        self.worker.accept_baseline(self.route_id, baseline)
        self.worker.stage(self.route_id); self.worker.apply(self.route_id)
        post = self.proof('backend')
        post['tests'][1].update(authenticated=False, http_code=0, returncodes=[28, 28])
        with self.assertRaises(c.SafetyError): self.worker.accept_backend(self.route_id, post)
        post = self.proof('backend')
        post['tests'][1].update(passed=True, exit_ip=self.inputs()['expected_egress'], returncodes=[0, 0])
        self.worker.accept_backend(self.route_id, post)
        result = self.worker.finish(self.route_id)
        self.assertEqual(result['preexisting_legacy_failures_remaining'], 0)

    def test_baseline_proof_required_before_apply_and_cannot_be_replaced_after_it(self):
        self.stage()
        self.store.data['operation'].pop('baseline_proof')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.apply(self.route_id)
        self.assertEqual(len(self.api.writes), count)
        self.worker.accept_baseline(self.route_id, self.proof('baseline'))
        self.worker.apply(self.route_id)
        with self.assertRaises(c.SafetyError): self.worker.accept_baseline(self.route_id, self.proof('baseline'))

    def test_baseline_cannot_hide_success_or_omit_active_tag_or_use_wrong_source_hash(self):
        self.prepare()
        changes = [lambda p: p['tests'][0].update(passed=False),
                   lambda p: p.update(source_sha256='f' * 64), lambda p: p['tests'].pop(),
                   lambda p: p['tests'][0].update(wire_sha256='invalid'),
                   lambda p: p['tests'][0].update(returncodes=[0, False]),
                   lambda p: p['tests'][0].update(test_id=''),
                   lambda p: p['tests'].append(deepcopy(p['tests'][0]))]
        for change in changes:
            proof = self.proof('baseline'); change(proof)
            with self.assertRaises(c.SafetyError): self.worker.accept_baseline(self.route_id, proof)
            self.assertNotIn('baseline_proof', self.store.get('operation'))

    def test_preexisting_legacy_failure_never_weakens_new_backend_gate(self):
        self.prepare()
        baseline = self.proof('baseline')
        for row in baseline['tests']:
            row.update(passed=False, authenticated=False, http_code=0, exit_ip=None, returncodes=[28, 28])
        self.worker.accept_baseline(self.route_id, baseline)
        self.worker.stage(self.route_id); self.worker.apply(self.route_id)
        for change in (dict(authenticated=False), dict(returncode=28), dict(http_code=0), dict(exit_ip=None)):
            proof = self.proof('backend'); proof['tests'][0].update(change)
            with self.assertRaises(c.SafetyError): self.worker.accept_backend(self.route_id, proof)
        self.assertNotIn('backend_proof', self.store.get('operation'))
        self.assertFalse(self.timer.cancels)

    def test_empty_noop_client_exports_are_private_deepcopies_and_no_console_secret(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.stage()
            config = self.worker.export_candidate(self.route_id); config['inbounds'].clear()
            with patch.object(c.p, 'public_key', return_value='test-public-key'):
                backend = self.worker.export_backend(self.route_id)
            summary = self.worker.status(self.route_id)
        self.assertTrue(self.worker.export_candidate(self.route_id)['inbounds'])
        self.assertNotIn(SECRET, json.dumps(summary))
        self.assertNotIn('privateKey', json.dumps(backend))
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(err.getvalue(), '')

    def test_cli_exports_reject_terminal_or_missing_flag_before_api(self):
        for args in (['export-candidate', '--id', 'at'], ['export-backend', '--id', 'at', '--secret-stdout']):
            with patch.object(c.sys.stdout, 'isatty', return_value=True), patch.object(c, 'RootStore') as store:
                with self.assertRaises(c.SafetyError): c.main(args)
                store.assert_not_called()


class SystemdTests(unittest.TestCase):
    def test_both_service_and_timer_checked_before_create_and_after_cancel(self):
        calls, units = [], {}
        def run(args, **kwargs):
            calls.append(args)
            self.assertNotIn('shell', kwargs)
            if args[0] == 'systemd-run':
                name = next(a.split('=', 1)[1] for a in args if a.startswith('--unit='))
                units[name + '.timer'] = 'LoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n'
                units[name + '.service'] = 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n'
                return SimpleNamespace(returncode=0, stdout='')
            if args[1] == 'stop':
                units.clear()
                return SimpleNamespace(returncode=5, stdout='')  # GC race isn't success without show.
            value = units.get(args[2], 'LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
            return SimpleNamespace(returncode=0 if args[2] in units else 1, stdout=value)
        timer = c.SystemdTimer(run)
        timer.start('at'); timer.cancel('at')
        command = next(v for v in calls if v[0] == 'systemd-run')
        self.assertIn('--on-active=1500s', command)
        self.assertEqual(command[-3:], ['rollback', '--id', 'at'])
        self.assertTrue(calls[-1][2].endswith('.service'))
        self.assertTrue(calls[-2][2].endswith('.timer'))

    def test_unknown_nonzero_show_is_not_treated_as_safe(self):
        timer = c.SystemdTimer(lambda *a, **k: SimpleNamespace(returncode=3, stdout='LoadState=loaded\nActiveState=inactive\nSubState=dead\n'))
        for action in (timer.start, timer.armed, timer.cancel):
            with self.assertRaises(c.SafetyError): action('at')

    def test_running_service_blocks_armed_and_cancel_readback(self):
        def run(args, **kwargs):
            return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n')
        timer = c.SystemdTimer(run)
        with self.assertRaises(c.SafetyError): timer.armed('at')
        with self.assertRaises(c.SafetyError): timer.cancel('at')


class StoreTests(unittest.TestCase):
    def test_only_mutable_operation_journal_can_be_replaced(self):
        for name in ('before', 'plan', '../operation', 'x'):
            with self.assertRaises(c.SafetyError): c.RootStore('at').save(name, {})

    def test_plan_and_operation_hashes_are_checked(self):
        f = CoordinatorTests(); f.setUp(); f.prepare()
        f.store.data['operation']['snapshot_sha256'] = 'wrong'
        with self.assertRaises(c.SafetyError): f.worker.status('at')


if __name__ == '__main__':
    unittest.main()
