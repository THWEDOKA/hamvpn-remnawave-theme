"""Offline API/state/timer simulations; never contact panel or execute services."""

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import coordinator as c
import preflight as p
from test_route_model import fixture, identities


NOW = 1800000000.0


def baseline():
    configs = {node['profile']: dict(uuid=node['profile'], name='Original-' + node['id'], config=fixture(),
               inbounds=[dict(tag='old-' + str(i), uuid=node['inbound'] if i == 0 else node['id'] + '-in-' + str(i))
                         for i in range(4)]) for node in p.NODES}
    configs['entry-profile'] = dict(uuid='entry-profile', name='Original-entry', config=fixture(),
                                   inbounds=[dict(tag='old-' + str(i), uuid='entry-in-' + str(i)) for i in range(4)])
    nodes = [dict(uuid=p.ENTRY_ID, address=p.ENTRY, name='Entry', port=2222, isConnected=True, isDisabled=False,
                  configProfile=dict(activeConfigProfileUuid='entry-profile',
                                     activeInbounds=deepcopy(configs['entry-profile']['inbounds'])))]
    for node in p.NODES:
        nodes.append(dict(uuid=node['node'], address=node['ip'], name='Exit-' + node['id'], port=2222,
                          isConnected=True, isDisabled=False, configProfile=dict(activeConfigProfileUuid=node['profile'],
                          activeInbounds=deepcopy(configs[node['profile']]['inbounds'][:2]))))
    # KZ shared consumer must remain exactly as it was.
    other = deepcopy(nodes[1]); other.update(uuid='other-node', address='192.0.2.10', name='Other')
    nodes.append(other)
    hosts = [dict(uuid=hid, nodes=[node['node']], inbound=dict(configProfileUuid=node['profile'],
                 configProfileInboundUuid=node['inbound']), address=node['ip'], sni=node['sni'], port=443,
                 fingerprint='firefox', isHidden=bool(index), remark='Preserve remark', isDisabled=False)
             for node in p.NODES for index, hid in enumerate(node['hosts'])]
    squads = [dict(uuid='base', name='BASE', inbounds=[dict(uuid=node['inbound']) for node in p.NODES]),
              dict(uuid='one-extra', name='EXTRA', inbounds=[dict(uuid='kz2-in-1'), dict(uuid='unrelated')]),
              dict(uuid='other-group', name='OTHER', inbounds=[dict(uuid='unrelated')])]
    return dict(nodes=nodes, profiles=configs, hosts=hosts, squads=squads)


class MemoryStore:
    def __init__(self):
        self.snapshot = baseline()
        self.digest = c.checksum(self.snapshot)
        self.values = {}

    def before(self):
        c.require(c.checksum(self.snapshot) == self.digest, 'Preflight snapshot digest mismatch')
        return deepcopy(self.snapshot), self.digest

    def exists(self, name): return name in self.values
    def read(self, name): return deepcopy(self.values[name])
    def save(self, name, value): self.values[name] = deepcopy(value)


class Timer:
    def __init__(self):
        self.active = set()
        self.started = []
        self.running = set()

    def start(self, route_id):
        if route_id in self.active:
            raise AssertionError('duplicate timer')
        self.active.add(route_id)
        self.started.append(route_id)

    def armed(self, route_id):
        c.require(route_id in self.active and route_id not in self.running, 'Rollback is not waiting')


class API:
    def __init__(self, snapshot):
        self.nodes = {node['uuid']: deepcopy(node) for node in snapshot['nodes']}
        self.profiles = deepcopy(snapshot['profiles'])
        self.hosts = {host['uuid']: deepcopy(host) for host in snapshot['hosts']}
        self.squads = {squad['uuid']: deepcopy(squad) for squad in snapshot['squads']}
        self.users = {}
        self.writes = []
        self.counter = 0
        self.fail_after = None
        self.fail_before = None
        self.ignore = None

    def __call__(self, method, path, body=None):
        if method != 'GET':
            self.writes.append((method, path, deepcopy(body)))
            if self.fail_before == (method, path):
                self.fail_before = None
                raise RuntimeError('Simulated timeout before applying')
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
            return { {'config-profiles': 'configProfiles', 'internal-squads': 'internalSquads'}[resource]: values} \
                if resource in ('config-profiles', 'internal-squads') else values
        if method == 'POST':
            self.counter += 1
            value = deepcopy(body)
            value.setdefault('uuid', 'new-' + resource + '-' + str(self.counter))
            if resource == 'config-profiles':
                value['inbounds'] = [dict(tag=item['tag'], uuid=value['uuid'] + '-in-' + str(i))
                                     for i, item in enumerate(value['config']['inbounds'])]
            if resource == 'internal-squads':
                value['inbounds'] = [dict(uuid=item) for item in value['inbounds']]
            if resource == 'users':
                value.update(status='ACTIVE', vlessUuid='00000000-0000-4000-8000-' + str(self.counter).zfill(12))
                value['activeInternalSquads'] = [dict(uuid=item) for item in value['activeInternalSquads']]
            bucket[value['uuid']] = value
            result = value
        elif method == 'PATCH':
            value = deepcopy(body)
            if resource == 'nodes':
                value['configProfile']['activeInbounds'] = [dict(uuid=item) for item in value['configProfile']['activeInbounds']]
            if resource == 'internal-squads':
                value['inbounds'] = [dict(uuid=item) for item in value['inbounds']]
            bucket[value['uuid']].update(value)
            result = bucket[value['uuid']]
        else:
            raise AssertionError('Unexpected mutation')
        if self.fail_after == (method, path):
            self.fail_after = None
            raise RuntimeError('Simulated response loss')
        return deepcopy(result)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.api = API(self.store.snapshot)
        self.timer = Timer()
        self.now = NOW
        self.worker = c.Coordinator(self.api, self.store, self.timer, lambda: self.now)

    def proof(self, route_id='kz2'):
        record = self.store.read('exit-' + route_id)
        node = c.target(route_id)
        return dict(id=route_id, node=node['node'], ip=node['ip'], sha256=record['sha256'], timestamp=self.now,
                    tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.7.28')])

    def prepared(self, route_id='kz2'):
        self.worker.prepare(route_id)
        self.worker.accept_test(route_id, self.proof(route_id))

    def staged(self, route_id='kz2'):
        self.prepared(route_id)
        self.worker.stage(route_id)
        return self.store.read('exit-' + route_id)

    def activated(self, route_id='kz2'):
        record = self.staged(route_id)
        self.worker.arm(route_id)
        self.worker.activate_exit(route_id)
        return self.store.read('exit-' + route_id)

    def test_prepare_is_non_applying_and_both_candidates_are_distinct_clones(self):
        for route_id in ('kz2', 'de245'):
            result = self.worker.prepare(route_id)
            record = self.store.read('exit-' + route_id)
            self.assertEqual(record['name'], 'HAM-CLOUD140-' + route_id.upper() + '-EXIT')
            self.assertFalse(result['staged'])
            self.assertTrue(all(item['tag'].startswith('cloud140-' + route_id + '-legacy-')
                                for item in record['candidate']['inbounds'][:-1]))
        self.assertEqual(self.api.writes, [])

    def test_snapshot_tamper_refused_before_any_write(self):
        self.store.snapshot['profiles']['entry-profile']['config']['stats']['changed'] = True
        with self.assertRaises(c.SafetyError): self.worker.prepare('kz2')
        self.assertFalse(self.api.writes)

    def test_fresh_source_profile_drift_refused(self):
        self.api.profiles[p.NODES[1]['profile']]['config']['stats']['changed'] = True
        with self.assertRaises(c.SafetyError): self.worker.prepare('kz2')
        self.assertFalse(self.api.writes)

    def test_fresh_entry_consumer_drift_refused(self):
        self.api.nodes['other-node']['configProfile'] = deepcopy(self.api.nodes[p.ENTRY_ID]['configProfile'])
        with self.assertRaises(c.SafetyError): self.worker.prepare('kz2')

    def test_prepare_resume_does_not_replace_candidate(self):
        first = self.worker.prepare('kz2')
        self.assertEqual(first, self.worker.prepare('kz2'))
        self.assertFalse(self.api.writes)

    def test_candidate_tamper_refused_even_with_recomputed_hash(self):
        self.worker.prepare('kz2')
        record = self.store.values['exit-kz2']
        record['candidate']['inbounds'][0]['port'] = 1234
        record['sha256'] = c.checksum(record['candidate'])
        with self.assertRaises(c.SafetyError): self.worker.export('kz2')

    def test_proof_rejects_empty_failed_future_stale_wrong_target_and_hash(self):
        self.worker.prepare('kz2')
        for change in (dict(tests=[]), dict(timestamp=self.now + 1), dict(timestamp=self.now - 1801),
                       dict(timestamp=float('nan')), dict(timestamp=True), dict(node='other'),
                       dict(ip='192.0.2.1'), dict(sha256='wrong'), dict(id='de245'),
                       dict(tests=[dict(kind='installed-xray', passed=True, returncode=False, version='26.7.28')]),
                       dict(tests=[dict(kind='installed-xray', passed=False, returncode=1, version='26.7.28')])):
            proof = self.proof(); proof.update(change)
            with self.assertRaises(c.SafetyError): self.worker.accept_test('kz2', proof)
        self.assertFalse(self.api.writes)

    def test_stage_cannot_run_without_installed_proof(self):
        self.worker.prepare('kz2')
        with self.assertRaises(c.SafetyError): self.worker.stage('kz2')
        self.assertFalse(self.api.writes)

    def test_new_failed_test_revokes_old_success(self):
        self.prepared()
        proof = self.proof(); proof['tests'][0]['returncode'] = 1
        with self.assertRaises(c.SafetyError): self.worker.accept_test('kz2', proof)
        with self.assertRaises(c.SafetyError): self.worker.stage('kz2')
        self.assertNotIn('installed_test', self.store.read('exit-kz2'))

    def test_stage_keeps_originals_nodes_hosts_and_exactly_unions_rights(self):
        old_nodes, old_hosts, old_profiles = deepcopy(self.api.nodes), deepcopy(self.api.hosts), deepcopy(self.api.profiles)
        self.api.squads['base']['inbounds'].append(dict(uuid='concurrent'))
        record = self.staged()
        self.assertEqual(self.api.nodes, old_nodes)
        self.assertEqual(self.api.hosts, old_hosts)
        self.assertTrue(all(self.api.profiles[key] == value for key, value in old_profiles.items()))
        self.assertIn('concurrent', c.ids(self.api.squads['base']['inbounds']))
        self.assertEqual(set(c.ids(self.api.squads['base']['inbounds'])),
                         set(record['rights']['base']['before'] + record['rights']['base']['added']))
        self.assertEqual(c.ids(self.api.squads[record['objects']['squad']]['inbounds']), [record['backend']])
        self.assertEqual(len(record['rights']['base']['added']), 1)
        self.assertEqual(len(record['rights']['one-extra']['added']), 1)

    def test_private_users_are_per_exit_infrastructure_only_for_ten_years(self):
        kz, de = self.staged('kz2'), self.staged('de245')
        self.assertNotEqual(kz['service_uuid'], de['service_uuid'])
        for record in (kz, de):
            user = self.api.users[record['objects']['user']]
            self.assertEqual(c.ids(user['activeInternalSquads']), [record['objects']['squad']])
            self.assertEqual(user['trafficLimitBytes'], 0)
            self.assertIn('not a customer', user['description'])
            self.assertAlmostEqual(datetime.fromisoformat(user['expireAt']).timestamp() - NOW, 3650 * 86400)
            self.assertEqual(c.ids(self.api.squads[record['objects']['squad']]['inbounds']), [record['backend']])

    def test_profile_response_loss_is_reconciled_without_duplicate_post(self):
        self.prepared()
        self.api.fail_after = ('POST', '/api/config-profiles/')
        with self.assertRaises(RuntimeError): self.worker.stage('kz2')
        self.worker.stage('kz2')
        self.assertEqual(sum(method == 'POST' and path == '/api/config-profiles/' for method, path, _ in self.api.writes), 1)

    def test_unapplied_profile_timeout_never_reposts_blindly(self):
        self.prepared()
        self.api.fail_before = ('POST', '/api/config-profiles/')
        with self.assertRaises(RuntimeError): self.worker.stage('kz2')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.stage('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_existing_name_without_intent_not_adopted(self):
        self.prepared()
        profile = deepcopy(self.api.profiles[p.NODES[0]['profile']])
        profile.update(uuid='unowned', name='HAM-CLOUD140-KZ2-EXIT')
        self.api.profiles['unowned'] = profile
        with self.assertRaises(c.SafetyError): self.worker.stage('kz2')
        self.assertFalse(self.api.writes)

    def test_user_response_loss_reconciles_uuid_without_duplicate_user(self):
        self.prepared()
        self.api.fail_after = ('POST', '/api/users/')
        with self.assertRaises(RuntimeError): self.worker.stage('kz2')
        self.worker.stage('kz2')
        self.assertEqual(len(self.api.users), 1)
        self.assertEqual(sum(method == 'POST' and path == '/api/users/' for method, path, _ in self.api.writes), 1)

    def test_stage_resume_is_idempotent(self):
        self.staged()
        count = len(self.api.writes)
        self.worker.stage('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_arm_and_activate_only_selected_node_binding(self):
        record = self.staged()
        old_nodes, old_hosts = deepcopy(self.api.nodes), deepcopy(self.api.hosts)
        self.worker.arm('kz2')
        self.assertEqual(self.timer.started, ['kz2'])
        self.worker.activate_exit('kz2')
        selected = p.NODES[0]['node']
        self.assertEqual(c.binding(self.api.nodes[selected]), record['desired_binding'])
        self.assertEqual(len(record['desired_binding']['inbounds']), 3)
        for key in old_nodes:
            if key != selected: self.assertEqual(self.api.nodes[key], old_nodes[key])
        self.assertEqual(self.api.hosts, old_hosts)
        self.assertFalse(any(method == 'PATCH' and path == '/api/config-profiles/' for method, path, _ in self.api.writes))

    def test_activate_requires_live_guard_and_fresh_proof(self):
        self.staged()
        with self.assertRaises(c.SafetyError): self.worker.activate_exit('kz2')
        self.worker.arm('kz2')
        self.timer.running.add('kz2')
        with self.assertRaises(c.SafetyError): self.worker.activate_exit('kz2')
        self.timer.running.clear()
        self.now += 1801
        with self.assertRaises(c.SafetyError): self.worker.activate_exit('kz2')
        self.assertFalse(any(method == 'PATCH' and path == '/api/nodes/' for method, path, _ in self.api.writes))

    def test_activation_response_loss_resumes_only_after_readback(self):
        self.staged(); self.worker.arm('kz2')
        self.api.fail_after = ('PATCH', '/api/nodes/')
        with self.assertRaises(RuntimeError): self.worker.activate_exit('kz2')
        self.worker.activate_exit('kz2')
        self.assertEqual(sum(method == 'PATCH' and path == '/api/nodes/' for method, path, _ in self.api.writes), 1)

    def test_activation_timeout_without_apply_requires_reconcile_not_repatch(self):
        self.staged(); self.worker.arm('kz2')
        self.api.fail_before = ('PATCH', '/api/nodes/')
        with self.assertRaises(RuntimeError): self.worker.activate_exit('kz2')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.activate_exit('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_backend_public_grant_blocks_activate(self):
        record = self.staged(); self.worker.arm('kz2')
        self.api.squads['base']['inbounds'].append(dict(uuid=record['backend']))
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.activate_exit('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_fresh_original_rights_require_restage_then_are_precisely_added(self):
        record = self.staged()
        self.api.squads['base']['inbounds'].append(dict(uuid='kz2-in-1'))
        with self.assertRaises(c.SafetyError): self.worker.arm('kz2')
        self.worker.stage('kz2')
        self.worker.arm('kz2')
        self.assertEqual(len(self.store.read('exit-kz2')['rights']['base']['added']), 2)

    def test_rollback_restores_only_selected_binding_and_own_rights(self):
        kz = self.activated('kz2')
        de = self.activated('de245')
        self.api.squads['base']['inbounds'].append(dict(uuid='concurrent-after-stage'))
        result = self.worker.rollback('kz2')
        self.assertTrue(result['original_binding_restored'])
        self.assertEqual(c.binding(self.api.nodes[p.NODES[0]['node']]), c.binding(self.store.snapshot['nodes'][1]))
        self.assertEqual(c.binding(self.api.nodes[p.NODES[1]['node']]), de['desired_binding'])
        actual = c.ids(self.api.squads['base']['inbounds'])
        self.assertIn('concurrent-after-stage', actual)
        self.assertTrue(set(de['rights']['base']['added']) <= set(actual))
        self.assertFalse(set(kz['rights']['base']['added']) & set(actual))
        self.assertIn(kz['objects']['profile'], self.api.profiles)
        self.assertIn(kz['objects']['user'], self.api.users)

    def test_both_exits_rollback_in_either_order(self):
        for order in (('kz2', 'de245'), ('de245', 'kz2')):
            with self.subTest(order=order):
                self.setUp(); self.activated('kz2'); self.activated('de245')
                for route_id in order:
                    self.worker.rollback(route_id)
                for original in self.store.snapshot['nodes']:
                    self.assertEqual(c.binding(self.api.nodes[original['uuid']]), c.binding(original))
                for original in self.store.snapshot['squads']:
                    self.assertEqual(self.api.squads[original['uuid']], original)

    def test_rolled_back_marker_does_not_allow_later_foreign_reactivation_to_be_undone(self):
        record = self.activated(); self.worker.rollback('kz2')
        wanted = record['desired_binding']
        self.api.nodes[p.NODES[0]['node']]['configProfile'] = dict(activeConfigProfileUuid=wanted['profile'],
                                                                 activeInbounds=[dict(uuid=item) for item in wanted['inbounds']])
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_preflights_all_rights_before_any_mutation(self):
        self.activated()
        self.api.squads['one-extra']['inbounds'] = [dict(uuid='removed-original')]
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_refuses_profile_drift_host_cutover_and_unowned_grants(self):
        for mutation in ('profile', 'host', 'grant', 'binding', 'entry'):
            with self.subTest(mutation=mutation):
                self.setUp(); record = self.activated()
                if mutation == 'profile': self.api.profiles[record['objects']['profile']]['config']['stats']['changed'] = True
                if mutation == 'host': self.api.hosts[p.NODES[0]['hosts'][0]]['address'] = p.ENTRY
                if mutation == 'grant': self.api.squads['other-group']['inbounds'].append(dict(uuid=record['rights']['base']['added'][0]))
                if mutation == 'binding': self.api.nodes[p.NODES[0]['node']]['configProfile']['activeInbounds'].append(dict(uuid='foreign'))
                if mutation == 'entry': self.api.profiles['entry-profile']['config']['stats']['changed'] = True
                count = len(self.api.writes)
                with self.assertRaises(c.SafetyError): self.worker.rollback('kz2')
                self.assertEqual(len(self.api.writes), count)

    def test_rollback_does_not_claim_success_or_remove_rights_when_binding_patch_ignored(self):
        record = self.activated()
        self.api.ignore = ('PATCH', '/api/nodes/')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback('kz2')
        self.assertNotIn('rolled_back', self.store.read('exit-kz2'))
        self.assertEqual(len(self.api.writes), count + 1)
        self.assertTrue(set(record['rights']['base']['added']) <= set(c.ids(self.api.squads['base']['inbounds'])))

    def test_rollback_response_loss_resumes_safely(self):
        self.activated()
        self.api.fail_after = ('PATCH', '/api/nodes/')
        with self.assertRaises(RuntimeError): self.worker.rollback('kz2')
        self.assertTrue(self.worker.rollback('kz2')['original_binding_restored'])
        count = len(self.api.writes)
        self.worker.rollback('kz2')
        self.assertEqual(len(self.api.writes), count)

    def test_rolled_back_operation_cannot_reactivate_or_restage(self):
        self.activated(); self.worker.rollback('kz2')
        for action in (self.worker.activate_exit, self.worker.stage, self.worker.arm, self.worker.prepare):
            with self.assertRaises(c.SafetyError): action('kz2')

    def test_explicit_exports_are_deep_copies_and_builders_never_print_secrets(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.staged('kz2'); self.staged('de245')
            self.store.save('entry-identities', identities())
            self.worker.prepare_entry()
            config = self.worker.export('kz2'); config['inbounds'].clear()
            entry = self.worker.export_entry(); entry['inbounds'].clear()
        self.assertTrue(self.worker.export('kz2')['inbounds'])
        self.assertEqual(len(self.worker.export_entry()['inbounds']), 6)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), '')

    def test_entry_candidate_uses_two_private_service_users_without_applying(self):
        records = [self.staged(route_id) for route_id in ('kz2', 'de245')]
        self.store.save('entry-identities', identities())
        count = len(self.api.writes)
        result = self.worker.prepare_entry()
        self.assertTrue(result['entry_not_applied'])
        config = self.worker.export_entry()
        self.assertEqual(config['inbounds'][:4], self.store.snapshot['profiles']['entry-profile']['config']['inbounds'])
        self.assertEqual([out['settings']['vnext'][0]['users'][0]['id'] for out in config['outbounds'][-2:]],
                         [record['service_uuid'] for record in records])
        self.assertEqual(len(self.api.writes), count)
        self.assertEqual(result, self.worker.prepare_entry())


class TimerTests(unittest.TestCase):
    def test_missing_unit_explicit_show_result_is_allowed_only_before_creation(self):
        runner = lambda *args, **kwargs: SimpleNamespace(returncode=1,
            stdout='LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
        timer = c.SystemdTimer(runner)
        self.assertEqual(timer.state('fixture', allow_missing=True)['LoadState'], 'not-found')
        with self.assertRaises(c.SafetyError): timer.armed('kz2')

    def test_arm_uses_exact_scoped_command_and_no_shell(self):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            self.assertNotIn('shell', kwargs)
            if args[0] == 'systemd-run': return SimpleNamespace(returncode=0, stdout='')
            created = any(command[0][0] == 'systemd-run' for command in calls)
            if not created: return SimpleNamespace(returncode=0, stdout='LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
            timer = args[2].endswith('.timer')
            return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=' + ('active' if timer else 'inactive')
                                   + '\nSubState=' + ('waiting' if timer else 'dead') + '\nResult=success\n')
        c.SystemdTimer(run).start('de245')
        command = next(args for args, kwargs in calls if args[0] == 'systemd-run')
        self.assertIn('--unit=ham-cloud140-kz245-de245-rollback', command)
        self.assertEqual(command[-3:], ['rollback', '--id', 'de245'])

    def test_unknown_nonzero_is_not_inactive_or_armed(self):
        runner = lambda *args, **kwargs: SimpleNamespace(returncode=3, stdout='LoadState=loaded\nActiveState=inactive\n')
        with self.assertRaises(c.SafetyError): c.SystemdTimer(runner).armed('kz2')

    def test_active_rollback_service_is_not_safe(self):
        runner = lambda *args, **kwargs: SimpleNamespace(returncode=0,
            stdout='LoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n')
        with self.assertRaises(c.SafetyError): c.SystemdTimer(runner).armed('kz2')


class RootStoreTests(unittest.TestCase):
    def test_unsafe_state_name_fails_before_file_access(self):
        with self.assertRaises(c.SafetyError): c.RootStore().read('../escape')

    def test_snapshot_bytes_digest_is_verified(self):
        # Mock filesystem reads: no secret fixture or root permission dependence.
        store = c.RootStore(Path('/root/fixture'))
        raw = json.dumps(baseline()).encode()
        digest = __import__('hashlib').sha256(raw).hexdigest()
        def read(path):
            return raw if path.name == 'before.json' else json.dumps(dict(sha256=digest)).encode()
        with patch.object(store, '_check'), patch.object(store, 'secure'), patch.object(Path, 'read_bytes', read):
            self.assertEqual(store.before()[1], digest)
        digest = 'wrong'
        with patch.object(store, '_check'), patch.object(store, 'secure'), patch.object(Path, 'read_bytes', read):
            with self.assertRaises(c.SafetyError): store.before()


if __name__ == '__main__': unittest.main()
