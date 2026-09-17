import copy
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import reality_compat as r


def config():
    return {'inbounds': [dict(tag=r.SCOPES['aeza-de3']['tag'], port=18443, protocol='vless',
            settings={'clients': [{'id': 'fixture-only'}]}, streamSettings={'security': 'reality',
            'realitySettings': {'privateKey': 'fixture-only', 'shortIds': ['aa'], 'serverNames': ['test.invalid']}}),
            dict(tag='untouched', streamSettings={'security': 'reality', 'realitySettings': {'privateKey': 'other'}})],
            'outbounds': [{'protocol': 'freedom'}], 'routing': {'rules': [{'type': 'field', 'outboundTag': 'exit'}]}}


class Memory:
    def __init__(self): self.records = {}
    def exists(self, k): return k in self.records
    def put(self, k, v):
        if k in self.records: raise RuntimeError('immutable')
        self.records[k] = copy.deepcopy(v)
    def get(self, k): return copy.deepcopy(self.records[k])


class Timer:
    def __init__(self): self.armed = False
    def active(self): return self.armed
    def arm(self): self.armed = True
    def cancel(self): self.armed = False


class Tests(unittest.TestCase):
    def setUp(self):
        self.target = r.SCOPES['aeza-de3']
        self.profile = {'uuid': self.target['profile'], 'config': config()}
        self.nodes = [dict(uuid=self.target['node'], address=self.target['address'], isConnected=True, isDisabled=False,
                     configProfile=dict(activeConfigProfileUuid=self.target['profile'],
                                        activeInbounds=[{'uuid': 'fixture-id', 'tag': self.target['tag']}]))]
        self.writes = []
        def api(method, path, body=None):
            if method == 'GET': return copy.deepcopy(self.nodes if path == '/api/nodes/' else self.profile)
            self.writes.append(copy.deepcopy(body))
            self.profile['config'] = copy.deepcopy(body['config'])
            return copy.deepcopy(self.profile)
        self.store, self.timer = Memory(), Timer()
        self.op = r.Operation('aeza-de3', api, self.store, self.timer, clock=lambda: 1000)

    def ready(self):
        self.op.plan()
        self.op.accept_installed(dict(sha256=self.op.load()['candidate_sha256'], timestamp=990,
                                      passed=True, returncode=0, version='26.7.28'))

    def test_exact_one_field_and_no_aliasing(self):
        original = config()
        changed = r.candidate(original, self.target)
        self.assertNotIn('minClientVer', original['inbounds'][0]['streamSettings']['realitySettings'])
        self.assertEqual(changed['inbounds'][0]['streamSettings']['realitySettings'].pop('minClientVer'), '1.8.2')
        self.assertEqual(changed, original)

    def test_explicit_policies_never_overwritten(self):
        for value in ('26.3.27', '1.8.2', '0.0.0', '', None):
            c = config(); c['inbounds'][0]['streamSettings']['realitySettings']['minClientVer'] = value
            with self.assertRaises(RuntimeError): r.candidate(c, self.target)

    def test_shared_consumer_refused(self):
        self.nodes.append({**self.nodes[0], 'uuid': 'unrelated-node'})
        with self.assertRaises(RuntimeError): self.op.plan()
        self.assertEqual(self.writes, [])

    def test_wrong_port_and_security_refused(self):
        for field, value in [('port', 443), ('protocol', 'trojan')]:
            c = config(); c['inbounds'][0][field] = value
            with self.assertRaises(RuntimeError): r.candidate(c, self.target)

    def test_install_proof_and_timer_required(self):
        self.op.plan()
        with self.assertRaises(KeyError): self.op.apply()
        self.assertEqual(self.writes, [])

    def test_drift_stops_before_timer_or_write(self):
        self.ready(); self.profile['config']['outbounds'].append({'protocol': 'blackhole'})
        with self.assertRaises(RuntimeError): self.op.apply()
        self.assertFalse(self.timer.active()); self.assertEqual(self.writes, [])

    def test_derived_raw_inbound_is_not_an_assignment_change(self):
        self.ready()
        self.nodes[0]['configProfile']['activeInbounds'][0]['rawInbound'] = {'owned-version-change': True}
        self.op.apply()
        self.assertEqual(len(self.writes), 1)

    def test_changed_inbound_identity_still_rejected(self):
        self.ready()
        self.nodes[0]['configProfile']['activeInbounds'][0]['uuid'] = 'different-inbound'
        with self.assertRaises(RuntimeError): self.op.apply()
        self.assertEqual(self.writes, [])

    def test_uncertain_apply_reconciles_without_another_patch(self):
        self.ready()
        self.store.put('apply-intent', {'timestamp': 999})
        self.profile['config'] = self.op.load()['candidate']
        self.timer.arm()
        self.op.reconcile_applied()
        self.assertEqual(self.writes, [])
        self.assertEqual(self.store.get('applied'), {'timestamp': 999})

    def test_apply_and_exact_rollback(self):
        original = config(); self.ready(); self.op.apply()
        self.assertTrue(self.timer.active())
        self.assertEqual(len(self.writes), 1)
        self.op.rollback()
        self.assertEqual(self.profile['config'], original)
        self.assertTrue(self.store.exists('rolled-back'))

    def test_rollback_preserves_unrelated_drift(self):
        self.ready(); self.op.apply(); self.profile['config']['outbounds'].append({'protocol': 'blackhole'})
        with self.assertRaises(RuntimeError): self.op.rollback()
        self.assertEqual(len(self.writes), 1)

    def test_rollback_still_restores_when_node_is_disconnected(self):
        self.ready(); self.op.apply(); self.nodes[0]['isConnected'] = False
        self.op.rollback()
        self.assertEqual(self.profile['config'], config())

    def test_bad_proof_leaves_rollback_armed(self):
        self.ready(); self.op.apply()
        with self.assertRaises(RuntimeError): self.op.finish(dict(timestamp=1000, sha256=self.op.load()['candidate_sha256'], tests=[]))
        self.assertTrue(self.timer.active())
        self.assertFalse(self.store.exists('finished'))

    def test_finish_requires_four_successful_exact_egress_tests(self):
        self.ready(); self.op.apply()
        proof = dict(timestamp=1000, sha256=self.op.load()['candidate_sha256'], live_mihomo_delay=99,
                     tests=[dict(id=i, http='204', exit_ip=self.target['exit_ip'], curl_codes=[0, 0], listener_removed=True)
                            for i in ('mihomo-firefox', 'mihomo-chrome', 'xray-firefox', 'xray-chrome')])
        self.op.finish(proof)
        self.assertTrue(self.op.finish(proof)['finished'])
        self.assertFalse(self.timer.active())
        self.assertTrue(self.store.exists('finished'))
        self.assertTrue(self.op.rollback()['rollback_skipped_finished'])


class TimerTests(unittest.TestCase):
    def test_inspection_error_is_not_inactive(self):
        with patch.object(r.subprocess, 'run', return_value=SimpleNamespace(returncode=5, stdout='')):
            with self.assertRaises(RuntimeError): r.Timer('aeza-de3').active()

    def test_missing_unit_is_verified_inactive(self):
        value = SimpleNamespace(returncode=4, stdout='LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
        with patch.object(r.subprocess, 'run', return_value=value):
            self.assertFalse(r.Timer('aeza-de3').active())

    def test_cancel_stops_and_checks_service_too(self):
        timer = r.Timer('aeza-de3')
        with patch.object(timer, 'run') as run, patch.object(timer, 'state', return_value={'ActiveState': 'inactive'}) as state:
            timer.cancel()
            run.assert_called_once_with(['systemctl', 'stop', timer.unit + '.timer', timer.unit + '.service'])
            self.assertEqual([call.args[0] for call in state.call_args_list], ['timer', 'service'])


if __name__ == '__main__': unittest.main()
