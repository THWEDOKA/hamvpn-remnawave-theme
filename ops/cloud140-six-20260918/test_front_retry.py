"""Offline eligibility regression tests; no production calls."""
import unittest
from copy import deepcopy

import front_retry as r
from test_frontend_stage import FrontendTests


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.fx = FrontendTests()
        self.fx.init('gbpower')
        self.fx.worker.prepare('gbpower', self.fx.inputs())

    def test_unused_preparation_eligible_without_api_writes(self):
        writes = deepcopy(self.fx.api.writes)
        r.eligible(self.fx.worker, 'gbpower')
        self.assertEqual(self.fx.api.writes, writes)

    def test_uncertain_or_completed_attempt_refused(self):
        original = self.fx.store.get('operation')
        for field in ('arm_intent', 'apply_intent', 'binding_intent', 'published', 'finished'):
            with self.subTest(field=field):
                record = deepcopy(original); record[field] = self.fx.exit.now
                self.fx.store.save('operation', record)
                with self.assertRaises(RuntimeError): r.eligible(self.fx.worker, 'gbpower')

    def test_preparation_with_grant_or_host_intent_refused(self):
        original = self.fx.store.get('operation')
        for field in ('grants', 'host_intents'):
            record = deepcopy(original); record[field] = {'unexpected': 'value'}
            self.fx.store.save('operation', record)
            with self.assertRaises(RuntimeError): r.eligible(self.fx.worker, 'gbpower')

    def test_unrelated_permission_removal_is_not_falsely_restored(self):
        before = self.fx.store.get('before')
        sid = next(iter(before['customers']))
        # Model a removed foreign grant without changing any selected host.
        before['customers'][sid]['inbounds'].append({'uuid': 'foreign-rolled-back-grant'})
        plan = self.fx.store.get('plan'); record = self.fx.store.get('operation')
        plan['snapshot_sha256'] = record['snapshot_sha256'] = r.f.checksum(before)
        record['plan_sha256'] = r.f.checksum(plan)
        self.fx.store.data.update(before=before, plan=plan, operation=record)
        writes = deepcopy(self.fx.api.writes)
        r.eligible(self.fx.worker, 'gbpower')
        self.assertEqual(writes, self.fx.api.writes)

    def test_profile_drift_refused(self):
        before = self.fx.store.get('before')
        self.fx.api.profiles[before['profile']['uuid']]['config']['log'] = {'loglevel': 'warning'}
        with self.assertRaises(RuntimeError): r.eligible(self.fx.worker, 'gbpower')


if __name__ == '__main__': unittest.main()
