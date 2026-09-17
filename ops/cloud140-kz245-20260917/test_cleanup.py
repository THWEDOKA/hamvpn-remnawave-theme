import unittest
from unittest.mock import Mock, patch
import preflight as p


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.intent = dict(uuid='a21919cb-8d1a-44b6-8c30-452ad04e74d5', username='probe', tag='CLOUD140_PROBE', description='owned')
        self.api = Mock(return_value=self.intent.copy())
        self.query = Mock(side_effect=[dict(remaining=1), dict(remaining=0)])
        for name, value in [('read', self.intent), ('exists', False), ('save', None)]:
            fixture = patch.object(p, name, return_value=value)
            fixture.start(); self.addCleanup(fixture.stop)

    def test_delete_and_database_absence(self):
        self.assertTrue(p.cleanup(self.api, self.query)['disposable_user_deleted'])
        self.assertEqual(self.api.call_args.args[0], 'DELETE')
        self.assertEqual(self.query.call_count, 2)

    def test_reconcile_already_absent(self):
        self.query.side_effect = [dict(remaining=0), dict(remaining=0)]
        p.cleanup(self.api, self.query)
        self.api.assert_not_called()

    def test_not_our_account(self):
        self.api.return_value['tag'] = 'OTHER'
        with self.assertRaises(AssertionError): p.cleanup(self.api, self.query)
        self.assertEqual(self.api.call_count, 1)

    def test_no_false_deletion_success(self):
        self.query.side_effect = [dict(remaining=1), dict(remaining=1)]
        with self.assertRaises(AssertionError): p.cleanup(self.api, self.query)
        self.assertNotIn('test-cleanup', [c.args[0] for c in p.save.call_args_list])


if __name__ == '__main__': unittest.main()
