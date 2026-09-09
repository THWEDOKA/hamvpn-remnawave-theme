import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('uk_firewall', Path(__file__).with_name('repair_firewall.py'))
repair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repair)


class RepairTests(unittest.TestCase):
    def fake(self, address=repair.TARGET, active=True, listener=True):
        def execute(args):
            if args[0] == 'ip':
                return json.dumps([{'addr_info': [{'local': address}]}])
            if args[0] == repair.UFW:
                return 'Status: active' if active else 'Status: inactive'
            if args[0] == 'ss':
                return 'LISTEN 0 4096 *:7443 *:*' if listener else ''
            raise AssertionError(args)
        return execute

    def test_scoped_rule_and_rollback(self):
        expected = [repair.UFW, 'allow', 'proto', 'tcp', 'from', '188.225.62.121',
                    'to', 'any', 'port', '7443', 'comment', repair.COMMENT]
        self.assertEqual(repair.command(), expected)
        self.assertEqual(repair.command(True), [repair.UFW, 'delete', *expected[1:]])

    def test_valid_preflight(self):
        repair.preflight(self.fake())

    def test_wrong_server_is_rejected(self):
        with self.assertRaises(RuntimeError):
            repair.preflight(self.fake(address='192.0.2.1'))

    def test_disabled_firewall_is_not_enabled(self):
        with self.assertRaises(RuntimeError):
            repair.preflight(self.fake(active=False))

    def test_missing_listener_is_rejected(self):
        with self.assertRaises(RuntimeError):
            repair.preflight(self.fake(listener=False))


if __name__ == '__main__':
    unittest.main()
