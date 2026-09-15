import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('dns_broker', ROOT / 'dns-broker.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
VALUE = 'A' * 43


class FakeAPI:
    def __init__(self):
        self.rows = {}; self.calls = []; self.next_id = 1
        self.lose_create = False; self.lose_delete = False

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))
        if method == 'GET' and '?' in path:
            return copy.deepcopy([row for row in self.rows.values()
                                  if row['name'] == module.NAME and row['type'] == 'TXT'])
        if method == 'POST':
            identifier = format(self.next_id, '032x'); self.next_id += 1
            self.rows[identifier] = dict(body, id=identifier)
            if self.lose_create: raise module.RemoteError('Simulated lost response')
            return copy.deepcopy(self.rows[identifier])
        identifier = path.rsplit('/', 1)[-1]
        if identifier not in self.rows: raise module.NotFound('Not found')
        if method == 'GET': return copy.deepcopy(self.rows[identifier])
        if method == 'DELETE':
            del self.rows[identifier]
            if self.lose_delete: raise module.RemoteError('Simulated lost response')
            return {'id': identifier}
        raise AssertionError('Unexpected operation')


class DNSBrokerTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI(); self.state = {}; self.saves = []
        self.broker = module.Broker(self.api, '0' * 32, self.state,
            lambda state: self.saves.append(copy.deepcopy(state)))

    def test_only_exact_request_shape_and_validation(self):
        good = {'action': 'present', 'validation': VALUE}
        self.assertEqual(module.parse_request(json.dumps(good).encode()), good)
        for bad in (dict(good, domain='other.example'), dict(good, action='delete'),
                    dict(good, validation='x' * 42), dict(good, validation='/' * 43),
                    dict(good, validation=None), ['present', VALUE]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                module.parse_request(json.dumps(bad).encode())
        with self.assertRaises(ValueError): module.parse_request(b' ' * 2049)

    def test_idempotent_present_and_owned_cleanup(self):
        first = self.broker.execute('present', VALUE)
        second = self.broker.execute('present', VALUE)
        self.assertEqual(first, second)
        self.assertEqual(sum(method == 'POST' for method, _, _ in self.api.calls), 1)
        self.assertEqual(self.saves[0][next(iter(self.saves[0]))]['status'], 'creating')
        result = self.broker.execute('cleanup', VALUE)
        self.assertEqual(result, {'ok': True, 'removed': True})
        self.assertEqual(self.api.rows, {}); self.assertEqual(self.state, {})
        self.assertEqual(self.broker.execute('cleanup', VALUE), {'ok': True, 'removed': False})

    def test_lost_create_response_readback_without_second_post(self):
        self.api.lose_create = True
        self.assertTrue(self.broker.execute('present', VALUE)['ok'])
        self.assertEqual(sum(method == 'POST' for method, _, _ in self.api.calls), 1)

    def test_lost_delete_response_readback(self):
        self.broker.execute('present', VALUE); self.api.lose_delete = True
        self.assertTrue(self.broker.execute('cleanup', VALUE)['removed'])
        self.assertEqual(self.state, {})

    def test_other_challenge_values_survive(self):
        first = self.broker.execute('present', VALUE)
        second = self.broker.execute('present', 'B' * 43)
        self.broker.execute('cleanup', VALUE)
        self.assertNotIn(first['record_id'], self.api.rows)
        self.assertIn(second['record_id'], self.api.rows)

    def test_changed_record_is_not_deleted(self):
        result = self.broker.execute('present', VALUE)
        self.api.rows[result['record_id']]['content'] = 'changed-by-administrator'
        with self.assertRaises(module.RemoteError): self.broker.execute('cleanup', VALUE)
        self.assertIn(result['record_id'], self.api.rows)
        self.assertFalse(any(method == 'DELETE' for method, _, _ in self.api.calls))

    def test_untracked_matching_record_not_adopted(self):
        created = self.broker.execute('present', VALUE)
        self.state.clear()
        with self.assertRaises(module.RemoteError): self.broker.execute('present', VALUE)
        self.assertIn(created['record_id'], self.api.rows)

    def test_fixed_api_name_and_no_caller_record_identifier(self):
        self.broker.execute('present', VALUE)
        post = next(body for method, _, body in self.api.calls if method == 'POST')
        self.assertEqual(post['name'], '_acme-challenge.ru214.torcalc.ru')
        self.assertEqual(post['type'], 'TXT')
        with self.assertRaises(ValueError):
            module.parse_request(json.dumps({'action': 'cleanup', 'validation': VALUE,
                                             'record_id': '0' * 32}).encode())

    def test_installer_has_fixed_privileged_command_and_fail_closed_key(self):
        source = (ROOT / 'dns-broker-install.py').read_text()
        self.assertIn('DisableForwarding yes', source)
        self.assertIn('from="161.104.90.214",restrict', source)
        self.assertIn("/usr/bin/python3 -I /usr/local/lib/hamvpn-dns-ru214/broker.py", source)
        self.assertLess(source.index("run('systemctl', 'reload', 'ssh')"), source.index('KEY.write_bytes'))
        self.assertLess(source.index('if KEY.exists(): KEY.replace'), source.index('if CONF.exists(): CONF.unlink'))
        self.assertIn('KEY.parent.chmod(0o755)', source)
        self.assertIn("assert KEY.parent.stat().st_mode & 0o001", source)
        self.assertIn("{path.name for path in KEY.parent.iterdir()} == {USER}", source)

    def test_propagation_claim_requires_successful_check(self):
        called = []
        self.broker.propagate = called.append
        self.assertTrue(self.broker.execute('present', VALUE)['propagated'])
        self.assertEqual(called, [VALUE])
        self.broker.propagate = lambda value: (_ for _ in ()).throw(module.RemoteError('Not propagated'))
        with self.assertRaises(module.RemoteError): self.broker.execute('present', VALUE)
        self.assertTrue(self.state)
        self.assertTrue(self.broker.execute('cleanup', VALUE)['removed'])

    def test_authoritative_check_requires_both_aa_responses(self):
        names = ['first.ns.cloudflare.com', 'second.ns.cloudflare.com']
        def fake_run(args, **kwargs):
            if args[3] == 'A':
                return module.subprocess.CompletedProcess(args, 0, stdout='173.245.58.1\n')
            return module.subprocess.CompletedProcess(args, 0, stdout=';; flags: qr aa; QUERY: 1\n'
                + module.NAME + '. 60 IN TXT "' + VALUE + '"\n')
        with patch.object(module.subprocess, 'run', side_effect=fake_run) as mocked:
            module.authoritative_propagation(VALUE, names)
        self.assertEqual(mocked.call_count, 4)
        with self.assertRaises(module.RemoteError):
            module.authoritative_propagation(VALUE, ['attacker.example', names[1]])


if __name__ == '__main__': unittest.main()
