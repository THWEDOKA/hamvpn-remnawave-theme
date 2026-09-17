"""Offline controller tests. No production calls or firewall mutations."""
import hashlib
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import udp_control as c


def rules_text(rules=None, jump=True, extra=''):
    selected = c.RULES if rules is None else rules
    lines = ['-P INPUT DROP', '-N ' + c.CHAIN]
    lines += [' '.join(['-A', c.CHAIN, *rule]) for rule in selected]
    if jump: lines += [' '.join(['-A', 'INPUT', *c.JUMP])]
    return '\n'.join(lines) + '\n' + extra


class ScopeTests(unittest.TestCase):
    def test_two_directions_two_ports_only(self):
        for identifier in c.PAIRS:
            for port in c.probe.PORTS:
                self.assertEqual(len(c.pair(identifier, port)), 2)
        for identifier, port in [('de245', 54433), ('entry-to-kz2', 443), (None, None)]:
            with self.assertRaises(c.ControlError): c.pair(identifier, port)

    def test_host_guard_checks_exact_local_ipv4(self):
        listing = json.dumps([{'addr_info': [{'family': 'inet', 'local': c.DESTINATION}]}])
        with patch.object(c.os, 'geteuid', return_value=0, create=True), patch.object(c, 'run', return_value=listing):
            c.guard_host('kz2')
            with self.assertRaises(c.ControlError): c.guard_host('entry')
            with self.assertRaises(c.ControlError): c.guard_host('panel')

    def test_non_root_rejected(self):
        with patch.object(c.os, 'geteuid', return_value=1000, create=True), self.assertRaises(c.ControlError):
            c.guard_host('entry')

    def test_prepare_secret_not_returned(self):
        with patch.object(c, 'guard_host'), patch.object(c, 'save') as save:
            result = c.prepare('entry-to-kz2', 54433)
        value = save.call_args.args[1]
        self.assertEqual(save.call_args.args[0], 'entry-to-kz2-54433.json')
        self.assertEqual(len(value['key_hex']), 64)
        self.assertEqual(len(value['nonce_hex']), 32)
        self.assertNotIn('key_hex', result)
        self.assertNotIn(value['key_hex'], json.dumps(result))

    def test_credential_record_wrong_id_rejected(self):
        with patch.object(c, 'read', return_value={'id': 'kz2-to-entry', 'port': 54433}), self.assertRaises(c.ControlError):
            c.credential_record('entry-to-kz2', 54433)

    def test_export_returns_only_protocol_secret_fields(self):
        record = {'id': 'entry-to-kz2', 'port': 54433, 'created_at': 1,
                  'key_hex': 'ab' * 32, 'nonce_hex': 'cd' * 16}
        with patch.object(c, 'read', return_value=record), patch.object(c, 'guard_host'):
            self.assertEqual(set(c.export_secret('entry-to-kz2', 54433)), {'key_hex', 'nonce_hex'})

    def test_role_swapping_rejected_before_host_or_socket(self):
        credentials = c.probe.Credentials(b'k' * 32, b'n' * 16)
        with patch.object(c, 'guard_host') as guard:
            with self.assertRaises(c.ControlError): c.launch_server('entry-to-kz2', 54433, 'entry', credentials)
            with self.assertRaises(c.ControlError): c.client('entry-to-kz2', 54433, 'kz2', credentials)
            guard.assert_not_called()

    def test_client_loss_retained_not_exception(self):
        with patch.object(c, 'guard_host'), patch.object(c, 'save') as save, \
             patch.object(c.probe, 'client', return_value={'all_passed': False}) as probe:
            result = c.client('entry-to-kz2', 54433, 'entry', object())
        self.assertFalse(result['all_passed'])
        self.assertEqual(save.call_count, 2)
        self.assertEqual(probe.call_args.args[0].duration, 45)


class FirewallTests(unittest.TestCase):
    def rollback_records(self):
        snapshot = '*filter\nCOMMIT\n'
        return {'firewall-intent.json': {'script': str(Path('/verified/udp_control.py')), 'sha256': 'a' * 64,
                                        'chain': c.CHAIN, 'source': c.SOURCE, 'destination': c.DESTINATION,
                                        'ports': list(c.probe.PORTS)},
                'firewall-before.json': {'iptables_save': snapshot, 'sha256': hashlib.sha256(snapshot.encode()).hexdigest()}}

    def test_full_owned_rules_and_unrelated_rules_accepted(self):
        state = c.cleanup_plan(rules_text(extra='-A INPUT -p tcp -j ACCEPT\n'))
        self.assertTrue(state[0])
        self.assertEqual(state[1], c.RULES)
        self.assertEqual(state[2], [['-A', 'INPUT', *c.JUMP]])

    def test_partial_creation_cleanup_supported(self):
        for count in (0, 1, 2):
            state = c.cleanup_plan(rules_text(c.RULES[:count], jump=False))
            self.assertEqual(len(state[1]), count)
        self.assertEqual(c.cleanup_plan('-P INPUT DROP'), (False, [], []))

    def test_external_changes_fail_before_cleanup(self):
        cases = [rules_text(extra='-A OUTPUT -j ' + c.CHAIN),
                 rules_text(extra='-A INPUT -g ' + c.CHAIN),
                 rules_text(extra=' '.join(['-A', 'INPUT', *c.JUMP])),
                 rules_text(extra='-A ' + c.CHAIN + ' -j ACCEPT'),
                 rules_text(list(reversed(c.RULES))),
                 rules_text().replace(c.SOURCE + '/32', '0.0.0.0/0')]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(c.ControlError): c.cleanup_plan(case)

    def test_every_allow_has_exact_source_destination_udp(self):
        self.assertEqual(c.JUMP[:8], ['-s', c.SOURCE + '/32', '-d', c.DESTINATION + '/32', '-p', 'udp', '-m', 'multiport'])
        for rule in c.RULES:
            self.assertEqual(rule[:8], ['-s', c.SOURCE + '/32', '-d', c.DESTINATION + '/32', '-p', 'udp', '-m', 'udp'])
            self.assertIn(rule[9], ('54433', '54434'))
            self.assertEqual(rule[-2:], ['-j', 'ACCEPT'])

    def test_prepare_timer_armed_before_first_firewall_write(self):
        calls = []
        def run(*args):
            calls.append(args)
            if args[0] == 'iptables' and args[-1] == '-S':
                return rules_text() if any('-I' in x for x in calls) else '-P INPUT DROP\n'
            if args[0] == 'iptables-save': return '*filter\nCOMMIT\n'
            if args[0] == 'systemctl': return 'active\n'
            return ''
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), patch.object(c, 'save'), patch.object(c, 'run', side_effect=run):
            result = c.firewall_prepare('a' * 64)
        arm = next(i for i, args in enumerate(calls) if args[0] == 'systemd-run')
        mutation = next(i for i, args in enumerate(calls) if '-N' in args)
        self.assertLess(arm, mutation)
        self.assertIn('--on-active=300s', calls[arm])
        self.assertTrue(result['rollback_timer_active'])

    def test_existing_chain_refused(self):
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), patch.object(c, 'save') as save, \
             patch.object(c, 'run', return_value=rules_text()) as run, self.assertRaises(c.ControlError):
            c.firewall_prepare('a' * 64)
        save.assert_not_called()
        self.assertEqual(run.call_count, 1)

    def test_inactive_timer_prevents_firewall_writes(self):
        def run(*args):
            if args[0] == 'iptables': return '-P INPUT DROP\n'
            if args[0] == 'systemctl': return 'inactive\n'
            return ''
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), patch.object(c, 'save'), \
             patch.object(c, 'run', side_effect=run) as runner, self.assertRaises(c.ControlError):
            c.firewall_prepare('a' * 64)
        self.assertFalse(any('-N' in call.args or '-I' in call.args for call in runner.call_args_list))

    def test_rollback_only_exact_owned_deletes_and_timer(self):
        state_reads = 0
        def run(*args):
            nonlocal state_reads
            if args[0] == 'iptables' and args[-1] == '-S':
                state_reads += 1
                return rules_text() if state_reads == 1 else '-P INPUT DROP\n-A INPUT -p tcp -j ACCEPT\n'
            if args[0] == 'systemctl' and 'show' in args: return 'inactive\n'
            return ''
        records = self.rollback_records()
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), patch.object(c, 'save'), \
             patch.object(c, 'read', side_effect=lambda name: records[name]), patch.object(c, 'run', side_effect=run) as runner:
            result = c.firewall_rollback('a' * 64)
        commands = [call.args for call in runner.call_args_list]
        self.assertIn(('iptables', '-w', '5', '-D', 'INPUT', *c.JUMP), commands)
        self.assertIn(('iptables', '-w', '5', '-X', c.CHAIN), commands)
        self.assertFalse(any('-F' in command or 'iptables-restore' in command for command in commands))
        self.assertTrue(result['timer_stopped'])

    def test_rollback_drift_no_mutations(self):
        records = self.rollback_records()
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), \
             patch.object(c, 'read', side_effect=lambda name: records[name]), \
             patch.object(c, 'run', return_value=rules_text(extra='-A OUTPUT -j ' + c.CHAIN)) as runner, \
             self.assertRaises(c.ControlError):
            c.firewall_rollback('a' * 64)
        self.assertEqual(len(runner.call_args_list), 1)

    def test_changed_backup_hash_refuses_before_any_command(self):
        records = self.rollback_records()
        records['firewall-before.json']['sha256'] = '0' * 64
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), None, 'a' * 64)), \
             patch.object(c, 'firewall_lock', return_value=io.StringIO()), \
             patch.object(c, 'read', side_effect=lambda name: records[name]), patch.object(c, 'run') as runner, \
             self.assertRaises(c.ControlError):
            c.firewall_rollback('a' * 64)
        runner.assert_not_called()


class LauncherTests(unittest.TestCase):
    def test_secret_only_pipe_ready_verified_and_child_bounded(self):
        process = Mock(pid=1234)
        process.stdin = Mock()
        ready = {'event': 'ready', 'local_ip': c.DESTINATION, 'peer_ip': c.SOURCE,
                 'port': 54433, 'exclusive_bind': True}
        credentials = c.probe.Credentials(b'k' * 32, b'n' * 16)
        def fake_fdopen(descriptor, mode):
            return io.StringIO(json.dumps(ready) + '\n') if mode == 'r' else io.BytesIO()
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), Path('/verified/udp_probe.py'), 'a' * 64)), \
             patch.object(c, 'save'), patch.object(c, 'private_open', return_value=100), \
             patch.object(c.os, 'fdopen', side_effect=fake_fdopen), patch.object(c.subprocess, 'Popen', return_value=process) as popen:
            result = c.launch_server('entry-to-kz2', 54433, 'kz2', credentials)
        command = popen.call_args.args[0]
        self.assertIn('90', command)
        self.assertNotIn(credentials.key.hex(), ' '.join(command))
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        transferred = json.loads(process.stdin.write.call_args.args[0])
        self.assertEqual(transferred['key_hex'], credentials.key.hex())
        process.stdin.close.assert_called_once()
        self.assertTrue(result['ready'])
        self.assertNotIn(credentials.key.hex(), json.dumps(result))

    def test_wrong_ready_kills_only_child_and_raises(self):
        process = Mock(pid=1234)
        process.poll.return_value = None
        credentials = c.probe.Credentials(b'k' * 32, b'n' * 16)
        def fake_fdopen(descriptor, mode):
            return io.StringIO('{"event":"ready","local_ip":"wrong"}\n') if mode == 'r' else io.BytesIO()
        with patch.object(c, 'guard_host'), patch.object(c, 'release_paths', return_value=(Path('/verified/udp_control.py'), Path('/verified/udp_probe.py'), 'a' * 64)), \
             patch.object(c, 'save'), patch.object(c, 'private_open', return_value=100), \
             patch.object(c.os, 'fdopen', side_effect=fake_fdopen), patch.object(c.subprocess, 'Popen', return_value=process), \
             self.assertRaises(c.ControlError):
            c.launch_server('entry-to-kz2', 54433, 'kz2', credentials)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)


if __name__ == '__main__':
    unittest.main()
