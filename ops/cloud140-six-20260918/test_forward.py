"""Offline only: no SSH, users, systemd, key generation or server writes."""
import base64
from copy import deepcopy
from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

import forward as f


KEY = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(range(32))).decode() + ' test-only'


class MemoryStore:
    def __init__(self, data=None): self.data = deepcopy(data or {})
    def exists(self, name): return name in self.data
    def get(self, name): return deepcopy(self.data[name])
    def put(self, name, value):
        if name in self.data: raise RuntimeError('immutable')
        self.data[name] = deepcopy(value)


class ForwardTests(unittest.TestCase):
    def setUp(self): self.n = f.route('at')

    def identity(self, n=None):
        n = n or self.n
        return dict(id=n['id'], entry=f.ENTRY, exit=n['ip'], public_key=KEY, public_key_id=f.key_id(KEY))

    def proof(self, n=None):
        n = n or self.n
        return dict(id=n['id'], entry=f.ENTRY, exit=n['ip'], timestamp=f.time.time(), public_key_id=f.key_id(KEY),
                    policy_sha256=f.sha(f.policy_text(n).encode()), fixed_target=n['ip'] + ':15444',
                    local_forward_only=True, no_sessions=True, source_restricted=True, operator_policies_preserved=True)

    def detach_proof(self, config=None):
        config = config or {'inbounds': [], 'outbounds': [{'protocol': 'freedom'}]}
        return dict(id='at', entry=f.ENTRY, timestamp=f.time.time(), source='installed-entry-xray', config=config, sha256=f.p.digest(config))

    def test_exact_four_routes(self):
        self.assertEqual(set(f.ROUTES), {'at', 'pl', 'cz', 'gbpower'})
        self.assertEqual(f.route('at')['port'], 21445)
        self.assertEqual(f.route('gbpower')['port'], 21448)
        self.assertEqual(f.route('gbpower')['ip'], '51.194.240.225')
        self.assertEqual(f.route('cz'), dict(id='cz', ip='45.151.180.85', port=21447, user='ham-c1406-cz'))
        self.assertEqual(f.route('pl'), dict(id='pl', ip='31.77.59.141', port=21446, user='ham-c1406-pl'))

    def test_unknown_withdrawn_routes_rejected(self):
        for value in ('gb', 'us1', '../../root', ''):
            with self.subTest(value=value), self.assertRaises(RuntimeError): f.route(value)

    def test_distinct_route_paths_users(self):
        nodes = [f.route(x) for x in f.ROUTES]
        self.assertEqual(len({n['user'] for n in nodes}), 4)
        self.assertEqual(len({n['port'] for n in nodes}), 4)
        for key in f.paths(nodes[0]): self.assertEqual(len({f.paths(n)[key] for n in nodes}), 4)

    def test_public_wire_encoding(self):
        self.assertEqual(len(f.public_blob(KEY)), 51)
        self.assertTrue(f.key_id(KEY).startswith('SHA256:'))
        self.assertNotIn('=', f.key_id(KEY))

    def test_public_key_rejects_injection_and_private(self):
        for value in (KEY + '\n', KEY + '\nssh-rsa x', 'command="evil" ' + KEY, '-----BEGIN OPENSSH PRIVATE KEY-----', KEY.replace('ssh-ed25519 ', 'ssh-rsa ', 1)):
            with self.subTest(value=value), self.assertRaises(RuntimeError): f.public_blob(value)

    def test_key_wire_corruption_rejected(self):
        value = 'ssh-ed25519 ' + base64.b64encode(b'x' * 51).decode()
        with self.assertRaises(RuntimeError): f.public_blob(value)

    def test_exact_host_pin_no_wildcard_dns_hash_alias(self):
        self.assertEqual(f.known_host(self.n, self.n['ip'] + ' ' + KEY), self.n['ip'] + ' ' + KEY + '\n')
        for name in ('*', '[147.45.71.38]:2222', '147.45.71.38,evil', 'example.com', f.ENTRY):
            with self.subTest(name=name), self.assertRaises(RuntimeError): f.known_host(self.n, name + ' ' + KEY)

    def test_authorized_exact_source_and_fixed_target(self):
        text = f.authorized(self.n, KEY)
        self.assertTrue(text.startswith('from="176.108.245.140",restrict,port-forwarding,command="/bin/false",'))
        self.assertIn('permitopen="147.45.71.38:15444"', text)
        self.assertNotIn('permitlisten', text)
        self.assertNotIn('*', text)

    def test_match_only_own_user_then_restores_context(self):
        text = f.policy_text(self.n)
        self.assertTrue(text.startswith('Match User ham-c1406-at\n'))
        self.assertTrue(text.endswith('Match all\n'))
        self.assertEqual(text.count('Match '), 2)
        self.assertNotIn('Match User root', text)

    def test_local_only_no_remote_sessions_streams(self):
        policy = f.policy(self.n)
        self.assertEqual(policy['AllowTcpForwarding'], 'local')
        self.assertEqual(policy['PermitOpen'], '147.45.71.38:15444')
        self.assertEqual(policy['PermitListen'], 'none')
        self.assertEqual(policy['MaxSessions'], '0')
        self.assertEqual(policy['ForceCommand'], '/bin/false')
        for name in ('PasswordAuthentication', 'KbdInteractiveAuthentication', 'AllowStreamLocalForwarding', 'PermitTTY', 'AllowAgentForwarding', 'X11Forwarding', 'PermitTunnel', 'PermitUserRC'):
            self.assertEqual(policy[name], 'no')

    def test_effective_policy_accepts_exact_and_bool_spellings(self):
        text = '\n'.join(k.lower() + ' ' + v for k, v in f.policy(self.n).items()) + '\ndisableforwarding no'
        f.check_policy(self.n, text)
        converted = '\n'.join(k.lower() + ' ' + {'yes': 'true', 'no': 'false'}.get(v, v) for k, v in f.policy(self.n).items())
        f.check_policy(self.n, converted + '\ndisableforwarding false')

    def test_any_weak_effective_policy_fails(self):
        for key in f.policy(self.n):
            actual = dict(f.policy(self.n)); actual[key] = 'ANY'
            text = '\n'.join(k.lower() + ' ' + v for k, v in actual.items()) + '\ndisableforwarding no'
            with self.subTest(key=key), self.assertRaises(RuntimeError): f.check_policy(self.n, text)

    def test_globally_disabled_forward_fails(self):
        text = '\n'.join(k.lower() + ' ' + v for k, v in f.policy(self.n).items()) + '\ndisableforwarding yes'
        with self.assertRaises(RuntimeError): f.check_policy(self.n, text)

    def test_ssh_explicit_loopback_and_existing_reality_ip(self):
        for name in f.ROUTES:
            n = f.route(name); args = f.ssh_args(n)
            self.assertEqual(args[args.index('-L') + 1], '127.0.0.1:' + str(n['port']) + ':' + n['ip'] + ':15444')
            self.assertEqual(args[-1], n['user'] + '@' + n['ip'])
            self.assertNotIn('-R', args); self.assertNotIn('-D', args)
            self.assertEqual(args[args.index('-F') + 1], '/dev/null')

    def test_ssh_no_ambient_identity_config_proxy_or_control(self):
        args = f.ssh_args(self.n)
        for value in ('IdentitiesOnly=yes', 'IdentityAgent=none', 'BatchMode=yes', 'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
                      'GlobalKnownHostsFile=/dev/null', 'PasswordAuthentication=no', 'KbdInteractiveAuthentication=no',
                      'ExitOnForwardFailure=yes', 'ServerAliveInterval=15', 'ServerAliveCountMax=3', 'ControlMaster=no',
                      'ControlPath=none', 'ConnectionAttempts=1', 'HostKeyAlgorithms=ssh-ed25519'):
            self.assertIn(value, args)
        self.assertNotIn('StrictHostKeyChecking=no', args)

    def test_service_sandbox_bounded_reconnect(self):
        text = f.unit_text(self.n)
        for value in ('RestartSec=5', 'TimeoutStopSec=15', 'NoNewPrivileges=true', 'ProtectSystem=strict', 'ProtectHome=true',
                      'CapabilityBoundingSet=\n', 'User=root', 'KillMode=control-group', 'WantedBy=multi-user.target'):
            self.assertIn(value, text)
        for bad in ('docker restart', 'nginx', 'systemctl restart', 'ssh -R', 'Environment='):
            self.assertNotIn(bad, text)

    def test_identity_input_exact_route_and_checksum(self):
        self.assertEqual(f.identity_input(self.n, self.identity()), KEY)
        for key, value in [('id', 'gbpower'), ('entry', '127.0.0.1'), ('exit', '51.194.240.225'), ('public_key_id', 'SHA256:bad')]:
            request = self.identity(); request[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): f.identity_input(self.n, request)

    def test_identity_input_rejects_operator_private_parameter(self):
        request = self.identity(); request['private_key'] = 'never'
        with self.assertRaises(RuntimeError): f.identity_input(self.n, request)

    def test_fresh_identity_proof(self): f.identity_proof(self.n, self.proof(), KEY)

    def test_identity_proof_rejects_missing_guards_or_changed_target(self):
        for key in ('local_forward_only', 'no_sessions', 'source_restricted', 'operator_policies_preserved', 'public_key_id', 'policy_sha256', 'fixed_target'):
            proof = self.proof(); del proof[key]
            with self.subTest(key=key), self.assertRaises(RuntimeError): f.identity_proof(self.n, proof, KEY)

    def test_proof_freshness(self):
        for value in (True, None, f.time.time() - 1900, f.time.time() + 60, float('nan')):
            proof = self.proof(); proof['timestamp'] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError): f.identity_proof(self.n, proof, KEY)

    def test_correct_owned_listener(self):
        f.check_listener(self.n, ['LISTEN 0 128 127.0.0.1:21445 0.0.0.0:* users:(("ssh",pid=42,fd=4))'], 42)

    def test_public_ipv6_or_other_pid_listener_rejected(self):
        for endpoint, pid, program in [('0.0.0.0:21445', 42, 'ssh'), ('[::]:21445', 42, 'ssh'), ('[::1]:21445', 42, 'ssh'),
                                       ('127.0.0.1:21445', 43, 'ssh'), ('127.0.0.1:21445', 42, 'xray')]:
            line = 'LISTEN 0 128 ' + endpoint + ' 0.0.0.0:* users:(("' + program + '",pid=' + str(pid) + ',fd=4))'
            with self.subTest(endpoint=endpoint, pid=pid, program=program), self.assertRaises(RuntimeError): f.check_listener(self.n, [line], 42)

    def test_missing_duplicate_listener_rejected(self):
        line = 'LISTEN 0 128 127.0.0.1:21445 0.0.0.0:* users:(("ssh",pid=42,fd=4))'
        for lines in ([], [line, line]):
            with self.assertRaises(RuntimeError): f.check_listener(self.n, lines, 42)

    def test_detach_requires_complete_hashed_fresh_config(self):
        f.detached(self.n, self.detach_proof())
        for key, value in [('sha256', 'bad'), ('entry', 'evil'), ('source', 'guessed'), ('timestamp', f.time.time()-121), ('config', {'outbounds': []})]:
            proof = self.detach_proof(); proof[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): f.detached(self.n, proof)

    def test_detach_blocks_all_references_not_just_vless(self):
        for value in (21445, '127.0.0.1:21445', {'unknown': [21445]}, 'http://localhost:21445/path'):
            proof = self.detach_proof({'outbounds': [{'protocol': 'unknown', 'target': value}]})
            with self.subTest(value=value), self.assertRaises(RuntimeError): f.detached(self.n, proof)

    def test_detach_other_route_can_remain(self):
        f.detached(self.n, self.detach_proof({'outbounds': [{'target': '127.0.0.1:21448'}]}))

    @patch.object(f, 'run')
    def test_active_consumers_prevent_stop(self, run):
        run.return_value.stdout = 'ESTAB consumer\n'
        with self.assertRaises(RuntimeError): f.no_connections(self.n)
        self.assertEqual(run.call_args.args[0][-1], 'sport = :21445')
        run.return_value.stdout = ''; f.no_connections(self.n)

    @patch.object(f.subprocess, 'run')
    def test_command_error_is_sanitized(self, run):
        run.return_value = subprocess.CompletedProcess(['x'], 7, 'PRIVATE', 'PRIVATE')
        with self.assertRaises(RuntimeError) as error: f.run(['x'])
        self.assertNotIn('PRIVATE', str(error.exception))

    @patch.object(f, 'wait_verified')
    @patch.object(f, 'run')
    @patch.object(f, 'store')
    @patch.object(f, 'no_connections')
    @patch.object(f, 'verify')
    def test_recovery_restarts_only_owned_unit_and_records_proof(self, verify, no_connections, store, run, wait):
        before = dict(pid=10, started_monotonic='1', restart_recovery_verified=False)
        after = dict(pid=11, started_monotonic='2', restart_recovery_verified=False)
        verify.return_value = before; wait.return_value = after; memory = MemoryStore(); store.return_value = memory
        result = f.recovery_test(self.n)
        self.assertTrue(result['restart_recovery_verified'])
        self.assertIn('recovery-intent', memory.data); self.assertIn('recovered', memory.data)
        run.assert_called_once_with(['systemctl', 'restart', 'ham-c1406-forward-at.service'])

    @patch.object(f, 'store')
    @patch.object(f, 'no_connections')
    @patch.object(f, 'verify')
    @patch.object(f, 'run')
    def test_uncertain_recovery_not_retried(self, run, verify, no_connections, store):
        verify.return_value = {'pid': 1}; store.return_value = MemoryStore({'recovery-intent': {'timestamp': 1}})
        with self.assertRaises(RuntimeError): f.recovery_test(self.n)
        run.assert_not_called()

    @patch.object(f, 'guard')
    @patch.object(f, 'check_keys', return_value=KEY)
    @patch.object(f, 'store')
    @patch.object(f, 'run')
    def test_uncertain_start_not_retried(self, run, store, keys, guard):
        store.return_value = MemoryStore({'start-intent': {'timestamp': 1}})
        with self.assertRaises(RuntimeError): f.start(self.n, self.proof())
        run.assert_not_called()

    def test_source_contains_no_api_or_vpn_mutation_or_recursive_delete(self):
        source = Path(f.__file__).read_text()
        for bad in ('shutil.rmtree', "'userdel'", "'PATCH'", "'POST'", "'iptables'", "'apt-get'", "'disableforwarding': 'yes'"):
            self.assertNotIn(bad, source)

    def test_account_unlock_is_stdin_random_hash_not_empty_password(self):
        source = Path(f.__file__).read_text()
        self.assertIn("secrets.token_urlsafe(64)", source)
        self.assertIn("run(['chpasswd', '-e'], data=", source)
        self.assertNotIn("--password", source)
        self.assertNotIn("--delete", source)
        self.assertLess(source.index("check_policy(n, effective(n, n['user'], address))"), source.index("run(['chpasswd', '-e']"))

    def test_fixed_expected_reality_backend_never_changed(self):
        self.assertEqual(f.BACKEND, 15444)
        self.assertNotEqual(f.ROUTES['gbpower']['ip'], '51.194.240.214')


class FailedStartTests(unittest.TestCase):
    """Mock operating-system effects; exercise all cleanup gates and ordering."""
    setUp = ForwardTests.setUp
    detach_proof = ForwardTests.detach_proof
    @contextmanager
    def environment(self, pair=('active', 'running'), pid='42'):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            loc = f.paths(self.n); loc['unit'] = Path(directory) / 'owned.service'
            stack.enter_context(patch.object(f, 'paths', return_value=loc))
            loc['unit'].write_text(f.unit_text(self.n))
            memory = MemoryStore({'start-intent': dict(id='at', unit=f.unit_text(self.n), baseline={'old': 'not restored'})})
            memory.path = Path(directory) / 'state'; memory.path.mkdir()
            first = dict(LoadState='loaded', ActiveState=pair[0], SubState=pair[1], MainPID=pid,
                         FragmentPath=str(loc['unit']), DropInPaths='')
            stopped = dict(first, ActiveState='inactive', SubState='dead', MainPID='0')
            removed = dict(stopped, LoadState='not-found', FragmentPath='')
            mocks = {}
            for name, value in [('guard', None), ('check_keys', KEY), ('store', memory), ('secure', None),
                                ('check_owned_process', None), ('listener_lines', []), ('no_connections', None),
                                ('service_baseline', {'current': 'preserved'}), ('run', None)]:
                mocks[name] = stack.enter_context(patch.object(f, name, return_value=value))
            mocks['unit_info'] = stack.enter_context(patch.object(f, 'unit_info', side_effect=[first, stopped, removed]))
            mocks['create'] = stack.enter_context(patch.object(f, 'create', side_effect=lambda path, data: path.write_bytes(data)))
            yield memory, loc, mocks, first, stopped, removed

    def test_failed_cleanup_stops_only_owned_unit_and_preserves_recovery(self):
        with self.environment() as (memory, loc, mocks, first, stopped, removed):
            result = f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertTrue(result['failed_start_cleaned'])
            self.assertTrue(result['entry_service_stopped'])
            self.assertTrue(result['keys_and_identity_retained'])
            self.assertFalse(loc['unit'].exists())
            self.assertEqual((memory.path / 'disabled-unit.conf').read_text(), f.unit_text(self.n))
            self.assertEqual(memory.get('rollback-intent')['current_services'], {'current': 'preserved'})
            self.assertEqual([x.args[0] for x in mocks['run'].call_args_list],
                             [['systemctl', 'disable', '--now', 'owned.service'], ['systemctl', 'daemon-reload']])
            mocks['check_owned_process'].assert_called_once_with(self.n, 42)

    def test_cleanup_failed_and_auto_restart_states_without_pid(self):
        for pair in [('activating', 'auto-restart'), ('failed', 'failed'), ('inactive', 'dead')]:
            with self.subTest(pair=pair), self.environment(pair=pair, pid='0') as (memory, loc, mocks, *_):
                self.assertTrue(f.cleanup_failed_start(self.n, self.detach_proof())['failed_start_cleaned'])
                mocks['check_owned_process'].assert_not_called()

    def test_cleanup_clears_only_own_failed_state_after_stop(self):
        with self.environment() as (memory, loc, mocks, first, stopped, removed):
            mocks['unit_info'].side_effect = [first, dict(stopped, ActiveState='failed', SubState='failed'), stopped, removed]
            f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertIn(['systemctl', 'reset-failed', 'owned.service'], [x.args[0] for x in mocks['run'].call_args_list])

    def test_verified_or_uncertain_cleanup_cannot_be_reused(self):
        for marker in ('started', 'recovered', 'recovery-intent', 'rollback-intent', 'rolled-back'):
            with self.subTest(marker=marker), self.environment() as (memory, loc, mocks, *_):
                memory.put(marker, {})
                with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
                mocks['run'].assert_not_called(); mocks['create'].assert_not_called()
                self.assertTrue(loc['unit'].exists())

    def test_cleanup_rejects_listener_before_any_mutation(self):
        with self.environment() as (memory, loc, mocks, *_):
            mocks['listener_lines'].return_value = ['LISTEN exists']
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertFalse(memory.exists('rollback-intent')); mocks['run'].assert_not_called()

    def test_cleanup_rejects_active_consumers(self):
        with self.environment() as (memory, loc, mocks, *_):
            mocks['no_connections'].side_effect = RuntimeError('consumer')
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertFalse(memory.exists('rollback-intent')); mocks['run'].assert_not_called()

    def test_cleanup_rejects_config_consumer(self):
        with self.environment() as (memory, loc, mocks, *_):
            request = self.detach_proof({'outbounds': [{'address': '127.0.0.1', 'port': 21445}]})
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, request)
            self.assertFalse(memory.exists('rollback-intent')); mocks['run'].assert_not_called()

    def test_cleanup_rejects_foreign_unit_or_override(self):
        for mode in ('file', 'dropin', 'fragment', 'intent'):
            with self.subTest(mode=mode), self.environment() as (memory, loc, mocks, first, *_):
                if mode == 'file': loc['unit'].write_text('foreign')
                elif mode == 'dropin': first['DropInPaths'] = '/some/override'
                elif mode == 'fragment': first['FragmentPath'] = '/other/service'
                else: memory.data['start-intent']['id'] = 'gbpower'
                with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
                self.assertFalse(memory.exists('rollback-intent')); mocks['run'].assert_not_called()

    def test_cleanup_rejects_unknown_pid_or_state(self):
        with self.environment() as (memory, loc, mocks, *_):
            mocks['check_owned_process'].side_effect = RuntimeError('foreign process')
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            mocks['run'].assert_not_called()
        with self.environment(pair=('deactivating', 'stop-sigterm')) as (memory, loc, mocks, *_):
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            mocks['run'].assert_not_called()

    def test_listener_race_stops_after_intent_without_touching_service(self):
        with self.environment() as (memory, loc, mocks, *_):
            mocks['listener_lines'].side_effect = [[], ['new listener']]
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertTrue(memory.exists('rollback-intent')); mocks['run'].assert_not_called()
            self.assertTrue(loc['unit'].exists())

    def test_failed_stop_does_not_remove_unit(self):
        with self.environment() as (memory, loc, mocks, first, stopped, removed):
            mocks['unit_info'].side_effect = [first, first]
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertTrue(loc['unit'].exists()); mocks['create'].assert_not_called()
            self.assertFalse(memory.exists('rolled-back'))

    def test_cleanup_baseline_drift_is_not_claimed_success(self):
        with self.environment() as (memory, loc, mocks, *_):
            mocks['service_baseline'].side_effect = [{'current': 1}, {'current': 2}]
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, self.detach_proof())
            self.assertFalse(memory.exists('rolled-back'))

    def test_cleanup_proof_stale_stops_before_systemd(self):
        with self.environment() as (memory, loc, mocks, *_):
            request = self.detach_proof(); request['timestamp'] -= 121
            with self.assertRaises(RuntimeError): f.cleanup_failed_start(self.n, request)
            mocks['run'].assert_not_called()

    @patch.object(f.Path, 'read_text')
    @patch.object(f.os, 'readlink', return_value='/usr/bin/ssh')
    @patch.object(f.Path, 'read_bytes')
    def test_owned_process_exact_executable_args_and_root_uid(self, read_bytes, readlink, read_text):
        read_bytes.return_value = ('\0'.join(f.ssh_args(self.n)) + '\0').encode()
        read_text.return_value = 'Uid:\t0\t0\t0\t0\n'
        f.check_owned_process(self.n, 42)
        read_bytes.return_value = b'foreign\0'
        with self.assertRaises(RuntimeError): f.check_owned_process(self.n, 42)
        read_bytes.return_value = ('\0'.join(f.ssh_args(self.n)) + '\0').encode()
        readlink.return_value = '/tmp/ssh'
        with self.assertRaises(RuntimeError): f.check_owned_process(self.n, 42)
        readlink.return_value = '/usr/bin/ssh'; read_text.return_value = 'Uid:\t1000\t1000\t1000\t1000\n'
        with self.assertRaises(RuntimeError): f.check_owned_process(self.n, 42)


if __name__ == '__main__': unittest.main()
