"""Offline USA-only contracts; fake public keys, sockets, SSH and package actions."""
import base64
import builtins
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import MagicMock, patch

import reverse244 as existing
import usa244reverse as u


def public_key():
    # Public wire-format fixture only, not a private key or deployed credential.
    wire = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'\x01' * 32
    return 'ssh-ed25519 ' + base64.b64encode(wire).decode() + ' fixture-only'


def mock_worker():
    fake = types.ModuleType('paramiko')
    fake.SSHException = type('SSHException', (Exception,), {})
    fake.SSHClient = MagicMock()
    fake.RejectPolicy = type('RejectPolicy', (), {})
    with patch.dict(sys.modules, {'paramiko': fake}):
        return u.worker_module()


class ProvisioningTests(unittest.TestCase):
    def test_exact_isolated_scope(self):
        self.assertEqual(u.SOURCE, '162.141.185.216')
        self.assertEqual(u.MANAGEMENT, '162.141.185.208')
        self.assertEqual(u.ENTRY, '193.233.222.244')
        self.assertEqual(u.USER, 'ham-usa244')
        self.assertEqual(str(u.HOME_DIR).replace('\\', '/'), '/var/lib/ham-usa244')
        self.assertEqual(u.KEY_DIR.name, 'hamvpn-usa244')
        self.assertEqual(u.SSH_CONF.name, '71-ham-usa244.conf')
        self.assertEqual(u.STATE.name, 'hamvpn-usa244-20260917')
        self.assertEqual(u.UNIT.name, 'ham-usa244-reverse.service')
        self.assertEqual(u.NODE['link'], 25443)
        self.assertEqual(u.TARGET, ('127.0.0.1', 15443))

    def test_reuse_never_mutates_existing_four_channel_module(self):
        before = {k: copy.deepcopy(getattr(existing, k)) for k in
                  ('USER', 'HOME_DIR', 'SSH_CONF', 'KEY_DIR', 'UNIT', 'NODES', 'STATE')}
        helper = u.provision()
        self.assertIsNot(helper, existing)
        self.assertEqual(helper.NODES, [u.NODE])
        for key, value in before.items():
            self.assertEqual(getattr(existing, key), value)

    def test_entry_provision_import_never_imports_paramiko(self):
        original = builtins.__import__
        def importing(name, *args, **kwargs):
            if name.startswith('paramiko'):
                raise AssertionError('Entry provisioning imported Paramiko')
            return original(name, *args, **kwargs)
        with patch.object(builtins, '__import__', side_effect=importing):
            module = u.isolated_module('_usa_import_test', Path(u.__file__))
        self.assertEqual(module.USER, 'ham-usa244')

    def test_only_one_source_restricted_key_and_loopback_port(self):
        text = u.authorized_keys({'usa2': public_key()})
        self.assertEqual(len(text.splitlines()), 1)
        self.assertTrue(text.startswith('from="162.141.185.216",restrict,port-forwarding,'
                                        'permitlisten="127.0.0.1:25443" '))
        self.assertNotIn(u.MANAGEMENT, text)
        self.assertEqual(text.count('permitlisten='), 1)

    def test_wrong_keys_or_injected_options_refused(self):
        for keys in ({}, {'de182': public_key()}, {'usa2': public_key(), 'other': public_key()},
                     {'usa2': public_key() + '\nssh-ed25519 injected'},
                     {'usa2': 'command="sh" ' + public_key()}, {'usa2': 'ssh-ed25519 invalid'}):
            with self.subTest(keys_count=len(keys)), self.assertRaises(RuntimeError):
                u.authorized_keys(keys)

    def test_full_restricted_policy(self):
        policy = u.ssh_policy()
        for key, value in {'AllowTcpForwarding': 'remote', 'PermitListen': '127.0.0.1:25443',
            'PermitOpen': 'none', 'ForceCommand': '/bin/false', 'MaxSessions': '0',
            'GatewayPorts': 'no', 'PermitTTY': 'no', 'PermitTunnel': 'no',
            'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
            'AllowAgentForwarding': 'no', 'AllowStreamLocalForwarding': 'no',
            'AuthorizedKeysCommand': 'none', 'TrustedUserCAKeys': 'none',
            'AuthenticationMethods': 'publickey'}.items():
            self.assertEqual(policy[key], value)
        self.assertEqual(policy['AuthorizedKeysFile'], str(u.HOME_DIR / '.ssh/authorized_keys'))
        text = u.provision().policy_text()
        self.assertTrue(text.startswith('Match User ham-usa244\n'))
        self.assertTrue(text.endswith('Match all\n'))
        self.assertNotIn('ham-exits244', text)

    def test_effective_unsafe_policy_is_rejected(self):
        helper = u.provision()
        output = '\n'.join(k.lower() + ' ' + v for k, v in helper.ssh_policy().items()) + '\ndisableforwarding no'
        helper.check_policy(output)
        for old, new in [('allowtcpforwarding remote', 'allowtcpforwarding yes'),
                         ('permitlisten 127.0.0.1:25443', 'permitlisten any'),
                         ('forcecommand /bin/false', 'forcecommand none'),
                         ('passwordauthentication no', 'passwordauthentication yes')]:
            with self.subTest(option=old), self.assertRaises(RuntimeError):
                helper.check_policy(output.replace(old, new))

    def test_guard_requires_exact_local_identity(self):
        with patch.object(u.os, 'geteuid', return_value=0, create=True), \
             patch.object(u, 'private_state'), \
             patch.object(u, 'run', return_value=json.dumps([{'addr_info': [{'local': u.SOURCE}]}])):
            u.guard(u.SOURCE)
            with self.assertRaises(RuntimeError): u.guard(u.ENTRY)
            with self.assertRaises(RuntimeError): u.guard(u.MANAGEMENT)

    def test_generate_rejects_unverified_wrong_or_injected_host_key_before_writing(self):
        for known in (u.MANAGEMENT + ' ' + public_key(), u.ENTRY + ' ssh-ed25519 invalid',
                      u.ENTRY + ' ' + public_key() + '\n' + u.ENTRY + ' ' + public_key()):
            with tempfile.TemporaryDirectory() as tmp, patch.object(u, 'KEY_DIR', Path(tmp) / 'keys'), \
                 patch.object(u, 'guard'), patch.object(u, 'run', return_value=u.SOURCE + '/24'), \
                 patch.object(u.sys, 'stdin', io.StringIO(known)):
                with self.assertRaises(RuntimeError): u.generate()
                self.assertFalse((Path(tmp) / 'keys').exists())

    def test_key_export_is_public_json_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_dir = Path(tmp)
            (key_dir / 'reverse_key.pub').write_text(public_key())
            with patch.object(u, 'KEY_DIR', key_dir), patch.object(u, 'guard'), \
                 patch.object(u, 'read', return_value={'id': 'usa2', 'entry': u.ENTRY}):
                result = u.export_key()
            self.assertEqual(result, {'usa2': public_key()})

    def test_backup_and_revocation_order_are_before_policy_removal(self):
        import inspect
        source = inspect.getsource(u.identity)
        self.assertLess(source.index('helper.backup_ssh()'), source.index("run('useradd'"))
        self.assertLess(source.index('authorized.rename'), source.index('SSH_CONF.rename'))
        self.assertIn('protected_snapshot(addresses) == before', source)

    def test_protected_policy_drift_quarantines_only_new_config(self):
        fake_pwd = types.ModuleType('pwd')
        account = types.SimpleNamespace(pw_uid=900, pw_gid=900)
        fake_pwd.getpwnam = MagicMock(side_effect=[KeyError(), account])
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp); home = root / 'new-home'; state = root / 'state'; state.mkdir()
            conf = root / '71-ham-usa244.conf'
            stack.enter_context(patch.dict(sys.modules, {'pwd': fake_pwd}))
            for name, value in [('HOME_DIR', home), ('STATE', state), ('SSH_CONF', conf)]:
                stack.enter_context(patch.object(u, name, value))
            stack.enter_context(patch.object(u, 'guard'))
            stack.enter_context(patch.object(u, 'save'))
            stack.enter_context(patch.object(u.os, 'chown', create=True))
            stack.enter_context(patch.object(u.sys, 'stdin', io.StringIO(json.dumps({'usa2': public_key()}))))
            stack.enter_context(patch.object(u.socket, 'socket'))
            stack.enter_context(patch.object(u._base, 'backup_ssh'))
            stack.enter_context(patch.object(u, 'protected_snapshot', side_effect=[{'before': True}, {'before': False}]))
            def command(*args):
                if args[0] == 'useradd': home.mkdir()
                return ''
            run = stack.enter_context(patch.object(u, 'run', side_effect=command))
            with self.assertRaisesRegex(RuntimeError, 'four-channel'):
                u.identity()
            self.assertFalse(conf.exists())
            self.assertTrue((state / 'reverse-failed-ssh-policy.conf').is_file())
            self.assertFalse((home / '.ssh/authorized_keys').exists())
            self.assertTrue(all('ham-exits244' not in str(call) for call in run.call_args_list))

    def test_failure_after_authorization_revokes_key_before_unrestricting(self):
        fake_pwd = types.ModuleType('pwd')
        fake_pwd.getpwnam = MagicMock(side_effect=[KeyError(), types.SimpleNamespace(pw_uid=900, pw_gid=900)])
        original_stat = Path.stat
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp); home = root / 'new-home'; state = root / 'state'; state.mkdir()
            conf = root / '71-ham-usa244.conf'
            stack.enter_context(patch.dict(sys.modules, {'pwd': fake_pwd}))
            for name, value in [('HOME_DIR', home), ('STATE', state), ('SSH_CONF', conf)]:
                stack.enter_context(patch.object(u, name, value))
            stack.enter_context(patch.object(u, 'guard'))
            stack.enter_context(patch.object(u.os, 'chown', create=True))
            stack.enter_context(patch.object(u.sys, 'stdin', io.StringIO(json.dumps({'usa2': public_key()}))))
            stack.enter_context(patch.object(u.socket, 'socket'))
            stack.enter_context(patch.object(u._base, 'backup_ssh'))
            stack.enter_context(patch.object(u, 'protected_snapshot', return_value={'unchanged': True}))
            stack.enter_context(patch.object(u._base, 'check_policy'))
            def stat(path, *args, **kwargs):
                actual = original_stat(path, *args, **kwargs)
                modes = {home: 0o700, home / '.ssh': 0o700, home / '.ssh/authorized_keys.pending': 0o600}
                if path not in modes: return actual
                values = list(actual); values[0] = (actual.st_mode & ~0o777) | modes[path]; values[4] = 900
                return os.stat_result(values)
            stack.enter_context(patch.object(Path, 'stat', autospec=True, side_effect=stat))
            def command(*args):
                if args[0] == 'useradd': home.mkdir()
                if args[:3] == ('systemctl', 'reload', 'ssh') and not conf.exists():
                    self.assertFalse((home / '.ssh/authorized_keys').exists())
                    self.assertTrue((home / '.ssh/authorized_keys.revoked').exists())
                return ''
            stack.enter_context(patch.object(u, 'run', side_effect=command))
            def save(name, value):
                if name == 'restricted-identity': raise RuntimeError('fixture late save failure')
            stack.enter_context(patch.object(u, 'save', side_effect=save))
            with self.assertRaisesRegex(RuntimeError, 'late save'):
                u.identity()
            self.assertTrue((home / '.ssh/authorized_keys.revoked').is_file())
            self.assertFalse(conf.exists())

    def test_atomic_new_file_refuses_overwrite_and_leaves_no_pending_on_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.conf'
            u.write_new(path, 'fixture\n', 0o600)
            self.assertEqual(path.read_text(), 'fixture\n')
            self.assertEqual(list(Path(tmp).iterdir()), [path])
            with self.assertRaises(RuntimeError): u.write_new(path, 'replacement', 0o600)
            self.assertEqual(path.read_text(), 'fixture\n')

    def test_stop_refuses_changed_service_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            unit = Path(tmp) / 'ham-usa244-reverse.service'; unit.write_text('fixture later edit')
            with patch.object(u, 'UNIT', unit), patch.object(u, 'guard'), \
                 patch.object(u, 'read', return_value={'sha256': 'fixture-original-hash'}), \
                 patch.object(u, 'run') as run, self.assertRaises(RuntimeError):
                u.stop()
            run.assert_not_called()

    def test_safe_new_dependencies_only(self):
        u.check_install_plan('Inst python3-paramiko (2.12 Ubuntu)\nInst python3-nacl (1.5 Ubuntu)\n'
                             'Inst python3-cryptography:amd64 (41 Ubuntu)\nConf python3-paramiko (2.12 Ubuntu)')
        for line in ('Remv nginx [1]', 'Inst nginx (1 Ubuntu)', 'Inst openssh-server (1 Ubuntu)',
                     'Inst python3-paramiko [2.9] (2.12 Ubuntu)', 'Inst python3-nacl [1] (2 Ubuntu)',
                     'Inst python3-paramiko', 'Inst python3-paramiko [2.9]'):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                u.check_install_plan(line)

    def test_successful_start_only_installs_scoped_packages_and_own_service(self):
        unit = MagicMock(); unit.exists.return_value = False; unit.is_symlink.return_value = False
        unit.name = 'ham-usa244-reverse.service'
        def command(*args):
            if args[0] == 'apt-get': return 'Inst python3-paramiko (2.12 Ubuntu)'
            if args[0] == '/usr/bin/python3':
                return json.dumps({'version': 'fixture', 'source': '/usr/lib/python3/dist-packages/paramiko/__init__.py'})
            if args[:2] == ('systemctl', 'is-active'): return 'active'
            return ''
        with patch.object(u, 'UNIT', unit), patch.object(u, 'guard'), patch.object(u, 'key_files'), \
             patch.object(u, 'read', return_value={'id': 'usa2', 'entry': u.ENTRY}), \
             patch.object(u.socket, 'create_connection') as connect, \
             patch.object(u, 'run', side_effect=command) as run, \
             patch.object(u, 'save'), patch.object(u, 'write_new') as write:
            result = u.start()
        self.assertTrue(result['usa_reverse_service_started'])
        connect.assert_called_once_with(('127.0.0.1', 15443), timeout=3)
        write.assert_called_once_with(unit, u.service_text(), 0o644)
        install = next(call.args for call in run.call_args_list if call.args[0] == 'env')
        for flag in ('--no-remove', '--no-upgrade', '--no-install-recommends', 'NEEDRESTART_MODE=l'):
            self.assertIn(flag, install)
        self.assertEqual(install[-1], 'python3-paramiko')
        self.assertFalse(any('ham-entry244-reverse' in str(call) for call in run.call_args_list))

    def test_failed_backend_prevents_any_package_install(self):
        unit = MagicMock(); unit.exists.return_value = False; unit.is_symlink.return_value = False
        with patch.object(u, 'UNIT', unit), patch.object(u, 'guard'), patch.object(u, 'key_files'), \
             patch.object(u, 'read', return_value={'id': 'usa2', 'entry': u.ENTRY}), \
             patch.object(u.socket, 'create_connection', side_effect=ConnectionRefusedError), \
             patch.object(u, 'run') as run, self.assertRaises(ConnectionRefusedError):
            u.start()
        run.assert_not_called()

    def test_unsafe_apt_plan_aborts_before_install_or_service_write(self):
        unit = MagicMock(); unit.exists.return_value = False; unit.is_symlink.return_value = False
        with patch.object(u, 'UNIT', unit), patch.object(u, 'guard'), patch.object(u, 'key_files'), \
             patch.object(u, 'read', return_value={'id': 'usa2', 'entry': u.ENTRY}), \
             patch.object(u.socket, 'create_connection'), \
             patch.object(u, 'run', side_effect=['', 'Inst python3-paramiko [2] (3 Ubuntu)']) as run, \
             patch.object(u, 'write_new') as write, self.assertRaises(RuntimeError):
            u.start()
        write.assert_not_called()
        self.assertFalse(any(call.args[0] == 'env' for call in run.call_args_list))

    def test_unit_only_runs_usa_worker_with_bounded_resources(self):
        text = u.service_text()
        self.assertIn('usa244reverse.py worker\n', text)
        for value in ('StartLimitIntervalSec=0', 'Restart=always', 'ProtectSystem=strict',
                      'ProtectHome=true', 'TasksMax=1152', 'UMask=0077', 'CapabilityBoundingSet='):
            self.assertIn(value, text)
        for value in ('reverse244_client.py', 'ham-exits244', 'ExecStartPre=', 'ExecStopPost=',
                      'PartOf=', 'BindsTo=', 'Requires=', 'nginx.service', 'ssh.service'):
            self.assertNotIn(value, text)

    def test_cli_error_never_prints_exception_details(self):
        with patch.object(u.sys, 'argv', ['usa244reverse.py', 'start']), \
             patch.object(u, 'start', side_effect=RuntimeError('FIXTURE_PRIVATE_SENTINEL')), \
             patch.object(u.os, 'umask'), contextlib.redirect_stderr(io.StringIO()) as output, \
             self.assertRaises(SystemExit):
            u.main()
        result = json.loads(output.getvalue())
        self.assertTrue(result['failed'])
        self.assertNotIn('SENTINEL', output.getvalue())


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.worker = mock_worker()

    def test_worker_isolated_target_is_15443(self):
        self.assertEqual(self.worker.TARGET, ('127.0.0.1', 15443))
        self.assertNotEqual(self.worker.TARGET[1], 443)
        self.assertEqual(u._base.USER, u.USER)

    def test_connect_pins_host_source_identity_and_own_listener(self):
        ssh, raw = MagicMock(), MagicMock()
        transport = ssh.get_transport.return_value
        transport.request_port_forward.return_value = 25443
        transport.is_active.return_value = False
        with patch.object(self.worker.paramiko, 'SSHClient', return_value=ssh), \
             patch.object(self.worker.socket, 'create_connection', return_value=raw) as connect, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'disconnected'):
            u.connect_and_forward(self.worker)
        connect.assert_called_once_with((u.ENTRY, u.SSH_PORT), timeout=10, source_address=(u.SOURCE, 0))
        ssh.load_host_keys.assert_called_once_with(str(u.KEY_DIR / 'known_hosts'))
        self.assertIsInstance(ssh.set_missing_host_key_policy.call_args.args[0], self.worker.paramiko.RejectPolicy)
        args = ssh.connect.call_args.kwargs
        self.assertEqual(args['username'], 'ham-usa244')
        self.assertEqual(args['key_filename'], str(u.KEY_DIR / 'reverse_key'))
        self.assertFalse(args['allow_agent']); self.assertFalse(args['look_for_keys'])
        self.assertEqual(transport.request_port_forward.call_args.args, ('127.0.0.1', 25443))
        transport.set_keepalive.assert_called_once_with(15)
        raw.setsockopt.assert_any_call(self.worker.socket.SOL_SOCKET, self.worker.socket.SO_KEEPALIVE, 1)
        ssh.exec_command.assert_not_called(); transport.open_session.assert_not_called()
        ssh.close.assert_called_once(); raw.close.assert_called_once()

    def test_failed_auth_and_wrong_port_close_both_connections(self):
        for authenticated, port in ((False, 25443), (True, 22)):
            with self.subTest(authenticated=authenticated, port=port):
                ssh, raw = MagicMock(), MagicMock()
                transport = ssh.get_transport.return_value
                transport.is_authenticated.return_value = authenticated
                transport.request_port_forward.return_value = port
                with patch.object(self.worker.paramiko, 'SSHClient', return_value=ssh), \
                     patch.object(self.worker.socket, 'create_connection', return_value=raw), \
                     self.assertRaises(RuntimeError):
                    u.connect_and_forward(self.worker)
                ssh.close.assert_called_once(); raw.close.assert_called_once()
                if not authenticated: transport.request_port_forward.assert_not_called()

    def test_bad_pinned_host_file_fails_before_network_and_closes_client(self):
        ssh = MagicMock(); ssh.load_host_keys.side_effect = ValueError('fixture bad pin')
        with patch.object(self.worker.paramiko, 'SSHClient', return_value=ssh), \
             patch.object(self.worker.socket, 'create_connection') as connect, self.assertRaises(ValueError):
            u.connect_and_forward(self.worker)
        connect.assert_not_called(); ssh.close.assert_called_once()

    def test_wrong_destination_or_full_capacity_never_spawns(self):
        slots = threading.BoundedSemaphore(1)
        callback = self.worker.incoming_handler(u.NODE, slots)
        for destination in (('0.0.0.0', 25443), ('127.0.0.1', 21443), ('localhost', 25443), ('::1', 25443)):
            channel = MagicMock()
            with patch.object(self.worker.threading, 'Thread') as thread:
                callback(channel, None, destination)
                thread.assert_not_called()
            channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))
        channel = MagicMock()
        with patch.object(self.worker.threading, 'Thread') as thread:
            callback(channel, None, ('127.0.0.1', 25443))
            thread.assert_not_called()
        channel.close.assert_called_once()

    def test_thread_failure_releases_usa_slot(self):
        slots = threading.BoundedSemaphore(1); channel = MagicMock()
        with patch.object(self.worker.threading, 'Thread') as thread:
            thread.return_value.start.side_effect = RuntimeError('fixture thread limit')
            self.worker.incoming_handler(u.NODE, slots)(channel, None, ('127.0.0.1', 25443))
        channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_relay_targets_legacy_15443_and_preserves_half_close(self):
        slots = threading.BoundedSemaphore(1); slots.acquire()
        channel, target = MagicMock(), MagicMock()
        channel.closed = False; channel.recv.side_effect = [b'']
        target.recv.side_effect = [b'tail', b'']
        with patch.object(self.worker.socket, 'create_connection', return_value=target) as connect, \
             patch.object(self.worker.select, 'select', side_effect=[([channel], [], []), ([target], [], []), ([target], [], [])]):
            self.worker.relay(channel, slots)
        connect.assert_called_once_with(('127.0.0.1', 15443), timeout=10)
        target.shutdown.assert_called_once_with(self.worker.socket.SHUT_WR)
        channel.sendall.assert_called_once_with(b'tail')
        self.assertTrue(slots.acquire(blocking=False))

    def test_target_failure_releases_slot(self):
        slots = threading.BoundedSemaphore(1); slots.acquire(); channel = MagicMock()
        with patch.object(self.worker.socket, 'create_connection', side_effect=ConnectionRefusedError):
            self.worker.relay(channel, slots)
        channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))


if __name__ == '__main__': unittest.main()
