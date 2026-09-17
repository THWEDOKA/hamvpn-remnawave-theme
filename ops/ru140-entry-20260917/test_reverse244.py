"""Narrow, offline contract tests. No server access or production key material."""
import base64
import importlib.util
import io
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import MagicMock, patch

import reverse244 as provision

if importlib.util.find_spec('paramiko') is None:
    # Windows test runtime need not install Paramiko; SSH contract is mocked below.
    stub = types.ModuleType('paramiko')
    stub.SSHException = type('SSHException', (Exception,), {})
    stub.SSHClient = MagicMock()
    stub.RejectPolicy = type('RejectPolicy', (), {})
    with patch.dict(sys.modules, {'paramiko': stub}):
        import reverse244_client as client
else:
    import reverse244_client as client


def public_key(index):
    blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes([index]) * 32
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' test-only'


class Restrictions(unittest.TestCase):
    def setUp(self):
        self.keys = {n['id']: public_key(i) for i, n in enumerate(provision.NODES, 1)}

    def test_exact_four_source_bound_keys_and_loopback_ports(self):
        lines = provision.authorized_keys(self.keys).splitlines()
        self.assertEqual(len(lines), 4)
        for node, line in zip(provision.NODES, lines):
            self.assertTrue(line.startswith('from="' + node['ip'] + '",restrict,port-forwarding,'
                                            'permitlisten="127.0.0.1:' + str(node['link']) + '" '))
            self.assertEqual(line.count('permitlisten='), 1)

    def test_duplicate_key_with_different_comment_rejected(self):
        ids = list(self.keys)
        self.keys[ids[1]] = self.keys[ids[0]].replace('test-only', 'different-comment')
        with self.assertRaises(RuntimeError): provision.authorized_keys(self.keys)

    def test_missing_extra_and_injected_keys_rejected(self):
        first = next(iter(self.keys))
        for keys in [{k: v for k, v in self.keys.items() if k != first},
                     {**self.keys, 'other': public_key(9)},
                     {**self.keys, first: self.keys[first] + '\nssh-ed25519 bad'},
                     {**self.keys, first: 'ssh-ed25519 ' + base64.b64encode(b'x' * 51).decode()}]:
            with self.subTest(keys_count=len(keys)), self.assertRaises(RuntimeError):
                provision.authorized_keys(keys)

    def test_wrong_ports_rejected(self):
        nodes = [dict(n) for n in provision.NODES]
        nodes[0]['link'] = 22
        with patch.object(provision, 'NODES', nodes), self.assertRaises(RuntimeError):
            provision.authorized_keys(self.keys)

    def test_policy_denies_sessions_and_alternative_auth(self):
        policy = provision.ssh_policy()
        self.assertEqual(policy['AllowTcpForwarding'], 'remote')
        self.assertEqual(policy['PermitOpen'], 'none')
        self.assertEqual(policy['MaxSessions'], '0')
        self.assertEqual(policy['GatewayPorts'], 'no')
        self.assertEqual(policy['AuthorizedKeysCommand'], 'none')
        self.assertEqual(policy['TrustedUserCAKeys'], 'none')
        self.assertEqual(policy['PubkeyAcceptedAlgorithms'], 'ssh-ed25519')
        self.assertEqual(policy['AuthorizedKeysFile'], str(provision.HOME_DIR / '.ssh/authorized_keys'))
        self.assertTrue(provision.policy_text().endswith('Match all\n'))

    def test_effective_policy_and_first_match_override(self):
        output = '\n'.join(k.lower() + ' ' + v for k, v in provision.ssh_policy().items()) + '\ndisableforwarding no'
        provision.check_policy(output)
        provision.check_policy(output.replace('permittunnel no', 'permittunnel false'))
        for old, new in [('maxsessions 0', 'maxsessions 10'), ('allowtcpforwarding remote', 'allowtcpforwarding yes'),
                         ('disableforwarding no', 'disableforwarding yes'),
                         ('authorizedkeyscommand none', 'authorizedkeyscommand /some/helper')]:
            with self.subTest(old=old), self.assertRaises(RuntimeError):
                provision.check_policy(output.replace(old, new))

    def test_apt_plan_cannot_upgrade_or_remove_other_services(self):
        provision.check_install_plan('Inst python3-paramiko (2.12.0 Ubuntu)\nInst python3-nacl (1.5 Ubuntu)')
        for line in ['Remv nginx [1]', 'Inst xray (1)', 'Inst python3-paramiko [2.9] (2.12)']:
            with self.subTest(line=line), self.assertRaises(RuntimeError): provision.check_install_plan(line)

    def test_unit_only_runs_reverse_client(self):
        text = provision.service_text(provision.NODES[0])
        self.assertIn('ExecStart=/usr/bin/python3 ', text)
        self.assertIn('reverse244_client.py --id de182\n', text)
        self.assertIn('StartLimitIntervalSec=0', text)
        self.assertIn('Restart=always', text)
        for directive in ['ExecStartPre=', 'ExecStopPost=', 'PartOf=', 'BindsTo=', 'Requires=',
                          'xray.service', 'nginx.service', 'remnawave.service', 'ssh.service']:
            self.assertNotIn(directive, text)

    def test_identity_archive_and_rollback_order(self):
        source = Path(provision.__file__).read_text()
        identity = source[source.index('def identity():'):source.index('def service_text(')]
        self.assertLess(identity.index('backup_ssh()'), identity.index("run('useradd'"))
        self.assertLess(identity.index('authorized.rename'), identity.index('SSH_CONF.rename'))
        self.assertIn("archive.open('xb')", source)
        self.assertIn('os.fsync(handle.fileno())', source)
        self.assertIn("bundle.add('/etc/ssh'", source)


class ClientContracts(unittest.TestCase):
    def test_rejects_wildcard_other_port_and_hostname(self):
        node = provision.NODES[0]
        slots = threading.BoundedSemaphore(1)
        callback = client.incoming_handler(node, slots)
        for destination in [('0.0.0.0', node['link']), ('127.0.0.1', 22), ('localhost', node['link']), ('::1', node['link'])]:
            channel = MagicMock()
            with patch.object(client.threading, 'Thread') as thread:
                callback(channel, ('127.0.0.1', 1234), destination)
                thread.assert_not_called()
            channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_thread_start_failure_releases_slot(self):
        slots = threading.BoundedSemaphore(1)
        channel = MagicMock()
        with patch.object(client.threading, 'Thread') as thread:
            thread.return_value.start.side_effect = RuntimeError('thread limit')
            client.incoming_handler(provision.NODES[0], slots)(channel, None, ('127.0.0.1', 21443))
        channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_capacity_rejects_without_spawning(self):
        slots = threading.BoundedSemaphore(1); slots.acquire()
        channel = MagicMock()
        with patch.object(client.threading, 'Thread') as thread:
            client.incoming_handler(provision.NODES[0], slots)(channel, None, ('127.0.0.1', 21443))
            thread.assert_not_called()
        channel.close.assert_called_once()

    def test_relay_fixed_target_preserves_half_closed_response(self):
        slots = threading.BoundedSemaphore(1); slots.acquire()
        channel, target = MagicMock(), MagicMock()
        channel.closed = False
        channel.recv.side_effect = [b'']
        target.recv.side_effect = [b'response-tail', b'']
        with patch.object(client.socket, 'create_connection', return_value=target) as connect, \
             patch.object(client.select, 'select', side_effect=[([channel], [], []), ([target], [], []), ([target], [], [])]):
            client.relay(channel, slots)
        connect.assert_called_once_with(('127.0.0.1', 443), timeout=10)
        target.shutdown.assert_called_once_with(client.socket.SHUT_WR)
        channel.sendall.assert_called_once_with(b'response-tail')
        channel.shutdown_write.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_failed_target_releases_slot(self):
        slots = threading.BoundedSemaphore(1); slots.acquire()
        channel = MagicMock()
        with patch.object(client.socket, 'create_connection', side_effect=ConnectionRefusedError):
            client.relay(channel, slots)
        channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_all_nodes_pin_host_and_only_request_own_loopback_listener(self):
        for node in provision.NODES:
            with self.subTest(node=node['id']):
                ssh, raw = MagicMock(), MagicMock()
                transport = ssh.get_transport.return_value
                transport.request_port_forward.return_value = node['link']
                transport.is_active.return_value = False
                with patch.object(client.paramiko, 'SSHClient', return_value=ssh), \
                     patch.object(client.socket, 'create_connection', return_value=raw) as connect, \
                     patch('sys.stdout', new_callable=io.StringIO), \
                     self.assertRaisesRegex(RuntimeError, 'disconnected'):
                    client.connect_and_forward(node)
                connect.assert_called_once_with((provision.ENTRY, 22), timeout=10)
                ssh.load_host_keys.assert_called_once_with('/etc/hamvpn-entry244/known_hosts')
                self.assertIsInstance(ssh.set_missing_host_key_policy.call_args.args[0], client.paramiko.RejectPolicy)
                kwargs = ssh.connect.call_args.kwargs
                self.assertFalse(kwargs['allow_agent']); self.assertFalse(kwargs['look_for_keys'])
                self.assertEqual(kwargs['username'], 'ham-exits244')
                self.assertEqual(transport.request_port_forward.call_args.args, ('127.0.0.1', node['link']))
                ssh.exec_command.assert_not_called(); transport.open_session.assert_not_called()
                ssh.close.assert_called_once(); raw.close.assert_called_once()

    def test_wrong_returned_port_fails_closed(self):
        ssh, raw = MagicMock(), MagicMock()
        ssh.get_transport.return_value.request_port_forward.return_value = 22
        with patch.object(client.paramiko, 'SSHClient', return_value=ssh), \
             patch.object(client.socket, 'create_connection', return_value=raw), \
             self.assertRaisesRegex(RuntimeError, 'listener port'):
            client.connect_and_forward(provision.NODES[0])
        ssh.close.assert_called_once(); raw.close.assert_called_once()


if __name__ == '__main__': unittest.main()
