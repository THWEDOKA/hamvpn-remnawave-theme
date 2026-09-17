"""Offline contracts only. Synthetic keys; no SSH, apt, API, or service calls."""
import base64
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import MagicMock, patch

import reverse as p
if importlib.util.find_spec('paramiko') is None:
    stub = types.ModuleType('paramiko'); stub.SSHException = type('SSHException', (Exception,), {})
    stub.SSHClient = MagicMock(); stub.RejectPolicy = type('RejectPolicy', (), {})
    with patch.dict(sys.modules, {'paramiko': stub}): import reverse_client as c
else: import reverse_client as c


def key(index):
    return 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + bytes([index]) * 32).decode() + ' test'


def effective(node):
    return '\n'.join(k.lower() + ' ' + v for k, v in p.ssh_policy(node).items()) + '\ndisableforwarding no'


class PolicyTests(unittest.TestCase):
    def setUp(self): self.keys = {n['id']: key(i) for i, n in enumerate(p.NODES, 1)}

    def test_exact_mapping(self):
        self.assertEqual(p.ENTRY, '176.108.245.140')
        self.assertEqual([(n['id'], n['ip'], n['link']) for n in p.NODES],
                         [('kz2', '206.223.240.179', 27443), ('de245', '196.251.107.245', 28443)])
        self.assertEqual(p.TARGET, ('127.0.0.1', 15443))

    def test_distinct_single_key_and_single_listener_per_user(self):
        keys = p.authorized_keys(self.keys)
        self.assertEqual(len(keys), len(p.NODES))
        for n in p.NODES:
            line = keys[n['id']]
            self.assertEqual(len(line.splitlines()), 1)
            self.assertIn('from="' + n['ip'] + '",restrict,port-forwarding,command="/bin/false",', line)
            self.assertIn('permitlisten="127.0.0.1:' + str(n['link']) + '"', line)
            self.assertEqual(line.count('permitlisten='), 1)
            self.assertEqual(p.ssh_policy(n)['PermitListen'], '127.0.0.1:' + str(n['link']))

    def test_counts_follow_selected_nodes_not_four(self):
        with patch.object(p, 'NODES', p.NODES[:1]):
            self.assertEqual(len(p.authorized_keys({'kz2': key(1)})), 1)
            self.assertEqual(p.policy_text().count('Match User '), 1)

    def test_missing_extra_duplicate_and_injected_keys_rejected(self):
        for keys in ({}, {'kz2': key(1)}, {**self.keys, 'extra': key(3)},
                     {'kz2': key(1), 'de245': key(1).replace(' test', ' other')},
                     {**self.keys, 'kz2': key(1) + '\n' + key(9)}):
            with self.subTest(keys=list(keys)), self.assertRaises(RuntimeError): p.authorized_keys(keys)

    def test_malformed_ed25519(self):
        for value in ('ssh-rsa AAAA', 'ssh-ed25519 '+base64.b64encode(b'x'*51).decode(), key(1)+' options="x"'):
            with self.assertRaises(RuntimeError): p.public_blob(value)

    def test_route_tampering_rejected(self):
        for change in ({'link': 21443}, {'link': 22}, {'user': 'root'}, {'ip': '127.0.0.1'}):
            with patch.object(p, 'NODES', ({**p.NODES[0], **change}, p.NODES[1])), self.assertRaises(RuntimeError): p.authorized_keys(self.keys)

    def test_known_host_is_exact_single_entry_only(self):
        self.assertEqual(p.known_host(p.ENTRY+' '+key(1)), p.ENTRY+' '+key(1)+'\n')
        for value in ('* '+key(1), '[176.108.245.140]:2222 '+key(1), p.ENTRY+' '+key(1)+'\nother '+key(2)):
            with self.assertRaises(RuntimeError): p.known_host(value)

    def test_every_policy_denies_alternative_auth_and_sessions(self):
        for n in p.NODES:
            policy = p.ssh_policy(n)
            for field, expected in {'MaxSessions':'0', 'AllowTcpForwarding':'remote', 'PermitOpen':'none',
                                   'GatewayPorts':'no', 'AuthorizedKeysCommand':'none', 'TrustedUserCAKeys':'none',
                                   'PasswordAuthentication':'no', 'PermitTTY':'no', 'ForceCommand':'/bin/false'}.items():
                self.assertEqual(policy[field], expected)
            p.check_policy(effective(n), n)
            p.check_policy(effective(n).replace('permittunnel no','permittunnel false'), n)
        self.assertTrue(p.policy_text().endswith('Match all\n'))

    def test_first_match_overrides_fail_closed(self):
        n=p.NODES[0]
        for old,new in [('maxsessions 0','maxsessions 10'), ('allowtcpforwarding remote','allowtcpforwarding yes'),
                        ('disableforwarding no','disableforwarding yes'), ('permitlisten 127.0.0.1:27443','permitlisten any'),
                        ('permitopen none','permitopen any')]:
            with self.subTest(old=old), self.assertRaises(RuntimeError): p.check_policy(effective(n).replace(old,new),n)

    def test_both_operator_policies_all_contexts(self):
        with patch.object(p,'effective',side_effect=lambda user,ip:user+'-'+ip) as call:
            before=p.operators(['127.0.0.1','192.0.2.1'])
        self.assertEqual(call.call_count,4)
        self.assertEqual(set(before),{'root','gasan'})
        p.check_operators(before,before)
        for user in before:
            after={**before,user:{'127.0.0.1':'changed'}}
            with self.assertRaises(RuntimeError):p.check_operators(before,after)

    def test_apt_only_new_approved_packages(self):
        self.assertEqual(p.check_install_plan('Inst python3-paramiko (3.4 Ubuntu)\nConf python3-paramiko (3.4 Ubuntu)'),['python3-paramiko'])
        for plan in ('Remv nginx [1]', 'Inst openssh-server (1)', 'Inst python3-paramiko [2] (3)',
                     'Conf nginx (1)', 'Inst python3-paramiko:amd64 (3)'):
            with self.assertRaises(RuntimeError):p.check_install_plan(plan)

    def test_start_does_not_install_packages_or_restart_vpn(self):
        import inspect
        self.assertNotIn('apt-get',inspect.getsource(p.start))
        for n in p.NODES:
            text=p.service_text(n)
            self.assertIn('reverse_client.py --id '+n['id']+'\n',text)
            self.assertIn('RestartSec=5',text)
            for unsafe in ('ExecStartPre=', 'ExecStopPost=', 'PartOf=', 'BindsTo=', 'Requires=', 'xray.service','nginx.service','ssh.service','remnanode.service'):
                self.assertNotIn(unsafe,text)

    def test_archive_before_useradd_and_revoke_before_policy_removal(self):
        import inspect
        source=inspect.getsource(p.identity)
        self.assertLess(source.index('backup_ssh(accounts)'),source.index("run('useradd'"))
        self.assertLess(source.index('authorized.rename'),source.index('SSH_CONF.rename'))
        self.assertIn("archive.open('xb')",inspect.getsource(p.backup_ssh))
        self.assertIn('os.fsync(handle.fileno())',inspect.getsource(p.backup_ssh))

    def test_exclusive_creation_never_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'state.json';path.write_bytes(b'original')
            with self.assertRaises(FileExistsError):p.create(path,b'replacement')
            self.assertEqual(path.read_bytes(),b'original')

    def test_systemd_absent_is_not_confused_with_failure(self):
        for status in (0,1,4):
            result=types.SimpleNamespace(returncode=status,stdout='LoadState=not-found\nMainPID=0\n')
            with patch.object(p.subprocess,'run',return_value=result):
                self.assertEqual(p.unit_info('missing.service'),{'LoadState':'not-found'})
        for status,output in [(1,''),(1,'LoadState=loaded\n'),(0,'LoadState=masked\n'),(5,'LoadState=not-found\n')]:
            with patch.object(p.subprocess,'run',return_value=types.SimpleNamespace(returncode=status,stdout=output)),self.assertRaises(RuntimeError):
                p.unit_info('test.service')

    def test_plan_never_runs_apt_install(self):
        with patch.object(p,'run',return_value='Inst python3-paramiko (3.4 Ubuntu)') as run:
            self.assertEqual(p.runtime_plan(),['python3-paramiko'])
        self.assertEqual(run.call_args.args,('apt-get','-s','--no-remove','--no-upgrade','--no-install-recommends','install','python3-paramiko'))


class ClientTests(unittest.TestCase):
    def test_acknowledged_health_accepts_protocol_denial_not_silence(self):
        transport=MagicMock(); transport.global_request.return_value=None
        transport.is_active.return_value=True
        with patch.object(c.threading,'Timer') as timer:c.acknowledged_health(transport)
        transport.global_request.assert_called_once_with('keepalive@openssh.com',wait=True)
        timer.return_value.cancel.assert_called_once()

    def test_acknowledged_health_deadline_closes_stuck_transport(self):
        transport=MagicMock(); transport.is_active.return_value=True
        def timer_factory(seconds, callback):
            timer=MagicMock(); timer.start.side_effect=callback; return timer
        with patch.object(c.threading,'Timer',side_effect=timer_factory),self.assertRaisesRegex(RuntimeError,'deadline'):
            c.acknowledged_health(transport)
        transport.close.assert_called_once()

    def test_acknowledged_health_rejects_disconnection(self):
        transport=MagicMock(); transport.is_active.return_value=False
        with patch.object(c.threading,'Timer'),self.assertRaisesRegex(RuntimeError,'deadline'):
            c.acknowledged_health(transport)

    def test_no_wildcard_other_identity_port_or_other_loopback(self):
        node=p.NODES[0];slots=threading.BoundedSemaphore(1)
        for dest in [('0.0.0.0',27443),('127.0.0.1',28443),('localhost',27443),('::1',27443)]:
            channel=MagicMock()
            with patch.object(c.threading,'Thread') as thread:c.incoming_handler(node,slots)(channel,None,dest);thread.assert_not_called()
            channel.close.assert_called_once()
        self.assertTrue(slots.acquire(blocking=False))

    def test_capacity_bound(self):
        slots=threading.BoundedSemaphore(1);slots.acquire();channel=MagicMock()
        with patch.object(c.threading,'Thread') as thread:
            c.incoming_handler(p.NODES[0],slots)(channel,None,('127.0.0.1',27443));thread.assert_not_called()
        channel.close.assert_called_once()

    def test_thread_failure_releases_slot(self):
        slots=threading.BoundedSemaphore(1);channel=MagicMock()
        with patch.object(c.threading,'Thread') as thread:
            thread.return_value.start.side_effect=RuntimeError()
            c.incoming_handler(p.NODES[0],slots)(channel,None,('127.0.0.1',27443))
        channel.close.assert_called_once();self.assertTrue(slots.acquire(blocking=False))

    def test_half_close_preserves_response_tail_both_directions(self):
        for client_first in (True,False):
            slots=threading.BoundedSemaphore(1);slots.acquire();channel,target=MagicMock(),MagicMock();channel.closed=False
            first,second=(channel,target) if client_first else (target,channel)
            first.recv.side_effect=[b''];second.recv.side_effect=[b'tail',b'']
            with patch.object(c.socket,'create_connection',return_value=target) as connect, \
                 patch.object(c.select,'select',side_effect=[([first],[],[]),([second],[],[]),([second],[],[])]):c.relay(channel,slots)
            connect.assert_called_once_with(('127.0.0.1',15443),timeout=10)
            first.sendall.assert_called_once_with(b'tail');target.shutdown.assert_called_once_with(socket_shutdown())
            channel.shutdown_write.assert_called_once();self.assertTrue(slots.acquire(blocking=False))

    def test_idle_bound(self):
        slots=threading.BoundedSemaphore(1);slots.acquire();channel,target=MagicMock(),MagicMock();channel.closed=False
        with patch.object(c.socket,'create_connection',return_value=target),patch.object(c.time,'monotonic',side_effect=[0,c.IDLE_TIMEOUT+1]),patch.object(c.select,'select') as select:
            c.relay(channel,slots);select.assert_not_called()
        channel.close.assert_called_once();self.assertTrue(slots.acquire(blocking=False))

    def test_half_close_deadline(self):
        slots=threading.BoundedSemaphore(1);slots.acquire();channel,target=MagicMock(),MagicMock();channel.closed=False
        channel.recv.return_value=b''
        with patch.object(c.socket,'create_connection',return_value=target), \
             patch.object(c.time,'monotonic',side_effect=[0,0,0,c.HALF_CLOSE_TIMEOUT+1]), \
             patch.object(c.select,'select',return_value=([channel],[],[])) as select:
            c.relay(channel,slots)
        select.assert_called_once();target.shutdown.assert_called_once_with(c.socket.SHUT_WR)
        self.assertTrue(slots.acquire(blocking=False))

    def test_target_failure_releases_slot(self):
        slots=threading.BoundedSemaphore(1);slots.acquire();channel=MagicMock()
        with patch.object(c.socket,'create_connection',side_effect=ConnectionRefusedError):c.relay(channel,slots)
        channel.close.assert_called_once();self.assertTrue(slots.acquire(blocking=False))

    def test_pinned_host_unique_username_and_only_own_forward(self):
        for node in p.NODES:
            ssh,raw=MagicMock(),MagicMock();transport=ssh.get_transport.return_value
            transport.request_port_forward.return_value=node['link'];transport.is_active.side_effect=[True,False]
            with patch.object(c.paramiko,'SSHClient',return_value=ssh),patch.object(c.socket,'create_connection',return_value=raw),patch.object(c.threading,'Timer') as timer,patch('sys.stdout',new_callable=io.StringIO),self.assertRaisesRegex(RuntimeError,'disconnected'):
                c.connect_and_forward(node)
            ssh.load_host_keys.assert_called_once_with(str(p.KEY_DIR/'known_hosts'))
            self.assertIsInstance(ssh.set_missing_host_key_policy.call_args.args[0],c.paramiko.RejectPolicy)
            args=ssh.connect.call_args.kwargs
            self.assertEqual(args['username'],node['user']);self.assertFalse(args['allow_agent']);self.assertFalse(args['look_for_keys'])
            self.assertEqual(transport.request_port_forward.call_args.args,('127.0.0.1',node['link']))
            transport.set_keepalive.assert_called_once_with(0)
            timer.assert_called_once_with(20,transport.close);timer.return_value.cancel.assert_called_once()
            ssh.exec_command.assert_not_called();transport.open_session.assert_not_called()
            ssh.close.assert_called_once();raw.close.assert_called_once()

    def test_wrong_forwarded_port_closes_transport(self):
        ssh,raw=MagicMock(),MagicMock();ssh.get_transport.return_value.request_port_forward.return_value=22
        with patch.object(c.paramiko,'SSHClient',return_value=ssh),patch.object(c.socket,'create_connection',return_value=raw),patch.object(c.threading,'Timer'),self.assertRaisesRegex(RuntimeError,'listener'):
            c.connect_and_forward(p.NODES[0])
        ssh.close.assert_called_once();raw.close.assert_called_once()


def socket_shutdown():return c.socket.SHUT_WR
if __name__=='__main__':unittest.main()
