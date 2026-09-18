from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import mihomo_auto_operator as o


class OperatorTests(unittest.TestCase):
    def test_cli_fixed_route_and_release(self):
        command = o.remote_command('a'*12, 'export', True)
        self.assertIn(' local export --secret-stdout', command)
        self.assertNotIn('PATCH', command)
        for invalid in ('main', 'a'*12+';x', '../secret'):
            with self.assertRaises(ValueError): o.remote_command(invalid, 'apply')
        with self.assertRaises(ValueError): o.remote_command('a'*12, 'delete')

    def test_independent_timer_exact_command_owner_and_deadline(self):
        sha = 'b'*64
        root = PurePosixPath('/opt/hamvpn-cloud140-six/releases/'+'a'*12+'/ops/cloud140-six-20260918')
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            output = ''
            if 'show' in args and args[2].endswith('.timer'):
                output = 'LoadState=loaded\nActiveState=active\nUnit='+o.TIMER+'.service\nNextElapseUSecMonotonic=20min\nJob=0\n'
            elif 'show' in args:
                output = 'LoadState=loaded\nActiveState=inactive\nMainPID=0\nJob=0\nExecStart={ argv[]='+' '.join(timer.command(sha))+' ; }'
            return SimpleNamespace(returncode=0, stdout=output)
        with patch.object(o, 'ROOT', root):
            timer = o.Timer(run)
            self.assertTrue(timer.active(sha))
            self.assertIn('rollback', timer.command(sha))
            with self.assertRaises(ValueError): timer.active('c'*64)
        self.assertTrue(all(call[0] == 'systemctl' for call in calls))

    def test_timer_refuses_unpublished_script(self):
        with patch.object(o, 'ROOT', Path('/tmp/unpublished')):
            with self.assertRaises(ValueError): o.Timer().command('b'*64)

    def test_service_running_queued_or_failed_not_reported_off(self):
        root = PurePosixPath('/opt/hamvpn-cloud140-six/releases/'+'a'*12+'/ops/cloud140-six-20260918')
        for active, job in [('active', '0'), ('activating', '12'), ('inactive', '12'), ('failed', '0')]:
            def run(args, **kwargs):
                if args[2].endswith('.timer'):
                    output = 'LoadState=loaded\nActiveState=inactive\nJob=0\n'
                else:
                    output = 'LoadState=loaded\nActiveState='+active+'\nMainPID=123\nJob='+job+'\nExecStart={ argv[]='+' '.join(timer.command('b'*64))+' ; }'
                return SimpleNamespace(returncode=0, stdout=output)
            with patch.object(o, 'ROOT', root):
                timer = o.Timer(run)
                self.assertTrue(timer.active('b'*64))
                with self.assertRaises(ValueError): timer.arm('b'*64)

    def test_own_service_not_stopped_and_not_falsely_reported_inactive(self):
        root = PurePosixPath('/opt/hamvpn-cloud140-six/releases/'+'a'*12+'/ops/cloud140-six-20260918')
        calls = []; states = {'timer': 'active', 'service': 'active'}
        def run(args, **kwargs):
            calls.append(args)
            is_timer = args[2].endswith('.timer')
            if args[1] == 'stop':
                self.assertTrue(is_timer); states['timer'] = 'inactive'; output = ''
            elif is_timer:
                output = 'LoadState=loaded\nActiveState='+states['timer']+'\nUnit='+o.TIMER+'.service\nNextElapseUSecMonotonic=20min\nJob=0\n'
            else:
                output = 'LoadState=loaded\nActiveState=active\nMainPID=555\nJob=0\nExecStart={ argv[]='+' '.join(timer.command('b'*64))+' ; }'
            return SimpleNamespace(returncode=0, stdout=output)
        with patch.object(o, 'ROOT', root), patch.object(o.os, 'getpid', return_value=555):
            timer = o.Timer(run); timer.disarm('b'*64)
            self.assertTrue(timer.is_current_rollback('b'*64))
            self.assertFalse(timer.status('b'*64)['all_inactive'])
            self.assertTrue(timer.active('b'*64))
        self.assertFalse(any(a[1] == 'stop' and a[2].endswith('.service') for a in calls))

    def test_cancel_other_owned_service_verifies_both_inactive(self):
        root = PurePosixPath('/opt/hamvpn-cloud140-six/releases/'+'a'*12+'/ops/cloud140-six-20260918')
        states = {'timer': 'active', 'service': 'activating'}
        def run(args, **kwargs):
            unit = 'timer' if args[2].endswith('.timer') else 'service'
            if args[1] == 'stop': states[unit] = 'inactive'; output = ''
            elif unit == 'timer':
                output = 'LoadState=loaded\nActiveState='+states[unit]+'\nUnit='+o.TIMER+'.service\nNextElapseUSecMonotonic=20min\nJob=0\n'
            else:
                output = 'LoadState=loaded\nActiveState='+states[unit]+'\nMainPID=123\nJob=0\nExecStart={ argv[]='+' '.join(timer.command('b'*64))+' ; }'
            return SimpleNamespace(returncode=0, stdout=output)
        with patch.object(o, 'ROOT', root), patch.object(o.os, 'getpid', return_value=555):
            timer = o.Timer(run); timer.disarm('b'*64)
            self.assertTrue(timer.status('b'*64)['all_inactive'])
            self.assertFalse(timer.active('b'*64))


if __name__ == '__main__': unittest.main()
