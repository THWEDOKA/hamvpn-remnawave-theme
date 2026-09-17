import unittest
from unittest.mock import patch
import usa244forward as f


class ForwardTests(unittest.TestCase):
    def test_restricted_local_direction_and_fixed_target(self):
        f.helper();policy=f.policy()
        self.assertEqual(policy['AllowTcpForwarding'],'local')
        self.assertEqual(policy['PermitOpen'],'127.0.0.1:15443')
        self.assertEqual(policy['PermitListen'],'none')
        self.assertEqual(policy['MaxSessions'],'0')
        self.assertEqual(policy['PasswordAuthentication'],'no')

    def test_ssh_args_preserve_trust_and_loopback_only(self):
        args=f.ssh_args()
        self.assertIn('127.0.0.1:25443:127.0.0.1:15443',args)
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('ExitOnForwardFailure=yes',args)
        self.assertIn('IdentitiesOnly=yes',args)
        self.assertEqual(args[-1],f.USER+'@'+f.EXIT)

    def test_identity_does_not_accept_other_sources_or_targets(self):
        with patch.object(f.base,'public_blob'):
            line=f.authorized({'entry244':'ssh-ed25519 FAKE'})
        self.assertIn('from="193.233.222.244"',line)
        self.assertIn('permitopen="127.0.0.1:15443"',line)
        self.assertNotIn('permitlisten',line)


if __name__=='__main__':unittest.main()
