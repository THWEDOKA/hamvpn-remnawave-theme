import unittest
from pathlib import Path
import reverse

class ReverseTests(unittest.TestCase):
    def test_policy_scoped(self):
        s=reverse.policy()
        self.assertTrue(s.startswith('Match User ham-mws2-link\n'))
        self.assertTrue(s.endswith('Match all\n'))
        for value in ['AllowTcpForwarding remote','PermitOpen none','MaxSessions 0',
                      'PermitListen 127.0.0.1:27443','GatewayPorts no','ForceCommand /bin/false']:
            self.assertIn(value,s)

    def test_persistent_client_pinned_and_bounded(self):
        s=Path(reverse.__file__).read_text()
        for value in ['StrictHostKeyChecking=yes','RestartSec=5','ServerAliveCountMax=3',
                      '127.0.0.1:{PORT}:127.0.0.1:443','from="72.56.101.218"']:
            self.assertIn(value,s)
        self.assertNotIn('StrictHostKeyChecking=no',s)

if __name__=='__main__':unittest.main()
