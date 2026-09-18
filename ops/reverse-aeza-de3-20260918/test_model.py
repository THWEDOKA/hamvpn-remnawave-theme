import unittest
import model as m


class Tests(unittest.TestCase):
    def test_single_outbound_delta(self):
        c = {'outbounds': [{'tag': 'neighbor', 'settings': {'x': 1}}, {'tag': 'exit-de182', 'old': True}],
             'inbounds': [{'port': 18443}], 'routing': {'rules': [1]}, 'custom': ['keep']}
        w = m.wire('fixture', 'fixture', '00'); new = m.entry(c, w)
        self.assertEqual(new['outbounds'][0], c['outbounds'][0])
        for k in ['inbounds', 'routing', 'custom']: self.assertEqual(new[k], c[k])
        self.assertEqual(w['streamSettings']['realitySettings']['fingerprint'], 'firefox')
        self.assertTrue(c['outbounds'][1]['old'])

    def test_legacy_exit_preserved(self):
        c = {'inbounds': [{'tag': 'legacy', 'port': 443}], 'outbounds': [1], 'routing': {'keep': True}}
        n = m.backend(c, 'fixture', '00')
        self.assertEqual(n['inbounds'][:-1], c['inbounds'])
        self.assertEqual(n['inbounds'][-1]['listen'], '127.0.0.1')
        for k in ['outbounds', 'routing']: self.assertEqual(n[k], c[k])
        with self.assertRaises(AssertionError): m.backend(n, 'fixture', '00')

    def test_ssh_restrictions(self):
        p, text = m.sshd()
        self.assertEqual(p['AllowTcpForwarding'], 'remote')
        self.assertEqual(p['AllowStreamLocalForwarding'], 'no')
        self.assertEqual(p['MaxSessions'], '0')
        self.assertEqual(p['PermitOpen'], 'none')
        self.assertEqual(p['PermitListen'], '127.0.0.1:36443')
        self.assertTrue(text.endswith('Match all\n'))
        self.assertIn('User=ham-rs633-de3\n', m.unit())
        self.assertIn('RemoteForward 127.0.0.1:36443 127.0.0.1:32443', m.client())


if __name__ == '__main__': unittest.main()
