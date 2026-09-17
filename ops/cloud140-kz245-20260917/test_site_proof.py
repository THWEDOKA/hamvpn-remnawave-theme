import unittest
from unittest.mock import patch
import site_proof as s


class ProofTests(unittest.TestCase):
    def setup_mocks(self):
        self.checked = dict(loopback_port=9443, checks=[dict(sni=s.DOMAIN, tls='TLSv1.3', alpn='h2')])
        self.saved = dict(passed=True, timestamp=900)
        for method, value in [('verify', self.checked), ('read', self.saved), ('save', None)]:
            mock = patch.object(s.site, method, return_value=value)
            mock.start(); self.addCleanup(mock.stop)
        mock = patch.object(s.time, 'time', return_value=1000)
        mock.start(); self.addCleanup(mock.stop)

    def setUp(self): self.setup_mocks()

    def test_tls(self):
        proof = s.attest('a' * 64)
        self.assertTrue(proof['tests'][0]['chain_verified'])
        s.site.verify.assert_called_once()

    def test_renewal_keeps_actual_time(self):
        with patch.object(s.site, 'run', side_effect=['enabled\n', 'active\n']):
            proof = s.attest('a' * 64, True)
        self.assertEqual(proof['timestamp'], 1000)
        self.assertEqual(proof['tests'][0]['performed_at'], 900)

    def test_bad_digest(self):
        with self.assertRaises(RuntimeError): s.attest('invalid')
        s.site.verify.assert_not_called()

    def test_missing_h2(self):
        self.checked['checks'][0]['alpn'] = 'http/1.1'
        with self.assertRaises(RuntimeError): s.attest('a' * 64)

    def test_old_or_future_renewal(self):
        for stamp in (-90000, 1001, float('nan')):
            self.saved['timestamp'] = stamp
            with self.assertRaises(RuntimeError): s.attest('a' * 64, True)

    def test_inactive_timer(self):
        with patch.object(s.site, 'run', side_effect=['enabled\n', 'inactive\n']):
            with self.assertRaises(RuntimeError): s.attest('a' * 64, True)


if __name__ == '__main__': unittest.main()
