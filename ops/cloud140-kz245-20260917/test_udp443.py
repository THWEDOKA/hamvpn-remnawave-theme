import io
import unittest
from unittest.mock import patch
import udp_probe
import udp_control
import udp443_control as w


class Port443Tests(unittest.TestCase):
    def test_isolated_port_and_private_state(self):
        self.assertEqual(w.p.PORTS, (443,))
        self.assertEqual(udp_probe.PORTS, (54433, 54434))
        self.assertEqual(udp_control.ROOT.name, 'udp')
        self.assertEqual(w.c.ROOT.name, 'udp443')

    def test_only_443_and_two_existing_hosts(self):
        self.assertEqual(w.p.Config('kz2', 443).peer, '176.108.245.140')
        for side, port in [('de245', 443), ('kz2', 54433), ('entry', 53)]:
            with self.assertRaises(w.p.ProbeError): w.p.Config(side, port)

    def test_authenticated_roundtrip(self):
        secret = w.p.Credentials(b'a' * 32, b'b' * 16)
        packet = w.p.encode(secret, 443, 0, 0, 1, b'c' * (64 - w.p.HEADER.size - w.p.MAC_SIZE))
        parsed, error = w.p.decode(secret, 443, packet, 0, 0)
        self.assertIsNone(error)
        self.assertEqual(parsed[0], 1)

    def test_no_firewall_cli(self):
        with patch('sys.argv', ['probe', 'firewall-prepare', '--id', 'entry-to-kz2']), patch('sys.stderr', io.StringIO()):
            with self.assertRaises(SystemExit): w.main()


if __name__ == '__main__': unittest.main()
