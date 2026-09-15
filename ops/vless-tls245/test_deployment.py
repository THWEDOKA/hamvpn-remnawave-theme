import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parent


class DeploymentTests(unittest.TestCase):
    def test_tls_not_reality(self):
        config = json.loads((ROOT / 'config.json').read_text())
        inbound, = config['inbounds']
        self.assertEqual(inbound['port'], 443)
        self.assertEqual(inbound['protocol'], 'vless')
        self.assertEqual(inbound['streamSettings']['security'], 'tls')
        self.assertNotIn('realitySettings', inbound['streamSettings'])
        self.assertEqual(inbound['settings']['clients'], [])
        self.assertEqual(inbound['streamSettings']['tlsSettings']['serverName'], 'tls245.torcalc.ru')

    def test_scoped_key_and_cert_mount(self):
        source = (ROOT / 'launch_node.py').read_text()
        self.assertIn('/etc/letsencrypt:/etc/letsencrypt:ro', source)
        self.assertIn('assert not compose.exists()', source)
        self.assertIn('secret_path.unlink()', source)
        self.assertIn('remnawave/node@sha256:', source)

    def test_no_global_firewall_mutation(self):
        source = (ROOT / 'node_firewall.sh').read_text()
        self.assertIn('64.225.109.248/32', source)
        self.assertNotIn('iptables -F', source)
        self.assertNotIn('iptables -P', source)
        self.assertIn('ip6tables', source)

    def test_renewal_and_no_site(self):
        source = (ROOT / 'bootstrap.sh').read_text()
        self.assertIn('systemctl enable --now certbot.timer', source)
        self.assertIn('--standalone', source)
        self.assertNotIn('nginx', source)
        self.assertIn('test ! -e /opt/remnanode/docker-compose.yml', source)

    def test_no_insecure_tls(self):
        source = (ROOT / 'config.json').read_text()
        self.assertNotIn('allowInsecure', source)


if __name__ == '__main__':
    unittest.main()
