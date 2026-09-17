import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


class Templates(unittest.TestCase):
    def test_targets(self):
        nodes = json.loads((ROOT / 'nodes.json').read_text(encoding='utf-8'))
        self.assertEqual(len(nodes), 4)
        self.assertEqual(len({n['ip'] for n in nodes}), 4)
        self.assertEqual(len({n['domain'] for n in nodes}), 4)
        for n in nodes:
            with self.subTest(node=n['id']):
                directory = ROOT / n['id']
                record = json.loads((directory / 'dns-record.json').read_text())
                self.assertEqual(record, {'type': 'A', 'name': n['domain'], 'content': n['ip'], 'ttl': 300, 'proxied': False})
                tls = (directory / 'nginx-tls.conf').read_text()
                self.assertIn('listen 127.0.0.1:8443 ssl http2;', tls)
                self.assertNotIn('listen 443', tls)
                self.assertIn('/etc/letsencrypt/live/' + n['domain'], tls)
                self.assertIn('TLSv1.3', tls)
                self.assertIn('nginx -t', (directory / 'renew-nginx.sh').read_text())
                self.assertIn('viewport', (directory / 'site/index.html').read_text())

    def test_python_compiles(self):
        for file in ROOT.glob('*.py'): compile(file.read_text(encoding='utf-8'), str(file), 'exec')

    def test_firewall_scoped(self):
        source = (ROOT / 'firewall.sh').read_text()
        self.assertIn('64.225.109.248/32', source)
        self.assertNotIn('iptables -F', source)
        self.assertNotIn('--dport 22 ', source)


if __name__ == '__main__': unittest.main()
