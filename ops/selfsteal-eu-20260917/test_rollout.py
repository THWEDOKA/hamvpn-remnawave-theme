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

    def test_revised_owner_template(self):
        for n in json.loads((ROOT / 'nodes.json').read_text(encoding='utf-8')):
            c = json.loads((ROOT / n['id'] / 'tls-hy2-config.json').read_text())
            self.assertEqual([i['protocol'] for i in c['inbounds']], ['vless', 'hysteria'])
            for i in c['inbounds']:
                self.assertEqual(i['port'], 443)
                self.assertEqual(i['streamSettings']['security'], 'tls')
                self.assertNotIn('realitySettings', i['streamSettings'])
                self.assertIn(n['domain'], i['streamSettings']['tlsSettings']['certificates'][0]['keyFile'])
            self.assertEqual(c['inbounds'][0]['settings']['fallbacks'], [{'dest': 9443}, {'alpn': 'h2', 'dest': 9444}])
            self.assertEqual(c['inbounds'][1]['streamSettings']['network'], 'hysteria')

    def test_subscription_pool_uses_verified_selector(self):
        source = (ROOT / 'panel.py').read_text(encoding='utf-8')
        self.assertIn("'tags': ['AUTO_BASE_POOL'] if is_hidden else []", source)
        self.assertIn("'pattern': '^AUTO_BASE_POOL$'", source)

    def test_firewall_scoped(self):
        source = (ROOT / 'firewall.sh').read_text()
        self.assertIn('64.225.109.248/32', source)
        self.assertNotIn('iptables -F', source)
        self.assertNotIn('--dport 22 ', source)
        self.assertEqual((ROOT / '.gitattributes').read_text().strip(), '* text eol=lf')
        self.assertIn("run('systemctl', 'is-active', '--quiet', unit.name)", (ROOT / 'node.py').read_text())

    def test_fresh_candidate_does_not_mutate_shared_profile(self):
        spec = importlib.util.spec_from_file_location('eu_panel', ROOT / 'panel.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        original = {'inbounds': [{'tag': 'old', 'port': 443, 'protocol': 'vless'}],
                    'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'}],
                    'routing': {'rules': [{'inboundTag': ['old', 'other'], 'outboundTag': 'DIRECT'}]}}
        serialized = json.dumps(original)
        configs = [module.candidate(original, n, 'test-key-only') for n in module.NODES]
        self.assertEqual(json.dumps(original), serialized)
        self.assertEqual(len({c['inbounds'][0]['tag'] for c in configs}), 4)
        for n, c in zip(module.NODES, configs):
            inbound = c['inbounds'][0]
            self.assertEqual(inbound['settings']['clients'], [])
            reality = inbound['streamSettings']['realitySettings']
            self.assertEqual(reality['serverNames'], [n['domain']])
            self.assertEqual(reality['target'], '127.0.0.1:8443')
            self.assertNotIn('dest', reality)
            self.assertEqual(len(reality['shortIds'][0]), 16)
            self.assertEqual(c['routing']['rules'][0]['inboundTag'], [inbound['tag'], 'other'])
            self.assertEqual(c['outbounds'], original['outbounds'])


if __name__ == '__main__': unittest.main()
