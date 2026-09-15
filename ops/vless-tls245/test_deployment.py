import json
from pathlib import Path
import unittest
from unittest.mock import patch

import panel_deploy

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

    def test_publication_rejects_unverified_probe(self):
        with patch.object(panel_deploy, 'read', return_value={'all_passed': False}):
            with self.assertRaises(AssertionError):
                panel_deploy.publish(lambda *args: self.fail('API mutation must not happen'))

    def test_publication_rejects_stale_probe(self):
        with patch.object(panel_deploy, 'read', return_value={'all_passed': True, 'timestamp': 0}):
            with self.assertRaises(AssertionError):
                panel_deploy.publish(lambda *args: self.fail('API mutation must not happen'))

    def test_rollback_preserves_unrelated_inbounds(self):
        calls = []
        def api(method, path, body=None):
            calls.append((method, path, body))
            return {'inbounds': [{'uuid': i} for i in ['original', 'new', 'concurrent']]}
        with patch.object(panel_deploy, 'read', return_value={
                'host': 'new-host', 'inbound': 'new', 'squads': ['selected']}), \
                patch.object(panel_deploy, 'save'):
            panel_deploy.rollback(api)
        self.assertEqual(calls[-1][2]['inbounds'], ['original', 'concurrent'])
        self.assertEqual(calls[0][2], {'uuid': 'new-host', 'isDisabled': True})


if __name__ == '__main__':
    unittest.main()
