import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import panel

ROOT = Path(__file__).parent


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((ROOT.parent / 'vless-tls245/config.json').read_text())

    def test_original_not_mutated(self):
        before = copy.deepcopy(self.original)
        panel.candidate(self.original, 'unit-test-placeholder', '0123456789abcdef')
        self.assertEqual(self.original, before)

    def test_cached_tls_compatibility_and_loopback_only(self):
        new = panel.candidate(self.original, 'unit-test-placeholder', '0123456789abcdef')
        main, legacy = new['inbounds']
        self.assertEqual(main['port'], 443)
        self.assertEqual(main['streamSettings']['security'], 'reality')
        self.assertEqual(main['streamSettings']['realitySettings']['target'], '127.0.0.1:8443')
        self.assertNotIn('tlsSettings', main['streamSettings'])
        self.assertEqual(legacy['listen'], '127.0.0.1')
        self.assertEqual(legacy['port'], 8443)
        self.assertEqual(legacy['streamSettings'], self.original['inbounds'][0]['streamSettings'])
        self.assertEqual(legacy['settings']['clients'], [])
        self.assertEqual(new['outbounds'], self.original['outbounds'])
        self.assertEqual(new['routing'], self.original['routing'])

    def test_routes_cover_both_migrated_inbounds(self):
        self.original['routing']['rules'][0]['inboundTag'] = ['other', 'vless-tls245']
        new = panel.candidate(self.original, 'unit-test-placeholder', '0123456789abcdef')
        self.assertEqual(new['routing']['rules'][0]['inboundTag'], ['other'] + panel.TAGS)

    def test_nginx_does_not_compete_for_tls_ports(self):
        source = (ROOT / 'nginx.conf').read_text()
        self.assertNotIn('listen 443', source)
        self.assertNotIn('listen 8443', source)
        self.assertIn('listen 127.0.0.1:8081 http2', source)
        self.assertIn('listen 127.0.0.1:8080', source)

    def test_publish_requires_successful_probe(self):
        with patch.object(panel, 'read', return_value={'all_passed': False}):
            with self.assertRaises(AssertionError):
                panel.publish(lambda *args: self.fail('No write before verification'))

    def test_backup_before_install_and_supported_renewal(self):
        source = (ROOT / 'deploy-web.sh').read_text()
        self.assertLess(source.index('tar -czf'), source.index('apt-get install'))
        self.assertIn('certbot reconfigure', source)
        self.assertNotIn('docker restart', source)

    def test_site_is_factual_and_self_contained(self):
        html = (ROOT / 'site/index.html').read_text(encoding='utf-8')
        self.assertIn('Справочная страница', html)
        self.assertNotIn('<form', html)
        self.assertNotIn('src="http', html)


if __name__ == '__main__': unittest.main()
