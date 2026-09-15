import copy
from pathlib import Path
import unittest

import panel


class MigrationTests(unittest.TestCase):
    def original(self):
        return {'inbounds': [{'tag': panel.OLD_TAG, 'port': 443, 'listen': '0.0.0.0',
            'protocol': 'vless', 'settings': {'clients': [{'id': 'test-fixture-only'}], 'decryption': 'none'},
            'sniffing': {'enabled': True}, 'streamSettings': {'network': 'raw', 'security': 'reality',
            'realitySettings': {'target': 'google.com:443', 'privateKey': 'test-fixture-not-a-key',
                'shortIds': ['00', '01'], 'serverNames': ['google.com', 'global.hambot.ru'], 'minClientVer': '1.8.2'}}}],
            'routing': {'rules': [{'inboundTag': [panel.OLD_TAG, 'unrelated'], 'outboundTag': 'direct'}]},
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}

    def test_candidate_preserves_credentials_and_original(self):
        old = self.original()
        backup = copy.deepcopy(old)
        new = panel.candidate(old)
        self.assertEqual(old, backup)
        oldr = old['inbounds'][0]['streamSettings']['realitySettings']
        newr = new['inbounds'][0]['streamSettings']['realitySettings']
        for key in ('privateKey', 'shortIds', 'minClientVer'):
            self.assertEqual(oldr[key], newr[key])
        self.assertEqual(newr['serverNames'], [panel.DOMAIN] + oldr['serverNames'])
        self.assertEqual(newr['target'], '127.0.0.1:8443')
        for key in ('settings', 'sniffing', 'listen', 'port', 'protocol'):
            self.assertEqual(old['inbounds'][0][key], new['inbounds'][0][key])
        self.assertEqual(old['outbounds'], new['outbounds'])

    def test_routing_tag_renamed_without_other_changes(self):
        new = panel.candidate(self.original())
        self.assertEqual(new['routing']['rules'][0]['inboundTag'], [panel.TAG, 'unrelated'])

    def test_wrong_source_stops(self):
        for mutate in (
                lambda c: c['inbounds'][0].update(port=444),
                lambda c: c['inbounds'][0]['streamSettings'].update(security='tls'),
                lambda c: c['inbounds'][0]['streamSettings']['realitySettings'].update(target='other:443'),
                lambda c: c['inbounds'][0]['streamSettings']['realitySettings'].update(dest='google.com:443')):
            with self.subTest(mutate=mutate):
                config = self.original(); mutate(config)
                with self.assertRaises(AssertionError): panel.candidate(config)

    def test_nginx_private_tls_and_renewal(self):
        root = Path(__file__).parent
        config = (root / 'nginx-tls.conf').read_text()
        self.assertIn('listen 127.0.0.1:8443 ssl http2;', config)
        self.assertNotIn('listen 443', config)
        self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', config)
        self.assertIn(panel.DOMAIN, config)
        renewal = (root / 'renew-nginx.sh').read_text()
        self.assertIn('nginx -t', renewal)
        self.assertIn('reload nginx', renewal)
        self.assertNotIn('restart', renewal)

    def test_site_no_external_resources_or_fake_orders(self):
        html = (Path(__file__).parent / 'site' / 'index.html').read_text(encoding='utf-8')
        self.assertIn('lang="ru"', html)
        self.assertNotIn('<script', html)
        self.assertNotIn('<form', html)
        self.assertIn('Ремонт чайников', html)

    def test_acme_identity_has_no_shell_or_broad_forwarding(self):
        root = Path(__file__).parent
        config = (root / 'acme-sshd.conf').read_text()
        for expected in ('MaxSessions 0', 'ForceCommand /bin/false', 'PermitListen none',
                         'AllowTcpForwarding local', 'AllowStreamLocalForwarding no',
                         'PermitTTY no', 'PermitTunnel no', 'PermitUserRC no',
                         'PasswordAuthentication no', 'KbdInteractiveAuthentication no'):
            self.assertIn(expected, config)
        allow = next(line for line in config.splitlines() if line.strip().startswith('PermitOpen '))
        self.assertEqual(set(allow.split()[1:]), {
            'acme-v02.api.letsencrypt.org:443', 'acme-staging-v02.api.letsencrypt.org:443'})
        panel_source = (root / 'acme-panel.py').read_text()
        self.assertIn('from="161.104.90.214",restrict,port-forwarding', panel_source)

    def test_acme_proxy_loopback_and_certbot_only(self):
        root = Path(__file__).parent
        service = (root / 'acme-relay.service').read_text()
        self.assertIn('-D 127.0.0.1:18089', service)
        self.assertIn('StrictHostKeyChecking=yes', service)
        self.assertIn('-F /dev/null', service)
        self.assertNotIn('StrictHostKeyChecking=no', service)
        dropin = (root / 'acme-certbot.conf').read_text()
        self.assertIn('HTTPS_PROXY=socks5h://127.0.0.1:18089', dropin)
        self.assertIn('ExecStartPre=/usr/bin/python3 /usr/local/lib/hamvpn-acme-ru214/acme-ready.py', dropin)
        node = (root / 'acme-node.sh').read_text()
        self.assertIn('/etc/systemd/system/certbot.service.d/ru214-acme.conf', node)
        self.assertNotIn('/etc/environment', node)


if __name__ == '__main__': unittest.main()
