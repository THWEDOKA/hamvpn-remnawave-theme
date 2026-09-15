import json
import importlib.util
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('panel_selfsteal', ROOT / 'panel-selfsteal.py')
PANEL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PANEL)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if 'id' in attrs:
            self.ids.add(attrs['id'])
        if 'href' in attrs:
            self.links.append(attrs['href'])


def contrast(a, b):
    def luminance(color):
        values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [v / 12.92 if v <= .04045 else ((v + .055) / 1.055) ** 2.4 for v in values]
        return sum(v * weight for v, weight in zip(linear, (.2126, .7152, .0722)))
    low, high = sorted((luminance(a), luminance(b)))
    return (high + .05) / (low + .05)


class DeploymentTests(unittest.TestCase):
    def test_profile_clone_changes_only_scoped_fields(self):
        old = {
            'inbounds': [{'tag': 'vless-reality-shared', 'port': 443, 'protocol': 'vless',
                          'settings': {'clients': []}, 'streamSettings': {
                              'network': 'raw', 'security': 'reality', 'realitySettings': {
                                  'target': 'google.com:443', 'privateKey': 'test-only-key',
                                  'shortIds': ['abcd'], 'serverNames': ['global.hambot.ru']}}}],
            'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'}],
            'routing': {'rules': [{'inboundTag': ['vless-reality-shared'], 'outboundTag': 'DIRECT'}]},
        }
        before = json.dumps(old, sort_keys=True)
        new = PANEL.clone_config(old)
        self.assertEqual(json.dumps(old, sort_keys=True), before)
        reality = new['inbounds'][0]['streamSettings']['realitySettings']
        self.assertEqual(reality['privateKey'], 'test-only-key')
        self.assertEqual(reality['shortIds'], ['abcd'])
        self.assertEqual(reality['serverNames'], ['us3.torcalc.ru', 'global.hambot.ru'])
        self.assertEqual(reality['target'], '127.0.0.1:8443')
        self.assertEqual(new['outbounds'], old['outbounds'])
        self.assertEqual(new['routing']['rules'][0]['inboundTag'], [PANEL.TAG])
        self.assertEqual(old['routing']['rules'][0]['inboundTag'], ['vless-reality-shared'])

    def test_operator_requires_scoped_backup_and_probe_before_publish(self):
        code = (ROOT / 'panel-selfsteal.py').read_text()
        self.assertLess(code.index("save('snapshot.json'"), code.index("api('POST'"))
        self.assertIn("assert len(profile['nodes']) == 15", code)
        self.assertIn("assert proof['all_passed']", code)
        self.assertIn("time.time() - proof['timestamp'] < 600", code)
        self.assertNotIn("api('DELETE', '/api/config-profiles", code)
        self.assertEqual(code.count("api('DELETE'"), 1)
        self.assertIn("current['tag'] == 'SELFSTEAL_PROBE'", code)
        self.assertIn("- {NODE}", code)

    def test_dns_is_scoped_and_unproxied(self):
        self.assertEqual(json.loads((ROOT / 'dns-record.json').read_text()), {
            'type': 'A', 'name': 'us3.torcalc.ru', 'content': '162.141.185.216',
            'ttl': 300, 'proxied': False,
        })

    def test_nginx_never_takes_vpn_port(self):
        for name in ['nginx-http.conf', 'nginx-tls.conf']:
            listeners = re.findall(r'listen\s+([^;]+);', (ROOT / name).read_text())
            self.assertTrue(set(listeners) <= {'80', '127.0.0.1:8443 ssl http2'})
        tls = (ROOT / 'nginx-tls.conf').read_text()
        self.assertIn('listen 127.0.0.1:8443 ssl http2;', tls)
        self.assertIn('TLSv1.3', tls)
        self.assertIn('location ^~ /.well-known/acme-challenge/', tls)
        self.assertIn('/etc/letsencrypt/live/us3.torcalc.ru/privkey.pem', tls)

    def test_deploy_has_backup_and_preserves_node(self):
        deploy = (ROOT / 'deploy-web.sh').read_text()
        self.assertLess(deploy.index('sha256sum -c SHA256SUMS'), deploy.index('apt-get update'))
        self.assertIn('NEEDRESTART_MODE=l', deploy)
        self.assertIn('"$before" == "$after"', deploy)
        for forbidden in ['docker restart', 'docker compose down', 'ufw reset', 'ufw disable', 'apt-get upgrade']:
            self.assertNotIn(forbidden, deploy)
        self.assertIn('systemctl enable --now certbot.timer', deploy)

    def test_page_is_static_semantic_and_local(self):
        html = (ROOT / 'site/index.html').read_text(encoding='utf-8')
        parser = PageParser()
        parser.feed(html)
        self.assertEqual(parser.tags.count('h1'), 1)
        self.assertIn('main', parser.tags)
        self.assertIn('lang="ru"', html)
        self.assertIn('width=device-width, initial-scale=1', html)
        for tag in ['script', 'iframe', 'form', 'input']:
            self.assertNotIn(tag, parser.tags)
        for href in parser.links:
            if href.startswith('#'):
                self.assertIn(href[1:], parser.ids)
            else:
                self.assertEqual(href, '/style.css')

    def test_palette_contrast(self):
        for foreground, background in [
            ('#242424', '#fffce8'), ('#242424', '#d0d0ba'),
            ('#242424', '#fff2b8'), ('#242424', '#ece9d4'),
            ('#152f73', '#fffce8'), ('#152f73', '#ece9d4'),
            ('#fffce8', '#152f73'),
        ]:
            self.assertGreaterEqual(contrast(foreground, background), 4.5)

    def test_linux_files_are_lf(self):
        for name in ['deploy-web.sh', 'renew-nginx.sh', 'nginx-http.conf', 'nginx-tls.conf']:
            self.assertNotIn(b'\r', (ROOT / name).read_bytes())


if __name__ == '__main__':
    unittest.main()
