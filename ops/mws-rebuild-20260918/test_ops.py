import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mws_ops', ROOT / 'ops.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class PreparationTests(unittest.TestCase):
    def test_exact_targets(self):
        self.assertEqual(m.TARGETS['entry']['ip'], '176.109.85.244')
        self.assertEqual(m.TARGETS['exit']['ip'], '72.56.101.218')

    def test_public_templates(self):
        for role, item in m.TARGETS.items():
            dns = json.loads((ROOT / role / 'dns-record.json').read_text())
            self.assertEqual(dns['content'], item['ip'])
            self.assertEqual(dns['name'], item['domain'])
            self.assertIs(dns['proxied'], False)
            tls = (ROOT / role / 'nginx-tls.conf').read_text()
            self.assertIn('listen 127.0.0.1:9444 ssl http2;', tls)
            self.assertNotIn('listen 443', tls)
            self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', tls)
            self.assertIn(item['domain']+'/fullchain.pem', tls)
            self.assertNotIn('{{', (ROOT / role / 'site/index.html').read_text(encoding='utf-8'))

    def test_no_panel_deletion_or_switch(self):
        src = (ROOT / 'ops.py').read_text()
        self.assertNotIn("api('DELETE'", src)
        self.assertNotIn("api('PATCH'", src)
        self.assertNotIn("'stop', OLD_CONTAINER", src)
        self.assertNotIn("'restart', OLD_CONTAINER", src)

    def test_no_shared_config_or_firewall_reset(self):
        src = (ROOT / 'ops.py').read_text()
        self.assertNotIn("'iptables', '-F'", src)
        self.assertNotIn("'ufw', 'disable'", src)
        self.assertNotIn("'apt-get', 'upgrade'", src)
        self.assertNotIn('StrictHostKeyChecking=no', src)

    def test_certificate_requires_external_proof(self):
        src = (ROOT / 'ops.py').read_text()
        self.assertIn('http_challenge_verified', src)
        self.assertIn('Uncertain certificate attempt', src)

    def test_new_services_do_not_stop_current_containers(self):
        src=(ROOT/'node.py').read_text()
        self.assertNotIn("'docker','stop'",src)
        self.assertNotIn("'docker','rm'",src)
        self.assertIn("'--env-file',str(env)",src)
        self.assertIn("'--network','host'",src)

    def test_panel_stage_requires_real_backend(self):
        src=(ROOT/'panel.py').read_text()
        self.assertIn("proof.get('backend_passed') is True",src)
        self.assertIn("'old_hosts_unchanged':True",src)
        self.assertNotIn("api('DELETE'",src)
        self.assertNotIn("api('POST','/api/hosts/",src)


if __name__ == '__main__': unittest.main()
