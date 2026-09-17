import copy
import json
from pathlib import Path
import unittest
import common
import auto_timeweb


class Pilot(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((common.ROOT.parent / 'selfsteal-eu-20260917/de182/tls-hy2-config.json').read_text())

    def test_only_one_inbound_added(self):
        original = copy.deepcopy(self.original)
        updated = common.candidate(self.original)
        self.assertEqual(self.original, original)
        self.assertEqual(updated['inbounds'][:2], original['inbounds'])
        updated['inbounds'].pop()
        self.assertEqual(updated, original)

    def test_backend_never_public(self):
        inbound = common.added_inbound()
        self.assertEqual(inbound['listen'], '127.0.0.1')
        self.assertEqual(inbound['port'], 10080)
        self.assertEqual(inbound['settings']['clients'], [])
        self.assertEqual(inbound['streamSettings']['xhttpSettings']['mode'], 'packet-up')

    def test_different_profile_refused(self):
        self.original['inbounds'][0]['tag'] = 'other'
        with self.assertRaises(AssertionError): common.candidate(self.original)

    def test_client_tls_without_vision(self):
        out = common.outbound({'vlessUuid': 'test-only'})
        self.assertEqual(out['streamSettings']['security'], 'tls')
        self.assertEqual(out['streamSettings']['tlsSettings']['alpn'], ['http/1.1'])
        self.assertFalse(out['streamSettings']['tlsSettings']['allowInsecure'])
        self.assertNotIn('flow', out['settings']['vnext'][0]['users'][0])
        self.assertEqual(out['settings']['vnext'][0]['port'], 443)

    def test_host_not_added_to_auto_selection(self):
        host = common.host_body('test-only')
        self.assertEqual(host['tags'], [])
        self.assertFalse(host['isHidden'])
        self.assertTrue(host['isDisabled'])
        self.assertEqual(host['securityLayer'], 'TLS')
        self.assertEqual(host['alpn'], 'http/1.1')
        self.assertEqual(host['nodes'], [common.NODE])

    def test_route_buffers_disabled(self):
        route = (common.ROOT / 'nginx-location.conf').read_text()
        for line in ['proxy_buffering off;', 'proxy_request_buffering off;', 'access_log off;',
                     'proxy_pass http://127.0.0.1:10080;']:
            self.assertIn(line, route)
        self.assertNotIn('listen', route)

    def test_python_compiles(self):
        for file in common.ROOT.glob('*.py'): compile(file.read_text(encoding='utf-8'), str(file), 'exec')

    def test_only_requested_timeweb_targets(self):
        self.assertEqual({t['name'] for t in auto_timeweb.TARGETS},
            {'Netherlands-HAM-TMWEB-1', 'HAM-GERMANY-TMWEB-1', 'HAM-NL-TMWEB-2'})
        self.assertNotIn(common.NODE, [t['node'] for t in auto_timeweb.TARGETS])
        for target in auto_timeweb.TARGETS:
            host = auto_timeweb.body(target)
            self.assertTrue(host['isDisabled'] and host['isHidden'])
            self.assertEqual(host['tags'], ['AUTO_BASE_POOL'])
            self.assertEqual(host['nodes'], [target['node']])
            self.assertEqual(host['address'], target['ip'])


if __name__ == '__main__': unittest.main()
