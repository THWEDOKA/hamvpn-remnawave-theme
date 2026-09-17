import copy
import importlib.util
import json
import unittest
from pathlib import Path
import pilot


class SalamanderPilot(unittest.TestCase):
    def setUp(self):
        root = pilot.ROOT.parent
        spec = importlib.util.spec_from_file_location('old_pilot', root / 'xhttp-de182-20260917/common.py')
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        self.original = mod.candidate(json.loads((root / 'selfsteal-eu-20260917/de182/tls-hy2-config.json').read_text()))
        self.password = 'synthetic-test-only-not-a-live-key-000000'

    def test_additive_only(self):
        before = copy.deepcopy(self.original)
        config = pilot.candidate(self.original, self.password)
        self.assertEqual(self.original, before)
        added = config['inbounds'].pop()
        self.assertEqual(config, before)
        self.assertEqual(added['protocol'], 'hysteria')
        self.assertEqual(added['port'], 8443)

    def test_mask_and_tls(self):
        i = pilot.candidate(self.original, self.password)['inbounds'][-1]
        self.assertEqual(i['streamSettings']['security'], 'tls')
        self.assertEqual(i['streamSettings']['finalmask']['udp'], pilot.mask(self.password)['udp'])
        self.assertEqual(i['streamSettings']['tlsSettings']['alpn'], ['h3'])
        self.assertEqual(i['settings']['clients'], [])

    def test_wrong_profile_refused(self):
        self.original['inbounds'][0]['tag'] = 'other'
        with self.assertRaises(AssertionError): pilot.candidate(self.original, self.password)

    def test_conflicting_port_refused(self):
        self.original['inbounds'][2]['port'] = 8443
        with self.assertRaises(AssertionError): pilot.candidate(self.original, self.password)

    def test_host_distributes_same_mask_not_auto(self):
        h = pilot.host_body('test-only', self.password)
        self.assertEqual(h['finalMask'], pilot.mask(self.password))
        self.assertEqual(h['port'], 8443)
        self.assertEqual(h['tags'], [])
        self.assertTrue(h['isDisabled'])
        self.assertFalse(h['isHidden'])
        self.assertLessEqual(len(h['remark']), 40)

    def test_short_password_rejected(self):
        with self.assertRaises(AssertionError): pilot.mask('short')

    def test_code_compiles(self):
        for p in pilot.ROOT.glob('*.py'): compile(p.read_text(encoding='utf-8'), str(p), 'exec')


if __name__ == '__main__': unittest.main()
