import unittest
import model


class Tests(unittest.TestCase):
    def test_preserves_existing_pool(self):
        c = {'outbounds': [{'tag': 'OLD'}], 'routing': {'rules': [{'keep': 1}],
             'balancers': [{'tag': 'BS3_AUTO', 'selector': ['BS3_AUTO_'], 'fallbackTag': 'OLD'}]},
             'observatory': {'subjectSelector': ['BS3_AUTO_']}, 'custom': [1]}
        w = model.wire('fixture', 'fixture', '00')
        n = model.candidate(c, w)
        self.assertEqual(n['outbounds'][:-1], c['outbounds'])
        for k in c:
            if k != 'outbounds': self.assertEqual(n[k], c[k])
        self.assertEqual(len(c['outbounds']), 1)
        with self.assertRaises(AssertionError): model.candidate(n, w)

    def test_backend_scope(self):
        c = {'inbounds': [{'tag': 'HAM-MWS2-REALITY', 'port': 18443,
             'settings': {'clients': []}, 'streamSettings': {'realitySettings': {'serverNames': ['mws.torcalc.ru']}}}],
             'routing': {'rules': [{'old': True}]}, 'outbounds': [{'tag': 'FOREIGN'}]}
        n = model.backend(c, 'secret-fixture', '00')
        self.assertEqual(n['inbounds'][:-1], c['inbounds'])
        self.assertEqual(n['routing']['rules'][2:], c['routing']['rules'])
        self.assertEqual(n['routing']['rules'][0]['source'], ['5.188.115.106'])
        self.assertEqual(n['routing']['rules'][1]['outboundTag'], 'BLOCK')
        self.assertEqual(n['outbounds'], c['outbounds'])


if __name__ == '__main__': unittest.main()
