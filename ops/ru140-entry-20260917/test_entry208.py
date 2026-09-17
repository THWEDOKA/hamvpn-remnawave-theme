import copy
import unittest
import panel208 as p


class Entry208Tests(unittest.TestCase):
    def test_preserves_legacy_and_routes_before_direct(self):
        profiles = {}
        for n in p.NODES:
            profiles[n['profile']] = {'inbounds': [{'uuid': n['inbound'], 'tag': 'test'}],
                'config': {'inbounds': [{'tag': 'test', 'streamSettings': {'network': 'raw', 'security': 'tls'}}]}}
        original = {'inbounds': [{'tag': 'old', 'listen': '0.0.0.0', 'port': 443, 'settings': {'clients': []},
                    'streamSettings': {'security': 'reality', 'realitySettings': {'privateKey': 'unit-test-only',
                        'shortIds': ['unit-test'], 'serverNames': ['us3.torcalc.ru', 'google.com'], 'target': '127.0.0.1:8443'}}}],
                    'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'}, {'tag': 'BLOCK', 'protocol': 'blackhole'}],
                    'routing': {'rules': [{'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'BLOCK'},
                                         {'type': 'field', 'ip': ['geoip:ru'], 'outboundTag': 'DIRECT'}]}}
        profiles[p.OLD_PROFILE] = {'config': copy.deepcopy(original)}
        config = p.candidate({'profiles': profiles}, {'vlessUuid': '00000000-0000-4000-8000-000000000001'})
        self.assertEqual(profiles[p.OLD_PROFILE]['config'], original)
        expected = copy.deepcopy(original['inbounds'][0])
        expected.update(tag=p.LEGACY_TAG, listen='127.0.0.1', port=15443)
        self.assertEqual(config['inbounds'][0], expected)
        self.assertEqual(len(config['inbounds']), 5)
        rules = config['routing']['rules']
        direct_index = next(i for i, r in enumerate(rules) if r['outboundTag'] == 'DIRECT')
        for n in p.NODES:
            tag = 'vless-entry208-' + n['id']
            match = [(i, r) for i, r in enumerate(rules) if tag in r.get('inboundTag', [])]
            self.assertEqual(len(match), 1)
            self.assertLess(match[0][0], direct_index)
            self.assertEqual(match[0][1]['outboundTag'], 'exit-' + n['id'])
            outbound = next(o for o in config['outbounds'] if o['tag'] == 'exit-' + n['id'])
            self.assertEqual(outbound['settings']['vnext'][0]['address'], n['ip'])
            inbound = next(i for i in config['inbounds'] if i['tag'] == tag)
            self.assertEqual(inbound['listen'], '127.0.0.1')
            self.assertEqual(inbound['streamSettings']['realitySettings']['target'], '127.0.0.1:9443')


if __name__ == '__main__': unittest.main()
