import copy
import unittest
from unittest.mock import patch
import preflight as p


class PreflightTests(unittest.TestCase):
    def test_targets_separate_and_four_exact_hosts(self):
        self.assertEqual(len({n['node'] for n in p.NODES}), 2)
        self.assertEqual(len({h for n in p.NODES for h in n['hosts']}), 4)
        self.assertEqual({n['port'] for n in p.NODES}, {18443, 18444})
        self.assertEqual({n['domain'] for n in p.NODES}, {'in-kz2.torcalc.ru', 'in-de245.torcalc.ru'})

    def test_wire_uses_reality_and_service_id_without_mutating_source(self):
        profiles = {}
        for n in p.NODES:
            profiles[n['profile']] = dict(inbounds=[dict(uuid=n['inbound'], tag='source')], config=dict(inbounds=[
                dict(tag='source', streamSettings=dict(realitySettings=dict(privateKey='MOCK', shortIds=['1234'])))]))
        before = copy.deepcopy(profiles)
        with patch.object(p, 'account', return_value={'vlessUuid':'test-user'}), patch.object(p, 'read', return_value={'profiles':profiles}), patch.object(p, 'public_key', return_value='public'):
            result = p.clients(lambda method, path: profiles[path.split('/')[-1]])
        self.assertEqual(profiles, before)
        self.assertEqual(len(result), 2)
        for item in result:
            self.assertEqual(item['outbound']['streamSettings']['security'], 'reality')
            self.assertEqual(item['outbound']['settings']['vnext'][0]['port'], 443)
            self.assertNotIn('privateKey', item['outbound']['streamSettings']['realitySettings'])


if __name__ == '__main__': unittest.main()
