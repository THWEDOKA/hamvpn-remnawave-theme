import copy
import unittest
from prune_hosts import NODES, KEPT, EXTRA_HOSTS, assert_scope, normalized, subscription_proof


def hosts():
    result = []
    for n in NODES:
        for i, identifier in enumerate(n['hosts']):
            result.append({'uuid': identifier, 'remark': identifier, 'address': n['ip'],
                           'nodes': [n['node']], 'isDisabled': False, 'isHidden': bool(i)})
    for identifier in EXTRA_HOSTS:
        result.append({'uuid': identifier, 'remark': identifier, 'address': NODES[0]['ip'],
                       'nodes': [NODES[0]['node']], 'isDisabled': False, 'isHidden': False})
    return result


class PruningTests(unittest.TestCase):
    def test_scope(self):
        assert_scope(hosts())
        self.assertEqual(len(KEPT), 8)
        self.assertEqual(len(EXTRA_HOSTS), 8)

    def test_unknown_group_host_refused(self):
        with self.assertRaises(AssertionError):
            assert_scope(hosts() + [{'uuid': 'new', 'nodes': [NODES[0]['node']]}])

    def test_shared_host_refused(self):
        changed = hosts()
        changed[-1]['nodes'].append('unrelated-node')
        with self.assertRaises(AssertionError):
            assert_scope(changed)

    def test_only_order_ignored(self):
        self.assertEqual(normalized({'uuid': 'a', 'viewPosition': 99}), {'uuid': 'a'})
        self.assertIn('finalMask', normalized({'finalMask': {'test': True}}))

    def test_subscription_membership(self):
        baseline = hosts()
        configs = [{'remarks': h['remark'], 'outbounds': []} for h in baseline if not h['isHidden']]
        configs.append({'remarks': 'unrelated', 'outbounds': []})
        configs.append({'remarks': '⚡ Автовыбор Серверов', 'outbounds': [{'protocol': 'vless'}]})
        current = [c for c in configs if c['remarks'] not in EXTRA_HOSTS]
        before = {'hosts': baseline, 'subscription': configs}
        self.assertTrue(subscription_proof(before, current)['four_visible_hosts'])
        bad = copy.deepcopy(current)
        bad[-1]['outbounds'] = []
        with self.assertRaises(AssertionError):
            subscription_proof(before, bad)


if __name__ == '__main__':
    unittest.main()
