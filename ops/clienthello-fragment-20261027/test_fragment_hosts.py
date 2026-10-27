import unittest
from copy import deepcopy
from fragment_hosts import clone_payload, FINAL_MASK


class CloneTests(unittest.TestCase):
    def source(self):
        return {'uuid': 'source', 'viewPosition': 5, 'remark': 'original', 'port': 443, 'isDisabled': False, 'isHidden': False, 'fingerprint': 'firefox', 'inbound': {'configProfileInboundUuid': 'inbound'}, 'finalMask': None, 'nodes': ['node'], 'sni': 'example.com', 'excludedInternalSquads': ['squad']}

    def test_only_expected_fields_differ_and_source_is_untouched(self):
        before = self.source(); original = deepcopy(before)
        clone = clone_payload(before, 'test')
        self.assertEqual(before, original)
        self.assertEqual(clone['finalMask'], FINAL_MASK)
        for key in before.keys() - {'uuid','viewPosition','remark','finalMask'}: self.assertEqual(clone[key], before[key])
        self.assertNotIn('uuid', clone)
        self.assertIn('CLASH', clone['excludeFromSubscriptionTypes'])

    def test_rejects_incompatible_or_already_masked_sources(self):
        for patch in [{'isDisabled': True}, {'port': 8443}, {'fingerprint': 'chrome'}, {'finalMask': {'tcp': []}}]:
            with self.assertRaises(ValueError): clone_payload(self.source() | patch, 'test')

    def test_experimental_clones_never_inherit_automatic_pool_membership(self):
        clone=clone_payload(self.source() | {'tags':['AUTO_BASE_POOL','REGION_DE','AUTO_WHITE_POOL']},'test')
        self.assertEqual(clone['tags'],['REGION_DE'])


if __name__ == '__main__': unittest.main()
