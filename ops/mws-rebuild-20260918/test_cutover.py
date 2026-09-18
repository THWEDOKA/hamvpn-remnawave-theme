import unittest
from pathlib import Path
import cutover
import routing

class CutoverTests(unittest.TestCase):
    def test_binding_shapes(self):
        ids={'profile':'p','inbounds':{routing.ENTRY_TAG:'a',routing.LEGACY_TAG:'b'}}
        self.assertEqual(cutover.desired_binding(ids,False)['activeInbounds'],['a'])
        self.assertEqual(cutover.desired_binding(ids,True)['activeInbounds'],['a','b'])
        self.assertEqual(cutover.binding({'configProfile':{'activeConfigProfileUuid':'p','activeInbounds':[{'uuid':'b'},{'uuid':'a'}]}}),cutover.desired_binding(ids,True))
    def test_only_owned_services_stopped(self):
        src=Path(cutover.__file__).read_text()
        self.assertNotIn('remnanode-gas',src)
        self.assertNotIn('remnanode-friend',src)
        self.assertIn("'Container ownership drift; do not overwrite'",src)
        self.assertIn("'Host ownership conflict'",src)
        self.assertIn("'service'",src)
        self.assertIn("'Final proof mismatch'",src)

if __name__=='__main__':unittest.main()
