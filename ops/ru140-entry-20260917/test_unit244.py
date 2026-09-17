import subprocess
import unittest
from unittest.mock import patch
import entry244_common as c


class UnitTests(unittest.TestCase):
    def test_inactive_or_confirmed_collected_only(self):
        for code, state, expected in [(3,'',True),(0,'',False),(1,'',False),
            (4,'LoadState=not-found\nActiveState=inactive\nSubState=dead\n',True),
            (4,'LoadState=loaded\nActiveState=activating\nSubState=start\n',False),(4,'',False)]:
            with self.subTest(code=code,state=state), patch.object(c.subprocess,'run',side_effect=[
                subprocess.CompletedProcess([],code),subprocess.CompletedProcess([],0,state,'')]):
                self.assertEqual(c.unit_inactive('test.timer'),expected)


if __name__=='__main__':unittest.main()
