import unittest
import front_operator as o

class Tests(unittest.TestCase):
    def test_explicit_secret_pipe_action(self):
        value=o.command('/published/','export-public','cz',True)
        self.assertEqual(value,'python3 /published/frontend_stage.py export-public --id cz --secret-stdout')
    def test_normal_action_does_not_export(self):
        self.assertNotIn('secret',o.command('/published/','publish','cz'))

if __name__=='__main__':unittest.main()
