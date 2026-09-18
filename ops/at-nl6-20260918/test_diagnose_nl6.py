import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import diagnose_nl6 as n


class NL6Tests(unittest.TestCase):
    def test_export_has_owned_new_identity_and_no_install(self):
        compile(n.EXPORT, '<nl6-export>', 'exec')
        self.assertIn("p.Store('aeza')", n.EXPORT)
        self.assertIn("routes==['nl6']", n.EXPORT)
        self.assertIn("node['address']==target['ip']", n.EXPORT)
        for method in ('POST', 'PATCH', 'DELETE'):
            self.assertNotIn("api('"+method+"'", n.EXPORT)
        self.assertIn("role,host_id in [('main'", n.EXPORT)

    def test_local_exact_wires_private_stdin(self):
        from types import SimpleNamespace
        items=[{'id':'synthetic-nl6','wire':{'synthetic_secret':'not-for-output'}}]
        with patch.object(n.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'{"tests":[]}')) as run:
            result=n.local_check(items)
        args,kwargs=run.call_args
        self.assertNotIn('not-for-output',' '.join(args[0]))
        self.assertIn(b'not-for-output',kwargs['input'])
        self.assertTrue(result['fresh_subscription'])
        self.assertNotIn('not-for-output',str(result))


if __name__ == '__main__':
    unittest.main()
