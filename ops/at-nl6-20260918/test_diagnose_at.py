import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('at_diagnostics', Path(__file__).with_name('diagnose_at.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DiagnosticsTests(unittest.TestCase):
    def test_remote_sources_compile(self):
        compile(d.EXPORT, '<export>', 'exec')
        code = d.server_code()
        compile(code, '<probe>', 'exec')
        self.assertIn("outbounds=[item['outbound']] + item.get('extra_outbounds', [])", code)
        self.assertIn("'2a12:5940:6020::2'", code)
        self.assertIn("TemporaryDirectory", code)
        self.assertIn("process.terminate()", code)

    def test_private_stdin_and_exact_strict_destination(self):
        fixture = {'settings': {'fixture': 'synthetic-private-marker'}}
        response = SimpleNamespace(returncode=0, stdout=b'{"result":{"passed":true}}')
        for name, ip in [('aeza', '193.233.222.244'), ('de182', '217.60.68.182')]:
            with patch.object(d.subprocess, 'run', return_value=response) as run:
                result = d.remote_check(name, 'reality', fixture)
                args, kwargs = run.call_args
                self.assertIn('root@'+ip, args[0])
                self.assertIn('StrictHostKeyChecking=yes', args[0])
                self.assertIn('BatchMode=yes', args[0])
                self.assertNotIn('synthetic-private-marker', ' '.join(args[0]))
                self.assertEqual(json.loads(kwargs['input'])['wire'], fixture)
                self.assertLessEqual(kwargs['timeout'], 125)
                self.assertNotIn('synthetic-private-marker', json.dumps(result))

    def test_unknown_source_cannot_run(self):
        with patch.object(d.subprocess, 'run') as run, self.assertRaises(KeyError):
            d.remote_check('unapproved-target', 'reality', {})
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
