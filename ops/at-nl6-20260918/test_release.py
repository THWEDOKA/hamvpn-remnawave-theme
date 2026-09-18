import io
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch
import release as r


def archive(items):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as stream:
        for name, kind in items:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = 1 if kind == tarfile.REGTYPE else 0
            stream.addfile(item, io.BytesIO(b'x') if item.size else None)
    return data.getvalue()


class ReleaseTests(unittest.TestCase):
    def test_exact_scope(self):
        self.assertTrue(r.allowed(r.SCOPE + '/preflight.py'))
        for bad in ['/root/key', 'ops/../key', 'ops/unrelated.py', r.SCOPE + '-other/x']:
            self.assertFalse(r.allowed(bad))

    def test_valid_manifest(self):
        self.assertEqual(len(r.manifest(archive([(r.SCOPE + '/preflight.py', tarfile.REGTYPE)]))), 1)

    def test_reject_symlink_duplicate_or_foreign(self):
        cases = [[(r.SCOPE + '/x', tarfile.SYMTYPE)],
                 [(r.SCOPE + '/x', tarfile.REGTYPE)] * 2,
                 [('../x', tarfile.REGTYPE)], [('other/x', tarfile.REGTYPE)]]
        for items in cases:
            with self.subTest(items=items), self.assertRaises(RuntimeError):
                r.manifest(archive(items))

    def test_published_live_remote(self):
        outputs = [r.REMOTE.encode(), b'main', b'', b'a' * 40, b'a' * 40, b'a' * 40 + b' refs/heads/main']
        with patch.object(r, 'git', side_effect=outputs):
            self.assertEqual(r.published(), 'a' * 40)
        outputs[-1] = b'b' * 40 + b' refs/heads/main'
        with patch.object(r, 'git', side_effect=outputs), self.assertRaises(RuntimeError):
            r.published()

    def test_receiver_compiles(self):
        compile(r.receiver('/opt/hamvpn-at-nl6/releases/' + 'a' * 12, 'b' * 64,
                           {r.SCOPE + '/preflight.py': 'c' * 64}), '<receiver>', 'exec')


if __name__ == '__main__':
    unittest.main()
