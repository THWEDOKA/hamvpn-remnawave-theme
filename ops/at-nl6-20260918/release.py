"""Publish only a synchronized main archive to the already pinned panel.

No production configuration is applied. Secrets never enter this archive.
Root-private, immutable releases are verified file-by-file before use.
"""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

REPO = Path(__file__).resolve().parents[2]
SCOPE = 'ops/at-nl6-20260918'
PARTS = (SCOPE, 'ops/cloud140-six-20260918',
         'ops/cloud140-kz245-20260917', 'ops/selfsteal-us3/panel_api.py')
REMOTE = 'https://github.com/THWEDOKA/hamvpn-remnawave-theme.git'


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, timeout=30)


def published():
    check(git('remote', 'get-url', 'origin').decode().strip() == REMOTE, 'Unexpected repository')
    check(git('branch', '--show-current').decode().strip() == 'main', 'Expected main')
    check(not git('status', '--porcelain').strip(), 'Working tree is not clean')
    revision = git('rev-parse', 'HEAD').decode().strip()
    check(revision == git('rev-parse', 'origin/main').decode().strip(), 'Main is not synchronized')
    # Check GitHub itself, not just the cached tracking ref.
    remote = git('ls-remote', 'origin', 'refs/heads/main').decode().split()
    check(remote and remote[0] == revision, 'Published main differs')
    return revision


def allowed(name):
    path = PurePosixPath(name)
    return (not path.is_absolute() and '..' not in path.parts and
            any(name == part or name.startswith(part + '/') for part in PARTS))


def manifest(archive):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        for member in stream.getmembers():
            if member.isdir():
                check(not PurePosixPath(member.name).is_absolute() and
                      '..' not in PurePosixPath(member.name).parts, 'Unsafe directory')
                continue
            check(member.isfile() and allowed(member.name), 'Unexpected archive entry')
            check(member.name not in files, 'Duplicate archive entry')
            files[member.name] = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
    check(files and any(name.startswith(SCOPE + '/') for name in files), 'New scope absent')
    return files


def receiver(directory, archive_hash, files):
    # All interpolated values are verified public paths, revision hashes and
    # file digests. tar is inspected, not blindly extracted.
    return '''import sys,os,io,tarfile,hashlib,stat,json
from pathlib import Path
os.umask(0o077)
data=sys.stdin.buffer.read()
assert hashlib.sha256(data).hexdigest()==ARCHIVE_HASH
base=Path(DIRECTORY)
assert os.geteuid()==0
for path in reversed((base,*base.parents)):
 if not path.exists() and not path.is_symlink(): path.mkdir(mode=0o700)
 info=path.lstat()
 assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
assert not base.stat().st_mode&0o077
expected=FILES
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
 members=[m for m in archive.getmembers() if not m.isdir()]
 assert len(members)==len(expected) and {m.name for m in members}==set(expected)
 for member in members:
  assert member.isfile()
  contents=archive.extractfile(member).read()
  assert hashlib.sha256(contents).hexdigest()==expected[member.name]
  target=base/member.name
  for parent in reversed(target.relative_to(base).parents):
   folder=base/parent
   if not folder.exists() and not folder.is_symlink(): folder.mkdir(mode=0o700)
   info=folder.lstat()
   assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077
  if not target.exists() and not target.is_symlink():
   with open(target,'xb') as output:
    output.write(contents);output.flush();os.fsync(output.fileno())
  info=target.lstat()
  assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077 and info.st_nlink==1
  assert hashlib.sha256(target.read_bytes()).hexdigest()==expected[member.name]
actual={str(p.relative_to(base)) for p in base.rglob('*') if not p.is_dir()}
assert actual==set(expected)
print(json.dumps({'verified':True,'files':len(expected)}))
'''.replace('ARCHIVE_HASH', repr(archive_hash)).replace('DIRECTORY', repr(directory)).replace('FILES', repr(files))


def main():
    revision = published()
    archive = git('-c', 'core.autocrlf=false', 'archive', '--format=tar', revision, *PARTS)
    files = manifest(archive)
    digest = hashlib.sha256(archive).hexdigest()
    directory = '/opt/hamvpn-at-nl6/releases/' + revision[:12]
    source = receiver(directory, digest, files)
    command = "python3 -B -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(source.encode()).decode() + "\"))'"
    run = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                          '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12',
                          '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                          'hamvpn-panel-via-jump', command], input=archive, capture_output=True, timeout=120)
    check(run.returncode == 0, 'Release verification failed; no configuration was applied')
    result = json.loads(run.stdout)
    check(result == {'verified': True, 'files': len(files)}, 'Unexpected release readback')
    print(json.dumps(dict(release=revision, archive_sha256=digest, directory=directory, **result)))


if __name__ == '__main__':
    main()
