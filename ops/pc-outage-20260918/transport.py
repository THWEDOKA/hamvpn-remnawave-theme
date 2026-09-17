"""Publish-verified, strict-SSH transport for the Mihomo compatibility repair.

No credentials/configuration in arguments or operator output. Only the panel
receives this release; its API applies separately reviewed profile deltas.
"""
import argparse
import base64
import hashlib
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
SCOPE = 'ops/pc-outage-20260918'


def remote(command, data=None):
    result = subprocess.run([
        'ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12',
        'hamvpn-panel-via-jump', command,
    ], input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError('Remote compatibility action failed; inspect protected state')
    return result.stdout


def revision():
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    origin = subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=ROOT, text=True).strip()
    if head != origin:
        raise RuntimeError('Only synchronized, published main may be deployed')
    return head


def release():
    commit = revision()
    archive = subprocess.check_output([
        'git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', commit,
        SCOPE, 'ops/selfsteal-us3/panel_api.py',
    ], cwd=ROOT)
    digest = hashlib.sha256(archive).hexdigest()
    directory = '/opt/hamvpn-mihomo-compat/releases/' + commit[:12]
    code = (
        'import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);'
        'b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==' + repr(digest) + ';'
        'p=Path(' + repr(directory) + ');p.mkdir(parents=True,exist_ok=True);'
        "tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter='data');print('RELEASE_VERIFIED')"
    )
    encoded = base64.b64encode(code.encode()).decode()
    result = remote("python3 -c 'import base64;exec(base64.b64decode(\"" + encoded + "\"))'", archive)
    if result.strip() != b'RELEASE_VERIFIED':
        raise RuntimeError('Unexpected release verification response')
    return dict(commit=commit, sha256=digest, directory=directory)


if __name__ == '__main__':
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['release'])
    parser.parse_args()
    print(json.dumps(release()))
