"""Strict SSH operator transport. Binary releases and secrets never cross stdout."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from common import ENTRY, NODES

SCOPE = 'ops/ru140-entry-20260917'
REPO = Path(__file__).resolve().parents[2]


def ssh(target):
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12']
    if target == 'panel': return args + ['hamvpn-panel-via-jump']
    address = ENTRY if target == 'entry' else next(n['ip'] for n in NODES if n['id'] == target)
    return args + ['-i', str(Path.home() / '.ssh/hamvpn-panel'), '-o', 'IdentitiesOnly=yes', ('gasan' if target == 'entry' else 'root') + '@' + address]


def remote(target, command, payload=None):
    if target == 'entry': command = 'sudo -n ' + command
    return subprocess.run(ssh(target) + [command], input=payload, capture_output=True)


def checked(result):
    if result.returncode:
        raise RuntimeError('Remote operation failed (code ' + str(result.returncode) + '); inspect private state before retry')
    return result.stdout


def release(target, revision):
    commit = subprocess.check_output(['git', 'rev-parse', revision + '^{commit}'], cwd=REPO, text=True).strip()
    assert commit == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=REPO, text=True).strip()
    archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', commit,
        SCOPE, 'ops/selfsteal-us3/panel_api.py', 'ops/selfsteal-ru214/panel.py'], cwd=REPO)
    directory = '/opt/hamvpn-ru140-entry/releases/' + commit[:12]
    checksum = hashlib.sha256(archive).hexdigest()
    code = ('import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);'
        'b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==' + repr(checksum) + ';'
        'p=Path(' + repr(directory) + ');p.mkdir(parents=True,exist_ok=True);'
        "tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter='data');print('RELEASE_VERIFIED')")
    encoded = base64.b64encode(code.encode()).decode()
    command = "python3 -c 'import base64;exec(base64.b64decode(\"" + encoded + "\"))'"
    checked(remote(target, command, archive))
    return {'target': target, 'release': commit, 'directory': directory, 'sha256': checksum}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('target', choices=['entry', 'panel', *[n['id'] for n in NODES]])
    p.add_argument('action', choices=['release', 'run', 'pipe'])
    p.add_argument('--revision', required=True)
    p.add_argument('--script', default='node.py')
    p.add_argument('--args', default='')
    p.add_argument('--source-target', choices=['entry','panel'])
    p.add_argument('--source-script', default='panel.py')
    p.add_argument('--source-args', default='')
    p.add_argument('--stdin', action='store_true')
    a = p.parse_args()
    commit = subprocess.check_output(['git','rev-parse',a.revision+'^{commit}'],cwd=REPO,text=True).strip()
    assert commit == subprocess.check_output(['git','rev-parse','origin/main'],cwd=REPO,text=True).strip(), 'Use verified published revision'
    base = '/opt/hamvpn-ru140-entry/releases/' + commit[:12] + '/' + SCOPE + '/'
    if a.action == 'release': print(json.dumps(release(a.target,a.revision)));return
    payload = sys.stdin.buffer.read() if a.stdin else None
    if a.action == 'pipe':
        assert a.source_target
        payload = checked(remote(a.source_target, 'python3 ' + base + a.source_script + ' ' + a.source_args))
    result = remote(a.target, 'python3 ' + base + a.script + ' ' + a.args, payload)
    print(checked(result).decode(),end='')


if __name__ == '__main__': main()
