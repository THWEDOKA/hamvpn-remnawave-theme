"""Verified Git release and secret stdin pipe over strict operator SSH."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
SCOPE = 'ops/cloud140-kz245-20260917'


def command(target):
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12']
    if target == 'panel': return args + ['hamvpn-panel-via-jump']
    return args + ['-i', str(Path.home() / '.ssh/hamvpn-panel'), '-o', 'IdentitiesOnly=yes', 'gasan@176.108.245.140']


def remote(target, code, data=None):
    result = subprocess.run(command(target) + [('sudo -n ' if target == 'entry' else '') + code], input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError('Remote action failed; inspect scoped private state. Code ' + str(result.returncode))
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', choices=['entry', 'panel'])
    parser.add_argument('action', choices=['release', 'run', 'probe'])
    parser.add_argument('--script', default='preflight.py')
    parser.add_argument('--args', default='')
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    assert commit == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=REPO, text=True).strip()
    directory = '/opt/hamvpn-cloud140-kz245/releases/' + commit[:12]
    if args.action == 'release':
        archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', commit, SCOPE, 'ops/selfsteal-us3/panel_api.py'], cwd=REPO)
        sha = hashlib.sha256(archive).hexdigest()
        code = "import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==" + repr(sha) + ";p=Path(" + repr(directory) + ");p.mkdir(parents=True,exist_ok=True);tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter='data');print('RELEASE_VERIFIED')"
        encoded = base64.b64encode(code.encode()).decode()
        remote(args.target, "python3 -c 'import base64;exec(base64.b64decode(\"" + encoded + "\"))'", archive)
        print(json.dumps(dict(release=commit, sha256=sha, target=args.target)))
    elif args.action == 'probe':
        data = remote('panel', 'python3 ' + directory + '/' + SCOPE + '/preflight.py export-clients')
        output = remote(args.target, 'python3 ' + directory + '/' + SCOPE + '/probe.py ' + args.args, data)
        print(output.decode())
    else:
        print(remote(args.target, 'python3 ' + directory + '/' + SCOPE + '/' + args.script + ' ' + args.args).decode())


if __name__ == '__main__': main()
