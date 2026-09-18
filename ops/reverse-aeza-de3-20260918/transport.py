"""Strict pinned SSH, GitHub-only immutable releases and private binary pipes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCOPE = 'ops/reverse-aeza-de3-20260918'


def ssh(role):
    a = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12']
    if role == 'panel': return a + ['hamvpn-panel-via-jump']
    return a + ['-i', 'C:/Users/User/.ssh/hamvpn-panel', '-o', 'IdentitiesOnly=yes',
                'root@' + {'entry': '193.233.222.244', 'exit': '217.60.68.182'}[role]]


def remote(role, command, data=None, timeout=210):
    p = subprocess.run(ssh(role) + [command], input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        try:
            safe = json.loads(p.stdout)
            if safe.get('failed'): print(json.dumps(safe), file=sys.stderr)
        except Exception: pass
        raise RuntimeError('Remote failure: ' + role)
    return p.stdout


def release(role):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    assert head == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=ROOT, text=True).strip()
    directory = '/opt/ham-reverse-de3/releases/' + head[:12]
    archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', head,
                                      SCOPE, 'ops/selfsteal-us3/panel_api.py'], cwd=ROOT)
    code = 'import sys,os,hashlib,io,tarfile;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==' + repr(hashlib.sha256(archive).hexdigest()) + ';p=Path(' + repr(directory) + ');p.mkdir(parents=True,exist_ok=True);tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter="data");print("verified")'
    command = "python3 -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(code.encode()).decode() + "\"))'"
    assert remote(role, command, archive).strip() == b'verified'
    return {'role': role, 'published_release': head, 'directory': directory}


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('role', choices=['panel', 'entry', 'exit']); a = p.parse_args()
    print(json.dumps(release(a.role)))
