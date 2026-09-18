"""Strict existing host pins; exact user-identified Selectal key; secret stdin pipes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCOPE = 'ops/mws-auto-20260918'


def command(role):
    args = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=12']
    if role == 'panel': return args + ['hamvpn-panel-via-jump']
    key = 'ssh-key-trz' if role == 'selectal' else 'hamvpn-panel'
    return args + ['-i', 'C:/Users/User/.ssh/' + key, '-o', 'IdentitiesOnly=yes',
                   'root@' + ('5.188.115.106' if role == 'selectal' else '176.109.85.244')]


def remote(role, cmd, data=None, timeout=100):
    p = subprocess.run(command(role) + [cmd], input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        try:
            safe = json.loads(p.stdout)
            if safe.get('failed'): print(json.dumps(safe), file=sys.stderr)
        except Exception: pass
        raise RuntimeError('Remote action failed: ' + role)
    return p.stdout


def main():
    p = argparse.ArgumentParser(); p.add_argument('role', choices=['panel', 'mws', 'selectal'])
    p.add_argument('action', choices=['release', 'run']); p.add_argument('--script', default='operate.py')
    p.add_argument('--args', default=''); p.add_argument('--input'); p.add_argument('--field')
    p.add_argument('--stdin', action='store_true'); a = p.parse_args()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    assert head == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=ROOT, text=True).strip()
    directory = '/opt/ham-mws-auto/releases/' + head[:12]
    if a.action == 'release':
        archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', head,
                                          SCOPE, 'ops/selfsteal-us3/panel_api.py'], cwd=ROOT)
        code = 'import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==' + repr(hashlib.sha256(archive).hexdigest()) + ';p=Path(' + repr(directory) + ');p.mkdir(parents=True,exist_ok=True);tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter="data");print("verified")'
        cmd = "python3 -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(code.encode()).decode() + "\"))'"
        assert remote(a.role, cmd, archive).strip() == b'verified'
        print(json.dumps({'release': head, 'role': a.role}))
    else:
        data = sys.stdin.buffer.read() if a.stdin else None
        if a.input:
            assert a.input.replace('-', '').isalnum()
            data = remote('panel', 'cat /root/ham-mws-auto-20260918/' + a.input + '.json')
            if a.field: data = json.dumps(json.loads(data)[a.field]).encode()
        assert '/' not in a.script and a.script.endswith('.py')
        print(remote(a.role, 'python3 ' + directory + '/' + SCOPE + '/' + a.script + ' ' + a.args, data).decode(), end='')


if __name__ == '__main__': main()
