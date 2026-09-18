"""Local strict-SSH transport; publish before deployment, secrets stay in pipes."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCOPE = 'ops/mws-rebuild-20260918'


def command(role):
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o',
            'UpdateHostKeys=no', '-o', 'ConnectTimeout=12']
    if role == 'panel': return args + ['hamvpn-panel-via-jump']
    args += ['-i', 'C:/Users/User/.ssh/hamvpn-panel', '-o', 'IdentitiesOnly=yes']
    if role == 'exit':
        args += ['-o', 'UserKnownHostsFile=C:/Users/User/.ssh/hamvpn-mws-rebuild-known_hosts',
                 '-o', 'ProxyCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no '
                 '-i C:/Users/User/.ssh/hamvpn-panel -W %h:%p root@176.109.85.244']
    return args + ['root@'+('176.109.85.244' if role == 'entry' else '72.56.101.218')]


def remote(role, cmd, data=None, timeout=600):
    p = subprocess.run(command(role)+[cmd], input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        # Reviewed scripts return safe diagnostics, but raw SSH stderr stays private.
        try:
            safe = json.loads(p.stdout)
            if safe.get('failed') is True: print(json.dumps(safe), file=sys.stderr)
        except Exception: pass
        raise RuntimeError('Remote action failed on '+role+', exit '+str(p.returncode))
    return p.stdout


def main():
    p = argparse.ArgumentParser()
    p.add_argument('role', choices=['panel','entry','exit'])
    p.add_argument('action', choices=['release','run'])
    p.add_argument('--script', default='ops.py')
    p.add_argument('--args', default='')
    p.add_argument('--input-panel', help='Protected operation state basename; never printed')
    p.add_argument('--stdin', action='store_true')
    a=p.parse_args()
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    origin=subprocess.check_output(['git','rev-parse','origin/main'],cwd=ROOT,text=True).strip()
    assert head==origin,'Only published main is deployable'
    directory='/opt/hamvpn-mws-rebuild/releases/'+head[:12]
    if a.action=='release':
        archive=subprocess.check_output(['git','-c','core.autocrlf=false','archive','--format=tar',head,SCOPE,'ops/selfsteal-us3/panel_api.py'],cwd=ROOT)
        digest=hashlib.sha256(archive).hexdigest()
        code='import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()=='+repr(digest)+';p=Path('+repr(directory)+');p.mkdir(parents=True,exist_ok=True);tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter="data");print("PUBLISHED_RELEASE_VERIFIED")'
        cmd="python3 -c 'import base64;exec(base64.b64decode(\""+base64.b64encode(code.encode()).decode()+"\"))'"
        assert remote(a.role,cmd,archive).strip()==b'PUBLISHED_RELEASE_VERIFIED'
        print(json.dumps({'release':head,'role':a.role,'archive_sha256':digest}))
    else:
        assert '/' not in a.script and a.script.endswith('.py')
        data=None
        if a.input_panel:
            assert a.input_panel.replace('-','').replace('.','').isalnum()
            data=remote('panel','cat /root/hamvpn-mws-rebuild-20260918/'+a.input_panel)
        elif a.stdin:data=sys.stdin.buffer.read()
        print(remote(a.role,'python3 '+directory+'/'+SCOPE+'/'+a.script+' '+a.args,data).decode(),end='')


if __name__=='__main__':main()
