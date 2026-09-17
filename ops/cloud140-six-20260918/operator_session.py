"""Scoped password-in-memory operator relay via the already pinned panel.

Passwords enter getpass, then pinned SSH stdin; never argv, disk or output.
This helper does not accept new host keys. Populate the separate known-hosts
file only with independently verified or explicitly TOFU-approved public keys.
Commands are operator-controlled; callers must request only safe output.
"""
import base64
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from inventory import TARGETS

REPO = Path(__file__).resolve().parents[2]
SCOPE = 'ops/cloud140-six-20260918'
SHARED = 'ops/cloud140-kz245-20260917'
_spec = importlib.util.spec_from_file_location('cloud140_six_operator_transport', REPO / SHARED / 'transport.py')
transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(transport)

RELAY = r'''
import sys,json,os,tempfile,subprocess,base64,concurrent.futures
initial=json.loads(sys.stdin.readline())
access=initial['access'];hostkeys=initial['hostkeys'];initial=None
with tempfile.TemporaryDirectory(prefix='ham-cloud140-six-ssh-') as folder:
 os.chmod(folder,0o700);known=folder+'/known_hosts'
 with open(known,'x') as f:f.write(hostkeys)
 os.chmod(known,0o600)
 def execute(r):
  target=access[r['id']]
  rd,wr=os.pipe();os.write(wr,(target['password']+'\n').encode());os.close(wr)
  try:
   cmd=['sshpass','-d',str(rd),'ssh','-T','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
        '-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null',
        '-o','PubkeyAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=12',
        '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','root@'+target['ip'],r['command']]
   p=subprocess.run(cmd,input=base64.b64decode(r.get('input','')),capture_output=True,
                    timeout=r.get('timeout',180),pass_fds=(rd,))
   category='remote_failure'
   for marker,label in [(b'Permission denied','authentication_denied'),(b'Host key verification failed','host_key_rejected'),
                        (b'REMOTE HOST IDENTIFICATION HAS CHANGED','host_key_changed'),(b'timed out','timeout'),
                        (b'Connection closed','connection_closed'),(b'Connection reset','connection_reset'),
                        (b'No route to host','no_route')]:
    if marker in p.stderr:category=label;break
   return {'id':r['id'],'exit_code':p.returncode,'category':category,'stdout':base64.b64encode(p.stdout).decode()}
  except subprocess.TimeoutExpired:return {'id':r['id'],'exit_code':124,'stdout':''}
  finally:os.close(rd)
 print('READY',flush=True)
 for line in sys.stdin:
  r=json.loads(line)
  if r.get('quit'):break
  if 'batch' in r:
   with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:result=list(pool.map(execute,r['batch']))
  else:result=execute(r)
  print(json.dumps(result),flush=True)
'''


def encoded_command(source):
    return "python3 -B -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(source.encode()).decode() + "\"))'"


def release(target):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    assert commit == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=REPO, text=True).strip()
    archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', commit,
                                       SCOPE, SHARED, 'ops/selfsteal-us3/panel_api.py'], cwd=REPO)
    sha = hashlib.sha256(archive).hexdigest()
    path = '/opt/hamvpn-cloud140-six/releases/' + commit[:12]
    code = ("import sys,os,hashlib,tarfile,io;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();"
            "assert hashlib.sha256(b).hexdigest()==" + repr(sha) + ";p=Path(" + repr(path) + ");"
            "assert not p.is_symlink();p.mkdir(parents=True,exist_ok=True);"
            "tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter='data');print('RELEASE_VERIFIED')")
    return dict(id=target, command=encoded_command(code), input=base64.b64encode(archive).decode()), dict(release=commit, sha256=sha)


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    known = (Path.home() / '.ssh/hamvpn-cloud140-six-known_hosts').read_text()
    available = [t for t in TARGETS if any(row.startswith(t['ip'] + ' ssh-') for row in known.splitlines())]
    assert available
    access = {t['id']: dict(ip=t['ip'], password=getpass.getpass(t['id'] + ' root password (hidden): ')) for t in available}
    process = subprocess.Popen(transport.command('panel') + [encoded_command(RELAY)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding='utf-8')
    process.stdin.write(json.dumps(dict(access=access, hostkeys=known)) + '\n'); process.stdin.flush()
    access = None
    assert process.stdout.readline().strip() == 'READY'
    print('PINNED_RELAY_READY ' + ','.join(t['id'] for t in available), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request.get('quit'): break
            meta = None
            if request.get('release'):
                request, meta = release(request['id'])
            elif request.get('panel_source'):
                source = request.pop('panel_source')
                request['input'] = base64.b64encode(transport.remote('panel', source)).decode()
            elif request.get('input_text') is not None:
                request['input'] = base64.b64encode(request.pop('input_text').encode()).decode()
            process.stdin.write(json.dumps(request) + '\n'); process.stdin.flush()
            result = json.loads(process.stdout.readline())
            items = result if isinstance(result, list) else [result]
            for item in items:
                data = base64.b64decode(item.pop('stdout'))
                if item['exit_code'] == 0:
                    if meta:
                        item['stdout'] = 'RELEASE_VERIFIED'
                    else:
                        try: item['result'] = json.loads(data)
                        except (ValueError, UnicodeError): item['stdout'] = data.decode('utf-8')[:16000]
                else:
                    item['error'] = 'Remote action failed; inspect scoped diagnostics before retry'
            if meta: items[0].update(meta)
            print(json.dumps(items, ensure_ascii=False), flush=True)
    finally:
        process.stdin.write('{"quit":true}\n'); process.stdin.flush(); process.stdin.close()
        process.wait(timeout=15)


if __name__ == '__main__': main()
