"""Password-in-memory transport. No credentials in argv, files or Git archives."""
import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import paramiko
import transport as t

KZ_CODE = r'''
import sys,json,os,tempfile,subprocess
first=json.loads(sys.stdin.readline());password=first['password'];key=first['hostkey'];first=None
with tempfile.TemporaryDirectory(prefix='ham-kz2-ssh-') as folder:
 os.chmod(folder,0o700);known=folder+'/known_hosts'
 with open(known,'w') as f:f.write('206.223.240.179 ssh-ed25519 '+key+'\n')
 os.chmod(known,0o600)
 print('READY',flush=True)
 for line in sys.stdin:
  r=json.loads(line)
  if r.get('quit'):break
  rd,wr=os.pipe();os.write(wr,(password+'\n').encode());os.close(wr)
  try:
   p=subprocess.run(['sshpass','-d',str(rd),'ssh','-T','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+known,'-o','GlobalKnownHostsFile=/dev/null','-o','PubkeyAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=12','root@206.223.240.179',r['command']],input=__import__('base64').b64decode(r['input']),capture_output=True,timeout=r.get('timeout',240),pass_fds=(rd,))
   print(json.dumps({'exit_code':p.returncode,'stdout':__import__('base64').b64encode(p.stdout).decode()}),flush=True)
  except subprocess.TimeoutExpired:print(json.dumps({'exit_code':124,'stdout':''}),flush=True)
  finally:os.close(rd)
'''


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('target', choices=['kz2', 'de245']); args = parser.parse_args()
    known = paramiko.HostKeys(str(Path.home() / '.ssh/known_hosts'))
    password = getpass.getpass('Node SSH password (hidden): ')
    client = process = None
    if args.target == 'de245':
        client = paramiko.SSHClient(); client.load_host_keys(str(Path.home() / '.ssh/known_hosts'))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect('196.251.107.245', username='root', password=password,
                       allow_agent=False, look_for_keys=False, timeout=12, banner_timeout=12, auth_timeout=12)
        def remote(command, data=b''):
            a,b,e = client.exec_command(command, timeout=300)
            a.write(data); a.channel.shutdown_write()
            output = b.read(); e.read(); status = b.channel.recv_exit_status()
            if status: raise RuntimeError('Remote action failed; inspect private state, exit ' + str(status))
            return output
    else:
        code = "python3 -u -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(KZ_CODE.encode()).decode() + "\"))'"
        process = subprocess.Popen(t.command('panel') + [code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        process.stdin.write(json.dumps(dict(password=password, hostkey=known.lookup('206.223.240.179')['ssh-ed25519'].get_base64())) + '\n')
        process.stdin.flush(); assert process.stdout.readline().strip() == 'READY'
        def remote(command, data=b''):
            process.stdin.write(json.dumps(dict(command=command, input=base64.b64encode(data).decode())) + '\n'); process.stdin.flush()
            result = json.loads(process.stdout.readline())
            if result['exit_code']: raise RuntimeError('Remote action failed; inspect private state, exit ' + str(result['exit_code']))
            return base64.b64decode(result['stdout'])
    password = None
    print('CONNECTED_WITH_PINNED_HOST_KEY', flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request.get('quit'): break
            try:
                commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=t.REPO, text=True).strip()
                assert commit == subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=t.REPO, text=True).strip()
                directory = '/opt/hamvpn-cloud140-kz245/releases/' + commit[:12]
                base = directory + '/' + t.SCOPE + '/'
                if request.get('release'):
                    archive = subprocess.check_output(['git','-c','core.autocrlf=false','archive','--format=tar',commit,t.SCOPE,'ops/selfsteal-us3/panel_api.py'],cwd=t.REPO)
                    digest = hashlib.sha256(archive).hexdigest()
                    code = "import os,sys,tarfile,io,hashlib;from pathlib import Path;os.umask(0o077);b=sys.stdin.buffer.read();assert hashlib.sha256(b).hexdigest()==" + repr(digest) + ";p=Path(" + repr(directory) + ");p.mkdir(parents=True,exist_ok=True);tarfile.open(fileobj=io.BytesIO(b)).extractall(p,filter='data');print('RELEASE_VERIFIED')"
                    command = "python3 -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(code.encode()).decode() + "\"))'"
                    remote(command, archive)
                    result = dict(release=commit, target=args.target, sha256=digest)
                else:
                    data = request.get('input', '').encode()
                    if request.get('panel_source'):
                        source = request['panel_source']
                        data = t.remote('panel', 'python3 ' + base + source['script'] + ' ' + source.get('args',''))
                    command = request.get('command') or 'python3 ' + base + request['script'] + ' ' + request.get('args', '')
                    output = remote(command, data)
                    if request.get('proof_name'):
                        proof = json.loads(output); name = request['proof_name']
                        assert name.replace('-', '').isalnum() and isinstance(proof, dict)
                        code = "import sys,json;sys.path.insert(0,"+repr(base)+");from preflight import save;save("+repr(name)+",json.load(sys.stdin));print('PROOF_SAVED')"
                        encoded=base64.b64encode(code.encode()).decode()
                        t.remote('panel',"python3 -c 'import base64;exec(base64.b64decode(\""+encoded+"\"))'",output)
                    result = dict(stdout=output.decode())
                print(json.dumps(result), flush=True)
            except Exception as error:
                print(json.dumps(dict(error=type(error).__name__, detail=str(error) if isinstance(error, RuntimeError) else 'Inspect state before retry')), flush=True)
    finally:
        if client: client.close()
        if process:
            process.stdin.write('{"quit":true}\n'); process.stdin.flush(); process.stdin.close(); process.wait(timeout=15)


if __name__ == '__main__': main()
