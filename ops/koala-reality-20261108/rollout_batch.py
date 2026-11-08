"""Sequential approved rollout. Credentials/reference proxies arrive only on stdin."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

import paramiko

BASE=Path(__file__).parent
WORKSPACE=BASE.parents[2]
SSH=Path('C:/Users/User/.ssh')
SUB=Path('C:/Users/User/.codex/.sandbox-secrets/koala-diagnostic-fresh-20261107.yaml')


def connect_bot():
    client=paramiko.SSHClient();client.load_host_keys(str(SSH/'known_hosts'))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect('85.192.61.140',username='root',key_filename=str(SSH/'ssh-key-trz'),look_for_keys=False,allow_agent=False,timeout=15)
    client.get_transport().set_keepalive(15);return client


def node_client(bot,row):
    channel=bot.get_transport().open_channel('direct-tcpip',(row['ip'],22),('127.0.0.1',0),timeout=15)
    client=paramiko.SSHClient()
    for file in SSH.iterdir():
        if file.name=='known_hosts' or file.name.endswith('-known_hosts'):client.load_host_keys(str(file))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(row['ip'],username='root',password=row['password'],sock=channel,look_for_keys=False,allow_agent=False,timeout=15,auth_timeout=15)
    return client


def remote(client,code,data=None,bot=False,timeout=120):
    python='/opt/hamvpn2/venv/bin/python' if bot else 'python3'
    stdin,stdout,stderr=client.exec_command(python+' -c '+shlex.quote(code),timeout=timeout)
    if data is not None:stdin.write(json.dumps(data));stdin.flush();stdin.channel.shutdown_write()
    output=stdout.read().decode(errors='replace');error=stderr.read();rc=stdout.channel.recv_exit_status()
    if rc:
        last=error.decode(errors='replace').splitlines()[-1:]
        category=next((v for v in ['Profile propagation timeout','Profile drift','Fresh preflight required','Original image tag changed','Existing operation requires review','Unexpected inbound changes'] if any(v in line for line in last)),'private remote operation')
        raise RuntimeError('Remote verification failed: '+category)
    return output


def profile(bot,policy,action):
    path='/root/ham-koala-batch-release-20261108/'+policy['node']+'.py'
    return remote(bot,"import subprocess;subprocess.run(['/opt/hamvpn2/venv/bin/python',"+repr(path)+","+repr(action)+"],check=True)",bot=True)


def core(client,action):
    return remote(client,"import subprocess;subprocess.run(['python3','/root/ham-koala-batch-release-20261108/batch_core.py',"+repr(action)+"],check=True)")


def main():
    payload=json.load(sys.stdin);results=[]
    bot=connect_bot()
    try:
        for policy in payload['policies']:
            ip=policy['ip'];client=None;profile_changed=False;core_changed=False
            print('ROLLOUT_BEGIN',ip,flush=True)
            try:
                client=node_client(bot,next(x for x in payload['access'] if x['ip']==ip))
                profile(bot,policy,'apply');profile_changed=True
                remote(client,"import time,sys;sys.path.insert(0,'/root/ham-koala-batch-release-20261108');import core_rollback as c;\nfor _ in range(40):\n cfg,_=c.runtime();i=next(x for x in cfg['inbounds'] if x.get('tag')=="+repr(policy['tag'])+")\n if i['streamSettings']['realitySettings'].get('minClientVer')=='1.8.2':break\n time.sleep(1)\nelse:raise RuntimeError('Profile propagation timeout')")
                before=remote(client,"import subprocess,json;d=json.loads(subprocess.check_output(['docker','ps','-q']).decode() and subprocess.check_output(['docker','inspect',*subprocess.check_output(['docker','ps','-q']).decode().split()]));print(json.dumps({x['Name']:x['State']['StartedAt'] for x in d if x['Name']!='/remnanode'}))")
                core_changed=True;print(core(client,'apply').strip(),flush=True)
                time.sleep(2)
                test=subprocess.run([sys.executable,str(BASE/'verify_mihomo.py'),str(SUB),'C:/Program Files/Koala Clash/resources/sidecar/mihomo.exe','--name',policy['name'],'--expected',ip],capture_output=True,timeout=150)
                print(test.stdout.decode(errors='replace'),flush=True)
                if test.returncode:raise RuntimeError('Windows Firefox client failed')
                result=remote(client,"import sys,json,subprocess;from pathlib import Path;d=json.load(sys.stdin);p=Path('/root/ham-koala-batch-release-20261108/verify_xray.py');p.write_text(d['source']);subprocess.run(['python3',str(p),'/root/ham-koala-batch-core-20261108/xray',d['ip']],input=json.dumps(d['reference']).encode(),check=True)",{'source':(BASE/'verify_xray.py').read_text(),'ip':ip,'reference':policy['reference']})
                print(result.strip(),flush=True)
                audit=remote(client,"import sys,json,importlib.util;from pathlib import Path;sys.path.insert(0,'/root/ham-koala-batch-release-20261108');import core_rollback as c;import batch_core as b;p=json.loads(b.POLICY.read_text());b.configure(c,p);old=json.loads((c.STATE/'runtime.before.json').read_text());now,_=c.runtime();i=c.target(old);j=c.target(now);i['settings'].pop('clients',None);j['settings'].pop('clients',None);i['streamSettings']['realitySettings']['minClientVer']='1.8.2';assert i==j;assert old.get('outbounds')==now.get('outbounds') and old.get('routing')==now.get('routing');d=json.loads(c.run(['docker','inspect',*c.run(['docker','ps','-q']).decode().split()]));after={x['Name']:x['State']['StartedAt'] for x in d if x['Name']!='/remnanode'};assert after==json.load(sys.stdin);print('INBOUND_ROUTES_AND_OTHER_CONTAINERS_PRESERVED')",json.loads(before))
                print(audit.strip(),flush=True)
                print(core(client,'accept').strip(),flush=True);profile(bot,policy,'accept')
                results.append({'ip':ip,'passed':True});print('ROLLOUT_ACCEPTED',ip,flush=True)
            except Exception as exc:
                print('ROLLOUT_FAILED',ip,type(exc).__name__,str(exc),flush=True)
                if core_changed:
                    try:print(core(client,'rollback').strip(),flush=True)
                    except Exception:print('CORE_RETURN_TIMER_LEFT_ARMED',ip,flush=True)
                if profile_changed:
                    try:print(profile(bot,policy,'rollback').strip(),flush=True)
                    except Exception:print('PROFILE_RETURN_TIMER_LEFT_ARMED',ip,flush=True)
                results.append({'ip':ip,'passed':False})
            finally:
                if client:client.close()
        print('ROLLOUT_SUMMARY',json.dumps(results),flush=True)
    finally:bot.close()


if __name__=='__main__':main()
