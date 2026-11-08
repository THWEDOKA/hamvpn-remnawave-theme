"""One-field canonical profile policy with an independent rollback timer."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

PROFILE='658bbbf6-f169-45ce-9771-f29b03a0d753'
NODE='99de873c-0819-4e33-b2bd-fd0e76432948'
HOST='48623028-3e31-405e-b613-fc3f28d96ed4'
STATE=Path('/root/ham-koala-profile-rollback-20261108')
UNIT='ham-koala-profile-rollback-20261108'


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def candidate(config):
    result=deepcopy(config)
    found=[i for i in result['inbounds'] if i.get('tag')=='plreg-raw']
    if len(found)!=1 or found[0].get('port')!=443 or found[0].get('protocol')!='vless':raise ValueError('Wrong inbound')
    stream=found[0].get('streamSettings',{})
    if stream.get('security')!='reality':raise ValueError('REALITY required')
    reality=stream['realitySettings']
    if reality.get('minClientVer') not in [None,'0.0.0','1.8.2']:raise ValueError('Preserve unexpected version policy')
    reality['minClientVer']='1.8.2'
    return result


def main(action):
    import httpx
    sys.path.insert(0,'/opt/hamvpn2');os.chdir('/opt/hamvpn2');os.umask(0o077)
    import config
    client=httpx.Client(base_url=config.REMWAVE_API_URL.rstrip('/')+'/api/',headers={'Authorization':'Bearer '+config.REMWAVE_API_KEY},timeout=30)
    def api(method,path,body=None):
        response=client.request(method,path,json=body);response.raise_for_status();return response.json()['response']
    def profile():return api('GET','config-profiles/'+PROFILE)
    def timer(*args):subprocess.run(['systemctl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if action=='prepare':
        if STATE.exists():raise ValueError('Existing operation must be reviewed')
        nodes=api('GET','nodes');nodes=nodes.get('nodes',nodes) if isinstance(nodes,dict) else nodes
        if [n['uuid'] for n in nodes if n.get('configProfile',{}).get('activeConfigProfileUuid')==PROFILE]!=[NODE]:raise ValueError('Shared profile is outside scope')
        hosts=api('GET','hosts');hosts=hosts.get('hosts',hosts) if isinstance(hosts,dict) else hosts
        if [h['uuid'] for h in hosts if h.get('inbound',{}).get('configProfileUuid')==PROFILE]!=[HOST]:raise ValueError('Unexpected host consumers')
        before=profile();cfg=before['config'];cfg=json.loads(cfg) if isinstance(cfg,str) else cfg
        after=candidate(cfg);STATE.mkdir(mode=0o700)
        (STATE/'profile.json').write_text(json.dumps({'before':cfg,'after':after,'before_sha':digest(cfg),'after_sha':digest(after)}))
        shutil.copy2(__file__,STATE/'operation.py');print('DEDICATED_PROFILE_BACKED_UP')
        return
    saved=json.loads((STATE/'profile.json').read_text());now=profile()['config'];now=json.loads(now) if isinstance(now,str) else now
    if action=='apply':
        if digest(now)!=saved['before_sha']:raise ValueError('Profile drift')
        subprocess.run(['systemd-run','--unit='+UNIT,'--on-active=20m','/opt/hamvpn2/venv/bin/python',str(STATE/'operation.py'),'rollback'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        api('PATCH','config-profiles',{'uuid':PROFILE,'config':saved['after']})
        if digest(profile()['config'])!=saved['after_sha']:raise ValueError('Profile readback failed')
        print('ONE_CANONICAL_COMPATIBILITY_FIELD_APPLIED_WITH_RETURN_TIMER')
    elif action=='rollback':
        if digest(now)==saved['before_sha']:print('PROFILE_ALREADY_ORIGINAL');return
        if digest(now)!=saved['after_sha']:raise ValueError('External profile change; refuse overwrite')
        api('PATCH','config-profiles',{'uuid':PROFILE,'config':saved['before']});print('ORIGINAL_PROFILE_RESTORED')
    else:
        if digest(now)!=saved['after_sha']:raise ValueError('Profile drift')
        if not api('GET','nodes/'+NODE).get('isConnected'):raise ValueError('Node disconnected')
        timer('stop',UNIT+'.timer');print('CANONICAL_PROFILE_ACCEPTED')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','apply','rollback','accept']);main(parser.parse_args().action)
