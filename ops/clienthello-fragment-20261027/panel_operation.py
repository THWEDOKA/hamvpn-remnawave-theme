"""Scoped HAMVPN API release. Credentials are imported only on the bot host."""
import argparse
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit
from fragment_hosts import clone_payload, SOURCE_UUIDS, NAMES, FINAL_MASK

STATE = Path('/root/ham-clienthello-release-20261027')
CONFIG_UUID = '00000000-0000-0000-0000-000000000000'
UNIT = 'ham-clienthello-release-rollback'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['prepare','apply','verify','rollback','accept'])
    parser.add_argument('--builder', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    sys.path.insert(0, '/opt/hamvpn2')
    import config, httpx
    base = config.REMWAVE_API_URL.rstrip('/')
    assert urlsplit(base).hostname == 'goszapravki.com', 'Wrong panel'
    if not base.endswith('/api'): base += '/api'
    client = httpx.Client(base_url=base+'/', headers={'Authorization':'Bearer '+config.REMWAVE_API_KEY}, timeout=40)

    def api(method, path, data=None):
        r = client.request(method, path, json=data)
        if r.status_code >= 400: raise RuntimeError(f'Panel request rejected: {method} {path.split("/")[0]} HTTP {r.status_code}')
        value = r.json() if r.content else {}
        return value.get('response', value)

    def save(name, value): (STATE/name).write_text(json.dumps(value, ensure_ascii=False), encoding='utf8')
    def load(name): return json.loads((STATE/name).read_text(encoding='utf8'))
    def hosts():
        value=api('GET','hosts')
        return value.get('hosts',value) if isinstance(value,dict) else value
    def cfg(): return api('GET','subscription-page-configs/'+CONFIG_UUID)
    def verify():
        current={h['uuid']:h for h in hosts()}
        before=load('before.json')
        for host in before['hosts']:
            assert current.get(host['uuid'])==host, 'An original host changed'
        created=load('created.json')
        assert len(created)==3
        for host in created:
            assert current.get(host['uuid'])==host, 'Test clone changed'
            assert host['finalMask']==FINAL_MASK and host['fingerprint']=='firefox'
        assert cfg()['config']==load('config-after.json'), 'Subscription config differs'
        print('API_VERIFIED: 3 clones, originals unchanged, VPNET config saved')

    if args.mode=='prepare':
        assert not STATE.exists(), 'Existing release requires review'
        STATE.mkdir(mode=0o700)
        before={'hosts':hosts(), 'subpage':cfg()}
        save('before.json',before);save('created.json',[])
        spec=importlib.util.spec_from_file_location('vpnet_ios',args.builder)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        save('config-after.json',module.add_vpnet(before['subpage']['config']))
        byid={h['uuid']:h for h in before['hosts']}
        save('payloads.json',[clone_payload(byid[uid],name) for uid,name in zip(SOURCE_UUIDS,NAMES)])
        print('PREPARED: private snapshot and scoped payloads')
    elif args.mode=='apply':
        before=load('before.json')
        assert hosts()==before['hosts'] and cfg()==before['subpage'], 'Concurrent changes; replan'
        command=[sys.executable,str(Path(__file__).resolve()),'rollback','--builder',args.builder]
        subprocess.run(['systemd-run','--unit='+UNIT,'--on-active=20m',*command],check=True,stdout=subprocess.DEVNULL)
        created=[]
        for payload in load('payloads.json'):
            assert not any(h['remark']==payload['remark'] for h in hosts()), 'Clone already exists'
            host=api('POST','hosts',payload);created.append(host);save('created.json',created)
        api('PATCH','subscription-page-configs',{'uuid':CONFIG_UUID,'config':load('config-after.json')})
        verify()
    elif args.mode=='verify': verify()
    elif args.mode=='accept':
        verify()
        subprocess.run(['systemctl','stop',UNIT+'.timer'],check=True)
        print('ACCEPTED')
    elif args.mode=='rollback':
        current={h['uuid']:h for h in hosts()}
        for host in load('created.json'):
            if host['uuid'] not in current: continue
            assert current[host['uuid']]==host, 'Refuse to delete externally modified clone'
            api('DELETE','hosts/'+host['uuid'])
        current=cfg()['config']
        if current==load('config-after.json'):
            api('PATCH','subscription-page-configs',{'uuid':CONFIG_UUID,'config':load('before.json')['subpage']['config']})
        elif current!=load('before.json')['subpage']['config']: raise RuntimeError('Config changed externally; manual review required')
        print('ROLLED_BACK: operation-owned objects only')


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('OPERATION_FAILED',type(error).__name__,str(error) if isinstance(error,AssertionError) else 'inspect private release state',file=sys.stderr)
        sys.exit(1)
