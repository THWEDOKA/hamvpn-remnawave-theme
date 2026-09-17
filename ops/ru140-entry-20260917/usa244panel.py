"""Add only USA2 to the dedicated healthy entry244 profile, with guarded rollback."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import panel244 as p
import usa244site as state
from entry244_common import ENTRY, NODE, ROOT, unit_inactive

STATE=state.STATE
DOMAIN=state.DOMAIN
PORT=18447
LINK=25443
TAG='vless-entry244-usa2'
OUT='exit-usa2'
SOURCE_PROFILE=p.SOURCE_PROFILE
SOURCE_NODE='22ac9320-4762-461d-b877-a9f33b58d492'
SOURCE_INBOUND='33bd54c0-83e3-4ffd-ac7e-4d8c3996d9a5'
HOSTS={'a2302256-68a3-4e3e-8213-5817b0177712','2a69e425-fb50-4bea-aeec-868735309ff4'}
EGRESS='162.141.185.216'
TIMER='ham-usa244-panel-rollback'

def read(name):return state.read('panel-'+name)
def save(name,value):state.save('panel-'+name,value)
def exists(name):return state.exists('panel-'+name)
def checksum(config):return hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()


def source_inbound(profile):
    tag=next(i['tag'] for i in profile['inbounds'] if i['uuid']==SOURCE_INBOUND)
    return next(i for i in profile['config']['inbounds'] if i['tag']==tag)


def build(before,backend_user):
    config=copy.deepcopy(before['profile']['config'])
    original=source_inbound(before['source_profile'])
    front=copy.deepcopy(original);front.update(tag=TAG,listen=ENTRY,port=PORT)
    front['settings']['clients']=[]
    stream=front['streamSettings'];assert stream['network'] in ('tcp','raw') and stream['security']=='reality'
    stream['sockopt']={**stream.get('sockopt',{}),'tcpMaxSeg':1200}
    reality=stream['realitySettings'];reality.pop('dest',None);reality['target']='127.0.0.1:19443'
    reality['serverNames']=list(dict.fromkeys([DOMAIN,*reality['serverNames']]))
    config['inbounds'].append(front)
    out=p.reality_client(original,backend_user,'127.0.0.1','us3.torcalc.ru','chrome')
    out['tag']=OUT;out['settings']['vnext'][0]['port']=LINK
    config['outbounds'].append(out)
    rules=config['routing']['rules']
    position=next((i for i,r in enumerate(rules) if r.get('outboundTag')=='DIRECT'),len(rules))
    rules.insert(position,{'type':'field','inboundTag':[TAG],'outboundTag':OUT})
    assert_preserved(config,before['profile']['config'])
    return config


def assert_preserved(config,old):
    stripped=copy.deepcopy(config)
    assert len([i for i in stripped['inbounds'] if i['tag']==TAG])==1
    stripped['inbounds']=[i for i in stripped['inbounds'] if i['tag']!=TAG]
    stripped['outbounds']=[o for o in stripped['outbounds'] if o.get('tag')!=OUT]
    stripped['routing']['rules']=[r for r in stripped['routing']['rules'] if r.get('inboundTag')!=[TAG]]
    assert stripped==old,'An existing route changed'


def snapshot(api):
    assert not exists('before') and p.exists('finished')
    assert all(unit_inactive(p.TIMER+s) for s in ('.timer','.service'))
    profile_id=p.read('created')['profile']
    nodes=api('GET','/api/nodes/');entry=next(n for n in nodes if n['uuid']==NODE)
    assert entry['address']==ENTRY and entry['isConnected'] and not entry['isDisabled']
    assert [n['uuid'] for n in nodes if p.binding(n)['profile']==profile_id]==[NODE]
    profile=api('GET','/api/config-profiles/'+profile_id)
    assert profile['config']==p.read('candidate')
    assert len(profile['config']['inbounds'])==5 and not any(i['tag']==TAG for i in profile['config']['inbounds'])
    hosts=api('GET','/api/hosts/');selected=[h for h in hosts if h['uuid'] in HOSTS]
    assert len(selected)==2 and sum(h['isHidden'] for h in selected)==1
    for host in selected:
        assert host['nodes']==[SOURCE_NODE] and not host['isDisabled']
        assert host['inbound']=={'configProfileUuid':SOURCE_PROFILE,'configProfileInboundUuid':SOURCE_INBOUND}
        assert host['address']==host['sni']=='us3.torcalc.ru' and host['port']==443
    source=api('GET','/api/config-profiles/'+SOURCE_PROFILE)
    before={'entry':entry,'profile':profile,'source_profile':source,'hosts':selected,
            'other_hosts':{h['uuid']:p.prior.stable_host(h) for h in hosts if h['uuid'] not in HOSTS},
            'squads':api('GET','/api/internal-squads/')['internalSquads']}
    save('before',before)
    return {'healthy_four_route_snapshot_saved':True,'usa_hosts':2}


def prepare(api):
    assert exists('before') and not exists('prepare-intent')
    before=read('before')
    assert api('GET','/api/config-profiles/'+before['profile']['uuid'])['config']==before['profile']['config']
    squad_id=p.prior.read('backend-squad')['uuid'];squad=api('GET','/api/internal-squads/'+squad_id)
    backend=api('GET','/api/users/'+p.prior.read('backend-user')['uuid'])
    assert backend['username']=='ham_entry140_backend' and backend['status']=='ACTIVE'
    save('prepare-intent',{'backend_squad_before':squad,'timestamp':time.time()})
    desired=list(dict.fromkeys(p.ids(squad)+[SOURCE_INBOUND]))
    changed=api('PATCH','/api/internal-squads/',{'uuid':squad_id,'inbounds':desired})
    assert set(p.ids(changed))==set(desired)
    config=build(before,backend);save('candidate',config)
    return {'candidate_ready':True,'existing_four_routes_identical':True}


def installed_test():
    config=json.load(sys.stdin);assert config['inbounds'][-1]['tag']==TAG
    assert config['inbounds'][-1]['port']==PORT and config['inbounds'][-1]['listen']==ENTRY
    state.guard();state.local_tls()
    assert not state.run('ss','-H','-ltn','sport = :'+str(PORT)).strip()
    result=subprocess.run(['docker','exec','-i','remnanode','xray','run','-test','-c','stdin:'],input=json.dumps(config),text=True,capture_output=True)
    save('installed-test-detail',{'passed':result.returncode==0,'output':result.stdout+result.stderr})
    assert result.returncode==0
    save('candidate',config)
    return {'installed_xray_test_passed':True,'sha256':checksum(config),'timestamp':time.time()}


def backend_probe():
    import probe
    probe.STATE=p.STATE;probe.save=p.save
    config=read('candidate');out=next(o for o in config['outbounds'] if o.get('tag')==OUT)
    result=probe.test({'id':'usa244-backend','ip':EGRESS,'outbound':out})
    proof={'result':result,'sha256':checksum(config),'timestamp':time.time()}
    save('backend-proof',proof);assert result['passed']
    return {'backend_passed':True,'sha256':proof['sha256'],'timestamp':proof['timestamp'],'exit_ip':EGRESS}


def activate(api):
    assert not exists('activate-intent')
    before=read('before');config=read('candidate');digest=checksum(config)
    assert read('installed-test')['installed_xray_test_passed'] and read('installed-test')['sha256']==digest
    proof=read('backend-proof');assert proof['backend_passed'] and proof['sha256']==digest and 0<=time.time()-proof['timestamp']<600
    assert api('GET','/api/config-profiles/'+before['profile']['uuid'])['config']==before['profile']['config']
    assert p.binding(api('GET','/api/nodes/'+NODE))==p.binding(before['entry'])
    save('activate-intent',{'timestamp':time.time()})
    subprocess.run(['systemd-run','--unit='+TIMER,'--on-active=25m','python3',str(ROOT/'usa244panel.py'),'rollback'],check=True,capture_output=True)
    changed=api('PATCH','/api/config-profiles/',{'uuid':before['profile']['uuid'],'config':config})
    assert changed['config']==config
    old_meta={i['tag']:i['uuid'] for i in before['profile']['inbounds']}
    now_meta={i['tag']:i['uuid'] for i in changed['inbounds']}
    assert all(now_meta[tag]==value for tag,value in old_meta.items())
    inbound=now_meta[TAG];save('inbound',{'uuid':inbound})
    backend_squad=p.prior.read('backend-squad')['uuid']
    for old in before['squads']:
        if old['uuid']==backend_squad or SOURCE_INBOUND not in p.ids(old):continue
        current=api('GET','/api/internal-squads/'+old['uuid'])
        assert set(p.ids(old))<=set(p.ids(current))
        wanted=list(dict.fromkeys(p.ids(current)+[inbound]))
        assert set(p.ids(api('PATCH','/api/internal-squads/',{'uuid':old['uuid'],'inbounds':wanted})))==set(wanted)
    api('PATCH','/api/nodes/',{'uuid':NODE,'configProfile':{'activeConfigProfileUuid':before['profile']['uuid'],
        'activeInbounds':[*p.binding(before['entry'])['inbounds'],inbound]}})
    save('activated',{'timestamp':time.time()})
    return {'usa_frontend_activated':True,'four_existing_inbounds_preserved':True}


def client(api,fp='chrome'):
    front=next(i for i in read('candidate')['inbounds'] if i['tag']==TAG)
    result=p.reality_client(front,p.user(api),ENTRY,DOMAIN,fp)
    result['settings']['vnext'][0]['port']=PORT
    return result


def probes(api):
    results=[]
    for fp in ('chrome','firefox'):
        result={'fingerprint':fp,**p.test_one(client(api,fp),EGRESS)}
        results.append(result);print(json.dumps(result),flush=True)
    proof={'all_passed':all(r['passed'] for r in results),'tests':results,'timestamp':time.time()}
    save('probes',proof);assert proof['all_passed']
    return {'usa2_frontend_passed':True,'tests':2}


def desired(host):
    return {'inbound':{'configProfileUuid':read('before')['profile']['uuid'],'configProfileInboundUuid':read('inbound')['uuid']},
        'nodes':[NODE],'address':ENTRY,'port':PORT,'sni':DOMAIN,'host':DOMAIN,'securityLayer':'DEFAULT',
        'fingerprint':host.get('fingerprint') or 'chrome','alpn':None,'isDisabled':False}


def verify(api,published):
    before=read('before');profile=api('GET','/api/config-profiles/'+before['profile']['uuid'])
    assert profile['config']==read('candidate');assert_preserved(profile['config'],before['profile']['config'])
    assert api('GET','/api/config-profiles/'+SOURCE_PROFILE)['config']==before['source_profile']['config']
    node=api('GET','/api/nodes/'+NODE)
    assert node['isConnected'] and node['address']==ENTRY and not node['isDisabled']
    assert p.binding(node)['profile']==profile['uuid']
    assert set(p.binding(node)['inbounds'])==set(p.binding(before['entry'])['inbounds']+[read('inbound')['uuid']])
    now={h['uuid']:h for h in api('GET','/api/hosts/')}
    for old in before['hosts']:
        wanted=copy.deepcopy(old)
        if published:wanted.update(desired(old))
        assert p.prior.stable_host(now[old['uuid']])==p.prior.stable_host(wanted)
    # Guard our four live routes while permitting unrelated operator panel edits.
    for identifier in p.TARGET_HOSTS:
        assert p.prior.stable_host(now[identifier])==before['other_hosts'][identifier]
    for old in before['squads']:
        required=p.ids(old)
        if SOURCE_INBOUND in required and old['uuid']!=p.prior.read('backend-squad')['uuid']:
            required=required+[read('inbound')['uuid']]
        assert set(required)<=set(p.ids(api('GET','/api/internal-squads/'+old['uuid'])))
    return {'usa2_route_verified':True,'previous_four_routes_and_hosts_preserved':True,'usa_exit_profile_unchanged':True}


def publish(api):
    assert not exists('publish-intent');proof=read('probes')
    assert proof['all_passed'] and 0<=time.time()-proof['timestamp']<600
    verify(api,False);save('publish-intent',{'timestamp':time.time()})
    for host in read('before')['hosts']:
        api('PATCH','/api/hosts/',{'uuid':host['uuid'],**desired(host)})
    result=verify(api,True);save('published',{'timestamp':time.time(),**result});return result


def subscription(api):
    import prune_hosts
    configs=prune_hosts.subscription(api);name=next(h['remark'] for h in read('before')['hosts'] if not h['isHidden'])
    results=[]
    for source,remark in [('visible',name),('automatic','⚡ Автовыбор Серверов')]:
        config=next(c for c in configs if c.get('remarks')==remark)
        outputs=[o for o in config['outbounds'] if o.get('protocol')=='vless' and any(v.get('address')==ENTRY and v.get('port')==PORT for v in o.get('settings',{}).get('vnext',[]))]
        assert len(outputs)==1
        out=outputs[0];assert out['streamSettings']['security']=='reality'
        assert out['streamSettings']['realitySettings']['serverName']==DOMAIN
        result={'source':source,**p.test_one(out,EGRESS)};results.append(result);print(json.dumps(result),flush=True)
    proof={'timestamp':time.time(),'all_passed':all(r['passed'] for r in results),'tests':results}
    save('subscription',proof);assert proof['all_passed'];return {'usa2_main_and_auto_verified':True}


def rollback(api):
    before=read('before');config=read('candidate');profile=api('GET','/api/config-profiles/'+before['profile']['uuid'])
    assert profile['config'] in (config,before['profile']['config']),'Later profile edit; rollback refused'
    current=api('GET','/api/nodes/'+NODE);old_binding=p.binding(before['entry'])
    allowed=[old_binding]
    if exists('inbound'):allowed.append({'profile':old_binding['profile'],'inbounds':old_binding['inbounds']+[read('inbound')['uuid']]})
    actual=p.binding(current)
    assert any(actual['profile']==v['profile'] and set(actual['inbounds'])==set(v['inbounds']) for v in allowed)
    now={h['uuid']:h for h in api('GET','/api/hosts/')};pending=[]
    for old in before['hosts']:
        actual=now[old['uuid']];new=copy.deepcopy(old)
        if exists('inbound'):new.update(desired(old))
        assert p.prior.stable_host(actual) in (p.prior.stable_host(old),p.prior.stable_host(new))
        if p.prior.stable_host(actual)!=p.prior.stable_host(old):pending.append(old)
    for old in pending:api('PATCH','/api/hosts/',{'uuid':old['uuid'],**{k:old[k] for k in desired(old)}})
    api('PATCH','/api/nodes/',{'uuid':NODE,'configProfile':{'activeConfigProfileUuid':old_binding['profile'],'activeInbounds':old_binding['inbounds']}})
    if profile['config']==config:api('PATCH','/api/config-profiles/',{'uuid':profile['uuid'],'config':before['profile']['config']})
    assert api('GET','/api/config-profiles/'+profile['uuid'])['config']==before['profile']['config']
    save('rollback',{'timestamp':time.time()});return {'previous_four_routes_restored':True,'usa2_hosts_restored':True}


def finish(api):
    proof=read('subscription');assert proof['all_passed'] and 0<=time.time()-proof['timestamp']<1800
    assert not exists('rollback');result=verify(api,True)
    subprocess.run(['systemctl','stop',TIMER+'.timer'],check=True,capture_output=True)
    assert all(unit_inactive(TIMER+s) for s in ('.timer','.service'))
    assert not exists('rollback');verify(api,True)
    save('finished',{'timestamp':time.time(),**result});return {**result,'rollback_inactive':True}


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['snapshot','prepare','export','test','backend','accept-test','accept-backend','activate','probes','publish','subscription','verify','rollback','finish'])
    action=parser.parse_args().action
    if action=='export':print(json.dumps(read('candidate')));sys.exit(0)
    if action.startswith('accept-'):
        proof=json.load(sys.stdin);assert proof['sha256']==checksum(read('candidate'))
        key='installed-test' if action=='accept-test' else 'backend-proof'
        assert proof['installed_xray_test_passed' if action=='accept-test' else 'backend_passed']
        save(key,proof);print('{"proof_accepted":true}');sys.exit(0)
    if action=='test':result=installed_test()
    elif action=='backend':result=backend_probe()
    else:
        api,_=p.prior.create_client();result=verify(api,exists('published')) if action=='verify' else globals()[action](api)
    print(json.dumps(result))
