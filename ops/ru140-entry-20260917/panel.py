"""Additive staging and guarded migration of precisely eight existing hosts."""
import argparse
import base64
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid
from common import ROOT,STATE,ENTRY,NODES,NAME,TIMER,save,read,exists,ids,binding,digest

sys.path.insert(0,str(ROOT.parent/'selfsteal-us3'))
from panel_api import create_client
XRAY='/root/selfsteal-us3-test/xray'
EXTRA_HOSTS={
 'fcc4fe74-8251-429f-8ef3-cf45f6101667','b98091cd-05d6-4eed-b3dd-23016bf6e5e3',
 '79496854-603a-401d-ba2a-640b728f4866','be656d37-28a8-446c-b957-5e18b4d0e4fc',
 'da7e708c-3771-468d-9069-33deedf35a0e','4beec50e-0e74-4bff-96e1-f84ab5ce4411',
 '3b965c19-538a-432a-9e9b-4ec44f71594b','f0d5bbfe-6fd2-46f0-8bd4-41876599c3b1'}
HOST_FIELDS=('inbound','address','port','sni','host','nodes','securityLayer','fingerprint','alpn','isDisabled')


def public_key(private):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    k=X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private+'='))
    return base64.urlsafe_b64encode(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode().rstrip('=')


def upstream(n,profiles,user,local):
    profile=profiles[n['profile']]
    meta=next(i for i in profile['inbounds'] if i['uuid']==n['inbound'])
    original=next(i for i in profile['config']['inbounds'] if i['tag']==meta['tag'])
    stream=original['streamSettings'];assert stream['network'] in ('raw','tcp')
    security=stream['security'];assert security in ('tls','reality')
    out={'tag':'exit-'+n['id'],'protocol':'vless','settings':{'vnext':[{
        'address':'127.0.0.1' if local else n['ip'],'port':n['link'] if local else 443,
        'users':[{'id':user['vlessUuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
        'streamSettings':{'network':'raw','security':security}}
    if security=='tls':
        out['streamSettings']['tlsSettings']={'serverName':n['exit_sni'],'allowInsecure':False,
            'fingerprint':'chrome','alpn':['h2','http/1.1']}
    else:
        r=stream['realitySettings'];assert n['exit_sni'] in r['serverNames']
        out['streamSettings']['realitySettings']={'serverName':n['exit_sni'],'fingerprint':'chrome',
            'publicKey':public_key(r['privateKey']),'shortId':r['shortIds'][0]}
    return out


def candidate(profiles,user):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
    config={'log':{'loglevel':'warning'},'inbounds':[],'outbounds':[{'tag':'BLOCK','protocol':'blackhole'}],
        'routing':{'rules':[{'type':'field','ip':['geoip:private'],'outboundTag':'BLOCK'},
            {'type':'field','domain':['geosite:private'],'outboundTag':'BLOCK'},
            {'type':'field','protocol':['bittorrent'],'outboundTag':'BLOCK'}]}}
    for n in NODES:
        private=X25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
        tag='ham-entry140-'+n['id']
        config['inbounds'].append({'tag':tag,'listen':'127.0.0.1','port':n['port'],'protocol':'vless',
            'settings':{'clients':[],'decryption':'none'},'sniffing':{'enabled':True,'destOverride':['http','tls']},
            'streamSettings':{'network':'raw','security':'reality','realitySettings':{
                'show':False,'target':'127.0.0.1:8443','xver':0,'serverNames':[n['domain']],
                'privateKey':base64.urlsafe_b64encode(private).decode().rstrip('='),'shortIds':[secrets.token_hex(8)]}}})
        config['outbounds'].append(upstream(n,profiles,user,True))
        config['routing']['rules'].append({'type':'field','inboundTag':[tag],'outboundTag':'exit-'+n['id']})
    return config


def snapshot(api):
    assert not exists('before'),'Previous intent exists; reconcile'
    nodes=api('GET','/api/nodes/');hosts=api('GET','/api/hosts/');squads=api('GET','/api/internal-squads/')['internalSquads']
    assert not any(n['address']==ENTRY or n['name']==NAME for n in nodes)
    assert not any(p['name']==NAME for p in api('GET','/api/config-profiles/')['configProfiles'])
    profiles={p:api('GET','/api/config-profiles/'+p) for p in {n['profile'] for n in NODES}}
    for n in NODES:
        node=next(x for x in nodes if x['uuid']==n['node'])
        assert node['address']==n['ip'] and node['isConnected'] and not node['isDisabled']
        assert binding(node)['profile']==n['profile'] and n['inbound'] in binding(node)['inbounds']
        for hid in n['hosts']:
            h=next(x for x in hosts if x['uuid']==hid)
            assert h['nodes']==[n['node']] and h['inbound']=={'configProfileUuid':n['profile'],'configProfileInboundUuid':n['inbound']}
            assert not h['isDisabled'] and h['port']==443
        assert any(n['inbound'] in ids(s) and s['name']=='BASE' for s in squads)
    for h in hosts:
        if h['uuid'] in EXTRA_HOSTS:assert len(h['nodes'])==1 and h['nodes'][0] in {n['node'] for n in NODES}
    save('before',{'nodes':nodes,'hosts':hosts,'profiles':profiles,'squads':squads})
    save('before-checksum',{'sha256':digest(STATE/'before.json')})
    return {'snapshot_verified':True,'nodes':len(nodes),'hosts':len(hosts),'migrate_hosts':8}


def backend(api):
    before=read('before');assert not exists('backend-intent')
    body={'name':'HAM-RU140-BACKEND','inbounds':[n['inbound'] for n in NODES]}
    assert not any(s['name']==body['name'] for s in api('GET','/api/internal-squads/')['internalSquads'])
    save('backend-intent',{'squad':body})
    squad=api('POST','/api/internal-squads/',body);save('backend-squad',squad)
    assert set(ids(squad))==set(body['inbounds'])
    identifier=str(uuid.uuid4())
    user_body={'uuid':identifier,'username':'ham_entry140_backend','expireAt':(datetime.now(timezone.utc)+timedelta(days=3650)).isoformat(),
        'trafficLimitBytes':0,'trafficLimitStrategy':'NO_RESET','tag':'RU140_BACKEND',
        'description':'Private infrastructure account for four entry140 exit links; not a customer',
        'activeInternalSquads':[squad['uuid']]}
    save('backend-user-intent',user_body);user=api('POST','/api/users/',user_body);save('backend-user',{'uuid':user['uuid']})
    assert user['uuid']==identifier
    config=candidate(before['profiles'],user);save('candidate',config)
    result=subprocess.run([XRAY,'run','-test','-c',str(STATE/'candidate.json')],cwd=str(Path(XRAY).parent),capture_output=True,text=True)
    save('panel-xray-test',{'passed':result.returncode==0,'output':result.stdout+result.stderr})
    assert result.returncode==0,'Candidate rejected, details private'
    return {'private_backend_ready':True,'panel_xray_test_passed':True}


def stage(api):
    assert not exists('create-intent')
    assert read('installed-xray-test')['installed_xray_test_passed']
    config=read('candidate');save('create-intent',{'name':NAME,'sha256':digest(STATE/'candidate.json')})
    p=api('POST','/api/config-profiles/',{'name':NAME,'config':config});assert p['config']==config
    created={'profile':p['uuid'],'inbounds':{n['id']:next(i['uuid'] for i in p['inbounds'] if i['tag']=='ham-entry140-'+n['id']) for n in NODES}}
    save('created',created)
    node=api('POST','/api/nodes/',{'name':NAME,'address':ENTRY,'port':2222,'countryCode':'RU','isTrafficTrackingActive':True,
        'configProfile':{'activeConfigProfileUuid':p['uuid'],'activeInbounds':list(created['inbounds'].values())},
        'note':'Self-steal entry; four independent restricted SSH links to existing exits'})
    created['node']=node['uuid'];save('created',created)
    for old in read('before')['squads']:
        additions=[created['inbounds'][n['id']] for n in NODES if n['inbound'] in ids(old)]
        if not additions:continue
        s=api('GET','/api/internal-squads/'+old['uuid']);assert set(ids(old))<=set(ids(s))
        wanted=list(dict.fromkeys(ids(s)+additions))
        assert set(ids(api('PATCH','/api/internal-squads/',{'uuid':s['uuid'],'inbounds':wanted})))==set(wanted)
    return {'isolated_profile_staged':True,'old_hosts_unchanged':True,'entry_node':node['uuid']}


def create_test(api):
    assert not exists('test-user')
    squad=next(s for s in read('before')['squads'] if s['name']=='BASE')
    identifier=str(uuid.uuid4());body={'uuid':identifier,'username':'entry140_probe_'+identifier[:8],
        'expireAt':(datetime.now(timezone.utc)+timedelta(hours=3)).isoformat(),
        'trafficLimitBytes':1073741824,'trafficLimitStrategy':'NO_RESET','tag':'ENTRY140_PROBE',
        'description':'Temporary entry140 end-to-end deployment check','activeInternalSquads':[squad['uuid']]}
    save('test-user',body);assert api('POST','/api/users/',body)['uuid']==identifier
    return {'test_user_created':True,'expires_hours':3}


def client(n,user,fingerprint='chrome'):
    config=read('candidate');r=next(i for i in config['inbounds'] if i['tag']=='ham-entry140-'+n['id'])['streamSettings']['realitySettings']
    return {'protocol':'vless','settings':{'vnext':[{'address':ENTRY,'port':443,
        'users':[{'id':user['vlessUuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]},
        'streamSettings':{'network':'raw','security':'reality','realitySettings':{'serverName':n['domain'],
            'fingerprint':fingerprint,'publicKey':public_key(r['privateKey']),'shortId':r['shortIds'][0]}}}


def test_outbound(outbound,n):
    spec=importlib.util.spec_from_file_location('test_support',ROOT.parent/'selfsteal-ru214/panel.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    mod.STATE=STATE;mod.IP=n['ip'];mod.XRAY=XRAY
    return mod.test_outbound(outbound)


def probes(api,old=False):
    user=api('GET','/api/users/'+read('test-user')['uuid']);tests=[]
    if not old:assert api('GET','/api/nodes/'+read('created')['node'])['isConnected']
    for n in NODES:
        for fp in (['cached'] if old else ['chrome','firefox']):
            out=upstream(n,read('before')['profiles'],user,False) if old else client(n,user,fp)
            result={'id':n['id'],'fingerprint':fp,**test_outbound(out,n)};tests.append(result)
    proof={'timestamp':time.time(),'all_passed':all(t['passed'] for t in tests),'tests':tests}
    save('old-probes' if old else 'new-probes',proof)
    assert proof['all_passed'],'Probe failed; do not migrate hosts'
    return proof


def desired_host(host):
    n=next(n for n in NODES if host['uuid'] in n['hosts']);created=read('created')
    return {'inbound':{'configProfileUuid':created['profile'],'configProfileInboundUuid':created['inbounds'][n['id']]},
        'address':n['domain'],'port':443,'sni':n['domain'],'host':n['domain'],'nodes':[created['node']],
        'securityLayer':'DEFAULT','fingerprint':host.get('fingerprint') or 'chrome','alpn':None,'isDisabled':False}


def stable_host(host):return {k:v for k,v in host.items() if k!='viewPosition'}


def verify(api,published=False):
    before=read('before');created=read('created')
    now_nodes={n['uuid']:n for n in api('GET','/api/nodes/')}
    now_hosts={h['uuid']:h for h in api('GET','/api/hosts/')}
    migrated={hid for n in NODES for hid in n['hosts']}
    for n in before['nodes']:
        current=now_nodes[n['uuid']]
        assert binding(n)==binding(current),'Existing node binding changed'
        assert all(n[k]==current[k] for k in ('name','address','port','isDisabled')),'Existing node changed'
    for h in before['hosts']:
        expected=copy.deepcopy(h)
        if published and h['uuid'] in migrated:expected.update(desired_host(h))
        if published and h['uuid'] in EXTRA_HOSTS:expected['isDisabled']=True
        assert stable_host(expected)==stable_host(now_hosts[h['uuid']]),'Host changed: '+h['uuid']
    for pid,p in before['profiles'].items():assert api('GET','/api/config-profiles/'+pid)['config']==p['config'],'Exit profile changed'
    for old in before['squads']:
        required=set(ids(old))|{created['inbounds'][n['id']] for n in NODES if n['inbound'] in ids(old)}
        assert required<=set(ids(api('GET','/api/internal-squads/'+old['uuid']))),'Existing entitlement lost'
    assert now_nodes[created['node']]['isConnected']
    return {'entry_connected':True,'old_node_bindings_preserved':len(before['nodes']),
        'old_profiles_preserved':len(before['profiles']),'other_hosts_preserved':len(before['hosts'])-len(migrated|EXTRA_HOSTS),
        'migrated_hosts':8 if published else 0,'disabled_old_direct_variants':len(EXTRA_HOSTS) if published else 0}


def publish(api):
    assert not exists('publish-intent')
    for name in ['old-probes','new-probes']:
        proof=read(name);assert proof['all_passed'] and time.time()-proof['timestamp']<1800
    verify(api)
    subprocess.run(['systemd-run','--unit='+TIMER,'--on-active=30m','--timer-property=AccuracySec=1s',
        '/usr/bin/python3',str(ROOT/'panel.py'),'rollback'],check=True,capture_output=True)
    subprocess.run(['systemctl','is-active','--quiet',TIMER+'.timer'],check=True)
    before=read('before');save('publish-intent',{'timestamp':time.time()})
    migrated={hid for n in NODES for hid in n['hosts']}
    try:
        for h in before['hosts']:
            if h['uuid'] not in migrated|EXTRA_HOSTS:continue
            current=api('GET','/api/hosts/'+h['uuid']);assert stable_host(current)==stable_host(h),'Concurrent host edit'
            change=desired_host(h) if h['uuid'] in migrated else {'isDisabled':True}
            api('PATCH','/api/hosts/',{'uuid':h['uuid'],**change})
        proof=verify(api,True);save('published',{'timestamp':time.time(),**proof})
        return proof
    except Exception:
        rollback(api);raise


def rollback(api):
    before=read('before');migrated={hid for n in NODES for hid in n['hosts']}
    for h in before['hosts']:
        if h['uuid'] not in migrated|EXTRA_HOSTS:continue
        current=api('GET','/api/hosts/'+h['uuid'])
        if h['uuid'] in migrated:
            wanted=desired_host(h)
            assert all(current[k] in (h[k],wanted[k]) for k in HOST_FIELDS),'Later host change; rollback refused'
            api('PATCH','/api/hosts/',{'uuid':h['uuid'],**{k:h[k] for k in HOST_FIELDS}})
        else:
            assert current['inbound']==h['inbound'] and current['address']==h['address'],'Later host change'
            api('PATCH','/api/hosts/',{'uuid':h['uuid'],'isDisabled':h['isDisabled']})
        restored=api('GET','/api/hosts/'+h['uuid'])
        assert all(restored[k]==h[k] for k in HOST_FIELDS),'Rollback verification failed'
    save('rollback',{'timestamp':time.time(),'old_hosts_restored':True})
    return {'old_hosts_restored':True,'new_profile_and_links_retained_for_inspection':True}


def subscription(api):
    assert exists('published') and not exists('rollback')
    sub=api('GET','/api/subscriptions/by-uuid/'+read('test-user')['uuid'])
    request=urllib.request.Request(sub['subscriptionUrl'],headers={'User-Agent':'Happ/5.7.0',
        'X-Hwid':'ham-entry140-deployment-probe','X-Device-Os':'iOS','X-Device-Model':'Deployment probe','X-Ver-Os':'18'})
    with urllib.request.urlopen(request,timeout=30) as response:
        configs=json.load(response);assert response.status==200
    before=read('before');tests=[]
    automatic=[c for c in configs if c.get('remarks')=='⚡ Автовыбор Серверов'];assert len(automatic)==1
    def targets(c,n):return [o for o in c.get('outbounds',[]) if o.get('protocol')=='vless' and
        any(v.get('address')==n['domain'] for v in o.get('settings',{}).get('vnext',[]))]
    for n in NODES:
        old=next(h for h in before['hosts'] if h['uuid']==n['hosts'][0])
        match=[c for c in configs if c.get('remarks')==old['remark']];assert len(match)==1
        one=targets(match[0],n);auto=targets(automatic[0],n);assert len(one)==len(auto)==1
        for kind,output in [('visible',one[0]),('auto',auto[0])]:
            assert output['streamSettings']['security']=='reality'
            assert output['streamSettings']['realitySettings']['serverName']==n['domain']
            assert output['settings']['vnext'][0]['port']==443
            result={'id':n['id'],'source':kind,**test_outbound(output,n)};tests.append(result)
    banned={h['remark'] for h in before['hosts'] if h['uuid'] in EXTRA_HOSTS and not h['isHidden']}
    assert not banned.intersection(c.get('remarks') for c in configs),'Old experimental direct host still published'
    proof={'timestamp':time.time(),'all_passed':all(t['passed'] for t in tests),'tests':tests,'configs':len(configs)}
    save('subscription-proof',proof)
    if not proof['all_passed']:
        rollback(api);raise RuntimeError('Subscription failed; hosts restored')
    return proof


def cleanup(api,query):
    intent=read('test-user');u=api('GET','/api/users/'+intent['uuid'])
    assert all(u[k]==intent[k] for k in ('username','tag','description'))
    api('DELETE','/api/users/'+intent['uuid'])
    count=query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='"+str(uuid.UUID(intent['uuid']))+"'")
    assert count['remaining']==0;save('test-cleanup',{'verified_absent':True})
    return {'temporary_test_user_deleted':True,'backend_service_user_retained':True}


def finish(api):
    proof=read('subscription-proof');assert proof['all_passed'] and time.time()-proof['timestamp']<1800
    assert read('test-cleanup')['verified_absent'];result=verify(api,True)
    subprocess.run(['systemctl','stop',TIMER+'.timer'],check=True,capture_output=True)
    assert subprocess.run(['systemctl','is-active','--quiet',TIMER+'.timer']).returncode!=0
    save('finished',{'timestamp':time.time(),**result})
    return {**result,'rollback_timer_inactive':True}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('action',choices=['snapshot','backend','stage','create-test','old-probes','new-probes',
        'publish','verify','rollback','subscription','cleanup','finish','export-candidate','export-node-key','accept-test']);a=p.parse_args()
    if a.action=='export-candidate':print(json.dumps(read('candidate')));return
    if a.action=='accept-test':
        data=json.load(sys.stdin);assert data['installed_xray_test_passed']
        assert data['sha256']==digest(STATE/'candidate.json')
        save('installed-xray-test',data);print('{"accepted":true}');return
    api,query=create_client()
    if a.action=='export-node-key':print(json.dumps(api('GET','/api/keygen/')));return
    if a.action=='cleanup':result=cleanup(api,query)
    elif a.action in ('old-probes','new-probes'):result=probes(api,a.action=='old-probes')
    elif a.action=='verify':result=verify(api,exists('published') and not exists('rollback'))
    else:result=globals()[a.action.replace('-','_')](api)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
