"""Protected runtime plans and panel staging. Never prints credentials."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
import secrets
import subprocess
import time
import uuid
from ops import *
import routing


def pair():
    private = run('openssl','genpkey','-algorithm','X25519','-outform','DER')
    public = run('openssl','pkey','-inform','DER','-pubout','-outform','DER',data=private)
    require(private.hex().startswith('302e020100300506032b656e04220420') and len(private)==48, 'Unexpected private key format')
    require(public.hex().startswith('302a300506032b656e032100') and len(public)==44, 'Unexpected public key format')
    enc=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
    return {'private':enc(private[-32:]),'public':enc(public[-32:]),'short':secrets.token_hex(8)}


def plan():
    before=read('panel-before')
    require(not (STATE/'plan.json').exists(),'Plan already exists; preserve identities')
    api=api_client()
    current=api('GET','/api/config-profiles/'+OLD_PROFILE)
    require(current['config']==before['profile']['config'],'Original profile changed')
    keys={'entry':pair(),'exit':pair()}; identity=str(uuid.uuid4())
    foreign=routing.outbound(TARGETS['exit']['ip'],TARGETS['exit']['domain'],443,
                              identity,keys['exit']['public'],keys['exit']['short'])
    legacy=next(i for i in before['profile']['config']['inbounds'] if i['tag']=='HAMWLMWS1-XHTTP')
    entry=routing.entry_config(foreign,keys['entry']['private'],keys['entry']['short'],legacy)
    bridge=routing.exit_config(keys['exit']['private'],keys['exit']['short'])
    bridge['inbounds'][0]['settings']['clients']=[{'id':identity,'flow':'xtls-rprx-vision','email':'mws-infrastructure'}]
    node_key=api('GET','/api/keygen/')
    require(isinstance(node_key.get('pubKey'),str) and len(node_key['pubKey'])>40,'Missing node authentication key')
    save('bridge-input',{'config':bridge,'image':IMAGE})
    save('entry-input',{'image':IMAGE,'pubKey':node_key['pubKey'],'config':entry})
    save('backend-probe-input',{'outbound':foreign,'expected_egress':TARGETS['exit']['ip']})
    save('plan',{'keys':keys,'entry':entry,'foreign':foreign,'created':time.time()})
    return {'runtime_plan_saved':True,'foreign_backend_encrypted':True,'no_panel_bindings_changed':True}


def stage():
    api=api_client(); before=read('panel-before'); plan=read('plan')
    proof=json.load(sys.stdin)
    require(proof.get('backend_passed') is True and proof.get('expected_egress')==TARGETS['exit']['ip']
            and 0<=time.time()-proof.get('time',0)<1800,'Fresh real backend proof required')
    require(proof.get('wire_sha256')==digest(json.dumps(plan['foreign'],sort_keys=True).encode()),'Backend proof is for another configuration')
    require(not (STATE/'stage-intent.json').exists(),'Staging intent exists; reconcile before retry')
    require(api('GET','/api/config-profiles/'+OLD_PROFILE)['config']==before['profile']['config'],'Old profile drift')
    name='HAM-MWS2-RU-DIRECT-FOREIGN'
    require(not any(n['name']==name for n in api('GET','/api/nodes/')),'Candidate node exists')
    save('stage-intent',{'name':name,'time':time.time()})
    profile=api('POST','/api/config-profiles/',{'name':name,'config':plan['entry']})
    created={'profile':profile['uuid'],'inbounds':{i['tag']:i['uuid'] for i in profile['inbounds']}}
    save('created',created)
    node=api('POST','/api/nodes/',{'name':name,'address':TARGETS['entry']['ip'],'port':2226,
        'countryCode':'RU','isTrafficTrackingActive':True,'configProfile':{
            'activeConfigProfileUuid':profile['uuid'],'activeInbounds':[created['inbounds'][routing.ENTRY_TAG]]},
        'note':'Russian direct egress, one encrypted foreign exit; replacement for MWS'})
    created['node']=node['uuid'];save('created',created)
    original_inbound=before['hosts'][0]['inbound']['configProfileInboundUuid']
    squad_ids=[]
    for old in before['squads']:
        if original_inbound not in {i['uuid'] for i in old.get('inbounds',[])}:continue
        fresh=api('GET','/api/internal-squads/'+old['uuid'])
        wanted=list(dict.fromkeys([i['uuid'] for i in fresh['inbounds']]+list(created['inbounds'].values())))
        result=api('PATCH','/api/internal-squads/',{'uuid':fresh['uuid'],'inbounds':wanted})
        require(set(wanted)=={i['uuid'] for i in result['inbounds']},'Squad readback mismatch')
        squad_ids.append(old['uuid'])
    require(squad_ids,'No customer rights found')
    identifier=str(uuid.uuid4())
    body={'uuid':identifier,'username':'mws2_probe_'+identifier[:8],
          'expireAt':(datetime.now(timezone.utc)+timedelta(hours=6)).isoformat(),
          'trafficLimitBytes':536870912,'trafficLimitStrategy':'NO_RESET','tag':'MWS2_PROBE',
          'description':'Temporary MWS split-route validation','activeInternalSquads':[squad_ids[0]]}
    save('test-user-intent',body)
    user=api('POST','/api/users/',body);save('test-user',user)
    wire=routing.outbound(TARGETS['entry']['ip'],TARGETS['entry']['domain'],18443,
                          user['vlessUuid'],plan['keys']['entry']['public'],plan['keys']['entry']['short'])
    save('frontend-probe-input',{'outbound':wire,'expected_egress':TARGETS['exit']['ip'],
                                'russian_egress':TARGETS['entry']['ip']})
    for _ in range(12):
        n=api('GET','/api/nodes/'+created['node'])
        if n.get('isConnected'):break
        time.sleep(2)
    require(n.get('isConnected'),'Candidate node did not connect; old node remains untouched')
    return {'candidate_node_connected':True,'old_hosts_unchanged':True,'preview_port':18443,'test_user_expires_hours':6}


def reverse_plan():
    require(not (STATE/'stage-intent.json').exists(),'Cannot change staged topology')
    proof=json.load(sys.stdin)
    require(proof.get('reverse_loopback_only') is True and proof.get('ssh_restrictions_verified') is True
            and 0<=time.time()-proof.get('time',0)<600,'Fresh restricted listener proof required')
    plan=read('plan');endpoint=plan['foreign']['settings']['vnext'][0]
    require(endpoint['address']==TARGETS['exit']['ip'] and endpoint['port']==443,'Plan already changed')
    save('direct-plan-before',plan)
    endpoint['address']='127.0.0.1';endpoint['port']=27443
    plan['entry']['outbounds'][0]=plan['foreign']
    plan['transport']='REALITY inside restricted reverse SSH'
    entry=read('entry-input');entry['config']=plan['entry']
    save('entry-input',entry);save('plan',plan)
    save('backend-probe-input',{'outbound':plan['foreign'],'expected_egress':TARGETS['exit']['ip']})
    return {'private_candidate_uses_reverse':True,'no_panel_bindings_changed':True}


if __name__=='__main__':
    try:
        guard('panel');p=argparse.ArgumentParser();p.add_argument('action',choices=['plan','stage','reverse_plan']);a=p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
