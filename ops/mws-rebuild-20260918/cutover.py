"""Owned two-host cutover with independent rollback timers and drift guards."""
import argparse
from copy import deepcopy
from ops import *
from node import ENTRY_CONTAINER, installed_test
import routing

TIMER='ham-mws2-cutover-rollback'
WATCHDOG='rw-core-watchdog-ham-shared'
HOST_FIELDS=('inbound','address','port','sni','host','path','alpn','fingerprint','securityLayer',
             'xhttpExtraParams','nodes','overrideSniFromAddress','keepSniBlank')


def binding(node):
    p=node['configProfile']
    return {'activeConfigProfileUuid':p['activeConfigProfileUuid'],
            'activeInbounds':sorted(i['uuid'] if isinstance(i,dict) else i for i in p['activeInbounds'])}


def selected(host):return {k:host[k] for k in HOST_FIELDS}


def desired_binding(created,final):
    ids=created['inbounds']
    return {'activeConfigProfileUuid':created['profile'],'activeInbounds':sorted(
        list(ids.values()) if final else [ids[routing.ENTRY_TAG]])}


def timer_status():
    result={}
    for suffix in ['timer','service']:
        p=subprocess.run(['systemctl','show',TIMER+'.'+suffix,'--property=LoadState,ActiveState,Job,MainPID,ExecStart'],capture_output=True,text=True)
        fields=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
        require(fields.get('LoadState') in ['loaded','not-found'],'Unknown rollback unit')
        require(fields.get('ActiveState') in ['active','inactive','activating','deactivating','failed'],'Unknown rollback state')
        result[suffix]=fields
    return result


def arm(role):
    guard(role);read('cutover-'+role)
    require(not (STATE/'cutover-armed.json').exists(),'Timer intent exists; reconcile')
    status=timer_status()
    require(all(s['ActiveState']=='inactive' and s.get('Job','0') in ('','0') for s in status.values()),'Rollback not quiescent')
    script=str(Path(__file__).resolve())
    save('cutover-armed',{'script':script,'role':role,'time':time.time()})
    run('systemd-run','--quiet','--unit='+TIMER,'--on-active='+('19m' if role=='panel' else '20m'),
        '/usr/bin/python3',script,'rollback','--role',role)
    require(timer_status()['timer']['ActiveState']=='active','Timer not armed')
    return {'rollback_armed':True,'role':role}


def disarm(role):
    guard(role);intent=read('cutover-armed');s=timer_status()
    require(intent['role']==role and intent['script'] in s['service'].get('ExecStart',''),'Timer owner mismatch')
    require(s['service']['ActiveState']=='inactive' and s['service'].get('Job','0') in ('','0'),'Rollback already executing or failed')
    run('systemctl','stop',TIMER+'.timer')
    s=timer_status()
    require(all(v['ActiveState']=='inactive' and v.get('Job','0') in ('','0') for v in s.values()),'Timer/service cancellation incomplete')
    require(not (STATE/'cutover-rollback.json').exists(),'Rollback marker exists')
    save('cutover-disarmed',{'time':time.time()})
    return {'rollback_timer_and_service_inactive':True,'role':role}


def prepare_panel():
    guard('panel');api=api_client();created=read('created');plan=read('plan');before=read('panel-before')
    proof=read('probe-frontend')
    require(proof.get('frontend_passed') is True and proof.get('probe_location')=='panel' and 0<=time.time()-proof['time']<1800,'External frontend proof required')
    require(proof['wire_sha256']==digest(json.dumps(read('frontend-probe-input')['outbound'],sort_keys=True).encode()),'Preview proof mismatch')
    require(not (STATE/'cutover-panel.json').exists(),'Cutover already prepared')
    require(api('GET','/api/config-profiles/'+created['profile'])['config']==plan['entry'],'Candidate drift')
    require(binding(api('GET','/api/nodes/'+created['node']))==desired_binding(created,False),'Candidate binding drift')
    require(binding(api('GET','/api/nodes/'+OLD_NODE))==binding(before['node']),'Old binding drift')
    require(api('GET','/api/config-profiles/'+OLD_PROFILE)['config']==before['profile']['config'],'Old profile drift')
    require(selected(api('GET','/api/hosts/'+OLD_HOST))==selected(before['hosts'][0]),'Host drift')
    final=deepcopy(plan['entry']);final['inbounds'][0]['port']=443
    wanted=selected(before['hosts'][0]);wanted.update(
        inbound={'configProfileUuid':created['profile'],'configProfileInboundUuid':created['inbounds'][routing.ENTRY_TAG]},
        address=TARGETS['entry']['domain'],port=443,sni=TARGETS['entry']['domain'],host=TARGETS['entry']['domain'],
        path=None,alpn=None,securityLayer='DEFAULT',xhttpExtraParams=None,nodes=[created['node']],
        overrideSniFromAddress=False,keepSniBlank=False)
    save('cutover-panel',{'config':final,'config_sha256':digest(json.dumps(final,sort_keys=True).encode()),
                          'before_host':selected(before['hosts'][0]),'wanted_host':wanted,'time':time.time()})
    front=read('frontend-probe-input');front['outbound']['settings']['vnext'][0]['port']=443
    save('final-probe-input',front)
    legacy=next(i for i in before['profile']['config']['inbounds'] if i['tag']=='HAMWLMWS1-XHTTP')
    host=before['hosts'][0]
    wire={'tag':'LEGACY','protocol':'vless','settings':{'vnext':[{'address':TARGETS['entry']['ip'],'port':2083,
          'users':[{'id':read('test-user')['vlessUuid'],'encryption':'none'}]}]},'streamSettings':{
          'network':'xhttp','security':'tls','tlsSettings':{'serverName':host['sni'],'fingerprint':host['fingerprint']},
          'xhttpSettings':deepcopy(legacy['streamSettings']['xhttpSettings'])}}
    save('legacy-probe-input',dict(front,outbound=wire))
    return {'cutover_prepared':True,'config_sha256':digest(json.dumps(final,sort_keys=True).encode())}


def containers():return {name:json.loads(run('docker','inspect',name))[0] for name in [OLD_CONTAINER,ENTRY_CONTAINER]}


def prepare_entry():
    guard('entry');read('node-before');data=json.load(sys.stdin)
    require(not (STATE/'cutover-entry.json').exists(),'Entry cutover already prepared')
    require(digest(json.dumps(data['config'],sort_keys=True).encode())==data['config_sha256'],'Config hash mismatch')
    installed_test(data['config']);c=containers()
    require(all(v['State']['Running'] for v in c.values()),'Both services must be running before preparation')
    save('cutover-entry',{'containers':{k:v['Id'] for k,v in c.items()},'config_sha256':data['config_sha256'],'time':time.time()})
    return {'installed_final_config_test_passed':True,'config_sha256':data['config_sha256']}


def stop_old():
    guard('entry');saved=read('cutover-entry');c=containers()
    require(timer_status()['timer']['ActiveState']=='active','Entry rollback must be armed')
    require({k:v['Id'] for k,v in c.items()}==saved['containers'],'Container ownership drift')
    require(not (STATE/'old-stopped.json').exists(),'Old stop already attempted')
    watchdog=Path('/etc/systemd/system/'+WATCHDOG+'.service')
    require('Environment=CONTAINER='+OLD_CONTAINER in watchdog.read_text(),'Unexpected watchdog scope')
    save('watchdog-before',{'service_sha256':digest(watchdog.read_bytes()),
        'enabled':subprocess.run(['systemctl','is-enabled',WATCHDOG+'.timer'],capture_output=True,text=True).stdout.strip(),
        'active':subprocess.run(['systemctl','is-active',WATCHDOG+'.timer'],capture_output=True,text=True).stdout.strip()})
    run('systemctl','disable','--now',WATCHDOG+'.timer');run('systemctl','stop',WATCHDOG+'.service')
    save('old-stopped',{'time':time.time()});run('docker','stop','--time','15',OLD_CONTAINER,timeout=30)
    require(not containers()[OLD_CONTAINER]['State']['Running'],'Old container still running')
    return {'old_target_stopped':True,'other_containers_untouched':True}


def activate():
    guard('panel');api=api_client();saved=read('cutover-panel');created=read('created');plan=read('plan')
    proof=json.load(sys.stdin)
    require(proof.get('installed_final_config_test_passed') is True and proof.get('config_sha256')==saved['config_sha256'],'Installed Xray proof mismatch')
    require(timer_status()['timer']['ActiveState']=='active','Panel rollback must be armed')
    require(api('GET','/api/config-profiles/'+created['profile'])['config']==plan['entry'],'Candidate drift')
    save('cutover-active-intent',{'time':time.time()})
    api('PATCH','/api/config-profiles/',{'uuid':created['profile'],'config':saved['config']})
    api('PATCH','/api/nodes/',{'uuid':created['node'],'configProfile':desired_binding(created,True)})
    for _ in range(15):
        n=api('GET','/api/nodes/'+created['node'])
        if n.get('isConnected'):break
        time.sleep(2)
    require(n.get('isConnected'),'Final node not connected')
    require(api('GET','/api/config-profiles/'+created['profile'])['config']==saved['config'],'Final config mismatch')
    return {'final_ports_activated':True,'subscription_not_yet_changed':True}


def publish():
    guard('panel');api=api_client();saved=read('cutover-panel');created=read('created')
    proof=json.load(sys.stdin)
    require(proof.get('mihomo_passed') is True and 0<=time.time()-proof.get('time',0)<600,'Fresh external mihomo proof required')
    require(proof.get('wire_sha256')==digest(json.dumps(read('final-probe-input')['outbound'],sort_keys=True).encode()),'Final proof mismatch')
    require(timer_status()['timer']['ActiveState']=='active','Rollback missing')
    require(selected(api('GET','/api/hosts/'+OLD_HOST))==saved['before_host'],'Host changed before publication')
    require(binding(api('GET','/api/nodes/'+created['node']))==desired_binding(created,True),'Final binding drift')
    save('published-intent',{'time':time.time()})
    result=api('PATCH','/api/hosts/',dict(saved['wanted_host'],uuid=OLD_HOST))
    require(selected(result)==saved['wanted_host'],'Published host mismatch')
    save('published',{'time':time.time()})
    return {'mws_host_replaced':True,'other_hosts_unchanged':True}


def rollback(role):
    guard(role)
    if role=='entry':
        saved=read('cutover-entry');c=containers()
        require({k:v['Id'] for k,v in c.items()}==saved['containers'],'Container ownership drift; do not overwrite')
        run('docker','stop','--time','10',ENTRY_CONTAINER,timeout=25)
        old=containers()[OLD_CONTAINER]
        if not old['NetworkSettings']['Networks']:
            run('docker','stop','--time','10',OLD_CONTAINER,timeout=25)
            before=next(c for c in read('node-before')['containers'] if c['Name']=='/'+OLD_CONTAINER)
            networks=before['NetworkSettings']['Networks']
            require(list(networks)==['remnanode-ham-shared_default'],'Unexpected original network')
            run('docker','network','connect','--ip',networks['remnanode-ham-shared_default']['IPAddress'],
                'remnanode-ham-shared_default',OLD_CONTAINER)
        run('docker','start',OLD_CONTAINER)
        require(containers()[OLD_CONTAINER]['State']['Running'],'Old service did not recover')
        if (STATE/'watchdog-before.json').exists():
            w=read('watchdog-before')
            require(digest(Path('/etc/systemd/system/'+WATCHDOG+'.service').read_bytes())==w['service_sha256'],'Watchdog ownership drift')
            if w['enabled']=='enabled':run('systemctl','enable',WATCHDOG+'.timer')
            if w['active']=='active':run('systemctl','start',WATCHDOG+'.timer')
    else:
        api=api_client();saved=read('cutover-panel');created=read('created');plan=read('plan')
        host=api('GET','/api/hosts/'+OLD_HOST);profile=api('GET','/api/config-profiles/'+created['profile'])
        require(selected(host) in [saved['before_host'],saved['wanted_host']],'Host ownership conflict')
        require(profile['config'] in [plan['entry'],saved['config']],'Profile ownership conflict')
        require(binding(api('GET','/api/nodes/'+created['node'])) in [desired_binding(created,False),desired_binding(created,True)],'Node ownership conflict')
        if selected(host)!=saved['before_host']:api('PATCH','/api/hosts/',dict(saved['before_host'],uuid=OLD_HOST))
        api('PATCH','/api/nodes/',{'uuid':created['node'],'configProfile':desired_binding(created,False)})
        api('PATCH','/api/config-profiles/',{'uuid':created['profile'],'config':plan['entry']})
    save('cutover-rollback',{'time':time.time(),'role':role})
    return {'scoped_rollback_applied':True,'role':role}


def retry(role):
    guard(role);read('cutover-rollback')
    require(all(v['ActiveState']=='inactive' and v.get('Job','0') in ('','0') for v in timer_status().values()),'Previous rollback still active')
    if role=='panel':
        api=api_client();c=read('created');before=read('panel-before')
        require(selected(api('GET','/api/hosts/'+OLD_HOST))==selected(before['hosts'][0]),'Old host not restored')
        require(api('GET','/api/nodes/'+OLD_NODE)['isConnected'],'Old node not connected')
        require(api('GET','/api/config-profiles/'+c['profile'])['config']==read('plan')['entry'],'Preview profile not restored')
    else:
        c=containers();require(c[OLD_CONTAINER]['State']['Running'],'Old service not restored')
        require('remnanode-ham-shared_default' in c[OLD_CONTAINER]['NetworkSettings']['Networks'],'Old network not restored')
        run('docker','start',ENTRY_CONTAINER)
    archive=STATE/('attempt-1-'+role);require(not archive.exists(),'Retry already prepared');archive.mkdir(mode=0o700)
    for name in ['cutover-armed','cutover-rollback','cutover-active-intent','old-stopped']:
        p=STATE/(name+'.json')
        if p.exists():p.rename(archive/p.name)
    return {'retry_prepared':True,'prior_attempt_retained':True,'role':role}


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare_panel','prepare_entry','arm','disarm','stop_old','activate','publish','rollback','retry']);p.add_argument('--role',choices=['entry','panel']);a=p.parse_args()
        print(json.dumps(globals()[a.action](a.role) if a.action in ['arm','disarm','rollback','retry'] else globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
