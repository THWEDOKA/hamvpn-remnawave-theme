"""Actual subscription readback and conservative cleanup of replaced MWS objects."""
import argparse
import uuid
from ops import *
from cutover import selected,binding,desired_binding,timer_status
import routing


def subscription():
    import yaml
    guard('panel');api=api_client();before=read('panel-before');created=read('created');plan=read('plan')
    require((STATE/'published.json').exists(),'Host not published')
    user=read('test-user');sub=api('GET','/api/subscriptions/by-uuid/'+user['uuid'])
    responses={}
    for kind,agent in [('happ','Happ/5.7.0'),('mihomo','mihomo/1.19.29')]:
        request=urllib.request.Request(sub['subscriptionUrl'],headers={'User-Agent':agent,
            'X-Hwid':'ham-mws2-deployment-probe','X-Device-Os':'Linux',
            'X-Device-Model':'Deployment probe','X-Ver-Os':'24.04'})
        with urllib.request.urlopen(request,timeout=25) as r:
            require(r.status==200,'Subscription HTTP failure');text=r.read().decode()
        responses[kind]=json.loads(text) if kind=='happ' else yaml.safe_load(text)
        save('subscription-'+kind,responses[kind])
    old=before['hosts'][0];domain=TARGETS['entry']['domain']
    main=[c for c in responses['happ'] if c.get('remarks')==old['remark']]
    require(len(main)==1,'Ambiguous Happ main host')
    wires=[o for o in main[0]['outbounds'] if o.get('protocol')=='vless' and any(v.get('address')==domain for v in o.get('settings',{}).get('vnext',[]))]
    require(len(wires)==1,'Missing new public outbound')
    wire=wires[0];v=wire['settings']['vnext'][0];s=wire['streamSettings'];r=s['realitySettings']
    expected_port=read('cutover-panel')['wanted_host']['port']
    require(v['port']==expected_port and v['users'][0]['id']==user['vlessUuid'] and v['users'][0]['flow']=='xtls-rprx-vision','Public credentials/port/flow mismatch')
    require(s['security']=='reality' and s['network'] in ('raw','tcp') and r['serverName']==domain
            and r['publicKey']==plan['keys']['entry']['public'] and r['shortId']==plan['keys']['entry']['short'],'Public REALITY mismatch')
    proxies=[p for p in responses['mihomo'].get('proxies',[]) if p.get('name')==old['remark']]
    require(len(proxies)==1,'Missing or duplicated PC host')
    p=proxies[0]
    require(p['server']==domain and p['port']==expected_port and p['type']=='vless' and p['tls'] is True
            and p['uuid']==user['vlessUuid'] and p['flow']=='xtls-rprx-vision' and p['servername']==domain
            and p['reality-opts']['public-key']==r['publicKey'] and p['reality-opts']['short-id']==r['shortId']
            and not p.get('skip-cert-verify',False),'PC subscription mismatch')
    data={'outbound':wire,'expected_egress':TARGETS['exit']['ip'],'russian_egress':TARGETS['entry']['ip']}
    save('subscription-probe-input',data);save('subscription-mihomo-input',dict(data,mihomo_proxy=p))
    before_auto=any(v.get('address')==old['address'] for c in read('subscription-before') if 'Автовыбор' in c.get('remarks','')
                    for o in c.get('outbounds',[]) for v in o.get('settings',{}).get('vnext',[]))
    after_auto=any(v.get('address')==domain for c in responses['happ'] if 'Автовыбор' in c.get('remarks','')
                    for o in c.get('outbounds',[]) for v in o.get('settings',{}).get('vnext',[]))
    require(not before_auto or after_auto,'Existing automatic membership lost')
    result={'happ_main_verified':True,'mihomo_main_verified':True,'auto_had_old':before_auto,'auto_has_new':after_auto,'time':time.time()}
    save('subscription-readback',result);return result


def verify():
    guard('panel');api=api_client();before=read('panel-before');created=read('created');expected=read('cutover-panel')
    nodes={n['uuid']:n for n in api('GET','/api/nodes/')};hosts={h['uuid']:h for h in api('GET','/api/hosts/')}
    require(nodes[created['node']]['isConnected'] and binding(nodes[created['node']])==desired_binding(created,True),'Replacement node unhealthy')
    require(selected(hosts[OLD_HOST])==expected['wanted_host'],'Replacement host drift')
    require(api('GET','/api/config-profiles/'+created['profile'])['config']==expected['config'],'Replacement config drift')
    for n in before['all_nodes']:
        if n['uuid']!=OLD_NODE:require(binding(nodes[n['uuid']])==binding(n),'Unrelated node binding changed')
    for h in before['all_hosts']:
        if h['uuid']!=OLD_HOST:require({k:v for k,v in h.items() if k!='viewPosition'}=={k:v for k,v in hosts[h['uuid']].items() if k!='viewPosition'},'Unrelated host changed')
    old_ids={i['uuid'] for i in before['profile']['inbounds']}
    for squad in before['squads']:
        fresh=api('GET','/api/internal-squads/'+squad['uuid'])
        preserved={i['uuid'] for i in squad['inbounds']}-old_ids
        require(preserved<={i['uuid'] for i in fresh['inbounds']},'Unrelated entitlement removed')
    result={'replacement_connected':True,'other_node_bindings_preserved':len(before['all_nodes'])-1,
            'other_hosts_preserved':len(before['all_hosts'])-1,'time':time.time()}
    save('final-verify',result);return result


def record_proofs():
    guard('panel');data=json.load(sys.stdin)
    require(set(data)=={'xray','mihomo','legacy'},'All final proofs required')
    for label,p in data.items():
        require(0<=time.time()-p.get('time',0)<900,'Stale final proof')
        require(p.get('mihomo_passed' if label=='mihomo' else 'frontend_passed') is True,'Failed final probe')
        require(set(p['checks'])=={'foreign_204','foreign_ip','russian_ip'} and all(c['passed'] for c in p['checks'].values()),'Incomplete checks')
        target=read('legacy-probe-input' if label=='legacy' else 'subscription-probe-input')
        require(p['wire_sha256']==digest(json.dumps(target['outbound'],sort_keys=True).encode()),'Proof config mismatch')
    save('final-proofs',data);return {'exact_subscription_and_cached_legacy_passed':True}


def cleanup():
    guard('panel');api=api_client();before=read('panel-before');created=read('created')
    read('cutover-disarmed');proofs=read('final-proofs')
    require(all(0<=time.time()-p['time']<1800 for p in proofs.values()),'Final proofs stale')
    require(all(s['ActiveState']=='inactive' and s.get('Job','0') in ('','0') for s in timer_status().values()),'Rollback still armed')
    verify()
    require(digest((STATE/'panel-before.json').read_bytes())==read('panel-before-checksum')['sha256'],'Snapshot hash mismatch')
    nodes=api('GET','/api/nodes/');old=next((n for n in nodes if n['uuid']==OLD_NODE),None)
    if old:
        require(binding(old)==binding(before['node']),'Old node binding drift')
        require(not any(OLD_NODE in h['nodes'] for h in api('GET','/api/hosts/')),'Old node still has hosts')
        save('delete-old-node-intent',{'uuid':OLD_NODE,'time':time.time()})
        api('DELETE','/api/nodes/'+OLD_NODE)
    require(not any(n['uuid']==OLD_NODE for n in api('GET','/api/nodes/')),'Old node still present')
    profiles=api('GET','/api/config-profiles/')['configProfiles']
    if any(p['uuid']==OLD_PROFILE for p in profiles):
        require(api('GET','/api/config-profiles/'+OLD_PROFILE)['config']==before['profile']['config'],'Old profile drift')
        require(not any((n.get('configProfile') or {}).get('activeConfigProfileUuid')==OLD_PROFILE for n in api('GET','/api/nodes/')),'Old profile still used')
        require(not any((h.get('inbound') or {}).get('configProfileUuid')==OLD_PROFILE for h in api('GET','/api/hosts/')),'Old inbound still published')
        save('delete-old-profile-intent',{'uuid':OLD_PROFILE,'time':time.time()});api('DELETE','/api/config-profiles/'+OLD_PROFILE)
    require(not any(p['uuid']==OLD_PROFILE for p in api('GET','/api/config-profiles/')['configProfiles']),'Old profile still present')
    save('cleanup-old',{'old_node_removed':True,'old_profile_removed':True,'old_host_replaced_in_place':True,'time':time.time()})
    return read('cleanup-old')


def cleanup_user():
    guard('panel');api=api_client();u=read('test-user')
    current=api('GET','/api/users/'+u['uuid'])
    require(all(current[k]==u[k] for k in ['uuid','username','tag','description']),'Test account ownership drift')
    api('DELETE','/api/users/'+u['uuid'])
    # API readback may return 404 or a deleted object depending on version; use read-only count.
    path=ROOT.parent/'selfsteal-us3/panel_api.py';spec=importlib.util.spec_from_file_location('cleanup_api',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);_,query=m.create_client()
    count=query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='"+str(uuid.UUID(u['uuid']))+"'")
    require(count['remaining']==0,'Test account still present')
    save('cleanup-test-user',{'verified_absent':True,'time':time.time()});return {'temporary_user_removed':True}


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['subscription','verify','record_proofs','cleanup','cleanup_user']);a=p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
