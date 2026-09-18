"""Change only the selected MWS host fingerprint, preserving its current name."""
import argparse
from copy import deepcopy
from ops import *
import diagnose


def preview():
    guard('panel');wire=read('diagnostic-input')['outbound']
    wire['streamSettings']['realitySettings']['fingerprint']='firefox'
    result=diagnose.pages(wire)
    require(len(result['results'])==5 and all(r['curl']==0 and r['stats'].startswith(('200 ','204 ')) for r in result['results']),
            'Firefox full-page probe failed')
    require(result['results'][3]['foreign_ip']==TARGETS['exit']['ip'] and result['results'][4]['russian_ip_present'],'Firefox egress mismatch')
    result['wire_sha256']=digest(json.dumps(wire,sort_keys=True).encode())
    save('firefox-preview',result);return {'firefox_full_pages_passed':True,'time':result['time']}


def apply():
    guard('panel');proof=read('firefox-preview');api=api_client();host=api('GET','/api/hosts/'+OLD_HOST)
    require(0<=time.time()-proof['time']<900,'Fresh Firefox proof required')
    require(host['address']=='mws.torcalc.ru' and host['port']==18443 and host['nodes']==[read('created')['node']],
            'Target host no longer matches MWS')
    if not (STATE/'fingerprint-before.json').exists():
        save('fingerprint-before',host)
    else:
        before=read('fingerprint-before')
        require({k:v for k,v in before.items() if k!='fingerprint'}=={k:v for k,v in host.items() if k!='fingerprint'},'Concurrent host change')
    if host['fingerprint']!='firefox':api('PATCH','/api/hosts/',{'uuid':OLD_HOST,'fingerprint':'firefox'})
    after=api('GET','/api/hosts/'+OLD_HOST);wanted=dict(host,fingerprint='firefox')
    require(after==wanted,'Unexpected host change')
    save('fingerprint-after',after)
    return {'host':after['remark'],'fingerprint':'firefox','only_fingerprint_changed':True,'time':time.time()}


def verify():
    import yaml
    guard('panel');api=api_client();u=read('diagnostic-user');sub=api('GET','/api/subscriptions/by-uuid/'+u['uuid'])
    host=api('GET','/api/hosts/'+OLD_HOST)
    require(host['fingerprint']=='firefox','Host fingerprint changed')
    data={}
    for kind,agent in [('happ','Happ/5.7.0'),('mihomo','mihomo/1.19.29')]:
        req=urllib.request.Request(sub['subscriptionUrl'],headers={'User-Agent':agent,'X-Hwid':'mws-fullpage-diagnostic',
            'X-Device-Os':'iOS','X-Device-Model':'Deployment diagnostic','X-Ver-Os':'18'})
        with urllib.request.urlopen(req,timeout=25) as r:text=r.read().decode()
        data[kind]=json.loads(text) if kind=='happ' else yaml.safe_load(text)
    configs=[c for c in data['happ'] if c.get('remarks')==host['remark']];require(len(configs)==1,'Happ host missing')
    wires=[o for o in configs[0]['outbounds'] if o.get('protocol')=='vless' and any(v.get('address')==host['address'] for v in o.get('settings',{}).get('vnext',[]))]
    require(len(wires)==1 and wires[0]['streamSettings']['realitySettings']['fingerprint']=='firefox','Happ fingerprint not Firefox')
    proxies=[p for p in data['mihomo']['proxies'] if p['name']==host['remark']]
    require(len(proxies)==1 and proxies[0]['client-fingerprint']=='firefox','Mihomo fingerprint not Firefox')
    probe={'outbound':wires[0],'expected_egress':TARGETS['exit']['ip'],'russian_egress':TARGETS['entry']['ip']}
    save('firefox-probe-input',dict(probe,mihomo_proxy=proxies[0]))
    pages=diagnose.pages(wires[0])
    require(all(r['curl']==0 and r['stats'].startswith(('200 ','204 ')) for r in pages['results']),'Generated Firefox client failed')
    result={'actual_Happ_fingerprint':'firefox','actual_mihomo_fingerprint':'firefox','pages':pages['results'],'time':time.time()}
    save('firefox-verified',result);return result


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['preview','apply','verify']);a=p.parse_args()
        print(json.dumps(globals()[a.action](),ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Private details suppressed'}));sys.exit(1)
