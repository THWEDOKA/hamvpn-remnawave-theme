"""Short-lived owned client and full-page data-plane checks; no production config edits."""
import argparse
from datetime import datetime,timedelta,timezone
import tempfile
import uuid
from ops import *


def create():
    guard('panel');api=api_client();created=read('created')
    require(not (STATE/'diagnostic-user-intent.json').exists(),'Existing diagnostic intent; reconcile')
    inbound=created['inbounds']['HAM-MWS2-REALITY']
    squads=[s for s in api('GET','/api/internal-squads/')['internalSquads'] if inbound in {i['uuid'] for i in s['inbounds']}]
    require(squads,'No current MWS entitlement')
    ident=str(uuid.uuid4());body={'uuid':ident,'username':'mws_fullpage_'+ident[:8],
        'expireAt':(datetime.now(timezone.utc)+timedelta(minutes=40)).isoformat(),
        'trafficLimitBytes':536870912,'trafficLimitStrategy':'NO_RESET','tag':'MWS2_DIAG',
        'description':'Temporary full-page diagnostic','activeInternalSquads':[squads[0]['uuid']]}
    save('diagnostic-user-intent',body);u=api('POST','/api/users/',body);save('diagnostic-user',u)
    sub=api('GET','/api/subscriptions/by-uuid/'+u['uuid'])
    req=urllib.request.Request(sub['subscriptionUrl'],headers={'User-Agent':'Happ/5.7.0',
        'X-Hwid':'mws-fullpage-diagnostic','X-Device-Os':'iOS','X-Device-Model':'Deployment diagnostic','X-Ver-Os':'18'})
    with urllib.request.urlopen(req,timeout=25) as r:configs=json.load(r)
    host=api('GET','/api/hosts/'+OLD_HOST)
    main=[c for c in configs if c.get('remarks')==host['remark']];require(len(main)==1,'Host missing')
    wires=[o for o in main[0]['outbounds'] if o.get('protocol')=='vless' and any(v.get('address')==host['address'] for v in o.get('settings',{}).get('vnext',[]))]
    require(len(wires)==1,'Diagnostic outbound ambiguous')
    save('diagnostic-input',{'outbound':wires[0],'expected_egress':TARGETS['exit']['ip'],'russian_egress':TARGETS['entry']['ip']})
    save('diagnostic-full-config',main[0])
    return {'temporary_diagnostic_created':True,'actual_Happ_subscription_read':True}


def pages():
    guard('panel');wire=read('diagnostic-input')['outbound']
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    cfg={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth'}}],'outbounds':[wire]}
    p=subprocess.Popen(['/root/selfsteal-us3-test/xray','run','-c','stdin:'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        p.stdin.write(json.dumps(cfg).encode());p.stdin.close();time.sleep(1)
        results=[]
        for url in ['https://www.gstatic.com/generate_204','https://www.instagram.com/','https://www.wikipedia.org/','https://api.ipify.org','https://internet.yandex.ru']:
            q=subprocess.run(['curl','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'-sSL','--max-time','25',
                '-w','\n%{http_code} bytes=%{size_download} time=%{time_total}',url],capture_output=True,timeout=30)
            body,_,stats=q.stdout.rpartition(b'\n')
            results.append({'url':url,'curl':q.returncode,'stats':stats.decode(errors='replace'),
                'foreign_ip':body.strip().decode() if url.endswith('ipify.org') and len(body)<50 else None,
                'russian_ip_present':b'176.109.85.244' in body if url.endswith('yandex.ru') else None})
        save('diagnostic-pages',{'time':time.time(),'results':results});return read('diagnostic-pages')
    finally:p.terminate();p.wait(timeout=5)


def cleanup():
    guard('panel');api=api_client();u=read('diagnostic-user');current=api('GET','/api/users/'+u['uuid'])
    require(all(current[k]==u[k] for k in ['uuid','username','tag','description']),'Diagnostic identity drift')
    api('DELETE','/api/users/'+u['uuid']);save('diagnostic-user-cleanup',{'time':time.time()})
    return {'diagnostic_user_deleted':True}


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['create','pages','cleanup']);a=p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Private diagnostic details suppressed'}));sys.exit(1)
