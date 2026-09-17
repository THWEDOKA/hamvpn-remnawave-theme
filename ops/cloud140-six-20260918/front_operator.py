"""Local operator orchestration. All credentials/configuration remain in RAM.

Deploy helpers must already be archived from verified origin/main to panel and
entry. This does not publish a host automatically: each lifecycle step is an
explicit CLI action, protected by the frontend coordinator's gates/timer.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import preflight as p
import frontend_stage as f
import operator_session as o


def command(root, action, route_id, secret=False):
    return 'python3 '+root+'frontend_stage.py '+action+' --id '+route_id+(' --secret-stdout' if secret else '')


def read_panel(root, code, data=None):
    prefix='import sys,json;sys.path.insert(0,'+repr(root)+');import preflight as p\n'
    return o.transport.remote('panel',o.encoded_command(prefix+code),data)


def measure(request):
    envelope=dict(request=request,binaries=dict(
        xray='C:/Users/User/AppData/Local/Temp/hamvpn-entry140-xray-26.3.27/xray.exe',
        mihomo='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe',
        curl='C:/Windows/System32/curl.exe'),concurrency=2)
    result=subprocess.run(['node','ops/cloud140-six-20260918/frontend_measure.cjs'],
                          input=p.encoded(envelope),capture_output=True,timeout=480)
    p.require(result.returncode==0,'Measured frontend runner failed')
    proof=json.loads(result.stdout)
    print(json.dumps(proof),flush=True)
    return proof


def prepare(root, route_id):
    runtime=json.loads(o.transport.remote('entry','python3 '+root+'node_ops.py runtime --id entry'))
    port=f.PORTS[route_id]
    p.require(port not in runtime['listening_ports'],'Frontend port is already occupied')
    # Existing nginx SNI router on 443 is not a public Xray inbound.
    inspect="import subprocess,json;v=subprocess.check_output(['ss','-H','-lntp','sport = :443'],text=True);rules=subprocess.check_output(['iptables','-S','INPUT'],text=True).splitlines();print(json.dumps({'nginx443':bool(v.strip()) and all('nginx' in x for x in v.splitlines()),'firewall_ready':rules==['-P INPUT ACCEPT','-A INPUT -p tcp -m tcp --dport 2222 -j HAM_ENTRY140_API']}))"
    actual=json.loads(o.transport.remote('entry',o.encoded_command(inspect)))
    p.require(actual['nginx443'] and actual['firewall_ready'],'Existing entry listener/firewall differs')
    site_root='/opt/hamvpn-cloud140-six/releases/6884c635ba3f/ops/cloud140-six-20260918/'
    dns=json.loads(o.transport.remote('panel','python3 '+site_root+'site.py dns-verify'))
    p.require(dns.get('dns_readback_and_two_resolvers_passed') is True,
              'Inspect actual DNS proof schema')
    verify=json.loads(o.transport.remote('entry','python3 '+site_root+'site.py verify'))
    completion=json.loads(o.transport.remote('entry',o.encoded_command(
        "from pathlib import Path;import json;print((Path('/root/hamvpn-cloud140-six-20260918/site/completion-proof.json')).read_text())")))
    p.require(completion['site_ready'] and completion['renewal']['passed'],'Site completion missing')
    site=dict(entry=p.ENTRY,timestamp=runtime['timestamp'],loopback_port=verify['loopback_port'],chain_verified=True,
              certificate_valid=True,dns_verified=True,checks=verify['checks'],https_sites=verify['https_sites'],
              renewal_dry_run_passed=True,renewal_performed_at=completion['renewal']['timestamp'],
              deploy_hook=True,timer_enabled=completion['renewal_timer_enabled'],timer_active=completion['renewal_timer_active'])
    data=dict(runtime=dict(id='entry',node=p.ENTRY_ID,ip=p.ENTRY,timestamp=runtime['timestamp'],port=port,
              port_free=True,namespace_verified=runtime['host_network'],firewall_ready=True,
              xray_version=runtime['version'],legacy443listening_nginx_verified=True),site=site)
    if p.AUTOS[route_id]:data['auto_remark']='⚡ Автовыбор Серверов'
    return o.transport.remote('panel',command(root,'prepare',route_id),p.encoded(data))


def installed(root, route_id):
    config=json.loads(o.transport.remote('panel',command(root,'export-config',route_id,True)))
    result=json.loads(o.transport.remote('entry','python3 '+root+'node_ops.py installed --id entry',
                                      p.encoded(dict(config=config,sha256=p.digest(config)))))
    proof={k:result[k] for k in ('id','node','ip','timestamp','sha256')}
    proof['tests']=[dict(kind='installed-xray',version=result['version'],passed=result['passed'],returncode=result['returncode'])]
    print(json.dumps(proof),flush=True)
    return o.transport.remote('panel',command(root,'accept-installed',route_id),p.encoded(proof))


def baseline(root, route_id):
    # A real pre-mutation reference for nginx's existing in-de3 route. It uses
    # the existing server wire and the owned temporary account, not an invented
    # cached customer. The second case uses the customer's ACTUAL cached DE5.
    source="""
api,_=p.load_file('front_legacy_api',p.ROOT.parent/'selfsteal-us3'/'panel_api.py').create_client()
n=api('GET','/api/nodes/'+p.ENTRY_ID)
profile=api('GET','/api/config-profiles/'+n['configProfile']['activeConfigProfileUuid'])
raw=next(i for i in profile['config']['inbounds'] if i['tag']=='ham-entry140-de182')
user=p.probe_user(api,p.Store());r=raw['streamSettings']['realitySettings']
wire=dict(protocol='vless',settings=dict(vnext=[dict(address=p.ENTRY,port=443,users=[dict(id=user['vlessUuid'],encryption='none',flow='xtls-rprx-vision')])]),
streamSettings=dict(network='raw',security='reality',realitySettings=dict(serverName=r['serverNames'][0],fingerprint='chrome',publicKey=p.public_key(r['privateKey']),shortId=r['shortIds'][0])))
print(json.dumps(wire))
"""
    old=json.loads(read_panel(root,source))
    script="const fs=require('fs'),yaml=require(require.resolve('yaml',{paths:['C:/Users/User/Documents/hamvpn/HamVPN-PC']}));const c=yaml.parse(fs.readFileSync('C:/Users/User/AppData/Roaming/hamvpn-pc/work/config.yaml','utf8'));const a=c.proxies.filter(p=>p.server==='176.108.245.140'&&p.port===18444);if(a.length!==1)process.exit(1);process.stdout.write(JSON.stringify(a[0]));"
    cached=subprocess.run(['node','-e',script],capture_output=True,timeout=20)
    p.require(cached.returncode==0,'Cached DE5 route ambiguous')
    cases=dict(items=[dict(id='legacy-443-reference',client='xray',wire=old,expected_egress='217.60.68.182'),
                     dict(id='legacy-18444-cached',client='mihomo',wire=json.loads(cached.stdout),expected_egress='196.251.107.245')])
    request=json.loads(o.transport.remote('panel',command(root,'export-baseline',route_id,True),p.encoded(cases)))
    return o.transport.remote('panel',command(root,'accept-baseline',route_id),p.encoded(measure(request)))


def traffic(root, route_id, phase):
    data=None
    if phase=='subscription':
        script="process.stdout.write(JSON.stringify({headers:require('./ops/pc-outage-20260918/subscription_readback.cjs').deviceHeaders()}))"
        headers=subprocess.run(['node','-e',script],capture_output=True,timeout=20)
        p.require(headers.returncode==0,'Existing device headers unavailable')
        data=headers.stdout
    request=json.loads(o.transport.remote('panel',command(root,'export-'+phase,route_id,True),data))
    return o.transport.remote('panel',command(root,'accept-'+phase,route_id),p.encoded(measure(request)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['prepare','installed','baseline','stage','public','publish','subscription','finish','status','rollback'])
    parser.add_argument('--id',required=True,choices=tuple(f.PORTS));parser.add_argument('--release',required=True)
    args=parser.parse_args()
    p.require(len(args.release)==12 and all(x in '0123456789abcdef' for x in args.release),'Exact published release prefix required')
    root='/opt/hamvpn-cloud140-six/releases/'+args.release+'/ops/cloud140-six-20260918/'
    if args.action in ('prepare','installed','baseline'):out=globals()[args.action](root,args.id)
    elif args.action in ('public','subscription'):out=traffic(root,args.id,args.action)
    else:out=o.transport.remote('panel',command(root,args.action,args.id))
    print(out.decode(),flush=True)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__,message='Frontend operator stopped; no hidden retry')),file=sys.stderr)
        sys.exit(1)
