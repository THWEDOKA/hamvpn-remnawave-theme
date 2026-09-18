"""Bounded AT path diagnostics, no production configuration changes.

Uses the new scope's owned account. Secrets remain SSH stdin/RAM. Temporary
cores bind loopback and are removed; the active application is untouched.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


previous_path = list(sys.path)
try:
    sys.path.insert(0, str(REPO/'ops/cloud140-six-20260918'))
    o = load('at_diagnostic_operator', REPO/'ops/cloud140-six-20260918/operator_session.py')
finally:
    sys.path[:] = previous_path
old = load('at_diagnostic_pure_helpers', REPO/'ops/cloud140-six-20260918/preflight.py')

EXPORT = '''import sys,json
sys.path.insert(0,'/opt/hamvpn-cloud140-six/releases/20f379110847/ops/cloud140-six-20260918')
import preflight as old,frontend_stage as f
p=old.load_file('atnl6_auth_probe','/opt/hamvpn-at-nl6/releases/09fbae986e0f/ops/at-nl6-20260918/preflight.py')
api,q=old.load_file('atnl6_auth_api',old.ROOT.parent/'selfsteal-us3/panel_api.py').create_client()
u=p.probe_user(api,p.Store('cloud'),'cloud')
request=json.load(sys.stdin)
if request['protocol']=='hysteria':
 sub=api('GET','/api/subscriptions/by-uuid/'+u['uuid'])
 main=api('GET','/api/hosts/'+p.TARGETS['at']['host'])
 happ=f.fetch_subscription(sub['subscriptionUrl'],request['headers'],'happ')
 mihomo=f.fetch_subscription(sub['subscriptionUrl'],request['headers'],'mihomo')
 cfg=[c for c in happ if c.get('remarks')==main['remark']]
 assert len(cfg)==1
 wires=[i for i in cfg[0]['outbounds'] if i['protocol']=='hysteria']
 proxies=[v for v in mihomo['proxies'] if v['name']==main['remark']]
 assert len(wires)==len(proxies)==1 and wires[0]['settings']['address']=='147.45.71.38' and proxies[0]['server']=='147.45.71.38'
 print(json.dumps({'xray':wires[0],'mihomo':proxies[0]}))
else:
 n=api('GET','/api/nodes/'+p.TARGETS['at']['node'])
 profile=api('GET','/api/config-profiles/'+p.active(n)[0])
 candidates=[i for i in profile['config']['inbounds'] if i['protocol']=='vless' and i.get('streamSettings',{}).get('security')=='reality']
 assert len(candidates)==1 and n['address']=='147.45.71.38'
 i=candidates[0];meta=next(m for m in profile['inbounds'] if m['tag']==i['tag'])
 body,_=p.read_intent(p.Store('cloud'),'cloud')
 squads=api('GET','/api/internal-squads/')['internalSquads']
 assert any(s['uuid'] in body['activeInternalSquads'] and meta['uuid'] in p.indexed(s['inbounds']) for s in squads)
 r=i['streamSettings']['realitySettings'];public=old.public_key(r['privateKey'])
 wire=dict(protocol='vless',settings=dict(vnext=[dict(address=n['address'],port=i['port'],users=[dict(id=u['vlessUuid'],encryption='none',flow='xtls-rprx-vision')])]),streamSettings=dict(network='raw',security='reality',realitySettings=dict(serverName=r['serverNames'][0],fingerprint='chrome',publicKey=public,shortId=r['shortIds'][0])))
 print(json.dumps({'xray':wire}))
'''


def server_code(target='at'):
    targets = {'at': (('147.45.71.38', '2a12:5940:6020::2'), '147.45.71.38'),
               'nl6': (('31.76.9.211',), '31.76.9.211')}
    addresses, expected_egress = targets[target]
    # Reuse the published, reviewed isolated core lifetime/curl implementation.
    source = (REPO/'ops/cloud140-six-20260918/node_ops.py').read_text()
    run = source[source.index('def run('):source.index('\ndef context(')]
    probe = source[source.index('def listening('):source.index('\ndef traffic(')]
    probe = probe.replace("outbounds=[item['outbound']])", "outbounds=[item['outbound']] + item.get('extra_outbounds', []))")
    code = '''import sys,json,os,tempfile,subprocess,ipaddress,time,socket,hashlib
from pathlib import Path
payload=json.load(sys.stdin)
addrs=json.loads(subprocess.check_output(['ip','-j','-4','addr','show']))
assert payload['entry'] in {a['local'] for i in addrs for a in i.get('addr_info',[])}
container=json.loads(subprocess.check_output(['docker','inspect','remnanode']))[0]
assert container['HostConfig']['NetworkMode']=='host' and container['State']['Running']
wire=payload['wire'];settings=wire['settings']
assert (settings.get('address') or settings.get('vnext',[{}])[0].get('address')) in APPROVED_TARGET_ADDRESSES
class Helpers:
 @staticmethod
 def require(ok,msg):
  if not ok: raise RuntimeError(msg)
 @staticmethod
 def encoded(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 @staticmethod
 def digest(v): return hashlib.sha256(Helpers.encoded(v)).hexdigest()
p=Helpers
''' + run + probe + '''
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='ham-atnl6-probe-',dir='/root') as folder:
 binary=Path(folder)/'xray'
 copied=subprocess.run(['docker','cp','-L','remnanode:/usr/local/bin/xray',str(binary)],capture_output=True,timeout=20)
 assert copied.returncode==0
 binary.chmod(0o700)
 extra=[]
 if payload['protocol']=='fragment':
  wire['streamSettings']['sockopt']={'dialerProxy':'fragment'}
  extra=[{'tag':'fragment','protocol':'freedom','settings':{'fragment':{'packets':'tlshello','length':'100-200','interval':'10-20'}},'streamSettings':{'sockopt':{'tcpNoDelay':True}}}]
 item={'id':APPROVED_TARGET_NAME+'-'+payload['protocol'],'outbound':wire,'extra_outbounds':extra,'expected_egress':APPROVED_EGRESS}
 result=one_probe(item,binary)
print(json.dumps({'entry':payload['entry'],'result':result}))
'''
    return code.replace('APPROVED_TARGET_ADDRESSES', repr(addresses)).replace(
        'APPROVED_TARGET_NAME', repr(target)).replace('APPROVED_EGRESS', repr(expected_egress))


def remote_check(name, protocol, wire, target='at'):
    ip = {'cloud': '176.108.245.140', 'aeza': '193.233.222.244', 'de182': '217.60.68.182'}[name]
    cmd = o.transport.command('entry') if name == 'cloud' else [
        'ssh', '-T', '-i', str(Path.home()/'.ssh/hamvpn-panel'), '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
        '-o', 'ConnectTimeout=12', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', 'root@'+ip]
    command = ('sudo -n ' if name == 'cloud' else '') + o.encoded_command(server_code(target))
    result = subprocess.run(cmd+[command], input=old.encoded(dict(entry=ip, protocol=protocol, wire=wire)),
                            capture_output=True, timeout=125)
    return dict(source=name, protocol=protocol, code=result.returncode,
                proof=json.loads(result.stdout) if result.returncode == 0 else None)


def local_hysteria(proxy):
    code = """let input='';process.stdin.on('data',b=>input+=b);process.stdin.on('end',async()=>{
 try{const i=JSON.parse(input),m=require('./ops/cloud140-six-20260918/frontend_measure.cjs'),a=require('./ops/cloud140-six-20260918/pc_audit.cjs');
 const v=await m.versions(i.binaries,new Set(['mihomo']));console.log(JSON.stringify(await a.probe(i.proxy,i.binaries,v)));}
 catch{console.error('Bounded private probe failed');process.exitCode=1;}});"""
    request = dict(proxy=proxy, binaries=dict(mihomo='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe',
                                             curl='C:/Windows/System32/curl.exe'))
    result = subprocess.run(['node', '-e', code], cwd=REPO, input=old.encoded(request), capture_output=True, timeout=160)
    return dict(source='local-mihomo', protocol='hysteria', code=result.returncode,
                proof=json.loads(result.stdout) if result.returncode == 0 else None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('protocol', choices=['hysteria', 'fragment', 'reality', 'reality6'])
    parser.add_argument('--source', choices=['both', 'cloud', 'aeza', 'de182'], default='both')
    args = parser.parse_args()
    headers = json.loads(subprocess.check_output(['node', '-e',
        "process.stdout.write(JSON.stringify(require('./ops/pc-outage-20260918/subscription_readback.cjs').deviceHeaders()))"],
        cwd=REPO, timeout=20))
    wires = json.loads(o.transport.remote('panel', o.encoded_command(EXPORT),
                       old.encoded(dict(protocol=args.protocol, headers=headers))))
    if args.protocol == 'reality6':
        # This global IPv6 was read from the same pinned AT host, not inferred
        # from DNS or copied from another node. Only the diagnostic wire changes.
        wires['xray']['settings']['vnext'][0]['address'] = '2a12:5940:6020::2'
    with ThreadPoolExecutor(max_workers=3) as pool:
        names = ('cloud', 'aeza') if args.source == 'both' else (args.source,)
        futures = [pool.submit(remote_check, name, args.protocol, wires['xray']) for name in names]
        if args.protocol == 'hysteria': futures.append(pool.submit(local_hysteria, wires['mihomo']))
        for future in as_completed(futures):
            try: print(json.dumps(future.result()), flush=True)
            except Exception as error: print(json.dumps(dict(error=type(error).__name__)), flush=True)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    try: main()
    except Exception:
        print('AT diagnostic stopped; private details suppressed', file=sys.stderr)
        sys.exit(1)
