"""NL6 read-only path preparation; no SSH login to NL6 or route publication.

The existing current subscriptions belong only to the new aeza-scope probe.
Shared G-CONFIG, main/auto bindings, DNS and self-steal remain untouched.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys
import diagnose_at as d

EXPORT = '''import sys,json
sys.path.insert(0,'/opt/hamvpn-cloud140-six/releases/20f379110847/ops/cloud140-six-20260918')
import preflight as old,frontend_stage as f
p=old.load_file('nl6_path_probe','/opt/hamvpn-at-nl6/releases/09fbae986e0f/ops/at-nl6-20260918/preflight.py')
api,q=old.load_file('nl6_path_api',old.ROOT.parent/'selfsteal-us3/panel_api.py').create_client()
user=p.probe_user(api,p.Store('aeza'),'aeza')
body,routes=p.read_intent(p.Store('aeza'),'aeza');assert routes==['nl6']
target=p.TARGETS['nl6'];node=api('GET','/api/nodes/'+target['node'])
assert node['address']==target['ip'] and node['isConnected'] and not node['isDisabled']
sub=api('GET','/api/subscriptions/by-uuid/'+user['uuid']);headers=json.load(sys.stdin)
happ=f.fetch_subscription(sub['subscriptionUrl'],headers,'happ')
mihomo=f.fetch_subscription(sub['subscriptionUrl'],headers,'mihomo')
items=[]
for role,host_id in [('main',target['host']),('auto',target['auto'])]:
 host=api('GET','/api/hosts/'+host_id)
 assert host['nodes']==[target['node']] and host['address']==target['ip'] and not host['isDisabled']
 if role=='main':
  configs=[cfg for cfg in happ if cfg.get('remarks')==host['remark']]
 else:
  configs=[cfg for cfg in happ if cfg.get('remarks')=='\\u26a1 \\u0410\\u0432\\u0442\\u043e\\u0432\\u044b\\u0431\\u043e\\u0440 \\u0421\\u0435\\u0440\\u0432\\u0435\\u0440\\u043e\\u0432']
 assert len(configs)==1
 outs=[o for o in configs[0]['outbounds'] if o.get('protocol')=='vless' and any(v.get('address')==target['ip'] and v.get('port')==host['port'] for v in o.get('settings',{}).get('vnext',[]))]
 proxies=[v for v in mihomo['proxies'] if v['name']==host['remark']]
 assert len(outs)==len(proxies)==1 and proxies[0]['server']==target['ip']
 for kind,wire in [('xray',outs[0]),('mihomo',proxies[0])]:
  items.append({'id':'nl6-'+role+'-'+kind,'client':kind,'wire':wire,'legacy':True,'expected_egress':target['ip'],'wire_sha256':f.wire_hash(kind,wire)})
print(json.dumps({'items':items}))
'''


def fetch():
    headers = json.loads(subprocess.check_output(['node', '-e',
        "process.stdout.write(JSON.stringify(require('./ops/pc-outage-20260918/subscription_readback.cjs').deviceHeaders()))"],
        cwd=d.REPO, timeout=20))
    return json.loads(d.o.transport.remote('panel', d.o.encoded_command(EXPORT), d.old.encoded(headers)))


def local_check(items):
    req = dict(sha256=d.old.digest(items), items=items)
    req['request_sha256'] = d.old.digest(req)
    envelope = dict(request=req, binaries=dict(
        xray='C:/Users/User/AppData/Local/Temp/hamvpn-entry140-xray-26.3.27/xray.exe',
        mihomo='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe', curl='C:/Windows/System32/curl.exe'), concurrency=2)
    result = subprocess.run(['node', 'ops/cloud140-six-20260918/frontend_measure.cjs'], cwd=d.REPO,
                            input=d.old.encoded(envelope), capture_output=True, timeout=180)
    return dict(source='local', code=result.returncode, fresh_subscription=True,
                proof=json.loads(result.stdout) if result.returncode == 0 else None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', choices=['both', 'cloud', 'aeza', 'de182'], default='both')
    parser.add_argument('--local', action='store_true')
    args = parser.parse_args()
    data = fetch()
    wire = next(i['wire'] for i in data['items'] if i['id']=='nl6-main-xray')
    names = ('cloud','aeza') if args.source=='both' else (args.source,)
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(d.remote_check, name, 'reality', wire, 'nl6') for name in names]
        if args.local: futures.append(pool.submit(local_check, data['items']))
        for future in as_completed(futures):
            try: print(json.dumps(future.result()), flush=True)
            except Exception as error: print(json.dumps(dict(error=type(error).__name__)), flush=True)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    try: main()
    except Exception:
        print('NL6 preparation stopped; private details suppressed', file=sys.stderr)
        sys.exit(1)
