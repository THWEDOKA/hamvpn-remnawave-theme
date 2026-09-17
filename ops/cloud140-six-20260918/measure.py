"""Measured legacy/backend proofs. Secret requests travel only over SSH stdin.

Panel actions retain an immutable original wire manifest in protected state.
Local run uses the installed entry Xray and, where necessary, an isolated
Mihomo using the existing local cached legacy Hysteria proxy. No app reload.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import preflight as p
import exit_stage as e


def legacy_result(item, result, version):
    p.require(result['id']==item['id'] and result['listener_removed'], 'Probe mismatch/listener leak')
    expected=p.digest({k:v for k,v in item['outbound'].items() if k!='tag'})
    p.require(result['wire_sha256']==expected, 'Actual wire hash differs')
    codes=result['curl_codes']; http=int(result['http'] or 0)
    return dict(kind='legacy',test_id=item['id'],tag=item['legacy_tag'],
                namespace='entry-xray',client='xray-'+version,wire_sha256=expected,
                passed=result['passed'],authenticated=http==204 or result['exit_ip']==item['expected_egress'],
                http_code=http,exit_ip=result['exit_ip'],returncodes=codes)


def panel(action, route_id, payload=None):
    adapter=p.load_file('measure_api',p.ROOT.parent/'selfsteal-us3'/'panel_api.py')
    api,_=adapter.create_client()
    state=e.RootStore(route_id)
    with state.locked():
        worker=e.Coordinator(api,state,e.SystemdTimer())
        before,plan,record=worker._load(route_id)
        if action=='export':
            if not state.exists('legacy-manifest'):
                wire=p.export_baseline(api,p.Store(),[route_id])
                metadata=p.indexed(before['profile']['inbounds'])
                for item in wire['items']:
                    item['expected_egress']=plan['inputs']['expected_egress']
                    item['legacy_tag']=metadata[item['inbound']]['tag']
                state.put('legacy-manifest',wire)
            wire=state.get('legacy-manifest')
            items=wire['items'].copy()
            if payload and payload['after']:
                backend=worker.export_backend(route_id)
                items.append(dict(id=route_id+'-backend',expected_egress=backend['expected_egress'],outbound=backend['outbound']))
            return dict(sha256=record['sha256'],items=items,id=route_id,ip=before['route']['ip'],
                        expected_egress=plan['inputs']['expected_egress'],
                        external=[dict(tag=v['tag'],port=v['port']) for v in before['profile']['config']['inbounds']
                                  if v['protocol']=='hysteria' and e.metadata(before['profile'])[v['tag']] in e.binding(before['node'])['inbounds']])
        raw=payload['entry']; external=payload['external']; after=payload['after']
        p.require(raw['id']=='entry' and raw['ip']==p.ENTRY and raw['node']==p.ENTRY_ID and raw['host_network'], 'Wrong probe namespace')
        p.require(raw['sha256']==record['sha256'], 'Wrong candidate')
        tests=[]; actual={r['id']:r for r in raw['tests']}
        for item in state.get('legacy-manifest')['items']:
            tests.append(legacy_result(item,actual.pop(item['id']),raw['version']))
        for value in external:
            p.require(value['listener_removed'] and value['client'].startswith('mihomo-'), 'External probe incomplete')
            tests.append({k:v for k,v in value.items() if k not in ('listener_removed','timestamp')})
        if after:
            backend=actual.pop(route_id+'-backend')
            p.require(backend['passed'] and backend['listener_removed'] and backend['curl_codes']==[0,0], 'New backend did not pass')
            expected_wire=worker.export_backend(route_id)['outbound']
            p.require(backend['wire_sha256']==p.digest(expected_wire),'Backend actual wire differs')
            tests.append(dict(kind='backend',namespace='entry-xray',authenticated=True,http_code=int(backend['http']),
                              exit_ip=backend['exit_ip'],returncode=0))
        p.require(not actual,'Unexpected probe')
        proof=dict(**before['route'],sha256=record['sha256'],timestamp=min([raw['timestamp']]+[v['timestamp'] for v in external]),tests=tests)
        proof.pop('host',None)
        if after:
            proof.update(entry=p.ENTRY,mode=plan['inputs']['mode'])
            return worker.accept_backend(route_id,proof)
        proof['source_sha256']=p.digest(before['profile']['config'])
        return worker.accept_baseline(route_id,proof)


def local(route_id, release, after):
    import operator_session as o
    root='/opt/hamvpn-cloud140-six/releases/'+release+'/ops/cloud140-six-20260918/'
    export='python3 '+root+'measure.py export --id '+route_id+(' --after' if after else '')
    request=json.loads(o.transport.remote('panel',export))
    raw=json.loads(o.transport.remote('entry','python3 '+root+'node_ops.py traffic --id entry',p.encoded(request)))
    external=[]
    if request['external']:
        script=r'''
const fs=require('fs'),crypto=require('crypto'),cp=require('child_process');
const {test}=require('./ops/pc-outage-20260918/local_matrix.cjs');
(async()=>{let text='';for await(const b of process.stdin)text+=b;const r=JSON.parse(text);
const yaml=require(require.resolve('yaml',{paths:['C:/Users/User/Documents/hamvpn/HamVPN-PC']}));
const config=yaml.parse(fs.readFileSync('C:/Users/User/AppData/Roaming/hamvpn-pc/work/config.yaml','utf8'));
const binary='C:/Program Files/HamVPN PC/resources/sidecar/mihomo.exe';
const version=cp.execFileSync(binary,['-v'],{windowsHide:true,encoding:'utf8'}).match(/Mihomo\s+(\S+)/i)[1];
const output=[];
for(const item of r.external){const matches=config.proxies.filter(p=>p.server===r.ip&&p.port===item.port&&p.type==='hysteria2');
if(matches.length!==1)throw Error('legacy selection');const proxy=matches[0];
const wire={...proxy,name:'MATRIX','client-fingerprint':'chrome'};
const hash=crypto.createHash('sha256').update(JSON.stringify(wire)).digest('hex');
const q=await test({mihomoBinary:binary},{target:{id:r.id,exit_ip:r.expected_egress},proxy,core:'mihomo',fp:'chrome'});
output.push({kind:'legacy',test_id:r.id+'-'+item.tag+'-mihomo',tag:item.tag,namespace:'external-client',client:'mihomo-'+version,
wire_sha256:hash,passed:q.passed===true,authenticated:q.http==='204'||q.exit_ip===r.expected_egress,http_code:Number(q.http||0),
exit_ip:q.exit_ip||null,returncodes:q.curl_codes,listener_removed:q.listener_removed,timestamp:Date.now()/1000});}
process.stdout.write(JSON.stringify(output));})().catch(()=>{console.error('External measured proof failed');process.exitCode=1;});
'''
        run=subprocess.run(['node','-e',script],input=p.encoded(request),capture_output=True,timeout=90)
        p.require(run.returncode==0,'External legacy probe failed')
        external=json.loads(run.stdout)
    print(json.dumps(dict(id=route_id,after=after,tests=raw['tests'],external=external)))
    result=o.transport.remote('panel','python3 '+root+'measure.py accept --id '+route_id,
                              p.encoded(dict(entry=raw,external=external,after=after)))
    print(result.decode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['export','accept','run'])
    parser.add_argument('--id',required=True,choices=sorted(e.ACTIVE_ROUTES))
    parser.add_argument('--after',action='store_true');parser.add_argument('--release')
    args=parser.parse_args()
    if args.action=='run': local(args.id,args.release,args.after)
    else:
        p.require(not sys.stdout.isatty() or args.action!='export','Secret export must be piped')
        print(json.dumps(panel(args.action,args.id,json.load(sys.stdin) if args.action=='accept' else dict(after=args.after))))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__,message='Measurement stopped; no automatic retry')),file=sys.stderr)
        sys.exit(1)
