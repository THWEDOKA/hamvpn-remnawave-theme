"""Isolated Windows mihomo probe; no active application settings are touched."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

BINARY=Path('C:/Users/User/Documents/hamvpn/HamVPN-PC/extra/sidecar/mihomo.exe')


def proxy(wire):
    endpoint=wire['settings']['vnext'][0];s=wire['streamSettings'];r=s['realitySettings']
    assert s['security']=='reality' and s['network'] in ('raw','tcp')
    return {'name':'MWS-PROBE','type':'vless','server':endpoint['address'],'port':endpoint['port'],
            'uuid':endpoint['users'][0]['id'],'flow':endpoint['users'][0]['flow'],'tls':True,
            'network':'tcp','servername':r['serverName'],'client-fingerprint':r['fingerprint'],
            'reality-opts':{'public-key':r['publicKey'],'short-id':r['shortId']},'udp':True}


def probe(data):
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config={'mixed-port':port,'bind-address':'127.0.0.1','allow-lan':False,'log-level':'silent',
            'mode':'rule','tun':{'enable':False},'dns':{'enable':False},'ipv6':False,
            'profile':{'store-selected':False,'store-fake-ip':False},
            'proxies':[data.get('mihomo_proxy') or proxy(data['outbound'])],
            'rules':['MATCH,'+(data.get('mihomo_proxy') or {}).get('name','MWS-PROBE')]}
    raw=json.dumps(config).encode();flags=subprocess.CREATE_NO_WINDOW
    with tempfile.TemporaryDirectory(prefix='ham-mws2-probe-') as folder:
        test=subprocess.run([str(BINARY),'-t','-d',folder,'-f','-'],input=raw,capture_output=True,creationflags=flags,timeout=20)
        assert test.returncode==0,'Mihomo configuration test failed'
        p=subprocess.Popen([str(BINARY),'-d',folder,'-f','-'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=flags)
        try:
            p.stdin.write(raw);p.stdin.close()
            for _ in range(80):
                assert p.poll() is None,'Isolated client exited'
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.1)
            else:raise RuntimeError('No client listener')
            base=['curl.exe','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'-4','-fsS','--max-time','25']
            checks={}
            for name,url in [('foreign_204','https://www.gstatic.com/generate_204'),('foreign_ip','https://api.ipify.org'),('russian_ip','https://internet.yandex.ru')]:
                args=['-o','NUL','-w','%{http_code}'] if name=='foreign_204' else []
                q=subprocess.run(base+args+[url],capture_output=True,creationflags=flags,timeout=30)
                value=q.stdout.decode(errors='replace').strip()
                expected='204' if name=='foreign_204' else data['expected_egress'] if name=='foreign_ip' else data['russian_egress']
                checks[name]={'passed':q.returncode==0 and (expected in value if name=='russian_ip' else expected==value),'curl_code':q.returncode}
            return {'mihomo_passed':all(v['passed'] for v in checks.values()),'checks':checks,'time':time.time(),
                    'wire_sha256':hashlib.sha256(json.dumps(data['outbound'],sort_keys=True).encode()).hexdigest(),
                    'expected_egress':data['expected_egress'],'russian_egress':data['russian_egress'],
                    'binary_sha256':hashlib.sha256(BINARY.read_bytes()).hexdigest()}
        finally:
            p.terminate();p.wait(timeout=5)
            with socket.socket() as s:assert s.connect_ex(('127.0.0.1',port))!=0,'Leaked listener'

if __name__=='__main__':
    try:
        result=probe(json.load(sys.stdin));print(json.dumps(result));sys.exit(0 if result['mihomo_passed'] else 2)
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':'Private client input suppressed'}));sys.exit(1)
