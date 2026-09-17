"""Windows external probe using verified release binary; no credentials on disk."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from common import NODES
from transport import remote,checked


def test(binary,outbound,expected):
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
        'outbounds':[outbound]}
    flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    proc=subprocess.Popen([binary,'run','-c','stdin:'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=flags)
    try:
        proc.stdin.write(json.dumps(config).encode());proc.stdin.close()
        for _ in range(60):
            assert proc.poll() is None,'Client failed to start'
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):break
            except OSError:time.sleep(.1)
        cmd=['curl.exe','-4','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'-fsS','--connect-timeout','7','--max-time','12']
        r=subprocess.run(cmd+['-o','NUL','-w','%{http_code}','https://www.gstatic.com/generate_204'],capture_output=True,text=True,creationflags=flags)
        ip=subprocess.run(cmd+['https://ifconfig.me/ip'],capture_output=True,text=True,creationflags=flags)
        return {'passed':r.returncode==ip.returncode==0 and r.stdout=='204' and ip.stdout.strip()==expected,
            'http_status':r.stdout,'exit_ip':ip.stdout.strip() if ip.returncode==0 else None,'curl_codes':[r.returncode,ip.returncode]}
    finally:
        proc.terminate()
        try:proc.wait(timeout=4)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=4)


def main():
    p=argparse.ArgumentParser();p.add_argument('--revision',required=True);p.add_argument('--binary',required=True);a=p.parse_args()
    base='/opt/hamvpn-ru140-entry/releases/'+a.revision+'/ops/ru140-entry-20260917/'
    items=json.loads(checked(remote('panel','python3 '+base+'panel.py export-clients')))
    results=[]
    for item in items:
        for fp in ['chrome','firefox']:
            outbound=copy.deepcopy(item['outbound']);outbound['streamSettings']['realitySettings']['fingerprint']=fp
            result={'id':item['id'],'fingerprint':fp,**test(a.binary,outbound,item['ip'])}
            results.append(result);print(json.dumps(result),flush=True)
    proof={'timestamp':time.time(),'source':'external-windows-26.3.27','all_passed':all(r['passed'] for r in results),'tests':results}
    print(json.dumps({'all_passed':proof['all_passed']}))
    if proof['all_passed']:
        print(checked(remote('panel','python3 '+base+'panel.py accept-external-proof',json.dumps(proof).encode())).decode())


if __name__=='__main__':main()
