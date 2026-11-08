"""Read private subscription; run an isolated no-TUN client, print no credentials."""
import argparse
from copy import deepcopy
import json
import re
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote

import httpx
import yaml


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('subscription');parser.add_argument('core')
    parser.add_argument('--expected',default='150.251.112.172')
    parser.add_argument('--name',default='🇵🇱 Польша')
    args=parser.parse_args()
    source=yaml.safe_load(Path(args.subscription).read_text(encoding='utf-8'))
    original=next(p for p in source['proxies'] if p['name']==args.name)
    proxy=deepcopy(original)
    if proxy.get('client-fingerprint')!='firefox':raise ValueError('Unexpected client fingerprint')
    proxy['name']='POLAND_CHECK'
    mixed,controller=port(),port();secret=secrets.token_hex(24)
    with tempfile.TemporaryDirectory(prefix='koala-rollback-verify-') as folder:
        cfg={'mixed-port':mixed,'external-controller':f'127.0.0.1:{controller}',
             'secret':secret,'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule',
             'ipv6':False,'tun':{'enable':False},'log-level':'debug',
             'dns':{'enable':True,'ipv6':False,'enhanced-mode':'redir-host',
                    'nameserver':['https://1.1.1.1/dns-query'],'default-nameserver':['1.1.1.1'],
                    'proxy-server-nameserver':['https://1.1.1.1/dns-query']},
             'proxies':[proxy],'rules':['MATCH,POLAND_CHECK']}
        path=Path(folder)/'config.json';path.write_text(json.dumps(cfg),encoding='utf-8')
        flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
        logfile=Path(folder)/'core.log';stream=logfile.open('wb')
        process=subprocess.Popen([args.core,'-d',folder,'-f',str(path)],stdout=stream,stderr=subprocess.STDOUT,creationflags=flags)
        try:
            with httpx.Client(base_url=f'http://127.0.0.1:{controller}',headers={'Authorization':'Bearer '+secret},timeout=25,trust_env=False) as client:
                for _ in range(200):
                    if process.poll() is not None:raise RuntimeError('Isolated core exited')
                    try:
                        ready=client.get('/proxies').json().get('proxies',{})
                        if 'POLAND_CHECK' in ready:break
                    except (httpx.HTTPError,ValueError):pass
                    time.sleep(.2)
                else:raise RuntimeError('Client configuration not ready')
                print('CORE',client.get('/version').json(),flush=True)
                for index in range(3):
                    response=client.get('/proxies/'+quote('POLAND_CHECK')+'/delay',params={'timeout':15000,'url':'https://www.gstatic.com/generate_204'})
                    if response.status_code!=200:
                        detail=response.text[:500]
                        print('URL_TEST_ERROR',response.status_code,re.sub(r'[A-Za-z0-9_+/=-]{24,}','[redacted]',detail),flush=True)
                        lines=[line for line in logfile.read_text(errors='replace').splitlines() if any(w in line.lower() for w in ['failed','error','refused','[tcp]']) and 'authentication:' not in line.lower()]
                        for line in lines[-3:]:print('CLIENT_DIAGNOSTIC',re.sub(r'[A-Za-z0-9_+/=-]{24,}','[redacted]',line),flush=True)
                        raise RuntimeError('URL test failed')
                    print('URL_TEST',index+1,response.json()['delay'],flush=True)
            curl='curl.exe' if flags else 'curl'
            for url in ['https://www.gstatic.com/generate_204']*3+['https://api.ipify.org','https://www.cloudflare.com/cdn-cgi/trace']:
                result=subprocess.run([curl,'--disable','--silent','--noproxy','','--proxy',f'http://127.0.0.1:{mixed}','--max-time','20','--write-out','\n%{http_code}',url],capture_output=True,timeout=25)
                body,_,status=result.stdout.rpartition(b'\n')
                good=status==b'204' if 'gstatic' in url else status==b'200' and (body.strip()==args.expected.encode() if 'ipify' in url else b'ip=' in body)
                if result.returncode or not good:raise RuntimeError('HTTPS or exit IP verification failed')
                print('HTTPS_OK','egress='+args.expected if 'ipify' in url else status.decode(),flush=True)
            print('FIREFOX_FULL_CLIENT_PROOF_PASSED',flush=True)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            stream.close()


if __name__=='__main__':main()
