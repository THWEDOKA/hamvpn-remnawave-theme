"""Private proxy JSON on stdin; isolated Xray client, no credentials in argv/log."""
import argparse
import json
import os
import secrets
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser=argparse.ArgumentParser();parser.add_argument('binary');parser.add_argument('expected');parser.add_argument('--docker-image');parser.add_argument('--web-test-url',default='https://www.gstatic.com/generate_204');args=parser.parse_args()
    proxy=json.load(sys.stdin)
    if proxy.get('client-fingerprint')!='firefox':raise ValueError('Firefox required')
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    cfg={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
         'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':proxy['server'],'port':proxy['port'],'users':[{'id':proxy['uuid'],'encryption':'none','flow':proxy.get('flow','')}]}]},
                      'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':proxy['servername'],'fingerprint':'firefox','publicKey':proxy['reality-opts']['public-key'],'shortId':proxy['reality-opts']['short-id']}}}]}
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ham-xray-proof-') as folder:
        path=Path(folder)/'config.json';path.write_text(json.dumps(cfg))
        name='ham-xray-client-proof-'+secrets.token_hex(5)
        command=[args.binary,'run','-config',str(path)]
        if args.docker_image:
            version=subprocess.check_output(['docker','run','--rm','--network','none','--entrypoint',args.binary,args.docker_image,'version'],text=True)
            print('XRAY_CLIENT_VERSION',version.splitlines()[0],flush=True)
            command=['docker','run','--rm','--name',name,'--network','host','-e','GODEBUG=multipathtcp=0','--mount',f'type=bind,src={folder},dst=/work,readonly','--entrypoint',args.binary,args.docker_image,'run','-config','/work/config.json']
        process=subprocess.Popen(command,env=dict(os.environ,GODEBUG='multipathtcp=0'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(1)
            for url in [args.web_test_url,'https://api.ipify.org','https://www.cloudflare.com/cdn-cgi/trace']:
                r=subprocess.run(['curl','--disable','--silent','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--max-time','20','--write-out','\n%{http_code}',url],capture_output=True,timeout=25)
                body,_,status=r.stdout.rpartition(b'\n')
                if r.returncode or status not in [b'200',b'204'] or ('ipify' in url and body.strip()!=args.expected.encode()):
                    print('XRAY_CLIENT_FAILURE',{'process_exit':process.poll(),'curl_exit':r.returncode,'status':status.decode(errors='replace'),'check':'ipify' if 'ipify' in url else 'cloudflare' if 'cloudflare' in url else 'web'},flush=True)
                    raise RuntimeError('Xray client HTTPS/egress check failed')
                print('XRAY_HTTPS_OK','egress='+args.expected if 'ipify' in url else status.decode(),flush=True)
            print('XRAY_FIREFOX_CLIENT_PROOF_PASSED')
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            if args.docker_image:subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)


if __name__=='__main__':main()
