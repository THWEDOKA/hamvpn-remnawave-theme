"""Private proxy JSON on stdin; isolated Xray client, no credentials in argv/log."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def main():
    parser=argparse.ArgumentParser();parser.add_argument('binary');parser.add_argument('expected');args=parser.parse_args()
    proxy=json.load(sys.stdin)
    if proxy.get('client-fingerprint')!='firefox':raise ValueError('Firefox required')
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    cfg={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
         'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':proxy['server'],'port':proxy['port'],'users':[{'id':proxy['uuid'],'encryption':'none','flow':proxy.get('flow','')}]}]},
                      'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':proxy['servername'],'fingerprint':'firefox','publicKey':proxy['reality-opts']['public-key'],'shortId':proxy['reality-opts']['short-id']}}}]}
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ham-xray-proof-') as folder:
        path=Path(folder)/'config.json';path.write_text(json.dumps(cfg))
        process=subprocess.Popen([args.binary,'run','-config',str(path)],env=dict(os.environ,GODEBUG='multipathtcp=0'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(1)
            for url in ['https://www.gstatic.com/generate_204','https://api.ipify.org','https://www.cloudflare.com/cdn-cgi/trace']:
                r=subprocess.run(['curl','--disable','--silent','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--max-time','20','--write-out','\n%{http_code}',url],capture_output=True,timeout=25)
                body,_,status=r.stdout.rpartition(b'\n')
                if r.returncode or status not in [b'200',b'204'] or ('ipify' in url and body.strip()!=args.expected.encode()):raise RuntimeError('Xray client HTTPS/egress check failed')
                print('XRAY_HTTPS_OK','egress='+args.expected if 'ipify' in url else status.decode(),flush=True)
            print('XRAY_FIREFOX_CLIENT_PROOF_PASSED')
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':main()
