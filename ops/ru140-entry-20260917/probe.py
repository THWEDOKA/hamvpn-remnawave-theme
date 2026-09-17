"""Temporary loopback-only client probes; runtime credentials arrive on stdin."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from common import STATE,save


def test(item):
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config={'log':{'loglevel':'debug'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
        'outbounds':[item['outbound']]}
    with tempfile.TemporaryFile() as log:
        proc=subprocess.Popen(['docker','exec','-i','remnanode','xray','run','-c','stdin:'],stdin=subprocess.PIPE,stdout=log,stderr=log)
        try:
            proc.stdin.write(json.dumps(config).encode());proc.stdin.close()
            for _ in range(60):
                assert proc.poll() is None,'Probe process failed'
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.1)
            curl=['curl','-4','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),'-fsS','--connect-timeout','6','--max-time','10']
            status=subprocess.run(curl+['-o','/dev/null','-w','%{http_code}','https://www.gstatic.com/generate_204'],capture_output=True,text=True)
            egress=subprocess.run(curl+['https://ifconfig.me/ip'],capture_output=True,text=True)
            result={'id':item['id'],'passed':status.returncode==egress.returncode==0 and status.stdout=='204' and egress.stdout.strip()==item['ip'],
                'http':status.stdout,'exit_ip':egress.stdout.strip() if egress.returncode==0 else None,'curl_codes':[status.returncode,egress.returncode]}
        finally:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=4)
        log.seek(0);text=log.read().decode(errors='replace')
        # Test account UUIDs and crypto fields never reach operator stdout.
        text=re.sub(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}','[test-account]',text)
        save('probe-debug-'+item['id'],{'log':text,'curl_errors':[status.stderr,egress.stderr]})
        return result


def main():
    os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('label');a=p.parse_args()
    items=json.load(sys.stdin);results=[]
    for item in items:
        r=test(item);results.append(r);print(json.dumps(r),flush=True)
    save('probe-'+a.label,{'timestamp':time.time(),'all_passed':all(r['passed'] for r in results),'tests':results})


if __name__=='__main__':main()
