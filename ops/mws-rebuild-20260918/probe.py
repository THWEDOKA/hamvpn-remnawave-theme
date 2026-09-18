"""Disposable authenticated Xray client; output excludes configuration and IDs."""
import argparse
import tempfile
from ops import *


def probe(label):
    guard('entry');data=json.load(sys.stdin)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config={'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':port,
             'protocol':'socks','settings':{'auth':'noauth','udp':False}}],'outbounds':[data['outbound']]}
    with tempfile.TemporaryDirectory(prefix='probe-',dir=STATE) as folder:
        binary=Path(folder)/'xray'
        run('docker','cp',OLD_CONTAINER+':/usr/local/bin/xray',str(binary));binary.chmod(0o700)
        p=subprocess.Popen([str(binary),'run','-c','stdin:'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            p.stdin.write(json.dumps(config).encode());p.stdin.close()
            for _ in range(50):
                require(p.poll() is None,'Probe process exited')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.1)
            else:raise RuntimeError('Probe listener unavailable')
            base=['curl','-4','--noproxy','','--socks5-hostname','127.0.0.1:'+str(port),
                  '-fsS','--connect-timeout','8','--max-time','18']
            checks=[('foreign_204',['-o','/dev/null','-w','%{http_code}','https://www.gstatic.com/generate_204']),
                    ('foreign_ip',['https://api.ipify.org'])]
            if label=='frontend':checks.append(('russian_ip',['https://2ip.ru']))
            results={}
            for name,args in checks:
                q=subprocess.run(base+args,capture_output=True,text=True,timeout=25)
                if name=='russian_ip':
                    results[name]={'passed':q.returncode==0 and data['russian_egress'] in q.stdout,'curl_code':q.returncode}
                else:
                    value=q.stdout.strip()
                    expected='204' if name=='foreign_204' else data['expected_egress']
                    results[name]={'passed':q.returncode==0 and value==expected,'curl_code':q.returncode,
                                   'value':value if len(value)<64 else '[unexpected response]'}
            result={label+'_passed':all(r['passed'] for r in results.values()),'checks':results,
                    'expected_egress':data['expected_egress'],'time':time.time(),
                    'wire_sha256':digest(json.dumps(data['outbound'],sort_keys=True).encode())}
            save('probe-'+label,result)
            return result
        finally:
            p.terminate()
            try:p.wait(timeout=4)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=4)
            with socket.socket() as s:require(s.connect_ex(('127.0.0.1',port))!=0,'Probe listener leaked')


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('label',choices=['backend','frontend']);a=p.parse_args()
        result=probe(a.label);print(json.dumps(result));sys.exit(0 if result[a.label+'_passed'] else 2)
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
