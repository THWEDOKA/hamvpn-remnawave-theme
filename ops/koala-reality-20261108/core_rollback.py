"""Single-node, owner-approved Xray rollback; private state never enters Git."""
import argparse
from copy import deepcopy
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import zipfile

ROOT=Path('/opt/remnanode')
STATE=Path('/root/ham-koala-core-rollback-20261108')
OVERRIDE=ROOT/'docker-compose.override.yml'
UNIT='ham-koala-core-rollback-20261108'
VERSION='26.7.28'
XRAY_URL='https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-linux-64.zip'
XRAY_SHA='8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40'
MIHOMO_URL='https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-amd64-compatible-v1.19.33.gz'
MIHOMO_SHA='386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6'
TAG='plreg-raw'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args,*,data=None,timeout=45):
    p=subprocess.run(args,input=data,capture_output=True,timeout=timeout,cwd=ROOT)
    if p.returncode:
        if STATE.exists():
            with (STATE/'private-operation.log').open('ab') as stream:stream.write(p.stdout+p.stderr)
        raise RuntimeError('Scoped operation failed; see private root log')
    return p.stdout


def runtime():
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            if (process/'comm').read_text().strip()!='rw-core':continue
            args=(process/'cmdline').read_bytes().decode().split('\0')
            uri=args[args.index('-config')+1]
            address,path=uri.split(':',1)
            if not address.startswith('@rwint-') or not path.startswith('/internal/get-config?token='):continue
            sock=socket.socket(socket.AF_UNIX);sock.settimeout(15);sock.connect('\0'+address[1:])
            client=http.client.HTTPConnection('localhost');client.sock=sock;client.request('GET',path)
            response=client.getresponse()
            if response.status!=200:raise RuntimeError('Runtime read rejected')
            data=json.loads(response.read());client.close()
            return data,process
        except (OSError,ValueError,KeyError):continue
    raise RuntimeError('Expected managed runtime not found')


def target(config):
    matches=[i for i in config['inbounds'] if i.get('tag')==TAG]
    if len(matches)!=1:raise ValueError('Expected dedicated Poland inbound')
    inbound=matches[0]
    if inbound.get('port')!=443 or inbound.get('protocol')!='vless' or inbound.get('streamSettings',{}).get('security')!='reality':
        raise ValueError('Inbound identity changed')
    if inbound['streamSettings']['realitySettings'].get('serverNames')!=['pl.yaneznayvas.lol']:
        raise ValueError('Unexpected client domain')
    return inbound


def candidate(config):
    result=deepcopy(config)
    target(result)['streamSettings']['realitySettings']['minClientVer']='1.8.2'
    return result


def godebug(value):
    parts=[s for s in (value or '').split(',') if s and not s.startswith('multipathtcp=')]
    return ','.join(parts+['multipathtcp=0'])


def download(url,path,expected):
    if not path.exists():
        with urllib.request.urlopen(url,timeout=60) as response,path.open('wb') as out:shutil.copyfileobj(response,out)
    if digest(path)!=expected:raise ValueError('Official artifact digest mismatch')


def free_port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def no_mptcp():
    lines=run(['ss','-M','-lnp']).decode().splitlines()
    if len(lines)>1:raise RuntimeError('MPTCP listener detected; refuse old core')


def prepare(reference):
    os.umask(0o077)
    if STATE.exists():raise RuntimeError('Existing operation requires review')
    STATE.mkdir(mode=0o700)
    if OVERRIDE.exists() or OVERRIDE.is_symlink():raise RuntimeError('Preserve existing Compose override')
    before=ROOT/'docker-compose.yml';shutil.copy2(before,STATE/'docker-compose.before.yml')
    container=json.loads(run(['docker','inspect','remnanode']))[0]
    current=container['Image']
    if '26.10.31' not in run(['docker','exec','remnanode','xray','version']).decode():raise ValueError('Unexpected installed version')
    config,_=runtime();target(config)
    (STATE/'runtime.before.json').write_text(json.dumps(config))
    updated=candidate(config)
    download(XRAY_URL,STATE/'xray.zip',XRAY_SHA)
    with zipfile.ZipFile(STATE/'xray.zip') as archive:
        with archive.open('xray') as source,(STATE/'xray').open('wb') as dest:shutil.copyfileobj(source,dest)
    (STATE/'xray').chmod(0o700)
    download(MIHOMO_URL,STATE/'mihomo.gz',MIHOMO_SHA)
    with gzip.open(STATE/'mihomo.gz','rb') as source,(STATE/'mihomo').open('wb') as dest:shutil.copyfileobj(source,dest)
    (STATE/'mihomo').chmod(0o700)
    base=['docker','run','--rm','--network','none','-e','GODEBUG=multipathtcp=0','--mount',f'type=bind,src={STATE},dst=/work,readonly','--entrypoint','/work/xray']
    if VERSION not in run(base+[current,'version']).decode():raise ValueError('Unexpected artifact version')
    run(base[:2]+['-i']+base[2:]+[current,'run','-test','-config','stdin:'],data=json.dumps(updated).encode())
    no_mptcp()
    inbound=deepcopy(target(updated));inbound['listen']='127.0.0.1';inbound['port']=free_port()
    matches=[u for u in inbound['settings']['clients'] if u.get('id')==reference['uuid']]
    if len(matches)!=1:raise ValueError('Probe user absent from live configuration')
    inbound['settings']['clients']=matches
    api_tag=config.get('api',{}).get('tag')
    probe={'log':{'loglevel':'none'},'inbounds':[inbound],'outbounds':deepcopy(config['outbounds']),'routing':deepcopy(config.get('routing',{}))}
    probe['routing']['rules']=[r for r in probe['routing'].get('rules',[]) if r.get('outboundTag')!=api_tag]
    (STATE/'canary.json').write_text(json.dumps(probe))
    name='ham-koala-old-core-canary'
    run(['docker','run','-d','--name',name,'--network','host','-e','GODEBUG=multipathtcp=0','--mount',f'type=bind,src={STATE},dst=/work,readonly','--mount','type=bind,src=/dev/shm,dst=/dev/shm','--entrypoint','/work/xray',current,'run','-config','/work/canary.json'])
    try:
        time.sleep(1);no_mptcp()
        proxy=deepcopy(reference);proxy['name']='OLD_CORE_CANARY';proxy['server']='127.0.0.1';proxy['port']=inbound['port'];proxy['client-fingerprint']='firefox'
        proof=probe_mihomo(proxy,STATE/'mihomo',expected='150.251.112.172')
    finally:run(['docker','rm','-f',name])
    manifest={'image':current,'image_ref':container['Config']['Image'],'compose_sha':digest(before),'core_sha':digest(STATE/'xray'),'prepared_at':int(time.time()),'proof':proof,'godebug_before':next((v.split('=',1)[1] for v in container['Config'].get('Env',[]) if v.startswith('GODEBUG=')),'')}
    (STATE/'manifest.json').write_text(json.dumps(manifest))
    shutil.copy2(__file__,STATE/'operation.py')
    print('PREFLIGHT_PASSED_OLD_CORE_FIREFOX_HTTPS_AND_EGRESS')


def probe_mihomo(proxy,binary,expected):
    mixed=free_port()
    with tempfile.TemporaryDirectory(prefix='mihomo-',dir=STATE) as folder:
        cfg={'mixed-port':mixed,'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule','ipv6':False,'tun':{'enable':False},'log-level':'silent','proxies':[proxy],'rules':['MATCH,'+proxy['name']]}
        path=Path(folder)/'config.json';path.write_text(json.dumps(cfg,ensure_ascii=False))
        process=subprocess.Popen([str(binary),'-d',folder,'-f',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:raise RuntimeError('Probe core failed')
                try:
                    with socket.create_connection(('127.0.0.1',mixed),timeout=.2):break
                except OSError:time.sleep(.1)
            time.sleep(1)
            checks=[]
            for url in ['https://www.gstatic.com/generate_204']*3+['https://api.ipify.org','https://www.cloudflare.com/cdn-cgi/trace']:
                result=run(['curl','--disable','--silent','--noproxy','','--proxy',f'http://127.0.0.1:{mixed}','--max-time','20','--write-out','\n%{http_code}',url],timeout=25)
                body,_,status=result.rpartition(b'\n')
                good=status==b'204' if 'gstatic' in url else status==b'200' and (body.strip()==expected.encode() if 'ipify' in url else b'ip=' in body)
                if not good:raise RuntimeError('Actual proxy HTTPS proof failed')
                checks.append('204' if 'gstatic' in url else 'egress' if 'ipify' in url else 'trace')
            return {'passed':True,'fingerprint':'firefox','checks':checks,'egress':expected,'time':int(time.time())}
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()


def apply():
    os.umask(0o077);manifest=json.loads((STATE/'manifest.json').read_text())
    if not manifest['proof']['passed'] or time.time()-manifest['proof']['time']>3600:raise ValueError('Fresh preflight required')
    if OVERRIDE.exists() or OVERRIDE.is_symlink() or digest(ROOT/'docker-compose.yml')!=manifest['compose_sha']:raise ValueError('Compose drift; refuse overwrite')
    config,_=runtime()
    if target(config)['streamSettings']['realitySettings'].get('minClientVer')!='1.8.2':raise ValueError('Canonical profile compatibility must be applied first')
    no_mptcp()
    run(['systemd-run','--unit='+UNIT,'--on-active=12m','/usr/bin/python3',str(STATE/'operation.py'),'rollback'])
    override={'services':{'remnanode':{'image':manifest['image'],'environment':{'GODEBUG':godebug(manifest['godebug_before'])},'volumes':[{'type':'bind','source':str(STATE/'xray'),'target':'/usr/local/bin/xray','read_only':True}]}}}
    OVERRIDE.write_text(json.dumps(override,indent=2));OVERRIDE.chmod(0o600)
    manifest['override_sha']=digest(OVERRIDE);(STATE/'manifest.json').write_text(json.dumps(manifest))
    run(['docker','compose','config','--quiet'])
    run(['docker','compose','up','-d','--no-deps','--no-build','--pull','never','remnanode'],timeout=90)
    print('CORE_ROLLBACK_APPLIED_WITH_INDEPENDENT_12_MINUTE_RETURN')


def rollback():
    manifest=json.loads((STATE/'manifest.json').read_text())
    if OVERRIDE.exists():
        if digest(OVERRIDE)!=manifest.get('override_sha'):raise ValueError('External override edit; manual review required')
    if digest(ROOT/'docker-compose.yml')!=manifest['compose_sha']:raise ValueError('Original Compose changed')
    if json.loads(run(['docker','image','inspect',manifest['image_ref']]))[0]['Id']!=manifest['image']:raise ValueError('Original image tag changed; manual review required')
    if OVERRIDE.exists():OVERRIDE.unlink()
    run(['docker','compose','up','-d','--no-deps','--no-build','--pull','never','remnanode'],timeout=90)
    print('ORIGINAL_CORE_CONFIGURATION_RESTORED')


def accept():
    manifest=json.loads((STATE/'manifest.json').read_text())
    if digest(OVERRIDE)!=manifest['override_sha']:raise ValueError('Override drift')
    config,process=runtime();target(config)
    if digest(process/'exe')!=manifest['core_sha']:raise ValueError('Running core is not the tested artifact')
    env=(process/'environ').read_bytes().split(b'\0')
    if not any(s.startswith(b'GODEBUG=') and b'multipathtcp=0' in s.split(b'=',1)[1].split(b',') for s in env):raise ValueError('Runtime MPTCP safeguard absent')
    no_mptcp();run(['systemctl','stop',UNIT+'.timer'])
    print('TESTED_CORE_RUNNING_MPTCP_DISABLED_RETURN_TIMER_CANCELLED')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','apply','rollback','accept']);args=parser.parse_args()
    if args.action=='prepare':
        import sys
        prepare(json.load(sys.stdin))
    else:globals()[args.action]()
