"""Independent new services; neither action stops the existing MWS container."""
import argparse
from ops import *

EXIT_CONTAINER='hamvpn-mws-exit'
ENTRY_CONTAINER='remnanode-ham-mws2'
MANAGEMENT_SOURCE='64.225.109.248'


def image_ready():
    found=subprocess.run(['docker','image','inspect',IMAGE],capture_output=True)
    if found.returncode:run('docker','pull',IMAGE,timeout=300)
    data=json.loads(run('docker','image','inspect',IMAGE))[0]
    require(IMAGE in data['RepoDigests'],'Pinned image mismatch')


def installed_test(config):
    image_ready()
    mounts=[]
    if Path('/opt/remnanode-ham-shared/letsencrypt').is_dir():
        mounts=['-v','/opt/remnanode-ham-shared/letsencrypt:/etc/letsencrypt:ro']
    result=run('docker','run','--rm','-i','--network','none',*mounts,'--entrypoint','/usr/local/bin/xray',
               IMAGE,'run','-test','-c','stdin:',data=json.dumps(config).encode(),timeout=30)
    save('installed-test',{'passed':True,'config_sha256':digest(json.dumps(config,sort_keys=True).encode())})


def bridge():
    guard('exit');read('certificate');read('node-before')
    data=json.load(sys.stdin);require(data['image']==IMAGE,'Unverified image')
    require(not run('ss','-H','-lnt','sport = :443').strip(),'Exit 443 occupied')
    require(not (STATE/'bridge-created.json').exists(),'Bridge creation already attempted')
    config=data['config'];installed_test(config)
    folder=Path('/opt/hamvpn-mws-exit');folder.mkdir(mode=0o700,exist_ok=True)
    path=folder/'config.json';require(not path.exists(),'Existing bridge config')
    write(path,json.dumps(config))
    save('bridge-created',{'intent':True,'config_sha256':digest(path.read_bytes())})
    run('docker','run','-d','--name',EXIT_CONTAINER,'--network','host','--restart','unless-stopped',
        '--read-only','--cap-drop','ALL','--cap-add','NET_BIND_SERVICE','--security-opt','no-new-privileges:true',
        '--log-opt','max-size=10m','--log-opt','max-file=3','-v',str(path)+':/etc/xray/config.json:ro',
        '--entrypoint','/usr/local/bin/xray',IMAGE,'run','-c','/etc/xray/config.json')
    time.sleep(2)
    state=json.loads(run('docker','inspect',EXIT_CONTAINER))[0]
    require(state['State']['Running'],'Bridge failed to start')
    require(run('ss','-H','-lnt','sport = :443').strip(),'No backend listener')
    return {'bridge_started':True,'port':443,'encrypted_backend':True,'not_a_customer_host':True}


def entry():
    guard('entry');read('certificate');read('node-before')
    data=json.load(sys.stdin);require(data['image']==IMAGE,'Unverified image')
    for port in [2226,18443]:require(not run('ss','-H','-lnt','sport = :'+str(port)).strip(),'New node port occupied')
    require(not (STATE/'entry-created.json').exists(),'Entry creation already attempted')
    installed_test(data['config'])
    # Restrict management before the listener starts; preserve every other chain.
    fw=Path('/usr/local/sbin/ham-mws2-management-firewall')
    require(not fw.exists(),'Existing firewall helper needs reconciliation')
    text='#!/bin/sh\nset -eu\n'
    for tool,allowed in [('iptables',['127.0.0.1/32',MANAGEMENT_SOURCE+'/32']),('ip6tables',['::1/128'])]:
        chain='HAM_MWS2_API'
        text+=f'{tool} -N {chain} 2>/dev/null || true\n'
        # Idempotent additions, no flush: never touch another operation's rules.
        for source in allowed:
            text+=f'{tool} -C {chain} -s {source} -j ACCEPT 2>/dev/null || {tool} -A {chain} -s {source} -j ACCEPT\n'
        text+=f'{tool} -C {chain} -j DROP 2>/dev/null || {tool} -A {chain} -j DROP\n'
        text+=f'{tool} -C INPUT -p tcp --dport 2226 -j {chain} 2>/dev/null || {tool} -I INPUT 1 -p tcp --dport 2226 -j {chain}\n'
    write(fw,text,0o700)
    unit=Path('/etc/systemd/system/ham-mws2-management-firewall.service')
    require(not unit.exists(),'Existing firewall service')
    write(unit,'[Unit]\nDescription=HAMVPN MWS2 management isolation\nBefore=docker.service\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='+str(fw)+'\n\n[Install]\nWantedBy=multi-user.target\n',0o644)
    run('systemctl','daemon-reload');run('systemctl','enable','--now',unit.name)
    folder=Path('/opt/remnanode-ham-mws2');folder.mkdir(mode=0o700,exist_ok=True)
    env=folder/'node.env';require(not env.exists(),'Existing node environment')
    require('\n' not in data['pubKey'] and '\r' not in data['pubKey'],'Invalid management key')
    write(env,'NODE_PORT=2226\nSECRET_KEY='+data['pubKey']+'\n')
    save('entry-created',{'intent':True,'time':time.time()})
    run('docker','run','-d','--name',ENTRY_CONTAINER,'--hostname',ENTRY_CONTAINER,'--network','host',
        '--restart','unless-stopped','--env-file',str(env),'--ulimit','nofile=1048576:1048576',
        '--log-opt','max-size=10m','--log-opt','max-file=3',
        '-v','/opt/remnanode-ham-shared/letsencrypt:/etc/letsencrypt:ro',
        '-v',str(folder/'configs')+':/var/lib/remnawave/configs',IMAGE)
    time.sleep(3)
    require(json.loads(run('docker','inspect',ENTRY_CONTAINER))[0]['State']['Running'],'New entry container stopped')
    old=json.loads(run('docker','inspect',OLD_CONTAINER))[0]
    require(old['State']['Running'],'Old entry unexpectedly stopped')
    return {'entry_service_started':True,'management_port':2226,'old_service_unchanged':True}


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['bridge','entry']);a=p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
