"""Fresh entry only. Root-only keys, isolated management, no default-route edits."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from common import ROOT,STATE,ENTRY,NODES,DOMAIN,IMAGE,save,read,run,assert_ip,digest

KEYS=Path('/etc/hamvpn-entry140')
VHOST=Path('/etc/nginx/sites-available/ham-entry140')


def copy(source,target,mode=0o644):
    shutil.copyfile(ROOT/source,target);Path(target).chmod(mode)


def install():
    assert not Path('/opt/remnanode').exists() and not Path('/etc/nginx').exists()
    assert not STATE.exists(), 'Existing preparation; reconcile first'
    for port in [80,443,8443,2222,*[n['port'] for n in NODES],*[n['link'] for n in NODES]]:
        assert not run('ss','-H','-lnt','sport = :'+str(port)).strip(),'Occupied port'
    STATE.mkdir(mode=0o700)
    with tarfile.open(STATE/'before.tar.gz','w:gz') as t:
        for path in ['/etc/ssh','/etc/systemd/system','/etc/ufw']:
            if Path(path).exists():t.add(path,arcname=path.lstrip('/'))
    save('before',{'sha256':digest(STATE/'before.tar.gz'),'iptables':run('iptables-save'),
        'ip6tables':run('ip6tables-save'),'packages':run('dpkg-query','-W')})
    os.environ.update(DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l')
    run('apt-get','update','-qq')
    run('apt-get','install','-y','--no-install-recommends','docker.io','docker-compose-v2','nginx',
        'libnginx-mod-stream','certbot','ca-certificates','curl','iptables')
    run('systemctl','enable','--now','docker')
    default=Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink():default.rename(STATE/'nginx-default-link')
    site=Path('/var/www/'+DOMAIN);site.mkdir(mode=0o755,parents=True);site.chmod(0o755)
    for file in ('index.html','style.css'):copy('site/'+file,site/file)
    acme=Path('/var/www/acme/.well-known/acme-challenge');acme.mkdir(mode=0o755,parents=True,exist_ok=True)
    for d in (acme,acme.parent,acme.parent.parent):d.chmod(0o755)
    (acme/'ham-entry140-check').write_text('ham-entry140-acme-ready\n');(acme/'ham-entry140-check').chmod(0o644)
    copy('nginx-http.conf',VHOST);Path('/etc/nginx/sites-enabled/ham-entry140').symlink_to(VHOST)
    run('nginx','-t');run('systemctl','enable','--now','nginx');run('systemctl','reload','nginx')
    KEYS.mkdir(mode=0o700)
    for n in NODES:
        run('ssh-keygen','-q','-t','ed25519','-N','','-C','HAMVPN-entry140-to-'+n['id'],'-f',str(KEYS/n['id']))
    run('docker','pull',IMAGE)
    assert IMAGE in json.loads(run('docker','image','inspect',IMAGE))[0]['RepoDigests']
    save('installed',{'image':IMAGE,'http_ready':True,'ssh_keys_generated':4})
    return {'entry_installed':True,'image_pinned':True,'http_ready':True}


def certificate():
    assert not Path('/etc/letsencrypt/live/'+DOMAIN).exists(), 'Inspect existing certificate'
    args=['certbot','certonly','--non-interactive','--agree-tos','--register-unsafely-without-email',
        '--webroot','-w','/var/www/acme','--preferred-challenges','http','--key-type','ecdsa',
        '--elliptic-curve','secp256r1','--cert-name',DOMAIN]
    for n in NODES:args+=['-d',n['domain']]
    run(*args)
    cert='/etc/letsencrypt/live/'+DOMAIN+'/fullchain.pem'
    run('openssl','x509','-in',cert,'-noout','-checkend','2592000')
    copy('nginx-tls.conf',VHOST)
    try:run('nginx','-t')
    except Exception:copy('nginx-http.conf',VHOST);raise
    run('systemctl','reload','nginx')
    copy('renew-nginx.sh','/etc/letsencrypt/renewal-hooks/deploy/ham-entry140-nginx',0o755)
    run('systemctl','enable','--now','certbot.timer')
    for n in NODES:
        run('curl','--noproxy','*','-fsS','--resolve',n['domain']+':8443:127.0.0.1','https://'+n['domain']+':8443/','-o','/dev/null')
    return {'certificate_ready':True,'details':run('openssl','x509','-in',cert,'-noout','-dates','-ext','subjectAltName')}


def links():
    known=json.load(sys.stdin)
    assert set(known)=={n['ip'] for n in NODES}
    path=KEYS/'known_hosts';assert not path.exists()
    for ip,line in known.items():assert line.startswith(ip+' ssh-ed25519 ') and len(line.split())==3
    path.write_text('\n'.join(known.values())+'\n');path.chmod(0o600)
    for n in NODES:
        service='ham-entry140-link-'+n['id']+'.service'
        unit=Path('/etc/systemd/system')/service;assert not unit.exists()
        command=('/usr/bin/ssh -NT -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes '
            '-o UpdateHostKeys=no -o UserKnownHostsFile='+str(path)+' -o GlobalKnownHostsFile=/dev/null '
            '-o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ExitOnForwardFailure=yes -o ConnectTimeout=10 '
            '-o ForwardAgent=no -o Compression=no -i '+str(KEYS/n['id'])+' -L 127.0.0.1:'+str(n['link'])+
            ':127.0.0.1:443 ham-entry140@'+n['ip'])
        unit.write_text('[Unit]\nDescription=HAMVPN encrypted exit link '+n['id']+'\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart='+command+'\nRestart=always\nRestartSec=3\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n');unit.chmod(0o644)
    run('systemctl','daemon-reload')
    for n in NODES:run('systemctl','enable','--now','ham-entry140-link-'+n['id']+'.service')
    return {'four_independent_links_started':True}


def start():
    data=json.load(sys.stdin);secret=data['pubKey'];assert isinstance(secret,str) and len(secret)>40
    compose=Path('/opt/remnanode/docker-compose.yml');assert not compose.exists()
    compose.parent.mkdir(mode=0o700)
    compose.write_text(json.dumps({'services':{'remnanode':{'image':IMAGE,'container_name':'remnanode',
        'hostname':'remnanode','network_mode':'host','restart':'always',
        'environment':{'NODE_PORT':'2222','SECRET_KEY':secret},
        'ulimits':{'nofile':{'soft':1048576,'hard':1048576}},
        'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}}}}));compose.chmod(0o600)
    copy('firewall.sh','/usr/local/sbin/ham-entry140-firewall',0o700)
    unit=Path('/etc/systemd/system/ham-entry140-firewall.service')
    unit.write_text('[Unit]\nDescription=HAMVPN entry management isolation\nBefore=docker.service\nAfter=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/ham-entry140-firewall\n\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl','daemon-reload');run('systemctl','enable','--now',unit.name)
    run('docker','compose','-f',str(compose),'up','-d')
    original=Path('/etc/nginx/nginx.conf');shutil.copyfile(original,STATE/'nginx-before-stream.conf')
    assert 'ham-entry140-stream' not in original.read_text()
    copy('nginx-stream.conf','/etc/nginx/ham-entry140-stream.conf')
    with original.open('a') as f:f.write('\ninclude /etc/nginx/ham-entry140-stream.conf;\n')
    try:run('nginx','-t')
    except Exception:shutil.copyfile(STATE/'nginx-before-stream.conf',original);raise
    run('systemctl','reload','nginx')
    return {'entry_started':True,'api_restricted':True,'public_port':443}


def test():
    config=sys.stdin.read();p=subprocess.run(['docker','run','--rm','-i','--network','host','--entrypoint','xray',IMAGE,'run','-test','-c','stdin:'],input=config,capture_output=True,text=True)
    save('xray-test',{'passed':p.returncode==0,'output':p.stdout+p.stderr})
    assert p.returncode==0,'Candidate rejected; details private'
    return {'installed_xray_test_passed':True}


def compatibility():
    os.environ.update(DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l')
    run('apt-get','install','-y','--no-install-recommends','python3-paramiko')
    unit=Path('/etc/systemd/system/ham-entry140-link-de182.service')
    backup=STATE/'de182-original-link.service';assert not backup.exists()
    text=unit.read_text();assert 'ExecStart=/usr/bin/ssh ' in text
    shutil.copyfile(unit,backup)
    lines=text.splitlines()
    lines=[('ExecStart=/usr/bin/python3 '+str(ROOT/'ssh_link.py')+' --id de182') if line.startswith('ExecStart=') else line for line in lines]
    unit.write_text('\n'.join(lines)+'\n')
    run('systemctl','daemon-reload');run('systemctl','restart',unit.name)
    return {'de182_compatibility_transport_started':True,'same_restricted_key_and_destination':True}


def main():
    os.umask(0o077);assert os.geteuid()==0;assert_ip(ENTRY)
    p=argparse.ArgumentParser();p.add_argument('action',choices=['install','certificate','links','start','test','public-key','renew-test','compatibility']);p.add_argument('--id',choices=[n['id'] for n in NODES]);a=p.parse_args()
    if a.action=='public-key':
        assert a.id;print((KEYS/(a.id+'.pub')).read_text().strip());return
    if a.action=='renew-test':
        run('certbot','renew','--cert-name',DOMAIN,'--dry-run','--run-deploy-hooks');save('renewal-test',{'passed':True});print('{"renewal_dry_run_passed":true}');return
    print(json.dumps(globals()[a.action]()))


if __name__=='__main__':main()
