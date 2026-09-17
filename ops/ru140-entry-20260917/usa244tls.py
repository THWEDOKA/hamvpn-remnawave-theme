"""USA-only TLS-wrapped SSH transport; existing public VPN listeners stay untouched."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import usa244site as s
import usa244reverse as r

PORT=18448
CONF=Path('/etc/nginx/modules-enabled/91-ham-usa244-transport.conf')


def config():
    return ('stream { server { listen '+s.ENTRY+':'+str(PORT)+' ssl;\n'
        'ssl_certificate /etc/letsencrypt/live/'+s.DOMAIN+'/fullchain.pem;\n'
        'ssl_certificate_key /etc/letsencrypt/live/'+s.DOMAIN+'/privkey.pem;\n'
        'ssl_protocols TLSv1.3; ssl_session_tickets off;\n'
        'allow '+r.SOURCE+'; deny all;\n'
        'proxy_pass '+s.ENTRY+':'+str(r.SSH_PORT)+'; proxy_connect_timeout 10s; proxy_timeout 1h; tcp_nodelay on;\n'
        '} }\n')


def install():
    s.guard();s.certificate_details()
    assert not CONF.exists() and not CONF.is_symlink()
    with socket.socket() as sock:sock.bind((s.ENTRY,PORT))
    baseline=s.baseline();candidate=config()
    s.save('transport-tls-intent',{'text':candidate,'before':baseline})
    s.write(CONF,candidate)
    try:s.run('nginx','-t');s.run('systemctl','reload','nginx')
    except Exception:
        assert CONF.read_text()==candidate
        CONF.rename(s.STATE/'failed-transport-tls.conf');s.run('nginx','-t');s.run('systemctl','reload','nginx');raise
    after=s.baseline();after['nginx_files'].pop(str(CONF),None)
    assert after==baseline
    return {'usa_only_tls_transport_port':PORT,'vpn_unchanged':True}


def authorize_proxy():
    s.guard();path=r.HOME_DIR/'.ssh/authorized_keys'
    assert not path.is_symlink()
    previous=path.read_text();old='from="'+r.SOURCE+'",'
    assert previous.startswith(old) and previous.count('\n')==1
    candidate=previous.replace(old,'from="'+r.SOURCE+','+s.ENTRY+'",',1)
    s.save('transport-key-before',{'text':previous})
    temporary=path.with_suffix('.pending')
    with temporary.open('x') as handle:os.chmod(temporary,0o600);handle.write(candidate)
    os.chown(temporary,path.stat().st_uid,path.stat().st_gid);temporary.replace(path)
    assert path.read_text()==candidate
    return {'only_existing_restricted_key_accepts_local_tls_proxy':True}


def xray():
    s.guard();s.certificate_details()
    assert CONF.is_file() and CONF.read_text()==s.read('transport-tls-intent')['text']
    unit=Path('/etc/systemd/system/ham-usa244-tls.service')
    assert not unit.exists()
    config={'log':{'loglevel':'warning'},'inbounds':[{'tag':'usa-only-tls-ssh','listen':s.ENTRY,'port':PORT,
        'protocol':'dokodemo-door','settings':{'address':s.ENTRY,'port':r.SSH_PORT,'network':'tcp'},
        'streamSettings':{'network':'raw','security':'tls','sockopt':{'tcpMaxSeg':1200},
            'tlsSettings':{'alpn':['http/1.1'],'certificates':[{'certificateFile':'/etc/letsencrypt/live/'+s.DOMAIN+'/fullchain.pem',
                'keyFile':'/etc/letsencrypt/live/'+s.DOMAIN+'/privkey.pem'}]}}}],
        'outbounds':[{'tag':'BLOCK','protocol':'blackhole'},{'tag':'SSH','protocol':'freedom'}],
        'routing':{'rules':[{'type':'field','source':[r.SOURCE+'/32'],'inboundTag':['usa-only-tls-ssh'],'outboundTag':'SSH'}]}}
    s.save('xray-tls-config',config);binary='/root/hamvpn-entry244-20260917/probe-xray'
    path=s.STATE/'xray-tls-config.json'
    s.run(binary,'run','-test','-c',str(path))
    before=s.baseline()
    CONF.rename(s.STATE/'superseded-nginx-transport.conf');s.run('nginx','-t');s.run('systemctl','reload','nginx')
    text=('[Unit]\nDescription=USA-only TLS protected SSH relay\nAfter=network-online.target ham-usa244-listener.service\n'
        '[Service]\nType=simple\nExecStart='+binary+' run -c '+str(path)+'\nRestart=always\nRestartSec=3\n'
        'NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\nCapabilityBoundingSet=\n'
        '[Install]\nWantedBy=multi-user.target\n')
    with unit.open('x') as handle:os.chmod(unit,0o644);handle.write(text)
    s.save('xray-tls-unit',{'text':text,'binary_sha256':hashlib.sha256(Path(binary).read_bytes()).hexdigest()})
    s.run('systemd-analyze','verify',str(unit));s.run('systemctl','daemon-reload');s.run('systemctl','enable','--now',unit.name)
    return {'xray_tls_transport':True,'port':PORT,'only_source':r.SOURCE}


if __name__=='__main__':
    os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('action',choices=['install','authorize-proxy','xray'])
    print(json.dumps(globals()[p.parse_args().action.replace('-','_')]()))
