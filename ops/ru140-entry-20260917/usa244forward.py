"""Use the verified working SSH direction: entry244 -> USA216, fixed local forward."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
ENTRY='193.233.222.244'
EXIT='162.141.185.216'
USER='ham-entry244-us'
KEY_DIR=Path('/etc/hamvpn-usa244-forward')
STATE=Path('/root/hamvpn-usa244-forward-20260917')
UNIT=Path('/etc/systemd/system/ham-usa244-forward.service')
spec=importlib.util.spec_from_file_location('_usa_forward_base',ROOT/'reverse244.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
base_policy=base.ssh_policy


def save(name,value):
    assert not STATE.is_symlink();STATE.mkdir(mode=0o700,exist_ok=True)
    assert STATE.stat().st_uid==0 and STATE.stat().st_mode&0o077==0
    path=STATE/(name+'.json');pending=path.with_suffix('.pending')
    with pending.open('x') as stream:
        os.chmod(pending,0o600);json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
    pending.replace(path)


def read(name):return json.loads((STATE/(name+'.json')).read_text())


def run(*args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=45)
    if result.returncode:
        save('command-error',{'program':args[0],'stdout':result.stdout,'stderr':result.stderr})
        raise RuntimeError('Command failed; diagnostics are private')
    return result.stdout


def authorized(keys):
    assert set(keys)=={'entry244'};base.public_blob(keys['entry244'])
    return 'from="'+ENTRY+'",restrict,port-forwarding,permitopen="127.0.0.1:15443" '+keys['entry244']+'\n'


def policy():
    result=base_policy()
    result.update(AllowTcpForwarding='local',PermitListen='none',PermitOpen='127.0.0.1:15443')
    return result


def helper():
    for key,value in {'ROOT':ROOT,'ENTRY':EXIT,'NODES':[{'id':'entry244','ip':ENTRY,'link':25443}],
        'USER':USER,'HOME_DIR':Path('/var/lib/'+USER),'SSH_CONF':Path('/etc/ssh/sshd_config.d/72-ham-entry244-us.conf'),
        'KEY_DIR':KEY_DIR,'STATE':STATE,'save':save,'read':read,'run':run,
        'authorized_keys':authorized,'ssh_policy':policy}.items():setattr(base,key,value)
    return base


def generate():return helper().generate({'id':'entry244','ip':ENTRY,'link':25443})


def export_key():
    assert read('key-intent')=={'id':'entry244','entry':EXIT}
    key=(KEY_DIR/'reverse_key.pub').read_text().strip();base.public_blob(key)
    return {'entry244':key}


def identity():
    with socket.create_connection(('127.0.0.1',15443),timeout=3):pass
    return helper().identity()


def ssh_args():
    return ['/usr/bin/ssh','-N','-T','-L','127.0.0.1:25443:127.0.0.1:15443',
        '-i',str(KEY_DIR/'reverse_key'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
        '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(KEY_DIR/'known_hosts'),
        '-o','GlobalKnownHostsFile=/dev/null','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=15',
        '-o','ServerAliveCountMax=3','-o','ConnectTimeout=10','-o','ConnectionAttempts=1','-o','ControlMaster=no',
        '-o','KexAlgorithms=curve25519-sha256','-o','HostKeyAlgorithms=ssh-ed25519',USER+'@'+EXIT]


def service_text():
    return ('[Unit]\nDescription=HAMVPN USA2-only authenticated SSH local forward\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n'
        '[Service]\nType=simple\nExecStart='+' '.join(ssh_args())+'\nRestart=always\nRestartSec=5\n'
        'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nUMask=0077\nCapabilityBoundingSet=\n'
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n[Install]\nWantedBy=multi-user.target\n')


def start():
    assert ENTRY+'/' in run('ip','-4','addr','show')
    assert not UNIT.exists() and not UNIT.is_symlink()
    assert read('key-intent')=={'id':'entry244','entry':EXIT}
    for path in (KEY_DIR/'reverse_key',KEY_DIR/'known_hosts'):
        assert path.is_file() and not path.is_symlink() and path.stat().st_mode&0o777==0o600
    with socket.socket() as sock:sock.bind(('127.0.0.1',25443))
    text=service_text();save('unit-intent',{'text':text})
    with UNIT.open('x') as stream:os.chmod(UNIT,0o644);stream.write(text)
    run('systemd-analyze','verify',str(UNIT));run('systemctl','daemon-reload');run('systemctl','enable','--now',UNIT.name)
    return {'usa_forward_started':True,'direction':'entry-to-USA','entry_loopback':25443,'usa_loopback':15443}


if __name__=='__main__':
    os.umask(0o077);assert os.geteuid()==0
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['generate','export-key','identity','start'])
    action=parser.parse_args().action
    try:print(json.dumps(globals()[action.replace('-','_')]()))
    except Exception as e:
        print(json.dumps({'failed':True,'type':type(e).__name__}));sys.exit(1)
