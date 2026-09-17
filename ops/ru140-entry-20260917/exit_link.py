"""Add one forwarding-only identity on each existing exit; preserve root access."""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import re
import sys
import tarfile
from common import ENTRY,NODES,STATE,save,run,assert_ip,digest

USER='ham-entry140'
HOME=Path('/var/lib/'+USER)
CONF=Path('/etc/ssh/sshd_config.d/70-ham-entry140.conf')


def effective(user): return run('/usr/sbin/sshd','-T','-C','user='+user+',addr='+ENTRY+',host=entry140')


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('id',choices=[n['id'] for n in NODES]);a=p.parse_args()
    n=next(n for n in NODES if n['id']==a.id);assert_ip(n['ip'])
    assert os.geteuid()==0 and not CONF.exists() and not HOME.exists()
    try:pwd.getpwnam(USER)
    except KeyError:pass
    else:raise RuntimeError('Identity already exists; reconcile')
    public=sys.stdin.read().strip()
    assert re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?',public)
    assert len(base64.b64decode(public.split()[1]))==51
    run('/usr/sbin/sshd','-t');before=effective('root')
    STATE.mkdir(mode=0o700,exist_ok=True)
    archive=STATE/'sshd-before.tar.gz';assert not archive.exists()
    with tarfile.open(archive,'w:gz') as t:
        t.add('/etc/ssh/sshd_config',arcname='etc/ssh/sshd_config')
        t.add('/etc/ssh/sshd_config.d',arcname='etc/ssh/sshd_config.d')
    save('ssh-backup',{'sha256':digest(archive)})
    run('useradd','--system','--create-home','--home-dir',str(HOME),'--shell','/usr/sbin/nologin',USER)
    account=pwd.getpwnam(USER);directory=HOME/'.ssh';directory.mkdir(mode=0o700)
    os.chown(directory,account.pw_uid,account.pw_gid)
    pending=directory/'authorized_keys.pending';authorized=directory/'authorized_keys'
    pending.write_text('from="'+ENTRY+'",restrict,port-forwarding,permitopen="127.0.0.1:443" '+public+'\n')
    pending.chmod(0o600);os.chown(pending,account.pw_uid,account.pw_gid)
    policy={'AuthenticationMethods':'publickey','PasswordAuthentication':'no','KbdInteractiveAuthentication':'no',
        'AllowTcpForwarding':'local','AllowStreamLocalForwarding':'no','PermitOpen':'127.0.0.1:443',
        'PermitListen':'none','PermitTTY':'no','PermitTunnel':'no','PermitUserRC':'no','AllowAgentForwarding':'no',
        'X11Forwarding':'no','MaxSessions':'0','ForceCommand':'/bin/false'}
    try:
        CONF.write_text('Match User '+USER+'\n'+''.join('    '+k+' '+v+'\n' for k,v in policy.items())+'Match all\n');CONF.chmod(0o644)
        run('/usr/sbin/sshd','-t');assert before==effective('root'),'Root policy changed'
        current=dict(x.split(' ',1) for x in effective(USER).splitlines() if ' ' in x)
        assert all(current[k.lower()]==v for k,v in policy.items())
        run('systemctl','reload','ssh');pending.replace(authorized)
    except Exception:
        if authorized.exists():authorized.rename(directory/'authorized_keys.revoked')
        if CONF.exists():CONF.unlink()
        run('/usr/sbin/sshd','-t');run('systemctl','reload','ssh');raise
    save('exit-link',{'id':n['id'],'root_policy_unchanged':True,'allowed_destination':'127.0.0.1:443'})
    print(json.dumps({'exit':n['id'],'restricted_identity_ready':True,'root_policy_unchanged':True}))


if __name__=='__main__':main()
