"""Restricted pair-specific reverse SSH; never exports its private key.

PermitListen constrains the server listener, not the client's destination.
The root-owned client unit fixes that destination to the local REALITY backend.
"""
import argparse
from ops import *

USER='ham-mws2-link'
PORT=27443
KEY=Path('/root/.ssh/ham-mws2-reverse')
HOSTS=Path('/root/.ssh/ham-mws2-known-hosts')
DROPIN=Path('/etc/ssh/sshd_config.d/90-ham-mws2-link.conf')
AUTH=Path('/etc/ssh/ham-mws2-link.authorized_keys')
UNIT=Path('/etc/systemd/system/ham-mws2-reverse.service')
FINGERPRINT='SHA256:ZLrj/W4UPr4CePOU9xa3vUiUalcnhKcyoffE33fxKbI'


def policy():
    return f'''Match User {USER}
    AuthorizedKeysFile {AUTH}
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding remote
    PermitListen 127.0.0.1:{PORT}
    PermitOpen none
    GatewayPorts no
    MaxSessions 0
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
    ForceCommand /bin/false
Match all
'''


def effective(user):
    return run('sshd','-T','-C',f'user={user},host=localhost,addr=72.56.101.218')


def verify_policy():
    settings=dict(line.split(' ',1) for line in effective(USER).decode().splitlines())
    wanted={'allowtcpforwarding':'remote','permitlisten':f'127.0.0.1:{PORT}',
            'permitopen':'none','gatewayports':'no','maxsessions':'0',
            'permittty':'no','x11forwarding':'no','allowagentforwarding':'no',
            'passwordauthentication':'no','kbdinteractiveauthentication':'no',
            'authenticationmethods':'publickey','forcecommand':'/bin/false',
            'authorizedkeysfile':str(AUTH)}
    require(all(settings.get(k)==v for k,v in wanted.items()),'Effective SSH restrictions mismatch')


def keygen():
    guard('exit');read('node-before')
    if not KEY.exists():
        require(not (STATE/'reverse-key-intent.json').exists(),'Key intent exists; reconcile')
        save('reverse-key-intent',{'time':time.time()})
        run('ssh-keygen','-q','-t','ed25519','-N','','-C','HAMVPN-MWS2-REVERSE-ONLY','-f',str(KEY))
    require(KEY.stat().st_uid==0 and KEY.stat().st_mode & 0o077==0,'Private key permissions')
    pub=run('ssh-keygen','-y','-f',str(KEY)).decode().strip()
    save('reverse-public',{'public_key':pub})
    return {'dedicated_key_ready':True,'private_key_remains_on_exit':True}


def server():
    import pwd
    guard('entry');read('node-before')
    public=json.load(sys.stdin)['public_key'].strip().split()
    require(len(public) in (2,3) and public[0]=='ssh-ed25519' and len(base64.b64decode(public[1]))==51,'Invalid public key')
    public=public[:2]
    require(not DROPIN.exists() and not AUTH.exists(),'SSH policy exists; reconcile instead of overwrite')
    require(not run('ss','-H','-lnt','sport = :'+str(PORT)).strip(),'Reverse port occupied')
    try:pwd.getpwnam(USER)
    except KeyError:pass
    else:raise RuntimeError('Dedicated username already exists')
    original=effective('root')
    save('reverse-server-intent',{'time':time.time(),'root_policy_sha256':digest(original)})
    run('useradd','--system','--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--password','*',USER)
    options=f'from="72.56.101.218",restrict,port-forwarding,permitlisten="127.0.0.1:{PORT}",command="/bin/false"'
    write(AUTH,options+' '+' '.join(public)+'\n',0o644)
    write(DROPIN,policy(),0o644)
    try:
        run('sshd','-t');verify_policy()
        require(effective('root')==original,'Unrelated root SSH policy changed')
    except Exception:
        # Only our new drop-in, before reload; preserve audit artifact.
        DROPIN.rename(STATE/'reverse-rejected.conf')
        raise
    run('systemctl','reload','ssh')
    save('reverse-server',{'policy_sha256':digest(DROPIN.read_bytes()),'auth_sha256':digest(AUTH.read_bytes()),
                           'root_policy_sha256':digest(original),'time':time.time()})
    return {'restricted_reverse_account_ready':True,'global_ssh_unchanged':True,'listener':'127.0.0.1:27443'}


def client():
    guard('exit');read('reverse-public')
    data=json.load(sys.stdin);key=data['host_key'].strip().split()
    require(len(key)>=2 and key[0]=='ssh-ed25519','Expected pinned host key')
    key=' '.join(key[:2])
    fingerprint=run('ssh-keygen','-lf','-',data=(key+'\n').encode()).decode()
    require(FINGERPRINT in fingerprint,'Entry host fingerprint mismatch')
    require(not UNIT.exists() and not HOSTS.exists(),'Reverse client exists; reconcile')
    write(HOSTS,TARGETS['entry']['ip']+' '+key+'\n')
    unit=f'''[Unit]
Description=HAMVPN MWS2 encrypted reverse link
After=network-online.target docker.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/ssh -NT -i {KEY} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={HOSTS} -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ConnectTimeout=12 -o LogLevel=ERROR -R 127.0.0.1:{PORT}:127.0.0.1:443 {USER}@{TARGETS['entry']['ip']}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
'''
    write(UNIT,unit,0o644)
    run('systemd-analyze','verify',str(UNIT))
    save('reverse-client',{'unit_sha256':digest(UNIT.read_bytes()),'time':time.time()})
    run('systemctl','daemon-reload');run('systemctl','enable','--now',UNIT.name)
    time.sleep(3)
    require(run('systemctl','is-active',UNIT.name).strip()==b'active','Tunnel client not active')
    return {'reverse_client_started':True,'real_transfer_not_yet_verified':True}


def verify():
    guard('entry');saved=read('reverse-server');verify_policy()
    require(saved['policy_sha256']==digest(DROPIN.read_bytes()) and saved['auth_sha256']==digest(AUTH.read_bytes()),'SSH policy drift')
    require(saved['root_policy_sha256']==digest(effective('root')),'Root policy drift')
    listeners=run('ss','-H','-lnt','sport = :'+str(PORT)).decode().splitlines()
    require(len(listeners)==1 and listeners[0].split()[3]=='127.0.0.1:'+str(PORT),'Reverse listener absent or exposed')
    return {'reverse_loopback_only':True,'ssh_restrictions_verified':True,'time':time.time()}


if __name__=='__main__':
    try:
        p=argparse.ArgumentParser();p.add_argument('action',choices=['keygen','server','client','verify']);a=p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed':True,'error':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'Inspect private state'}));sys.exit(1)
