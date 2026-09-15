"""Install one forwarding-only user after explicit ACME relay authorization."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tarfile

USER = 'hamvpn-acme-ru214'
HOME = Path('/var/lib/' + USER)
CONF = Path('/etc/ssh/sshd_config.d/70-hamvpn-acme-ru214.conf')
STATE = Path('/root/selfsteal-ru214-acme-panel')
OPTIONS = ('from="161.104.90.214",restrict,port-forwarding,'
           'permitopen="acme-v02.api.letsencrypt.org:443",'
           'permitopen="acme-staging-v02.api.letsencrypt.org:443"')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def effective(user):
    return run('/usr/sbin/sshd', '-T', '-C', 'user=' + user + ',addr=161.104.90.214,host=ru214')


def validate(values):
    config = dict(line.split(' ', 1) for line in values.splitlines() if ' ' in line)
    for key, value in {'authenticationmethods': 'publickey', 'passwordauthentication': 'no',
                       'kbdinteractiveauthentication': 'no', 'allowtcpforwarding': 'local',
                       'allowstreamlocalforwarding': 'no', 'permitlisten': 'none', 'permittty': 'no',
                       'permittunnel': 'no', 'permituserrc': 'no', 'allowagentforwarding': 'no',
                       'x11forwarding': 'no', 'maxsessions': '0', 'forcecommand': '/bin/false'}.items():
        assert config[key] == value, key
    assert set(config['permitopen'].split()) == {
        'acme-v02.api.letsencrypt.org:443', 'acme-staging-v02.api.letsencrypt.org:443'}


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    assert not CONF.exists() and not STATE.exists() and not HOME.exists()
    try: pwd.getpwnam(USER)
    except KeyError: pass
    else: raise RuntimeError('Identity already exists; inspect instead of overwrite')
    public = sys.stdin.read().strip()
    assert re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?', public)
    assert len(base64.b64decode(public.split()[1])) == 51
    run('/usr/sbin/sshd', '-t')
    before = effective('root')
    STATE.mkdir(mode=0o700)
    with tarfile.open(STATE / 'sshd-before.tar.gz', 'w:gz') as archive:
        archive.add('/etc/ssh/sshd_config', arcname='etc/ssh/sshd_config')
        archive.add('/etc/ssh/sshd_config.d', arcname='etc/ssh/sshd_config.d')
    (STATE / 'SHA256SUMS').write_text(hashlib.sha256((STATE / 'sshd-before.tar.gz').read_bytes()).hexdigest() + '  sshd-before.tar.gz\n')
    run('useradd', '--system', '--create-home', '--home-dir', str(HOME), '--shell', '/usr/sbin/nologin', USER)
    account = pwd.getpwnam(USER)
    directory = HOME / '.ssh'
    directory.mkdir(mode=0o700)
    authorized = directory / 'authorized_keys'
    authorized.write_text(OPTIONS + ' ' + public + '\n'); authorized.chmod(0o600)
    os.chown(directory, account.pw_uid, account.pw_gid)
    os.chown(authorized, account.pw_uid, account.pw_gid)
    CONF.write_text((Path(__file__).parent / 'acme-sshd.conf').read_text())
    CONF.chmod(0o644)
    try:
        run('/usr/sbin/sshd', '-t')
        assert effective('root') == before, 'Root SSH configuration changed'
        validate(effective(USER))
        run('systemctl', 'reload', 'ssh')
    except Exception:
        # Remove only our new drop-in; existing SSH files are never overwritten.
        CONF.unlink()
        run('/usr/sbin/sshd', '-t')
        run('systemctl', 'reload', 'ssh')
        raise
    (STATE / 'installed.json').write_text(json.dumps({'user': USER, 'root_config_preserved': True}))
    print(json.dumps({'forwarding_identity_created': USER, 'root_config_preserved': True,
                      'allowed_destinations': 2, 'sshd_configuration_valid': True}))


if __name__ == '__main__': main()
