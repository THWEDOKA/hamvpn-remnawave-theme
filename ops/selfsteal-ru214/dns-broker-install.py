"""Provision the explicitly approved fixed-name DNS broker from a verified release."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tarfile

USER = 'hamvpn-dns-ru214'
STATE = Path('/root/selfsteal-ru214-dns-panel')
CONF = Path('/etc/ssh/sshd_config.d/71-hamvpn-dns-ru214.conf')
SUDO = Path('/etc/sudoers.d/hamvpn-dns-ru214')
KEY = Path('/etc/ssh/authorized_keys/hamvpn-dns-ru214')
ROOT = Path('/etc/hamvpn-dns-ru214')
LIB = Path('/usr/local/lib/hamvpn-dns-ru214')
COMMAND = '/usr/bin/python3 -I /usr/local/lib/hamvpn-dns-ru214/broker.py'
SSHD = '''Match User hamvpn-dns-ru214
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthorizedKeysFile /etc/ssh/authorized_keys/hamvpn-dns-ru214
    DisableForwarding yes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    PermitOpen none
    PermitListen none
    PermitTTY no
    PermitTunnel no
    PermitUserRC no
    AllowAgentForwarding no
    X11Forwarding no
    MaxSessions 1
    ForceCommand /usr/bin/sudo -n ''' + COMMAND + '\nMatch all\n'


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def effective(user):
    return run('/usr/sbin/sshd', '-T', '-C', 'user=' + user + ',addr=161.104.90.214,host=ru214')


def repair_key_directory():
    """Repair only this installer's new public-key directory, never a shared one."""
    assert os.geteuid() == 0 and (STATE / 'installed.json').is_file()
    assert KEY.parent.stat().st_uid == 0 and KEY.stat().st_uid == 0
    assert {path.name for path in KEY.parent.iterdir()} == {USER}
    assert KEY.parent.stat().st_mode & 0o777 == 0o700
    assert KEY.stat().st_mode & 0o777 == 0o644
    record = {'directory': str(KEY.parent), 'previous_mode': '0700', 'new_mode': '0755',
              'only_public_key_present': True}
    (STATE / 'key-directory-repair.json').write_text(json.dumps(record))
    KEY.parent.chmod(0o755)
    assert KEY.parent.stat().st_mode & 0o777 == 0o755
    print(json.dumps({'public_key_directory_traversable': True, 'other_directories_changed': False}))


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    payload = json.loads(sys.stdin.buffer.read(8193))
    assert set(payload) == {'token', 'public_key'}
    token, public = payload['token'], payload['public_key'].strip()
    assert isinstance(token, str) and 20 <= len(token) <= 256 and not any(c.isspace() for c in token)
    assert re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?', public)
    assert len(base64.b64decode(public.split()[1])) == 51
    assert not any(path.exists() for path in (STATE, CONF, SUDO, KEY, ROOT, LIB, Path('/var/lib/' + USER)))
    try: pwd.getpwnam(USER)
    except KeyError: pass
    else: raise RuntimeError('Identity exists; inspect instead of overwriting')
    spec = importlib.util.spec_from_file_location('dns_broker', Path(__file__).with_name('dns-broker.py'))
    broker = importlib.util.module_from_spec(spec); spec.loader.exec_module(broker)
    zones = broker.Cloudflare(token)('GET', '/zones?name=torcalc.ru')
    assert len(zones) == 1 and zones[0]['name'] == 'torcalc.ru'
    zone = zones[0]['id']; assert re.fullmatch(r'[0-9a-f]{32}', zone)
    nameservers = zones[0]['name_servers']
    assert isinstance(nameservers, list) and len(nameservers) == 2 and len(set(nameservers)) == 2
    assert all(re.fullmatch(r'[a-z0-9-]+\.ns\.cloudflare\.com', value) for value in nameservers)
    assert Path('/usr/bin/dig').is_file()
    run('/usr/sbin/sshd', '-t'); run('/usr/sbin/visudo', '-c')
    before = effective('root')
    STATE.mkdir(mode=0o700)
    with tarfile.open(STATE / 'before.tar.gz', 'w:gz') as archive:
        for path in ('/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d', '/etc/sudoers', '/etc/sudoers.d'):
            archive.add(path, arcname=path.lstrip('/'))
    (STATE / 'SHA256SUMS').write_text(hashlib.sha256((STATE / 'before.tar.gz').read_bytes()).hexdigest() + '  before.tar.gz\n')
    ROOT.mkdir(mode=0o700)
    broker.atomic_json(ROOT / 'credentials.json', {'token': token, 'zone_id': zone, 'name_servers': nameservers})
    token = None; payload = None
    LIB.mkdir(mode=0o755)
    script = LIB / 'broker.py'; script.write_bytes(Path(__file__).with_name('dns-broker.py').read_bytes()); script.chmod(0o644)
    run('useradd', '--system', '--create-home', '--home-dir', '/var/lib/' + USER, '--shell', '/bin/sh', USER)
    os.chown('/var/lib/' + USER, 0, 0); os.chmod('/var/lib/' + USER, 0o755)
    if not KEY.parent.exists():
        KEY.parent.mkdir(mode=0o755)
        KEY.parent.chmod(0o755)  # Explicitly counter the secret-safe process umask.
    assert KEY.parent.stat().st_uid == 0 and not KEY.parent.stat().st_mode & 0o022
    assert KEY.parent.stat().st_mode & 0o001, 'Existing public-key directory is not traversable'
    pending = STATE / 'authorized_key.pending'
    pending.write_text('from="161.104.90.214",restrict ' + public + '\n'); pending.chmod(0o600)
    try:
        SUDO.write_text(USER + ' ALL=(root) NOPASSWD: ' + COMMAND + '\n'); SUDO.chmod(0o440)
        run('/usr/sbin/visudo', '-c')
        CONF.write_text(SSHD); CONF.chmod(0o644)
        run('/usr/sbin/sshd', '-t')
        assert effective('root') == before
        values = dict(line.split(' ', 1) for line in effective(USER).splitlines() if ' ' in line)
        expected = {'forcecommand': '/usr/bin/sudo -n ' + COMMAND, 'disableforwarding': 'yes',
                    'authorizedkeysfile': str(KEY), 'passwordauthentication': 'no',
                    'authenticationmethods': 'publickey', 'maxsessions': '1', 'permittty': 'no',
                    'permituserrc': 'no', 'allowagentforwarding': 'no', 'x11forwarding': 'no'}
        for key, value in expected.items(): assert values[key] == value, key
        run('systemctl', 'reload', 'ssh')
        # Root-owned key is readable by sshd during unprivileged identity checks.
        KEY.write_bytes(pending.read_bytes()); KEY.chmod(0o644)
        (STATE / 'installed.json').write_text(json.dumps({'user': USER, 'fixed_name': broker.NAME,
            'root_ssh_preserved': True, 'credential_root_only': True}))
    except Exception:
        if KEY.exists(): KEY.replace(STATE / 'authorized_key.revoked')
        if CONF.exists(): CONF.unlink()
        if SUDO.exists(): SUDO.unlink()
        run('/usr/sbin/sshd', '-t'); run('/usr/sbin/visudo', '-c'); run('systemctl', 'reload', 'ssh')
        raise
    print(json.dumps({'dns_broker_installed': True, 'user': USER, 'fixed_name': broker.NAME,
                      'root_ssh_preserved': True, 'token_stored_only_on_panel': True}))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--repair-key-directory']:
            repair_key_directory()
        elif not sys.argv[1:]:
            main()
        else:
            raise ValueError('Unsupported operator arguments')
    except Exception as error:
        print(json.dumps({'ok': False, 'error': 'DNS broker provisioning stopped; inspect protected state',
                          'error_type': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
