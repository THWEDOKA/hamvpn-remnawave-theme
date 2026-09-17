"""Provision four unique reverse-channel keys with forwarding-only restrictions."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
from entry244_common import ROOT, ENTRY, NODES, STATE, save, read, run

USER = 'ham-exits244'
HOME_DIR = Path('/var/lib/' + USER)
SSH_CONF = Path('/etc/ssh/sshd_config.d/70-ham-exits244.conf')
KEY_DIR = Path('/etc/hamvpn-entry244')
UNIT = Path('/etc/systemd/system/ham-entry244-reverse.service')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def public_blob(value):
    require(isinstance(value, str) and re.fullmatch(
        r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?', value), 'Invalid public key')
    blob = base64.b64decode(value.split()[1], validate=True)
    require(len(blob) == 51 and blob[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20',
            'Invalid Ed25519 wire format')
    return blob


def authorized_keys(keys):
    require(isinstance(keys, dict) and set(keys) == {n['id'] for n in NODES}, 'Exactly four exit keys required')
    require(len({public_blob(v) for v in keys.values()}) == 4, 'Exit public keys must be unique')
    require({n['link'] for n in NODES} == {21443, 22443, 23443, 24443}, 'Unexpected reverse ports')
    return ''.join('from="' + n['ip'] + '",restrict,port-forwarding,permitlisten="127.0.0.1:'
                   + str(n['link']) + '" ' + keys[n['id']] + '\n' for n in NODES)


def ssh_policy():
    return {'AuthenticationMethods': 'publickey', 'PubkeyAuthentication': 'yes',
            'PubkeyAcceptedAlgorithms': 'ssh-ed25519',
            'AuthorizedKeysFile': str(HOME_DIR / '.ssh/authorized_keys'),
            'AuthorizedKeysCommand': 'none', 'TrustedUserCAKeys': 'none',
            'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
            'HostbasedAuthentication': 'no', 'GSSAPIAuthentication': 'no',
            'AllowTcpForwarding': 'remote', 'AllowStreamLocalForwarding': 'no', 'GatewayPorts': 'no',
            'PermitOpen': 'none', 'PermitListen': ' '.join('127.0.0.1:' + str(n['link']) for n in NODES),
            'PermitTTY': 'no', 'PermitTunnel': 'no', 'PermitUserRC': 'no', 'AllowAgentForwarding': 'no',
            'X11Forwarding': 'no', 'MaxSessions': '0', 'ForceCommand': '/bin/false'}


def policy_text():
    return 'Match User ' + USER + '\n' + ''.join('    ' + k + ' ' + v + '\n'
                                               for k, v in ssh_policy().items()) + 'Match all\n'


def check_policy(output):
    actual = dict(line.split(' ', 1) for line in output.splitlines() if ' ' in line)
    for name, expected in ssh_policy().items():
        value = actual.get(name.lower())
        # OpenSSH versions may render these boolean options as yes/no or true/false.
        if expected in ('yes', 'no'):
            value = {'true': 'yes', 'false': 'no'}.get(value, value)
        require(value == expected, 'Effective SSH policy mismatch: ' + name)
    require(actual.get('disableforwarding') == 'no', 'Forwarding globally disabled')


def backup_ssh():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'Unsafe private state directory')
    archive = STATE / 'ssh-before-identity.tar.gz'
    # Exclusive creation: never replace the original before-image on a retry.
    with archive.open('xb') as handle:
        os.chmod(archive, 0o600)
        with tarfile.open(fileobj=handle, mode='w:gz') as bundle:
            bundle.add('/etc/ssh', arcname='etc/ssh')
            if Path('/root/.ssh').exists():
                bundle.add('/root/.ssh', arcname='root/.ssh')
        handle.flush()
        os.fsync(handle.fileno())
    save('ssh-identity-backup', {'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})


def generate(node):
    require(node and node['ip'] + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong exit')
    directory = KEY_DIR
    require(not directory.exists(), 'Existing intent; inspect before retry')
    known = sys.stdin.read().strip()
    require(known.startswith(ENTRY + ' '), 'Wrong entry host key')
    public_blob(known[len(ENTRY) + 1:])
    directory.mkdir(mode=0o700)
    (directory / 'known_hosts').write_text(known + '\n'); (directory / 'known_hosts').chmod(0o600)
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'HAMVPN-exit244-' + node['id'], '-f', str(directory / 'reverse_key'))
    (directory / 'reverse_key').chmod(0o600)
    save('key-intent', {'id': node['id'], 'entry': ENTRY})
    return {'id': node['id'], 'dedicated_private_key_created_on_exit': True}


def identity():
    import pwd
    require(ENTRY + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong entry')
    require(not SSH_CONF.exists() and not HOME_DIR.exists(), 'Existing SSH identity files; inspect')
    try: pwd.getpwnam(USER)
    except KeyError: pass
    else: raise RuntimeError('Identity exists; inspect')
    key_text = authorized_keys(json.load(sys.stdin))
    def effective(name, address):
        return run('/usr/sbin/sshd', '-T', '-C', 'user=' + name + ',addr=' + address + ',host=entry244')
    run('/usr/sbin/sshd', '-t')
    addresses = list(dict.fromkeys([n['ip'] for n in NODES] + ['127.0.0.1', '::1',
                                   os.environ.get('SSH_CONNECTION', '127.0.0.1').split()[0]]))
    before = {address: effective('root', address) for address in addresses}
    backup_ssh()
    save('ssh-policy-before', before)
    directory = HOME_DIR / '.ssh'
    pending = directory / 'authorized_keys.pending'
    authorized = directory / 'authorized_keys'
    try:
        run('useradd', '--system', '--create-home', '--home-dir', str(HOME_DIR), '--shell', '/usr/sbin/nologin', USER)
        account = pwd.getpwnam(USER)
        HOME_DIR.chmod(0o700); os.chown(HOME_DIR, account.pw_uid, account.pw_gid)
        directory.mkdir(mode=0o700); os.chown(directory, account.pw_uid, account.pw_gid)
        pending.write_text(key_text)
        pending.chmod(0o600); os.chown(pending, account.pw_uid, account.pw_gid)
        SSH_CONF.write_text(policy_text())
        SSH_CONF.chmod(0o644); run('/usr/sbin/sshd', '-t')
        for address in addresses:
            require(effective('root', address) == before[address], 'Root SSH policy changed')
            check_policy(effective(USER, address))
        # Verify owner/modes explicitly; useradd defaults and umask are not sufficient.
        for path, mode in [(HOME_DIR, 0o700), (directory, 0o700), (pending, 0o600)]:
            require(path.stat().st_uid == account.pw_uid and path.stat().st_mode & 0o777 == mode,
                    'Unsafe identity permissions')
        run('systemctl', 'reload', 'ssh'); pending.rename(authorized)
        save('restricted-identity', {'root_policy_preserved': True, 'four_unique_loopback_ports': True})
    except Exception:
        # Revoke authentication BEFORE removing restrictions, even if the final save failed.
        if authorized.exists(): authorized.rename(directory / 'authorized_keys.revoked')
        if SSH_CONF.exists(): SSH_CONF.rename(STATE / 'failed-ssh-policy.conf')
        run('/usr/sbin/sshd', '-t'); run('systemctl', 'reload', 'ssh'); raise
    return {'forwarding_only_identity_ready': True, 'root_policy_preserved': True}


def service_text(node):
    return ('[Unit]\nDescription=HAMVPN dedicated reverse exit channel to entry244\nAfter=network-online.target\nWants=network-online.target\n'
        'StartLimitIntervalSec=0\n'
        '[Service]\nType=simple\nExecStart=/usr/bin/python3 ' + str(ROOT / 'reverse244_client.py') + ' --id ' + node['id'] + '\n'
        'Restart=always\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
        'UMask=0077\nCapabilityBoundingSet=\nRestrictSUIDSGID=true\n'
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nLimitNOFILE=16384\nTasksMax=1152\n[Install]\nWantedBy=multi-user.target\n')


def check_install_plan(plan):
    for line in plan.splitlines():
        require(not line.startswith('Remv '), 'Dependency installation would remove packages')
        if line.startswith('Inst '):
            require(line.split()[1] in {'python3-paramiko', 'python3-nacl', 'python3-bcrypt'}
                    and not line.split()[2].startswith('['), 'Dependency installation would update unrelated packages')


def start(node):
    require(node and node['ip'] + '/' in run('ip', '-4', 'addr', 'show')
            and read('key-intent')['id'] == node['id'], 'Wrong exit or key intent')
    unit = UNIT
    require(not unit.exists(), 'Existing reverse unit; inspect')
    for path, mode in [(KEY_DIR, 0o700), (KEY_DIR / 'reverse_key', 0o600), (KEY_DIR / 'known_hosts', 0o600)]:
        require(path.stat().st_uid == 0 and path.stat().st_mode & 0o777 == mode, 'Unsafe exit key permissions')
    check_install_plan(run('apt-get', '-s', '--no-install-recommends', 'install', 'python3-paramiko'))
    run('env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'NEEDRESTART_SUSPEND=1',
        'apt-get', 'install', '-y', '--no-remove', '--no-upgrade', '--no-install-recommends', 'python3-paramiko')
    runtime = json.loads(run('/usr/bin/python3', '-c',
        'import json,paramiko;print(json.dumps({"version":paramiko.__version__,"source":paramiko.__file__}))'))
    require(runtime['source'].startswith('/usr/lib/python3/dist-packages/paramiko/'), 'Unexpected Paramiko source')
    save('reverse-runtime', runtime)
    unit.write_text(service_text(node))
    unit.chmod(0o644)
    run('systemd-analyze', 'verify', str(unit))
    unit.chmod(0o644); run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', unit.name)
    require(run('systemctl', 'is-active', unit.name).strip() == 'active', 'Reverse unit is not active')
    return {'id': node['id'], 'reverse_service_started': True, 'paramiko_runtime': runtime}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['generate', 'export-key', 'identity', 'start'])
    parser.add_argument('--id', choices=[n['id'] for n in NODES])
    args = parser.parse_args()
    node = next((n for n in NODES if n['id'] == args.id), None)
    if args.action != 'identity' and node is None: parser.error('--id is required for exit actions')
    require(os.geteuid() == 0, 'Root required')
    if args.action == 'export-key':
        require(read('key-intent')['id'] == node['id'], 'Wrong exit key intent')
        print((KEY_DIR / 'reverse_key.pub').read_text().strip()); return
    result = identity() if args.action == 'identity' else globals()[args.action](node)
    print(json.dumps(result))


if __name__ == '__main__': main()
