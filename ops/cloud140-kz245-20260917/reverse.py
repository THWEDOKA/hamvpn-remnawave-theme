"""Optional reverse fallback, not a deployment decision. No API/DNS/VPN writes.

After main verifies direct is unavailable and publishes a release:
  exit: runtime-plan; [explicit install-runtime]; generate --id ID < pinned-entry-known-host
  exit: export-key --id ID (PUBLIC ONLY)
  entry: identity < JSON mapping exit ids to their public keys
  exit: start --id ID (requires an existing loopback backend on 15443)
All mutation intents are exclusive. Interrupted operations require inspection,
not a blind retry. Only the operation's own SSH policy/service may be changed.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent
ENTRY = '176.108.245.140'
NODES = (
    dict(id='kz2', ip='206.223.240.179', user='ham-cloud140-kz2', link=27443),
    dict(id='de245', ip='196.251.107.245', user='ham-cloud140-de245', link=28443),
)
TARGET = ('127.0.0.1', 15443)
STATE = Path('/root/hamvpn-cloud140-kz245-20260917/reverse')
KEY_DIR = Path('/etc/hamvpn-cloud140')
SSH_CONF = Path('/etc/ssh/sshd_config.d/70-ham-cloud140-reverse.conf')
UNIT = Path('/etc/systemd/system/ham-cloud140-reverse.service')
APT_PACKAGES = {'libsodium23', 'python3-paramiko', 'python3-nacl', 'python3-bcrypt',
                'python3-cryptography', 'python3-cffi-backend', 'python3-pyasn1', 'python3-six'}


def require(ok, message):
    if not ok: raise RuntimeError(message)


def digest(data): return hashlib.sha256(data).hexdigest()
def home(node): return Path('/var/lib') / node['user']
def absent(path): return not path.exists() and not path.is_symlink()


def run(*args, timeout=45):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(p.returncode == 0, 'Command failed: ' + Path(args[0]).name)
    return p.stdout


def secure(path, mode, owner=0):
    require(not path.is_symlink() and path.stat().st_uid == owner
            and path.stat().st_mode & 0o777 == mode, 'Unsafe owner/mode: ' + str(path))


def state_dir():
    for p in (STATE.parent, STATE):
        if absent(p): p.mkdir(mode=0o700)
        secure(p, 0o700)


def create(path, data, mode=0o600):
    """No overwrite, including dangling symlinks; fsync before returning."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode); f.write(data); f.flush(); os.fsync(f.fileno())


def save(name, value):
    state_dir()
    create(STATE / (name + '.json'), json.dumps(value).encode())


def read(name):
    secure(STATE.parent, 0o700); secure(STATE, 0o700)
    path = STATE / (name + '.json'); secure(path, 0o600)
    return json.loads(path.read_text())


def guard(address):
    require(os.geteuid() == 0, 'Root required')
    addresses = json.loads(run('ip', '-j', '-4', 'addr', 'show'))
    require(address in {a['local'] for i in addresses for a in i.get('addr_info', [])}, 'Wrong server')


def public_blob(value):
    require(isinstance(value, str) and re.fullmatch(
        r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?', value), 'Invalid public key')
    blob = base64.b64decode(value.split()[1], validate=True)
    require(len(blob) == 51 and blob[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20',
            'Invalid Ed25519 wire format')
    return blob


def known_host(value):
    require(isinstance(value, str) and value.startswith(ENTRY + ' '), 'Wrong pinned entry host')
    public_blob(value[len(ENTRY) + 1:])
    return value + '\n'


def validate_nodes():
    require(NODES and len({n['id'] for n in NODES}) == len(NODES)
            and len({n['ip'] for n in NODES}) == len(NODES)
            and len({n['user'] for n in NODES}) == len(NODES)
            and len({n['link'] for n in NODES}) == len(NODES), 'Duplicate route identity')
    for n in NODES:
        require(n['id'] in ('kz2', 'de245') and n['user'] == 'ham-cloud140-' + n['id'], 'Unexpected identity')
        expected = {'kz2': ('206.223.240.179', 27443), 'de245': ('196.251.107.245', 28443)}[n['id']]
        require((n['ip'], n['link']) == expected, 'Unexpected route')


def authorized_keys(keys):
    validate_nodes()
    require(isinstance(keys, dict) and set(keys) == {n['id'] for n in NODES}, 'Exact selected exit keys required')
    require(len({public_blob(v) for v in keys.values()}) == len(NODES), 'Exit keys must be unique')
    return {n['id']: ('from="' + n['ip'] + '",restrict,port-forwarding,command="/bin/false",'
            'permitlisten="127.0.0.1:' + str(n['link']) + '" ' + keys[n['id']] + '\n') for n in NODES}


def ssh_policy(node):
    return {'AuthenticationMethods': 'publickey', 'PubkeyAuthentication': 'yes',
            'PubkeyAcceptedAlgorithms': 'ssh-ed25519',
            'AuthorizedKeysFile': str(home(node) / '.ssh/authorized_keys'),
            'AuthorizedKeysCommand': 'none', 'TrustedUserCAKeys': 'none',
            'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
            'HostbasedAuthentication': 'no', 'GSSAPIAuthentication': 'no',
            'AllowTcpForwarding': 'remote', 'AllowStreamLocalForwarding': 'no',
            'GatewayPorts': 'no', 'PermitOpen': 'none', 'PermitListen': '127.0.0.1:' + str(node['link']),
            'PermitTTY': 'no', 'PermitTunnel': 'no', 'PermitUserRC': 'no',
            'AllowAgentForwarding': 'no', 'X11Forwarding': 'no', 'MaxSessions': '0', 'ForceCommand': '/bin/false'}


def policy_text():
    validate_nodes()
    return ''.join('Match User ' + n['user'] + '\n' + ''.join(
        '    ' + k + ' ' + v + '\n' for k, v in ssh_policy(n).items()) for n in NODES) + 'Match all\n'


def check_policy(output, node):
    actual = dict(line.split(' ', 1) for line in output.splitlines() if ' ' in line)
    for name, expected in ssh_policy(node).items():
        value = actual.get(name.lower())
        if expected in ('yes', 'no'): value = {'true': 'yes', 'false': 'no'}.get(value, value)
        require(value == expected, 'Effective SSH policy mismatch: ' + name)
    require(actual.get('disableforwarding') in ('no', 'false'), 'Forwarding globally disabled')


def contexts():
    # Cover both exit sources, operator source, loopbacks and a disallowed source.
    addresses = [n['ip'] for n in NODES] + ['127.0.0.1', '::1', '192.0.2.1']
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if connection: addresses.append(str(ipaddress.ip_address(connection[0])))
    return list(dict.fromkeys(addresses))


def effective(user, address):
    return run('/usr/sbin/sshd', '-T', '-C',
               'user=' + user + ',addr=' + address + ',host=' + address + ',laddr=' + ENTRY + ',lport=22')


def operators(addresses):
    return {user: {ip: effective(user, ip) for ip in addresses} for user in ('root', 'gasan')}


def check_operators(before, after):
    require(before == after, 'Root/gasan effective SSH policies changed')


def backup_ssh(accounts):
    state_dir(); archive = STATE / 'ssh-before-identity.tar.gz'
    with archive.open('xb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        with tarfile.open(fileobj=handle, mode='w:gz') as bundle:
            bundle.add('/etc/ssh', arcname='etc/ssh')
            for name in ('passwd', 'group', 'shadow', 'gshadow'):
                bundle.add('/etc/' + name, arcname='etc/' + name)
            for account in accounts:
                p = Path(account.pw_dir) / '.ssh'
                if p.exists(): bundle.add(p, arcname=str(p).lstrip('/'))
        handle.flush(); os.fsync(handle.fileno())
    with tarfile.open(archive, 'r:gz') as bundle:
        require('etc/ssh' in bundle.getnames(), 'SSH archive verification failed')
    save('ssh-backup', {'sha256': digest(archive.read_bytes())})


def identity(keys):
    import pwd
    guard(ENTRY); lines = authorized_keys(keys)
    accounts = [pwd.getpwnam(name) for name in ('root', 'gasan')]
    require(absent(SSH_CONF), 'Existing SSH policy; inspect')
    for n in NODES:
        require(absent(home(n)), 'Existing identity home; inspect')
        try: pwd.getpwnam(n['user'])
        except KeyError: pass
        else: raise RuntimeError('Identity already exists; inspect')
        require(not run('ss', '-H', '-ltn', 'sport = :' + str(n['link'])).strip(), 'Entry reverse port occupied')
    run('/usr/sbin/sshd', '-t'); addresses = contexts(); before = operators(addresses)
    backup_ssh(accounts)
    save('identity-intent', {'before': before, 'policy_sha256': digest(policy_text().encode()),
                           'public_key_sha256': {k: digest(public_blob(v)) for k, v in keys.items()}})
    created = []; policy_created = False
    try:
        for n in NODES:
            run('useradd', '--system', '--create-home', '--home-dir', str(home(n)), '--shell', '/usr/sbin/nologin', n['user'])
            account = pwd.getpwnam(n['user']); directory = home(n) / '.ssh'
            require(absent(directory), 'Unexpected initial .ssh directory')
            home(n).chmod(0o700); os.chown(home(n), account.pw_uid, account.pw_gid)
            directory.mkdir(mode=0o700); os.chown(directory, account.pw_uid, account.pw_gid)
            pending = directory / 'authorized_keys.pending'
            create(pending, lines[n['id']].encode()); os.chown(pending, account.pw_uid, account.pw_gid)
            created.append(n)
            for p, mode in ((home(n), 0o700), (directory, 0o700), (pending, 0o600)):
                secure(p, mode, account.pw_uid)
        create(SSH_CONF, policy_text().encode(), 0o644); policy_created = True
        run('/usr/sbin/sshd', '-t'); check_operators(before, operators(addresses))
        for n in NODES:
            for address in addresses: check_policy(effective(n['user'], address), n)
        run('systemctl', 'reload', 'ssh')
        # Keep keys disabled until restrictions are loaded. No VPN restart.
        time.sleep(1)
        require(run('systemctl', 'is-active', 'ssh').strip() == 'active', 'SSH is not active')
        for n in NODES:
            directory = home(n) / '.ssh'
            require(absent(directory / 'authorized_keys'), 'Unexpected authorized_keys')
            (directory / 'authorized_keys.pending').rename(directory / 'authorized_keys')
        check_operators(before, operators(addresses))
        save('identity-ready', {'identities': len(NODES), 'operator_policies_preserved': True})
    except Exception:
        # Disable our authentication first; never remove someone else's policy.
        for n in created:
            authorized = home(n) / '.ssh/authorized_keys'
            if authorized.exists():
                require(not authorized.is_symlink() and authorized.read_text() == lines[n['id']], 'Concurrent key change')
                authorized.rename(authorized.with_name('authorized_keys.revoked'))
        if policy_created:
            require(not SSH_CONF.is_symlink() and SSH_CONF.read_text() == policy_text(), 'Concurrent SSH policy change')
            SSH_CONF.rename(STATE / 'failed-policy.conf')
            run('/usr/sbin/sshd', '-t'); run('systemctl', 'reload', 'ssh')
            check_operators(before, operators(addresses))
        raise
    return {'forwarding_only_identities': len(NODES), 'root_gasan_policy_preserved': True}


def generate(node, pinned):
    guard(node['ip']); known = known_host(pinned)
    require(absent(KEY_DIR), 'Existing key directory; inspect before retry')
    save('key-intent', {'id': node['id'], 'entry': ENTRY, 'known_hosts_sha256': digest(known.encode())})
    KEY_DIR.mkdir(mode=0o700); create(KEY_DIR / 'known_hosts', known.encode())
    run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'HAM-cloud140-' + node['id'], '-f', str(KEY_DIR / 'reverse_key'))
    (KEY_DIR / 'reverse_key').chmod(0o600); (KEY_DIR / 'reverse_key.pub').chmod(0o600)
    check_keys(node)
    save('key-ready', {'id': node['id'], 'public_key_sha256': digest(public_blob((KEY_DIR / 'reverse_key.pub').read_text().strip()))})
    return {'id': node['id'], 'private_key_created_locally': True}


def check_keys(node):
    intent = read('key-intent')
    require(intent['id'] == node['id'] and intent['entry'] == ENTRY, 'Wrong key intent')
    for p, mode in ((KEY_DIR, 0o700), (KEY_DIR / 'reverse_key', 0o600),
                    (KEY_DIR / 'reverse_key.pub', 0o600), (KEY_DIR / 'known_hosts', 0o600)):
        secure(p, mode)
    text = (KEY_DIR / 'known_hosts').read_text()
    require(text == known_host(text.rstrip('\n')) and digest(text.encode()) == intent['known_hosts_sha256'], 'Pinned host key changed')
    require(public_blob(run('ssh-keygen', '-y', '-P', '', '-f', str(KEY_DIR / 'reverse_key')).strip())
            == public_blob((KEY_DIR / 'reverse_key.pub').read_text().strip()), 'Public/private key mismatch')


def check_install_plan(plan):
    planned = []
    for line in plan.splitlines():
        words = line.split()
        if not words: continue
        require(words[0] != 'Remv', 'APT would remove packages')
        if words[0] in ('Inst', 'Conf'):
            require(len(words) >= 3 and words[1] in APT_PACKAGES and not words[2].startswith('['), 'APT would upgrade/configure unrelated packages')
            if words[0] == 'Inst': planned.append(words[1])
    return planned


def runtime_plan():
    return check_install_plan(run('apt-get', '-s', '--no-remove', '--no-upgrade', '--no-install-recommends', 'install', 'python3-paramiko'))


def runtime():
    result = json.loads(run('/usr/bin/python3', '-I', '-c',
        'import json,paramiko; print(json.dumps({"version":paramiko.__version__,"source":paramiko.__file__}))'))
    require(result['source'].startswith('/usr/lib/python3/dist-packages/paramiko/'), 'Paramiko is not the apt runtime')
    return result


def unit_info(unit):
    args = ['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'MainPID', '-p', 'ExecMainStartTimestampMonotonic']
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if fields.get('LoadState') == 'not-found' and result.returncode in (0, 1, 4):
        return {'LoadState': 'not-found'}
    require(result.returncode == 0 and fields.get('LoadState') == 'loaded', 'Cannot inspect service: ' + unit)
    return fields


def service_baseline():
    # No environment/config dump. Includes native services and container start identity.
    result = {unit: unit_info(unit)
              for unit in ('ssh.service', 'nginx.service', 'docker.service', 'xray.service', 'remnanode.service')}
    if Path('/usr/bin/docker').exists():
        ids = run('docker', 'ps', '-q').split()
        result['containers'] = [run('docker', 'inspect', '--format',
            '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}', cid).strip() for cid in sorted(ids)]
    return result


def install_runtime(node):
    guard(node['ip']); plan = runtime_plan(); before = service_baseline()
    save('runtime-install-intent', {'id': node['id'], 'packages': plan, 'services': before})
    run('env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'NEEDRESTART_SUSPEND=1',
        'apt-get', 'install', '-y', '--no-remove', '--no-upgrade', '--no-install-recommends', 'python3-paramiko', timeout=180)
    require(service_baseline() == before, 'Existing service start identity changed')
    result = runtime(); save('runtime-ready', result); return result


def service_text(node):
    return ('[Unit]\nDescription=HAM cloud140 restricted reverse ' + node['id'] + '\n'
        'After=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n'
        '[Service]\nType=simple\nUser=root\nWorkingDirectory=/\n'
        'ExecStart=/usr/bin/python3 -B ' + str(ROOT / 'reverse_client.py') + ' --id ' + node['id'] + '\n'
        'Environment=PYTHONNOUSERSITE=1\nRestart=always\nRestartSec=5\nTimeoutStopSec=15\n'
        'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
        'UMask=0077\nCapabilityBoundingSet=\nRestrictSUIDSGID=true\n'
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\nLimitNOFILE=8192\nTasksMax=320\n'
        '[Install]\nWantedBy=multi-user.target\n')


def start(node):
    guard(node['ip']); check_keys(node); read('key-ready'); details = runtime()
    require(absent(UNIT), 'Existing reverse service; inspect')
    require(unit_info(UNIT.name)['LoadState'] == 'not-found', 'Existing service definition elsewhere')
    listeners = run('ss', '-H', '-ltn', 'sport = :15443').splitlines()
    require(listeners and all(line.split()[3] == '127.0.0.1:15443' for line in listeners), 'Backend must listen only on loopback 15443')
    before = service_baseline(); text = service_text(node)
    save('start-intent', {'id': node['id'], 'unit_sha256': digest(text.encode()), 'services': before, 'runtime': details})
    create(UNIT, text.encode(), 0o644)
    run('systemd-analyze', 'verify', str(UNIT)); run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', UNIT.name)
    require(run('systemctl', 'is-active', UNIT.name).strip() == 'active', 'Reverse unit inactive')
    require(service_baseline() == before, 'Existing service start identity changed')
    save('service-started', {'id': node['id']})
    return {'id': node['id'], 'service_started': True, 'channel_and_backend_proof_still_required': True}


def repair_unit(node):
    """Permit read-only interface inventory; CAP_NET_ADMIN remains unavailable."""
    guard(node['ip']); check_keys(node)
    intent = read('start-intent'); secure(UNIT, 0o644)
    require(intent['id'] == node['id'] and digest(UNIT.read_bytes()) == intent['unit_sha256'],
            'Owned unit changed; repair refused')
    state_dir()
    create(STATE / 'unit-before-netlink.conf', UNIT.read_bytes(), 0o600)
    text = service_text(node)
    require('CapabilityBoundingSet=\n' in text and 'AF_NETLINK' in text, 'Unexpected capabilities')
    save('unit-netlink-intent', {'before_sha256': intent['unit_sha256'], 'after_sha256': digest(text.encode())})
    pending = UNIT.with_name(UNIT.name + '.pending')
    create(pending, text.encode(), 0o644); pending.replace(UNIT)
    run('systemd-analyze', 'verify', str(UNIT)); run('systemctl', 'daemon-reload')
    run('systemctl', 'restart', UNIT.name)
    return {'owned_reverse_unit_updated': True, 'network_admin_capability': False, 'channel_proof_required': True}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['runtime-plan', 'install-runtime', 'generate', 'export-key', 'identity', 'start', 'repair-unit'])
    p.add_argument('--id', choices=[n['id'] for n in NODES]); args = p.parse_args()
    node = next((n for n in NODES if n['id'] == args.id), None)
    if args.action != 'identity' and node is None: p.error('--id is required for exit actions')
    guard(ENTRY if args.action == 'identity' else node['ip'])
    if args.action == 'identity': result = identity(json.load(sys.stdin))
    elif args.action == 'generate': result = generate(node, sys.stdin.read().rstrip('\n'))
    elif args.action == 'runtime-plan': result = {'new_packages_only': runtime_plan(), 'installation_performed': False}
    elif args.action == 'export-key':
        check_keys(node); read('key-ready'); print((KEY_DIR / 'reverse_key.pub').read_text().strip()); return
    else: result = globals()[args.action.replace('-', '_')](node)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'message': str(error) if isinstance(error, RuntimeError) else 'Inspect operation state; no blind retry'}))
        raise SystemExit(1)
