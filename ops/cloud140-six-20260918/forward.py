"""Scoped deployment helper requiring review; not a fallback decision/VPN proof.

Only AT, PL, CZ and GB-power, entry-initiated SSH forwarding to the EXISTING
REALITY backend. No API, Xray, firewall, DNS, certificate or package writes.

CLI (root, exact published release, --id at|pl|cz|gbpower on every command):
  ENTRY generate         < {"known_host":"EXIT_IP ssh-ed25519 PUBLIC_KEY"}
  ENTRY export-key       # PUBLIC JSON only, pipe to next command
  EXIT  install-identity < export-key JSON
  EXIT  verify-identity  # fresh, effective server-side restrictions proof
  ENTRY start            < verify-identity JSON
  ENTRY verify           # read-only process/listener ownership inspection
  ENTRY recovery-test    # restarts ONLY this route's SSH service
  ENTRY rollback-entry   < fresh live-config readback supplied by coordinator
  ENTRY cleanup-failed-start < same readback; never for a verified start
  EXIT  rollback-exit    < rollback-entry receipt

The coordinator must separately prove authenticated VLESS 204 + expected egress
through the loopback before publishing a frontend. verify/recovery-test do NOT
claim backend authentication, destination reachability, or VPN success.

Rollback readback input is {id,entry,timestamp,source:'installed-entry-xray',
config,sha256}. It is a coordinator attestation of the actual running config,
not independently fetched here. It must show no reference to this local port;
active forwarding connections also prohibit rollback. The exit rollback
requires the fresh entry stop receipt. Root-only keys/backups and a disabled,
locked exit account are retained; no recursive removal or userdel is used.
cleanup-failed-start additionally requires absence of started/recovered markers,
no listener/consumers and exact unit/process ownership. It preserves the CURRENT
unrelated service baseline, not an obsolete snapshot from the failed attempt.

Every mutation has an immutable intent before the write. An interrupted
generate/install/start/recovery/rollback is NOT retried or adopted. Inspect
private state, use the read-only verification commands, then review recovery.
"""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tarfile
import time

import preflight as p

ENTRY = '176.108.245.140'
BACKEND = 15444
ROUTES = {
    'at': dict(ip='147.45.71.38', port=21445, user='ham-c1406-at'),
    'pl': dict(ip='31.77.59.141', port=21446, user='ham-c1406-pl'),
    'cz': dict(ip='45.151.180.85', port=21447, user='ham-c1406-cz'),
    'gbpower': dict(ip='51.194.240.225', port=21448, user='ham-c1406-gbpower'),
}
STATE = Path('/root/hamvpn-cloud140-six-20260918/forward')
KEY_ROOT = Path('/etc/hamvpn-cloud140-six-forward')
SSH_ROOT = Path('/etc/ssh')
UNIT_ROOT = Path('/etc/systemd/system')
ACCOUNT_FILES = ('passwd', 'shadow', 'group', 'gshadow')
require = p.require


def route(identifier):
    require(identifier in ROUTES, 'Only approved AT/PL/CZ/GB-power forwards allowed')
    return dict(id=identifier, **ROUTES[identifier])


def paths(n):
    return dict(key=KEY_ROOT / n['id'], home=Path('/var/lib') / n['user'],
                policy=SSH_ROOT / 'sshd_config.d' / ('73-' + n['user'] + '.conf'),
                unit=UNIT_ROOT / ('ham-c1406-forward-' + n['id'] + '.service'))


def store(n, side):
    require(side in ('entry', 'exit'), 'Invalid state side')
    return p.Store(STATE / n['id'] / side)


def run(args, *, data=None, timeout=30, allowed=(0,)):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout)
    require(result.returncode in allowed, 'Scoped command failed; inspect private state')
    return result


def sha(value):
    return hashlib.sha256(value).hexdigest()


def absent(path):
    return not path.exists() and not path.is_symlink()


def secure(path, mode, uid=0, directory=False):
    info = path.lstat()
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == uid and stat.S_IMODE(info.st_mode) == mode
            and (directory or info.st_nlink == 1), 'Unsafe owned object')


def trusted_parent(path):
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Unsafe object ancestor')


def create(path, data, mode=0o600, uid=0, gid=0):
    require(isinstance(data, bytes), 'Bytes required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode); os.fchown(stream.fileno(), uid, gid)
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    require(path.read_bytes() == data, 'Created object readback differs')


def guard(ip):
    require(os.name == 'posix' and os.geteuid() == 0, 'Linux root required')
    addresses = json.loads(run(['ip', '-j', '-4', 'addr', 'show']).stdout)
    require(ip in {a['local'] for i in addresses for a in i.get('addr_info', [])}, 'Wrong server')


def public_blob(value):
    require(isinstance(value, str) and re.fullmatch(
        r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [A-Za-z0-9_.@-]+)?', value), 'Invalid public key')
    blob = base64.b64decode(value.split()[1], validate=True)
    require(len(blob) == 51 and blob[:19] == b'\0\0\0\x0bssh-ed25519\0\0\0\x20',
            'Invalid Ed25519 public key encoding')
    return blob


def key_id(value):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(public_blob(value)).digest()).decode().rstrip('=')


def known_host(n, text):
    require(isinstance(text, str) and text.startswith(n['ip'] + ' '), 'Wrong pinned exit IP')
    public_blob(text[len(n['ip']) + 1:])
    return text + '\n'


def generate(n, request):
    guard(ENTRY); s = store(n, 'entry'); directory = paths(n)['key']
    require(set(request) == {'known_host'}, 'One verified public host pin required')
    known = known_host(n, request['known_host'])
    require(not s.exists('key-intent') and absent(directory), 'Existing or uncertain key operation')
    if absent(KEY_ROOT):
        trusted_parent(KEY_ROOT); KEY_ROOT.mkdir(mode=0o700)
    secure(KEY_ROOT, 0o700, directory=True); trusted_parent(directory)
    s.put('key-intent', dict(id=n['id'], entry=ENTRY, exit=n['ip'], known_sha256=sha(known.encode()), timestamp=time.time()))
    directory.mkdir(mode=0o700)
    create(directory / 'known_hosts', known.encode())
    run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'HAM-C1406-forward-' + n['id'],
         '-f', str(directory / 'key')])
    (directory / 'key.pub').chmod(0o600)
    public = check_keys(n, ready=False)
    # No operator key is read or copied. Distinct per-route generated identity.
    for other in ROUTES:
        if other != n['id'] and (KEY_ROOT / other / 'key.pub').exists():
            secure(KEY_ROOT / other / 'key.pub', 0o600)
            require(public_blob((KEY_ROOT / other / 'key.pub').read_text().strip()) != public_blob(public), 'Route key collision')
    s.put('key-ready', dict(public_key_id=key_id(public), timestamp=time.time()))
    return dict(id=n['id'], private_key_generated_on_entry=True, public_key_id=key_id(public))


def check_keys(n, ready=True):
    s = store(n, 'entry'); intent = s.get('key-intent'); directory = paths(n)['key']
    require((intent['id'], intent['entry'], intent['exit']) == (n['id'], ENTRY, n['ip']), 'Foreign key state')
    trusted_parent(directory); secure(directory, 0o700, directory=True)
    for name in ('key', 'key.pub', 'known_hosts'): secure(directory / name, 0o600)
    known = (directory / 'known_hosts').read_text()
    require(known == known_host(n, known.rstrip('\n')) and sha(known.encode()) == intent['known_sha256'], 'Host pin drift')
    public = (directory / 'key.pub').read_text().strip()
    actual = run(['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(directory / 'key')]).stdout.strip()
    require(public_blob(actual) == public_blob(public), 'Public/private identity mismatch')
    if ready: require(s.get('key-ready')['public_key_id'] == key_id(public), 'Ready identity drift')
    return public


def export_key(n):
    guard(ENTRY); public = check_keys(n)
    return dict(id=n['id'], entry=ENTRY, exit=n['ip'], public_key=public, public_key_id=key_id(public))


def authorized(n, public):
    public_blob(public)
    return ('from="' + ENTRY + '",restrict,port-forwarding,command="/bin/false",permitopen="' +
            n['ip'] + ':' + str(BACKEND) + '" ' + public + '\n')


def policy(n):
    return {'AuthenticationMethods': 'publickey', 'PubkeyAuthentication': 'yes',
            'PubkeyAcceptedAlgorithms': 'ssh-ed25519',
            'AuthorizedKeysFile': str(paths(n)['home'] / '.ssh/authorized_keys'),
            'AuthorizedKeysCommand': 'none', 'TrustedUserCAKeys': 'none',
            'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
            'HostbasedAuthentication': 'no', 'GSSAPIAuthentication': 'no',
            'AllowTcpForwarding': 'local', 'PermitOpen': n['ip'] + ':' + str(BACKEND),
            'PermitListen': 'none', 'AllowStreamLocalForwarding': 'no', 'GatewayPorts': 'no',
            'PermitTTY': 'no', 'PermitTunnel': 'no', 'PermitUserRC': 'no',
            'AllowAgentForwarding': 'no', 'X11Forwarding': 'no', 'MaxSessions': '0', 'ForceCommand': '/bin/false'}


def policy_text(n):
    return 'Match User ' + n['user'] + '\n' + ''.join('    ' + k + ' ' + v + '\n' for k, v in policy(n).items()) + 'Match all\n'


def check_policy(n, text):
    actual = dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)
    for key, expected in policy(n).items():
        value = actual.get(key.lower())
        if expected in ('yes', 'no'): value = {'true': 'yes', 'false': 'no'}.get(value, value)
        require(value == expected, 'Effective forwarding policy mismatch')
    require(actual.get('disableforwarding') in ('no', 'false'), 'Forwarding disabled by another rule')


def contexts(n):
    sources = [ENTRY, n['ip'], '127.0.0.1', '::1', '192.0.2.1']
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if connection: sources.append(str(ipaddress.ip_address(connection[0])))
    return list(dict.fromkeys(sources))


def effective(n, user, ip):
    return run(['/usr/sbin/sshd', '-T', '-C', 'user=' + user + ',addr=' + ip + ',host=' + ip +
                ',laddr=' + n['ip'] + ',lport=22']).stdout


def account_rows(n):
    # Protect ALL pre-existing accounts, not only the current operator.
    return {name: [line for line in (Path('/etc') / name).read_text().splitlines()
                   if line.split(':', 1)[0] != n['user']] for name in ACCOUNT_FILES}


def ssh_manifest(excluded):
    result = {}
    for path in sorted(SSH_ROOT.rglob('*')):
        if path == excluded: continue
        info = path.lstat(); mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISREG(info.st_mode): value = sha(path.read_bytes())
        elif stat.S_ISLNK(info.st_mode): value = 'link:' + os.readlink(path)
        elif stat.S_ISDIR(info.st_mode): continue
        else: raise RuntimeError('Unexpected SSH configuration object')
        result[str(path)] = [mode, info.st_uid, info.st_gid, value]
    return result


def policies(n, users, addresses):
    return {user: {ip: effective(n, user, ip) for ip in addresses} for user in users}


def backup(n, s):
    import pwd
    archive = s.path / 'ssh-account-before.tar.gz'
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        with tarfile.open(fileobj=stream, mode='w:gz', dereference=False) as bundle:
            bundle.add(SSH_ROOT, arcname='etc/ssh')
            for name in ACCOUNT_FILES: bundle.add('/etc/' + name, arcname='etc/' + name)
            for account in pwd.getpwall():
                directory = Path(account.pw_dir) / '.ssh'
                if directory.is_dir() and not directory.is_symlink():
                    bundle.add(directory, arcname=str(directory).lstrip('/'))
        stream.flush(); os.fsync(stream.fileno())
    secure(archive, 0o600)
    with tarfile.open(archive, 'r:gz') as bundle:
        require({'etc/ssh', 'etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow'} <= set(bundle.getnames()), 'Backup verification failed')
    s.put('backup', dict(sha256=sha(archive.read_bytes()), timestamp=time.time()))


def preservation(n, before):
    require(ssh_manifest(paths(n)['policy']) == before['ssh_manifest'], 'Unrelated SSH configuration changed')
    require(p.digest(account_rows(n)) == before['account_rows_sha256'], 'Unrelated accounts changed')
    require(policies(n, before['users'], before['contexts']) == before['policies'], 'Existing effective SSH policy changed')


def identity_input(n, request):
    require(set(request) == {'id', 'entry', 'exit', 'public_key', 'public_key_id'}, 'Unexpected identity input')
    require((request['id'], request['entry'], request['exit']) == (n['id'], ENTRY, n['ip']), 'Wrong identity route')
    require(key_id(request['public_key']) == request['public_key_id'], 'Public identity mismatch')
    return request['public_key']


def install_identity(n, request):
    import pwd
    import grp
    guard(n['ip']); public = identity_input(n, request); s = store(n, 'exit'); loc = paths(n)
    require(not s.exists('identity-intent') and absent(loc['policy']) and absent(loc['home']), 'Existing/uncertain identity scope')
    require(all(a.pw_name != n['user'] for a in pwd.getpwall()) and all(g.gr_name != n['user'] for g in grp.getgrall()), 'Existing account/group; no adoption')
    trusted_parent(loc['policy']); trusted_parent(loc['home'])
    require(Path('/usr/sbin/nologin').is_file(), 'Non-login shell unavailable')
    run(['/usr/sbin/sshd', '-t'])
    require(run(['systemctl', 'is-active', 'ssh.service']).stdout.strip() == 'active', 'Expected SSH service unavailable')
    users = sorted({a.pw_name for a in pwd.getpwall()} | {'root', 'gasan'})
    addresses = contexts(n)
    before = dict(id=n['id'], users=users, contexts=addresses, policies=policies(n, users, addresses),
                  account_rows_sha256=p.digest(account_rows(n)), ssh_manifest=ssh_manifest(loc['policy']),
                  policy=policy_text(n), authorized=authorized(n, public), public_key_id=key_id(public), timestamp=time.time())
    backup(n, s); s.put('identity-intent', before)
    run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(loc['home']),
         '--shell', '/usr/sbin/nologin', n['user']])
    account = pwd.getpwnam(n['user'])
    require(account.pw_uid != 0 and account.pw_gid != 0 and account.pw_shell == '/usr/sbin/nologin', 'Unexpected new account')
    s.put('account-created', dict(uid=account.pw_uid, gid=account.pw_gid, home=str(loc['home'])))
    loc['home'].mkdir(mode=0o700); os.chown(loc['home'], account.pw_uid, account.pw_gid)
    directory = loc['home'] / '.ssh'; directory.mkdir(mode=0o700); os.chown(directory, account.pw_uid, account.pw_gid)
    pending = directory / 'authorized_keys.pending'
    create(pending, before['authorized'].encode(), uid=account.pw_uid, gid=account.pw_gid)
    create(loc['policy'], before['policy'].encode(), 0o644)
    # Keys remain disabled and account locked until effective policy is checked.
    try:
        run(['/usr/sbin/sshd', '-t']); preservation(n, before)
        for address in addresses: check_policy(n, effective(n, n['user'], address))
        run(['systemctl', 'reload', 'ssh.service'])
        require(run(['systemctl', 'is-active', 'ssh.service']).stdout.strip() == 'active', 'SSH reload failed')
        # Linux sshd can reject locked accounts even for public-key auth.
        # Use a random unrecoverable password HASH, supplied only on stdin;
        # Match forbids all password/interactive methods, never an empty hash.
        random_password = secrets.token_urlsafe(64)
        password_hash = run(['openssl', 'passwd', '-6', '-stdin'], data=random_password + '\n').stdout.strip()
        require(re.fullmatch(r'\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}', password_hash), 'Password hash generator failed')
        run(['chpasswd', '-e'], data=n['user'] + ':' + password_hash + '\n')
        del random_password, password_hash
        require(absent(directory / 'authorized_keys'), 'Unexpected authorized key file')
        pending.rename(directory / 'authorized_keys')
        preservation(n, before)
        s.put('identity-ready', dict(public_key_id=key_id(public), timestamp=time.time()))
    except Exception:
        # Disable ONLY a positively owned key/account; never restore global SSH.
        current = pwd.getpwnam(n['user'])
        require(current.pw_uid == account.pw_uid, 'Account changed; recovery stopped')
        auth = directory / 'authorized_keys'
        if not absent(auth):
            secure(auth, 0o600, account.pw_uid)
            require(auth.read_text() == before['authorized'], 'Key drift; recovery stopped')
            require(absent(directory / 'authorized_keys.revoked'), 'Existing recovery file')
            auth.rename(directory / 'authorized_keys.revoked')
        run(['usermod', '--lock', n['user']])
        # A failed syntax/effective-policy check must not leave a broken new
        # sshd include behind for a future reboot. Quarantine ONLY our exact
        # bytes; retain the account disabled and all immutable intent records.
        secure(loc['policy'], 0o644)
        require(loc['policy'].read_text() == before['policy'], 'Policy drift; recovery stopped')
        require(ssh_manifest(loc['policy']) == before['ssh_manifest'], 'Foreign SSH change; recovery stopped')
        require(absent(s.path / 'failed-policy.conf'), 'Existing failed-policy archive')
        loc['policy'].rename(s.path / 'failed-policy.conf'); (s.path / 'failed-policy.conf').chmod(0o600)
        run(['/usr/sbin/sshd', '-t']); preservation(n, before)
        run(['systemctl', 'reload', 'ssh.service'])
        raise
    return verify_identity(n)


def verify_identity(n):
    import pwd
    guard(n['ip']); s = store(n, 'exit'); before = s.get('identity-intent'); ready = s.get('identity-ready')
    require(not s.exists('rollback-intent'), 'Identity is being revoked')
    loc = paths(n); owner = s.get('account-created'); account = pwd.getpwnam(n['user'])
    require((account.pw_uid, account.pw_gid, account.pw_dir, account.pw_shell) ==
            (owner['uid'], owner['gid'], str(loc['home']), '/usr/sbin/nologin'), 'Owned account drift')
    secure(loc['home'], 0o700, owner['uid'], directory=True)
    secure(loc['home'] / '.ssh', 0o700, owner['uid'], directory=True)
    auth = loc['home'] / '.ssh/authorized_keys'; secure(auth, 0o600, owner['uid'])
    secure(loc['policy'], 0o644)
    require(auth.read_text() == before['authorized'] and loc['policy'].read_text() == before['policy'], 'Identity files drift')
    shadow = next(line.split(':') for line in Path('/etc/shadow').read_text().splitlines() if line.split(':', 1)[0] == n['user'])
    require(shadow[1].startswith('$6$') and (not shadow[7] or int(shadow[7]) > int(time.time() / 86400)), 'Account locked/expired')
    run(['/usr/sbin/sshd', '-t']); preservation(n, before)
    for address in before['contexts']: check_policy(n, effective(n, n['user'], address))
    require(run(['systemctl', 'is-active', 'ssh.service']).stdout.strip() == 'active', 'SSH is inactive')
    return dict(id=n['id'], entry=ENTRY, exit=n['ip'], timestamp=time.time(), public_key_id=ready['public_key_id'],
                policy_sha256=sha(before['policy'].encode()), fixed_target=n['ip'] + ':' + str(BACKEND),
                local_forward_only=True, no_sessions=True, source_restricted=True, operator_policies_preserved=True)


def ssh_args(n):
    directory = paths(n)['key']
    return ['/usr/bin/ssh', '-F', '/dev/null', '-4', '-N', '-T', '-n', '-L',
            '127.0.0.1:' + str(n['port']) + ':' + n['ip'] + ':' + str(BACKEND),
            '-i', str(directory / 'key'), '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'PreferredAuthentications=publickey', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
            '-o', 'UserKnownHostsFile=' + str(directory / 'known_hosts'), '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', '-o', 'ConnectTimeout=10',
            '-o', 'ConnectionAttempts=1', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'LogLevel=ERROR', n['user'] + '@' + n['ip']]


def unit_text(n):
    return ('[Unit]\nDescription=HAMVPN fixed-target CLOUDru SSH forward ' + n['id'] + '\n'
            'After=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n'
            '[Service]\nType=simple\nUser=root\nWorkingDirectory=/\nExecStart=' + ' '.join(ssh_args(n)) + '\n'
            'Restart=always\nRestartSec=5\nTimeoutStopSec=15\nKillMode=control-group\n'
            'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
            'UMask=0077\nCapabilityBoundingSet=\nRestrictSUIDSGID=true\n'
            'RestrictAddressFamilies=AF_INET AF_UNIX\nLimitNOFILE=8192\nTasksMax=32\n'
            '[Install]\nWantedBy=multi-user.target\n')


def unit_info(name):
    fields = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainStartTimestampMonotonic', 'FragmentPath', 'DropInPaths')
    args = ['systemctl', 'show', name]
    for field in fields: args += ['-p', field]
    result = run(args, allowed=(0, 1, 4))
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(set(fields) <= set(values), 'Incomplete systemd readback')
    require(result.returncode == 0 or values['LoadState'] == 'not-found', 'Cannot inspect systemd service')
    return values


def service_baseline():
    result = {name: {k: v for k, v in unit_info(name).items() if k in
              ('LoadState', 'MainPID', 'ExecMainStartTimestampMonotonic')}
              for name in ('ssh.service', 'nginx.service', 'docker.service', 'remnanode.service')}
    if Path('/usr/bin/docker').exists():
        ids = run(['docker', 'ps', '-q']).stdout.split()
        result['containers'] = [run(['docker', 'inspect', '--format',
            '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}', cid]).stdout.strip() for cid in sorted(ids)]
    return result


def listener_lines(n):
    return run(['ss', '-H', '-ltnp', 'sport = :' + str(n['port'])]).stdout.splitlines()


def check_listener(n, lines, pid):
    require(len(lines) == 1, 'Expected exactly one TCP listener across IPv4/IPv6')
    fields = lines[0].split()
    require(len(fields) >= 6 and fields[3] == '127.0.0.1:' + str(n['port']), 'Forward listener is not IPv4 loopback-only')
    owners = re.findall(r'\("([^"]+)",pid=(\d+),fd=\d+\)', lines[0])
    require(owners == [('ssh', str(pid))], 'Listener not exclusively owned by service SSH PID')


def no_connections(n):
    # Entry Xray connects TO local listener; SSH accepted socket has source port.
    lines = run(['ss', '-H', '-tn', 'state', 'established', 'sport = :' + str(n['port'])]).stdout
    require(not lines.strip(), 'Active forward consumers exist; do not interrupt')


def fresh(value, max_age=1800):
    require(type(value) in (int, float) and 0 <= time.time() - value <= max_age, 'Stale/future evidence')


def identity_proof(n, request, public):
    require((request.get('id'), request.get('entry'), request.get('exit')) == (n['id'], ENTRY, n['ip']), 'Foreign identity proof')
    fresh(request.get('timestamp'))
    require(request.get('public_key_id') == key_id(public) and request.get('policy_sha256') == sha(policy_text(n).encode())
            and request.get('fixed_target') == n['ip'] + ':' + str(BACKEND), 'Wrong identity/policy proof')
    require(all(request.get(k) is True for k in ('local_forward_only', 'no_sessions', 'source_restricted', 'operator_policies_preserved')),
            'Restrictions were not verified')


def start(n, request):
    guard(ENTRY); public = check_keys(n); identity_proof(n, request, public)
    s = store(n, 'entry'); unit = paths(n)['unit']
    require(not s.exists('start-intent') and absent(unit), 'Existing/uncertain forward unit')
    require(unit_info(unit.name)['LoadState'] == 'not-found', 'Existing systemd definition elsewhere')
    require(not listener_lines(n), 'Local TCP port already occupied')
    with socket.socket() as sock: sock.bind(('127.0.0.1', n['port']))
    trusted_parent(unit); baseline = service_baseline(); text = unit_text(n)
    s.put('start-intent', dict(id=n['id'], unit=text, identity_proof=request, baseline=baseline, timestamp=time.time()))
    create(unit, text.encode(), 0o644)
    run(['systemd-analyze', 'verify', str(unit)]); run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', unit.name])
    proof = wait_verified(n)
    require(service_baseline() == baseline, 'Unrelated service/container restarted')
    s.put('started', proof)
    return proof


def verify(n):
    guard(ENTRY); public = check_keys(n); s = store(n, 'entry'); before = s.get('start-intent'); unit = paths(n)['unit']
    require(not s.exists('rollback-intent'), 'Forward rollback in progress')
    secure(unit, 0o644); require(unit.read_text() == before['unit'] == unit_text(n), 'Owned unit changed')
    state = unit_info(unit.name)
    require(state['LoadState'] == 'loaded' and state['ActiveState'] == 'active' and state['SubState'] == 'running', 'Forward service is not running')
    require(state['FragmentPath'] == str(unit) and not state['DropInPaths'], 'Unexpected systemd overrides')
    require(run(['systemctl', 'is-enabled', unit.name]).stdout.strip() == 'enabled', 'Forward is not persistent')
    pid = int(state['MainPID']); require(pid > 1, 'No SSH process')
    command = Path('/proc') / str(pid) / 'cmdline'
    require(command.read_bytes().rstrip(b'\0').decode().split('\0') == ssh_args(n), 'Running SSH command differs')
    check_listener(n, listener_lines(n), pid)
    require(service_baseline() == before['baseline'], 'Unrelated service baseline drift')
    return dict(id=n['id'], entry=ENTRY, exit=n['ip'], timestamp=time.time(), pid=pid,
                started_monotonic=state['ExecMainStartTimestampMonotonic'], public_key_id=key_id(public),
                loopback='127.0.0.1', port=n['port'], target=n['ip'] + ':' + str(BACKEND),
                listener_address='127.0.0.1', listener_port=n['port'],
                transport='ssh-local-forward', persistent=True, exact_process_and_listener=True,
                host_key_pinned=True, restricted_identity=True, fixed_target_verified=True,
                persistent_service_verified=True, restart_recovery_verified=s.exists('recovered'),
                loopback_only=True, ssh_server=n['ip'], target_address=n['ip'], target_port=BACKEND,
                backend_authentication_not_tested=True)


def wait_verified(n):
    # SSH authenticates before creating a -L listener; this is still NOT a
    # destination-channel/REALITY/VPN test. Total polling bounded to 25 seconds.
    deadline = time.monotonic() + 25
    while True:
        try: return verify(n)
        except (RuntimeError, OSError, ValueError):
            if time.monotonic() >= deadline: raise
            time.sleep(.5)


def recovery_test(n):
    before = verify(n); no_connections(n); s = store(n, 'entry')
    require(not s.exists('recovery-intent'), 'Existing/uncertain recovery test')
    s.put('recovery-intent', dict(before=before, timestamp=time.time()))
    run(['systemctl', 'restart', paths(n)['unit'].name])
    after = wait_verified(n)
    require((after['pid'], after['started_monotonic']) != (before['pid'], before['started_monotonic']), 'Service restart not observed')
    proof = dict(after, service_restart_recovered=True, restart_recovery_verified=True, previous_pid=before['pid'])
    s.put('recovered', proof)
    return proof


def detached(n, proof):
    require((proof.get('id'), proof.get('entry'), proof.get('source')) ==
            (n['id'], ENTRY, 'installed-entry-xray'), 'Actual entry-config attestation required')
    fresh(proof.get('timestamp'), 120)
    config = proof.get('config')
    require(isinstance(config, dict) and isinstance(config.get('outbounds'), list) and config['outbounds'], 'Complete live configuration required')
    require(proof.get('sha256') == p.digest(config), 'Live configuration checksum mismatch')
    # Conservative: any occurrence of this reserved port blocks removal,
    # including unsupported outbound forms. Do not assume VLESS-only shapes.
    def contains(value):
        if isinstance(value, dict): return any(contains(v) for v in value.values())
        if isinstance(value, list): return any(contains(v) for v in value)
        if type(value) is int: return value == n['port']
        if isinstance(value, str): return re.search(r'(?<!\d)' + str(n['port']) + r'(?!\d)', value) is not None
        return False
    require(not contains(config), 'Entry configuration still references forward')


def rollback_entry(n, request):
    proof = verify(n); detached(n, request); no_connections(n)
    s = store(n, 'entry'); unit = paths(n)['unit']
    require(not s.exists('rollback-intent'), 'Existing/uncertain rollback')
    s.put('rollback-intent', dict(before=proof, config_sha256=request['sha256'], timestamp=time.time()))
    run(['systemctl', 'disable', '--now', unit.name])
    state = unit_info(unit.name)
    require(state['ActiveState'] == 'inactive' and state['SubState'] == 'dead' and state['MainPID'] == '0', 'Forward stop not confirmed')
    require(not listener_lines(n), 'Owned listener remains')
    secure(unit, 0o644); require(unit.read_text() == s.get('start-intent')['unit'], 'Unit drift during rollback')
    require(absent(s.path / 'disabled-unit.conf'), 'Rollback archive already exists')
    unit.rename(s.path / 'disabled-unit.conf'); (s.path / 'disabled-unit.conf').chmod(0o600)
    run(['systemctl', 'daemon-reload'])
    require(unit_info(unit.name)['LoadState'] == 'not-found', 'Unexpected remaining unit definition')
    require(service_baseline() == s.get('start-intent')['baseline'], 'Unrelated service changed')
    result = dict(id=n['id'], entry=ENTRY, exit=n['ip'], public_key_id=proof['public_key_id'], timestamp=time.time(),
                  entry_service_stopped=True, entry_listener_absent=True, detached_config_sha256=request['sha256'])
    s.put('rolled-back', result)
    return result


def check_owned_process(n, pid):
    require(type(pid) is int and pid > 1, 'Invalid live process identity')
    root = Path('/proc') / str(pid)
    require(root.joinpath('cmdline').read_bytes().rstrip(b'\0').decode().split('\0') == ssh_args(n),
            'Failed-start process is not the exact owned SSH command')
    require(os.readlink(root / 'exe') == '/usr/bin/ssh', 'Unexpected failed-start executable')
    status = dict(line.split(':', 1) for line in root.joinpath('status').read_text().splitlines() if ':' in line)
    require(status.get('Uid', '').split() == ['0', '0', '0', '0'], 'Unexpected failed-start process owner')


def failed_start_state(n, s):
    require(not any(s.exists(name) for name in ('started', 'recovered', 'recovery-intent', 'rollback-intent', 'rolled-back')),
            'Only a never-verified failed start can be cleaned')
    before = s.get('start-intent'); unit = paths(n)['unit']
    require(before.get('id') == n['id'], 'Foreign failed-start intent')
    secure(unit, 0o644)
    require(unit.read_text() == before['unit'] == unit_text(n), 'Failed-start unit drift')
    state = unit_info(unit.name)
    require(state['LoadState'] == 'loaded' and state['FragmentPath'] == str(unit) and not state['DropInPaths'],
            'Failed-start unit definition/overrides changed')
    pid = int(state['MainPID'])
    pair = state['ActiveState'], state['SubState']
    if pair == ('active', 'running'):
        check_owned_process(n, pid)
    else:
        require(pid == 0 and pair in (('activating', 'auto-restart'), ('failed', 'failed'), ('inactive', 'dead')),
                'Unexpected failed-start systemd/process state')
    require(not listener_lines(n), 'Listener exists; use verified rollback workflow')
    no_connections(n)
    return state


def cleanup_failed_start(n, request):
    """Stop a positively owned, unpublished failed attempt without verify()."""
    guard(ENTRY); public = check_keys(n); detached(n, request)
    s = store(n, 'entry'); unit = paths(n)['unit']; state = failed_start_state(n, s)
    baseline = service_baseline()
    require(absent(s.path / 'disabled-unit.conf'), 'Existing cleanup archive; inspect first')
    s.put('rollback-intent', dict(mode='failed-start', before=state,
        config_sha256=request['sha256'], current_services=baseline, timestamp=time.time()))
    # Refuse a listener appearing between the read-only gate and stop. The
    # immutable intent then requires explicit inspection, never a blind retry.
    require(not listener_lines(n), 'Listener appeared during cleanup; inspect')
    no_connections(n)
    run(['systemctl', 'disable', '--now', unit.name])
    stopped = unit_info(unit.name)
    if stopped['ActiveState'] == 'failed' and stopped['MainPID'] == '0':
        run(['systemctl', 'reset-failed', unit.name])
        stopped = unit_info(unit.name)
    require(stopped['ActiveState'] == 'inactive' and stopped['SubState'] == 'dead' and stopped['MainPID'] == '0',
            'Failed-start process stop not confirmed')
    require(not listener_lines(n), 'Listener remains after stopping owned unit')
    no_connections(n)
    secure(unit, 0o644)
    require(unit.read_text() == s.get('start-intent')['unit'] == unit_text(n), 'Unit changed during cleanup')
    # Copy-and-remove rather than cross-filesystem rename. Recovery bytes are
    # fsynced/read back before unlinking only this exact root-owned unit file.
    create(s.path / 'disabled-unit.conf', unit.read_bytes())
    secure(unit, 0o644)
    require(unit.read_text() == s.get('start-intent')['unit'], 'Unit changed before removal')
    unit.unlink(); run(['systemctl', 'daemon-reload'])
    final = unit_info(unit.name)
    require(final['LoadState'] == 'not-found' and final['MainPID'] == '0', 'Unexpected remaining service definition/process')
    require(not listener_lines(n), 'Listener reappeared after cleanup')
    require(service_baseline() == baseline, 'Unrelated service/container changed during cleanup')
    receipt = dict(id=n['id'], entry=ENTRY, exit=n['ip'], public_key_id=key_id(public), timestamp=time.time(),
                   entry_service_stopped=True, entry_listener_absent=True,
                   detached_config_sha256=request['sha256'], failed_start_cleaned=True,
                   keys_and_identity_retained=True)
    s.put('rolled-back', receipt)
    return receipt


def rollback_exit(n, receipt):
    verify_identity(n); s = store(n, 'exit'); before = s.get('identity-intent'); owner = s.get('account-created'); loc = paths(n)
    require(not s.exists('rollback-intent'), 'Existing/uncertain identity rollback')
    require((receipt.get('id'), receipt.get('entry'), receipt.get('exit'), receipt.get('public_key_id')) ==
            (n['id'], ENTRY, n['ip'], before['public_key_id']), 'Wrong entry stop receipt')
    fresh(receipt.get('timestamp'), 300)
    require(receipt.get('entry_service_stopped') is True and receipt.get('entry_listener_absent') is True and
            re.fullmatch('[0-9a-f]{64}', receipt.get('detached_config_sha256', '')), 'Verified detach/stop required')
    processes = run(['ps', '-u', str(owner['uid']), '-o', 'pid='], allowed=(0, 1)).stdout
    require(not processes.strip(), 'Forward identity still has processes')
    s.put('rollback-intent', dict(receipt=receipt, timestamp=time.time()))
    directory = loc['home'] / '.ssh'; auth = directory / 'authorized_keys'
    require(absent(directory / 'authorized_keys.revoked'), 'Existing revocation file')
    auth.rename(directory / 'authorized_keys.revoked'); run(['usermod', '--lock', n['user']])
    secure(loc['policy'], 0o644); require(loc['policy'].read_text() == before['policy'], 'Policy changed during rollback')
    require(absent(s.path / 'disabled-policy.conf'), 'Existing policy archive')
    loc['policy'].rename(s.path / 'disabled-policy.conf'); (s.path / 'disabled-policy.conf').chmod(0o600)
    run(['/usr/sbin/sshd', '-t']); preservation(n, before); run(['systemctl', 'reload', 'ssh.service'])
    require(run(['systemctl', 'is-active', 'ssh.service']).stdout.strip() == 'active', 'SSH reload not healthy')
    require(absent(auth) and absent(loc['policy']), 'Identity revocation not confirmed')
    result = dict(id=n['id'], identity_disabled=True, locked_account_and_backups_retained=True, timestamp=time.time())
    s.put('rolled-back', result)
    return result


def main():
    os.umask(0o077)
    actions = ('generate', 'export-key', 'install-identity', 'verify-identity', 'start', 'verify', 'recovery-test', 'rollback-entry', 'cleanup-failed-start', 'rollback-exit')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=actions); parser.add_argument('--id', required=True, choices=sorted(ROUTES))
    args = parser.parse_args(); n = route(args.id)
    import fcntl
    side = 'exit' if args.action in ('install-identity', 'verify-identity', 'rollback-exit') else 'entry'
    guard(n['ip'] if side == 'exit' else ENTRY)
    s = store(n, side); s.secure()
    # A shared lock serializes selected entry changes and accidental overlap.
    lock_store = p.Store(STATE); lock_store.secure()
    fd = os.open(STATE / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        info = os.fstat(lock.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1, 'Unsafe operation lock')
        fcntl.flock(lock, fcntl.LOCK_EX)
        handler = globals()[args.action.replace('-', '_')]
        result = handler(n, json.load(sys.stdin)) if args.action in ('generate', 'install-identity', 'start', 'rollback-entry', 'cleanup-failed-start', 'rollback-exit') else handler(n)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__, message='Forward operation stopped; inspect protected state, do not blindly retry')), file=sys.stderr)
        raise SystemExit(1)
