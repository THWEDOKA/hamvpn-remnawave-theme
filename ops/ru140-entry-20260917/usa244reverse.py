"""Dedicated USA2 reverse link; never changes the four existing exit channels.

USA (.208 management, .216 source): generate < operator-verified entry known_host;
export-key emits {"usa2": public_key} for entry244 identity's JSON stdin. Then
start on USA. Only worker imports Paramiko. All private material stays on USA.
Entry loopback25443 forwards exclusively to USA loopback15443, never public443.
"""
import argparse
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
ENTRY = '193.233.222.244'
SSH_PORT = 25444
MANAGEMENT = '162.141.185.208'
SOURCE = '162.141.185.216'
NODE = {'id': 'usa2', 'ip': SOURCE, 'link': 25443}
TARGET = ('127.0.0.1', 15443)
USER = 'ham-usa244'
HOME_DIR = Path('/var/lib/ham-usa244')
SSH_CONF = Path('/etc/ssh/sshd_config.d/71-ham-usa244.conf')
KEY_DIR = Path('/etc/hamvpn-usa244')
STATE = Path('/root/hamvpn-usa244-20260917')
UNIT = Path('/etc/systemd/system/ham-usa244-reverse.service')
LISTENER_UNIT = Path('/etc/systemd/system/ham-usa244-listener.service')
PROTECTED = (Path('/etc/ssh/sshd_config.d/70-ham-exits244.conf'),
             Path('/var/lib/ham-exits244/.ssh/authorized_keys'))
NEW_PACKAGES = frozenset({'python3-paramiko', 'python3-nacl', 'python3-bcrypt',
                          'python3-cryptography', 'python3-cffi-backend',
                          'python3-six', 'python3-pyasn1'})


def isolated_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A separate namespace: assigning globals below cannot mutate reverse244 itself.
_base = isolated_module('_usa244_provision', ROOT / 'reverse244.py')
FOUR_EXITS = tuple(dict(n) for n in _base.NODES)
require = _base.require
_public_blob = _base.public_blob


def public_blob(value):
    try:
        return _public_blob(value)
    except ValueError:
        raise RuntimeError('Invalid Ed25519 public key encoding') from None


def private_state():
    require(not STATE.is_symlink(), 'Unsafe USA reverse state')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0,
            'USA reverse state must be root-only')


def save(name, value):
    private_state()
    target = STATE / ('reverse-' + name + '.json')
    require(not target.is_symlink(), 'Unsafe state destination')
    pending = target.with_suffix('.pending')
    with pending.open('x', encoding='utf-8') as stream:
        os.chmod(pending, 0o600)
        json.dump(value, stream)
        stream.flush(); os.fsync(stream.fileno())
    pending.replace(target)


def read(name):
    private_state()
    target = STATE / ('reverse-' + name + '.json')
    private_file(target)
    return json.loads(target.read_text())


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=600)
    if result.returncode:
        save('command-error', {'program': args[0], 'status': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Command failed; inspect private reverse-command-error.json')
    return result.stdout


def private_file(path, mode=0o600):
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0
            and path.stat().st_mode & 0o777 == mode, 'Unsafe USA reverse private file')


def guard(address):
    require(os.geteuid() == 0, 'Root required')
    local = json.loads(run('ip', '-j', '-4', 'addr', 'show'))
    require(address in {a.get('local') for interface in local
                        for a in interface.get('addr_info', [])}, 'Wrong server')
    private_state()


def provision():
    # Reuse validation, policy rendering and private SSH backup, not global state.
    for key, value in {'ROOT': ROOT, 'ENTRY': ENTRY, 'NODES': [dict(NODE)],
        'STATE': STATE, 'USER': USER, 'HOME_DIR': HOME_DIR, 'SSH_CONF': SSH_CONF,
        'KEY_DIR': KEY_DIR, 'UNIT': UNIT, 'save': save, 'read': read, 'run': run,
        'authorized_keys': authorized_keys, 'public_blob': public_blob}.items():
        setattr(_base, key, value)
    return _base


def authorized_keys(keys):
    require(isinstance(keys, dict) and set(keys) == {'usa2'}, 'Exactly one USA2 public key required')
    public_blob(keys['usa2'])
    return ('from="' + SOURCE + '",restrict,port-forwarding,permitlisten="127.0.0.1:25443" '
            + keys['usa2'] + '\n')


def ssh_policy():
    return provision().ssh_policy()


def generate():
    guard(SOURCE)
    require(not KEY_DIR.exists() and not KEY_DIR.is_symlink(), 'Existing USA key directory; inspect')
    # Reused generator validates the pinned entry Ed25519 wire format before
    # creating any key files, and generates the private key on this USA host.
    return provision().generate(NODE)


def export_key():
    guard(SOURCE)
    require(read('key-intent') == {'id': 'usa2', 'entry': ENTRY}, 'Wrong USA key intent')
    path = KEY_DIR / 'reverse_key.pub'
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0, 'Unsafe public key file')
    value = path.read_text().strip()
    public_blob(value)
    return {'usa2': value}


def effective(user, address):
    return run('/usr/sbin/sshd', '-T', '-C', 'user=' + user + ',addr=' + address + ',host=entry244')


def protected_snapshot(addresses):
    """Private before-image of root and the existing four-channel identity."""
    import pwd
    files = {}
    for path in PROTECTED:
        require(path.is_file() and not path.is_symlink(), 'Existing four-channel SSH files missing/unsafe')
        stat = path.stat()
        files[str(path)] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                           'uid': stat.st_uid, 'gid': stat.st_gid, 'mode': stat.st_mode}
    account = pwd.getpwnam('ham-exits244')
    return {'files': files, 'account': [account.pw_uid, account.pw_gid, account.pw_dir, account.pw_shell],
            'policies': {user: {address: effective(user, address) for address in addresses}
                         for user in ('root', 'ham-exits244')}}


def write_new(path, text, mode):
    require(not path.exists() and not path.is_symlink(), 'Existing USA destination; inspect')
    pending = path.with_name(path.name + '.usa244-pending')
    with pending.open('x', encoding='utf-8', newline='\n') as stream:
        os.chmod(pending, mode)
        stream.write(text); stream.flush(); os.fsync(stream.fileno())
    # Atomic exclusive publication: do not expose a partially written sshd
    # include, and never replace a destination created by another operator.
    os.link(pending, path)
    pending.unlink()


def identity():
    import pwd
    guard(ENTRY)
    require(not SSH_CONF.exists() and not SSH_CONF.is_symlink()
            and not HOME_DIR.exists() and not HOME_DIR.is_symlink(), 'Existing USA SSH identity files')
    try: pwd.getpwnam(USER)
    except KeyError: pass
    else: raise RuntimeError('USA SSH identity exists; inspect')
    key_text = authorized_keys(json.load(sys.stdin))
    # Never replace any of the four existing forward listeners.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', NODE['link']))
    helper = provision()
    policy = helper.policy_text()
    run('/usr/sbin/sshd', '-t')
    addresses = list(dict.fromkeys([SOURCE, *[n['ip'] for n in FOUR_EXITS], '127.0.0.1', '::1',
                                   os.environ.get('SSH_CONNECTION', '127.0.0.1').split()[0]]))
    before = protected_snapshot(addresses)
    helper.backup_ssh()
    save('protected-before', before)
    directory = HOME_DIR / '.ssh'
    pending, authorized = directory / 'authorized_keys.pending', directory / 'authorized_keys'
    owned_config = False
    try:
        run('useradd', '--system', '--create-home', '--home-dir', str(HOME_DIR), '--shell', '/usr/sbin/nologin', USER)
        account = pwd.getpwnam(USER)
        HOME_DIR.chmod(0o700); os.chown(HOME_DIR, account.pw_uid, account.pw_gid)
        directory.mkdir(mode=0o700); os.chown(directory, account.pw_uid, account.pw_gid)
        write_new(pending, key_text, 0o600); os.chown(pending, account.pw_uid, account.pw_gid)
        write_new(SSH_CONF, policy, 0o644); owned_config = True
        run('/usr/sbin/sshd', '-t')
        require(protected_snapshot(addresses) == before, 'Root or existing four-channel SSH identity changed')
        for address in addresses: helper.check_policy(effective(USER, address))
        for path, mode in ((HOME_DIR, 0o700), (directory, 0o700), (pending, 0o600)):
            require(path.stat().st_uid == account.pw_uid and path.stat().st_mode & 0o777 == mode,
                    'Unsafe USA identity permissions')
        run('systemctl', 'reload', 'ssh')
        pending.rename(authorized)
        require(protected_snapshot(addresses) == before, 'Existing SSH identity changed during reload')
        save('restricted-identity', {'root_policy_preserved': True, 'four_channels_preserved': True,
                                     'source': SOURCE, 'listen': '127.0.0.1:25443'})
    except Exception:
        # Revoke the only new credential before removing its restrictions.
        if authorized.exists():
            require(not authorized.is_symlink() and authorized.read_text() == key_text, 'USA authorized key changed; inspect')
            authorized.rename(directory / 'authorized_keys.revoked')
        if owned_config:
            require(not SSH_CONF.is_symlink() and SSH_CONF.read_text() == policy, 'USA SSH policy changed; inspect')
            SSH_CONF.rename(STATE / 'reverse-failed-ssh-policy.conf')
            run('/usr/sbin/sshd', '-t'); run('systemctl', 'reload', 'ssh')
        raise
    return {'usa_identity_ready': True, 'root_policy_preserved': True, 'four_channels_preserved': True,
            'source': SOURCE, 'listen': '127.0.0.1:25443'}


def service_text():
    return ('[Unit]\nDescription=HAMVPN USA2-only reverse channel to entry244\n'
        'After=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n'
        '[Service]\nType=simple\nExecStart=/usr/bin/python3 ' + str(ROOT / 'usa244reverse.py') + ' worker\n'
        'Restart=always\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n'
        'UMask=0077\nCapabilityBoundingSet=\nRestrictSUIDSGID=true\n'
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\nLimitNOFILE=16384\nTasksMax=1152\n'
        '[Install]\nWantedBy=multi-user.target\n')


def check_install_plan(plan):
    for line in plan.splitlines():
        require(not line.startswith('Remv '), 'Package removal refused')
        if line.startswith('Inst '):
            match = re.fullmatch(r'Inst ([\w.+:-]+) (\([^\n]+\))', line)
            require(match and match.group(1).split(':')[0] in NEW_PACKAGES,
                    'Only new allowlisted Paramiko dependencies permitted; upgrades refused')


def key_files():
    require(KEY_DIR.is_dir() and not KEY_DIR.is_symlink() and KEY_DIR.stat().st_uid == 0
            and KEY_DIR.stat().st_mode & 0o777 == 0o700, 'Unsafe USA key directory')
    for name in ('reverse_key', 'known_hosts'): private_file(KEY_DIR / name)
    known = (KEY_DIR / 'known_hosts').read_text().strip()
    require(known.startswith(ENTRY + ' '), 'Wrong pinned entry host key')
    public_blob(known[len(ENTRY) + 1:])


def start():
    guard(SOURCE)
    require(read('key-intent') == {'id': 'usa2', 'entry': ENTRY}, 'Wrong USA key intent')
    require(not UNIT.exists() and not UNIT.is_symlink(), 'Existing USA reverse service; inspect')
    key_files()
    with socket.create_connection(TARGET, timeout=3): pass
    require(not run('dpkg', '--audit').strip(), 'Unfinished package transaction; installation refused')
    check_install_plan(run('apt-get', '-s', '--no-remove', '--no-upgrade', '--no-install-recommends',
                           'install', 'python3-paramiko'))
    run('env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'NEEDRESTART_SUSPEND=1',
        'apt-get', 'install', '-y', '--no-remove', '--no-upgrade', '--no-install-recommends', 'python3-paramiko')
    runtime = json.loads(run('/usr/bin/python3', '-c',
        'import json,paramiko;print(json.dumps({"version":paramiko.__version__,"source":paramiko.__file__}))'))
    require(runtime['source'].startswith('/usr/lib/python3/dist-packages/paramiko/'), 'Unexpected Paramiko source')
    text = service_text()
    save('service-intent', {'sha256': hashlib.sha256(text.encode()).hexdigest(), 'runtime': runtime})
    write_new(UNIT, text, 0o644)
    run('systemd-analyze', 'verify', str(UNIT))
    run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', UNIT.name)
    require(run('systemctl', 'is-active', UNIT.name).strip() == 'active', 'USA reverse service not active')
    return {'usa_reverse_service_started': True, 'source': SOURCE, 'entry': ENTRY,
            'listen_port': 25443, 'target_port': 15443, 'paramiko_version': runtime['version']}


def stop():
    guard(SOURCE)
    require(UNIT.is_file() and not UNIT.is_symlink(), 'Owned USA reverse service missing')
    require(hashlib.sha256(UNIT.read_bytes()).hexdigest() == read('service-intent')['sha256'],
            'USA service changed; stop refused')
    run('systemctl', 'disable', '--now', UNIT.name)
    status = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT.name], capture_output=True)
    require(status.returncode == 3, 'USA reverse service not confirmed inactive')
    return {'usa_reverse_service_stopped': True, 'four_channels_untouched': True}


def listener():
    guard(ENTRY)
    require(read('restricted-identity')['four_channels_preserved'], 'Restricted USA identity required')
    require(not LISTENER_UNIT.exists(), 'USA SSH listener exists; inspect')
    with socket.socket() as sock: sock.bind((ENTRY,SSH_PORT))
    options=['-f','/etc/ssh/sshd_config','-p',str(SSH_PORT),'-o','ListenAddress='+ENTRY,'-o','AllowUsers='+USER,
             '-o','PidFile=/run/ham-usa244-listener.pid']
    run('/usr/sbin/sshd','-t',*options)
    actual=run('/usr/sbin/sshd','-T',*options,'-C','user='+USER+',addr='+SOURCE+',host=entry244')
    provision().check_policy(actual)
    fields=dict(line.split(' ',1) for line in actual.splitlines() if ' ' in line)
    require(fields['allowusers']==USER and fields['port']==str(SSH_PORT), 'Unexpected dedicated listener policy')
    text=('[Unit]\nDescription=USA-only restricted SSH transport listener\nAfter=network.target\n'
          '[Service]\nType=simple\nExecStart=/usr/sbin/sshd -D '+ ' '.join(options)+'\n'
          'Restart=always\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n')
    save('listener-intent',{'sha256':hashlib.sha256(text.encode()).hexdigest(),'port':SSH_PORT})
    write_new(LISTENER_UNIT,text,0o644)
    run('systemd-analyze','verify',str(LISTENER_UNIT));run('systemctl','daemon-reload')
    run('systemctl','enable','--now',LISTENER_UNIT.name)
    require(run('systemctl','is-active',LISTENER_UNIT.name).strip()=='active','Listener inactive')
    return {'usa_only_ssh_port':SSH_PORT,'root_and_other_users_disallowed':True}


def refresh_worker():
    guard(SOURCE);key_files()
    previous=UNIT.read_text();intent=read('service-intent')
    require(hashlib.sha256(previous.encode()).hexdigest()==intent['sha256'],'Owned worker changed')
    save('worker-before-refresh',{'unit':previous,'intent':intent})
    text=service_text();pending=UNIT.with_suffix('.pending')
    write_new(pending,text,0o644);pending.replace(UNIT)
    run('systemd-analyze','verify',str(UNIT));run('systemctl','daemon-reload')
    save('service-intent',{'sha256':hashlib.sha256(text.encode()).hexdigest(),'runtime':intent['runtime']})
    run('systemctl','restart',UNIT.name)
    return {'usa_worker_updated':True,'ssh_port':SSH_PORT}


def worker_module():
    # Import lazily: the entry server needs no Paramiko package for identity().
    worker = isolated_module('_usa244_relay', ROOT / 'reverse244_client.py')
    worker.ENTRY = ENTRY
    worker.TARGET = TARGET
    return worker


def connect_and_forward(worker):
    client = worker.paramiko.SSHClient()
    raw = None
    try:
        client.load_host_keys(str(KEY_DIR / 'known_hosts'))
        client.set_missing_host_key_policy(worker.paramiko.RejectPolicy())
        raw = worker.socket.create_connection((ENTRY, SSH_PORT), timeout=10, source_address=(SOURCE, 0))
        raw.setsockopt(worker.socket.SOL_SOCKET, worker.socket.SO_KEEPALIVE, 1)
        for name, value in [('TCP_KEEPIDLE', 15), ('TCP_KEEPINTVL', 5), ('TCP_KEEPCNT', 3), ('TCP_USER_TIMEOUT', 45000)]:
            if hasattr(worker.socket, name): raw.setsockopt(worker.socket.IPPROTO_TCP, getattr(worker.socket, name), value)
        client.connect(ENTRY, username=USER, sock=raw, key_filename=str(KEY_DIR / 'reverse_key'),
                       allow_agent=False, look_for_keys=False, timeout=10, banner_timeout=12, auth_timeout=15)
        transport = client.get_transport()
        require(transport is not None and transport.is_authenticated(), 'USA reverse SSH authentication failed')
        transport.set_keepalive(15)
        slots = worker.threading.BoundedSemaphore(1024)
        actual = transport.request_port_forward('127.0.0.1', NODE['link'], handler=worker.incoming_handler(NODE, slots))
        require(actual == NODE['link'], 'Unexpected USA reverse listener port')
        print(json.dumps({'usa_reverse_authenticated': True, 'listen_port': 25443, 'target_port': 15443}), flush=True)
        while transport.is_active(): worker.time.sleep(1)
        raise RuntimeError('USA reverse SSH disconnected; supervisor will reconnect')
    finally:
        try: client.close()
        finally:
            if raw is not None: raw.close()


def worker():
    # ProtectHome hides /root state in the service; the worker only needs /etc keys.
    require(os.geteuid() == 0, 'Root required')
    key_files()
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    connect_and_forward(worker_module())


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['generate', 'export-key', 'identity', 'start', 'stop', 'worker','listener','refresh-worker'])
    action = parser.parse_args().action
    try:
        result = globals()[action.replace('-', '_')]()
        if result is not None: print(json.dumps(result))
    except Exception as error:
        # Never print exception details, subprocess output, key/config contents.
        print(json.dumps({'action': action, 'failed': True, 'error_type': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__': main()
