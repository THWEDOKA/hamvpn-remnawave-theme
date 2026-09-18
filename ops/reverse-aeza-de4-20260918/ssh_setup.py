"""Independent native -R identity; no operator key leaves the workstation."""
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import socket
import sys
import time
from common import *
import model as m

CONF = Path('/etc/ham-rs633-de4')
DROP = Path('/etc/ssh/sshd_config.d/71-ham-rs633-de4.conf')
UNIT = Path('/etc/systemd/system/ham-rs633-de4.service')
HOME = Path('/var/lib/ham-rs633-de4')


def role():
    addresses = run('ip', '-4', 'addr', 'show').decode()
    if m.ENTRY + '/' in addresses: return 'entry'
    require(m.EXIT + '/' in addresses, 'Wrong server')
    return 'exit'


def snapshot():
    which = role(); name = 'snapshot-' + which
    require(not (STATE / (name + '.json')).exists(), 'Snapshot exists; reconcile')
    files = [Path('/etc/ssh/sshd_config'), *Path('/etc/ssh/sshd_config.d').glob('*.conf'),
             Path('/etc/systemd/system/ham-entry244-reverse.service')]
    snap = {'role': which, 'time': time.time(), 'files': {str(p): p.read_text() for p in files if p.is_file()},
            'listeners': run('ss', '-lntp').decode(), 'firewall4': run('iptables-save').decode(),
            'firewall6': run('ip6tables-save').decode()}
    d = json.loads(run('docker', 'inspect', 'remnanode'))[0]
    require(d['HostConfig']['NetworkMode'] == 'host', 'Xray namespace requires separate design')
    snap['runtime'] = {k: d[k] for k in ['Id', 'State', 'Mounts']}
    snap['version'] = run('docker', 'exec', 'remnanode', 'xray', 'version').decode()
    save(name, snap); require(read(name) == snap, 'Snapshot readback')
    return {'snapshot': which, 'sha256': sha(snap)}


def mirror():
    payload = json.load(sys.stdin); name = payload['name']
    require(name in ['panel-before', 'snapshot-entry', 'snapshot-exit'], 'Invalid mirror scope')
    require(sha(payload['data']) == payload['sha256'], 'Mirror hash mismatch')
    require(not (STATE / ('mirror-' + name + '.json')).exists(), 'Mirror already exists')
    save('mirror-' + name, payload)
    return {'external_copy_verified': True, 'name': name, 'sha256': payload['sha256']}


def require_backup():
    which = role(); proof = read('external-proof-' + which)
    require(proof['sha256'] == sha(read('snapshot-' + which)), 'External backup required')


def accept_backup():
    which = role(); proof = json.load(sys.stdin)
    require(proof.get('external_copy_verified') and proof['sha256'] == sha(read('snapshot-' + which)), 'Wrong mirror proof')
    save('external-proof-' + which, proof); return {'backup_gate_passed': True}


def create_account():
    try: pwd.getpwnam(m.ACCOUNT)
    except KeyError: pass
    else: raise RuntimeError('Account already exists; reconcile')
    run('useradd', '--system', '--create-home', '--home-dir', str(HOME), '--shell', '/usr/sbin/nologin', m.ACCOUNT)
    account = pwd.getpwnam(m.ACCOUNT); HOME.chmod(0o700)
    return account


def generate():
    require(role() == 'exit', 'Exit only'); require_backup()
    require(not CONF.exists() and not HOME.exists(), 'Existing native channel files')
    account = create_account()
    directory = HOME / '.ssh'; directory.mkdir(mode=0o700); os.chown(directory, account.pw_uid, account.pw_gid)
    run('runuser', '-u', m.ACCOUNT, '--', 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
        '-C', 'HAM-AEZA633-DE4-REVERSE', '-f', str(directory / 'id_ed25519'))
    require((directory / 'id_ed25519').stat().st_mode & 0o077 == 0, 'Private key mode')
    save('generated', {'account': m.ACCOUNT, 'time': time.time()})
    return {'private_key_generated_only_on_exit': True}


def identity():
    require(role() == 'entry', 'Entry only'); require_backup()
    public = sys.stdin.read().strip()
    import re, base64
    require(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2} HAM-AEZA633-DE4-REVERSE', public), 'Wrong public key')
    require(len(base64.b64decode(public.split()[1], validate=True)) == 51, 'Key format')
    require(not CONF.exists() and not DROP.exists() and not HOME.exists(), 'Identity exists; reconcile')
    users = ['root'] + [p.pw_name for p in pwd.getpwall() if p.pw_name.startswith('ham-')]
    sources = [m.EXIT, os.environ.get('SSH_CONNECTION', '127.0.0.1').split()[0]]
    def effective(user, source):
        return run('/usr/sbin/sshd', '-T', '-C', f'user={user},addr={source},host=aeza633').decode()
    before = {u + '@' + s: effective(u, s) for u in users for s in sources}
    save('ssh-policies-before', before)
    account = create_account(); CONF.mkdir(mode=0o750); CONF.chmod(0o750); os.chown(CONF, 0, account.pw_gid)
    authorized = CONF / 'authorized_keys'
    write(authorized, f'from="{m.EXIT}/32",restrict,port-forwarding,permitlisten="127.0.0.1:{m.R}",command="/usr/sbin/nologin" {public}\n', 0o640)
    os.chown(authorized, 0, account.pw_gid)
    expected, text = m.sshd()
    try:
        write(DROP, text, 0o644); run('/usr/sbin/sshd', '-t')
        require(all(effective(u, s) == before[u + '@' + s] for u in users for s in sources), 'Existing SSH policy changed')
        current = dict(line.split(' ', 1) for line in effective(m.ACCOUNT, m.EXIT).splitlines() if ' ' in line)
        require(all(current.get(k.lower()) == v for k, v in expected.items()), 'New effective policy mismatch')
        require(current.get('disableforwarding') == 'no', 'Remote forwarding disabled')
        run('systemctl', 'reload', 'ssh')
    except Exception:
        authorized.rename(CONF / 'authorized_keys.revoked')
        if DROP.exists(): DROP.rename(STATE / 'failed-dropin.conf')
        run('/usr/sbin/sshd', '-t'); run('systemctl', 'reload', 'ssh'); raise
    save('identity', {'policy_sha256': sha(text), 'time': time.time()})
    return {'entry_restricted_identity_ready': True, 'existing_ssh_policies_preserved': True}


def install():
    require(role() == 'exit', 'Exit only'); read('generated')
    pinned = sys.stdin.read().strip()
    require(pinned.startswith(m.ENTRY + ' ssh-ed25519 '), 'Wrong entry pin')
    require(not (STATE / 'installed.json').exists(), 'Installed unit exists; reconcile')
    account = pwd.getpwnam(m.ACCOUNT)
    if CONF.exists() or UNIT.exists():
        require((CONF / 'known_hosts').read_text() == pinned + '\n' and
                (CONF / 'ssh_config').read_text() == m.client() and UNIT.read_text() == m.unit(),
                'Partial installation ownership mismatch')
    else:
        CONF.mkdir(mode=0o755)
        write(CONF / 'known_hosts', pinned + '\n', 0o644)
        write(CONF / 'ssh_config', m.client(), 0o644)
        write(UNIT, m.unit(), 0o644)
    CONF.chmod(0o755)  # Explicitly override the process root-only umask for public config.
    run('runuser', '-u', m.ACCOUNT, '--', 'test', '-r', str(HOME / '.ssh/id_ed25519'))
    expanded = run('runuser', '-u', m.ACCOUNT, '--', 'ssh', '-G', '-F', str(CONF / 'ssh_config'), 'aeza-de4').decode()
    # OpenSSH -G renders numeric forward addresses in brackets even for IPv4.
    forwards = [line.replace('[127.0.0.1]', '127.0.0.1') for line in expanded.splitlines()
                if line.startswith('remoteforward ')]
    require(forwards == [f'remoteforward 127.0.0.1:{m.R} 127.0.0.1:{m.B}'], 'Client forward mismatch')
    run('systemd-analyze', 'verify', str(UNIT)); run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', m.UNIT + '.service')
    save('installed', {'time': time.time(), 'unit_sha256': sha(m.unit())})
    return {'native_service_started': True}


def repair_identity_permissions():
    require(role() == 'entry', 'Entry only'); read('identity')
    require(DROP.read_text() == m.sshd()[1], 'Identity ownership drift')
    account = pwd.getpwnam(m.ACCOUNT)
    require(CONF.stat().st_uid == 0 and CONF.stat().st_gid == account.pw_gid, 'Directory owner drift')
    require((CONF / 'authorized_keys').stat().st_uid == 0, 'Authorized keys owner drift')
    CONF.chmod(0o750)
    require((CONF / 'authorized_keys').stat().st_mode & 0o777 == 0o640, 'Key file mode drift')
    run('runuser', '-u', m.ACCOUNT, '--', 'test', '-r', str(CONF / 'authorized_keys'))
    return {'owned_authorized_key_readable': True}


def bpf_query():
    # Query actual kernel cgroup attachments; unit properties alone are not proof.
    import platform
    require(platform.machine() == 'x86_64', 'Adapt BPF query syscall for architecture')
    class Query(ctypes.Structure):
        _fields_ = [('target_fd', ctypes.c_uint32), ('attach_type', ctypes.c_uint32),
            ('query_flags', ctypes.c_uint32), ('attach_flags', ctypes.c_uint32),
            ('prog_ids', ctypes.c_uint64), ('prog_cnt', ctypes.c_uint32), ('padding', ctypes.c_uint32),
            ('prog_attach_flags', ctypes.c_uint64)]
    libc = ctypes.CDLL(None, use_errno=True)
    group = run('systemctl', 'show', m.UNIT + '.service', '-p', 'ControlGroup', '--value').decode().strip()
    fd = os.open('/sys/fs/cgroup' + group, os.O_RDONLY | os.O_DIRECTORY)
    try:
        counts = []
        for direction in [0, 1]:
            q = Query(target_fd=fd, attach_type=direction, query_flags=1)
            rc = libc.syscall(321, 16, ctypes.byref(q), ctypes.sizeof(q))
            require(rc == 0, 'Cannot confirm kernel IP sandbox')
            counts.append(q.prog_cnt)
        require(all(n > 0 for n in counts), 'IP sandbox not attached')
        return counts
    finally: os.close(fd)


def verify():
    require(role() == 'exit', 'Exit only'); require(UNIT.read_text() == m.unit(), 'Unit drift')
    state = dict(line.split('=', 1) for line in run('systemctl', 'show', m.UNIT + '.service',
        '-p', 'User,ActiveState,MainPID,NRestarts,IPAddressAllow,IPAddressDeny').decode().splitlines() if '=' in line)
    require(state['User'] == m.ACCOUNT and state['ActiveState'] == 'active', 'Service not active as isolated user')
    counts = bpf_query(); save('sandbox-proof', {'bpf_programs': counts, 'time': time.time()})
    return {'service_non_root': True, 'kernel_ip_sandbox_attached': True,
            'restarts': state['NRestarts'], 'pid': state['MainPID']}


def listener():
    require(role() == 'entry', 'Entry only')
    lines = run('ss', '-H', '-lnt', 'sport = :' + str(m.R)).decode().splitlines()
    require(len(lines) == 1 and lines[0].split()[3] == '127.0.0.1:' + str(m.R), 'Wrong/missing reverse listener')
    return {'exact_loopback_listener': True, 'port': m.R}


def restart():
    require(role() == 'exit', 'Exit only'); verify()
    run('systemctl', 'restart', m.UNIT + '.service'); return {'only_new_unit_restarted': True}


def retire_old():
    require(role() == 'exit', 'Exit only')
    proof = json.load(sys.stdin)
    require(proof.get('entry_candidate_active') and proof.get('clients_passed'), 'Cutover proof required')
    old = Path('/etc/systemd/system/ham-entry244-reverse.service')
    require(old.read_text() == read('snapshot-exit')['files'][str(old)], 'Old unit changed')
    run('systemctl', 'disable', '--now', 'ham-entry244-reverse.service')
    save('old-retired', {'time': time.time()})
    return {'old_de4_unit_disabled': True, 'old_files_retained_for_recovery': True}


if __name__ == '__main__':
    cli({k: globals()[k] for k in ['snapshot', 'mirror', 'accept_backup', 'generate', 'identity',
        'install', 'verify', 'listener', 'restart', 'retire_old', 'repair_identity_permissions']})
