"""Approved isolated SSH/22222; never reload or change the primary SSH daemon."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ENTRY = '193.233.222.244'
PORT = 22222
PAIRS = {'ham-rs633-de3': ('217.60.68.182', 36443), 'ham-rs633-pl2': ('31.56.188.150', 37443)}
STATE = Path('/root/ham-rs633-pair-20260918')
CONF = Path('/etc/ham-rs633-pair')
UNIT = Path('/etc/systemd/system/ham-rs633-pair-sshd.service')
CHAIN = 'HAM_RS633_PAIR'


def require(ok, message):
    if not ok: raise RuntimeError(message)


def sha(value): return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(*args):
    proc = subprocess.run(args, capture_output=True, timeout=25)
    if proc.returncode:
        save('last-error', {'program': args[0], 'stdout': proc.stdout.decode(errors='replace'), 'stderr': proc.stderr.decode(errors='replace')})
        raise RuntimeError('Command failed; details retained privately: ' + args[0])
    return proc.stdout


def save(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'Unsafe state')
    path = STATE / (name + '.json')
    require(not path.exists(), 'Immutable state already exists: ' + name)
    with path.open('x', encoding='utf-8') as f:
        os.chmod(path, 0o600); json.dump(value, f); f.flush(); os.fsync(f.fileno())


def read(name):
    path = STATE / (name + '.json')
    require(not path.is_symlink() and path.stat().st_uid == 0 and path.stat().st_mode & 0o077 == 0, 'Unsafe state file')
    return json.loads(path.read_text())


def settings():
    lines = [f'Port {PORT}', f'ListenAddress {ENTRY}', 'AddressFamily inet',
        'HostKey /etc/ssh/ssh_host_ed25519_key', 'PidFile /run/ham-rs633-pair-sshd.pid',
        'UsePAM yes', 'PermitRootLogin no', 'AuthenticationMethods publickey',
        'PubkeyAuthentication yes', 'AuthorizedKeysCommand none', 'TrustedUserCAKeys none',
        'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'AllowTcpForwarding remote', 'AllowStreamLocalForwarding no',
        'PermitListen none', 'PermitOpen none', 'GatewayPorts no',
        'AllowAgentForwarding no', 'X11Forwarding no', 'PermitTTY no',
        'PermitUserRC no', 'PermitTunnel no', 'MaxSessions 0',
        'ForceCommand /usr/sbin/nologin', 'LogLevel VERBOSE',
        'AllowUsers ' + ' '.join(user + '@' + ip for user, (ip, _) in PAIRS.items())]
    for user, (_, port) in PAIRS.items():
        lines += ['Match User ' + user, '    AuthorizedKeysFile /etc/' + user + '/authorized_keys',
                  '    PermitListen 127.0.0.1:' + str(port), 'Match all']
    return '\n'.join(lines) + '\n'


def snapshot():
    require(ENTRY + '/' in run('ip', '-4', 'addr', 'show').decode(), 'Wrong server')
    require(not CONF.exists() and not UNIT.exists(), 'Separate SSH already exists')
    require(not run('ss', '-H', '-lnt', 'sport = :' + str(PORT)).strip(), 'Port occupied')
    files = [Path('/etc/ssh/sshd_config'), *Path('/etc/ssh/sshd_config.d').glob('*.conf')]
    value = {'time': time.time(), 'files': {str(p): p.read_text() for p in files},
             'sshd': run('/usr/sbin/sshd', '-T').decode(),
             'firewall': run('iptables-save').decode(), 'firewall6': run('ip6tables-save').decode(),
             'listeners': run('ss', '-lntp').decode()}
    save('before', value); return {'snapshot': True, 'sha256': sha(value)}


def backup():
    value = json.load(sys.stdin)
    require(value['external_copy_verified'] and value['sha256'] == sha(read('before')), 'External backup required')
    save('external-proof', value); return {'external_backup_verified': True}


def firewall():
    # This uniquely named chain and one scoped jump are the entire firewall delta.
    lines = ['-N ' + CHAIN] + ['-A ' + CHAIN + ' -s ' + ip + '/32 -j ACCEPT' for ip, _ in PAIRS.values()] + ['-A ' + CHAIN + ' -j DROP']
    proc = subprocess.run(['iptables', '-S', CHAIN], capture_output=True, text=True)
    if proc.returncode == 0:
        require(proc.stdout.splitlines() == lines, 'Firewall chain ownership conflict')
    else:
        require(proc.returncode == 1, 'Cannot inspect firewall')
        run('iptables', '-N', CHAIN)
        for ip, _ in PAIRS.values(): run('iptables', '-A', CHAIN, '-s', ip + '/32', '-j', 'ACCEPT')
        run('iptables', '-A', CHAIN, '-j', 'DROP')
    jump = ['INPUT', '-d', ENTRY + '/32', '-p', 'tcp', '--dport', str(PORT), '-m', 'comment', '--comment', 'ham-rs633-pair', '-j', CHAIN]
    proc = subprocess.run(['iptables', '-C', *jump], capture_output=True)
    if proc.returncode == 1: run('iptables', '-I', *jump)
    else: require(proc.returncode == 0, 'Cannot inspect firewall jump')
    return {'only_two_exit_sources_allowed_on_new_port': True}


def install():
    require(read('external-proof')['sha256'] == sha(read('before')), 'Backup missing')
    require(not CONF.exists() and not UNIT.exists(), 'Installation intent already exists')
    require(run('/usr/sbin/sshd', '-T').decode() == read('before')['sshd'], 'Primary SSH policy drift')
    save('install-intent', {'time': time.time(), 'config_sha256': sha(settings())})
    CONF.mkdir(mode=0o700)
    (CONF / 'sshd_config').write_text(settings()); os.chmod(CONF / 'sshd_config', 0o600)
    script = str(Path(__file__).resolve())
    text = f'''[Unit]
Description=HAM AEZA dedicated reverse SSH endpoint for DE3 and PL2
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=/usr/bin/python3 {script} firewall
ExecStart=/usr/sbin/sshd -D -e -f {CONF}/sshd_config
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
[Install]
WantedBy=multi-user.target
'''
    UNIT.write_text(text); os.chmod(UNIT, 0o644)
    run('/usr/sbin/sshd', '-t', '-f', str(CONF / 'sshd_config'))
    for user, (ip, port) in PAIRS.items():
        raw = run('/usr/sbin/sshd', '-T', '-f', str(CONF / 'sshd_config'), '-C', f'user={user},addr={ip},host=aeza633').decode()
        values = dict(line.split(' ', 1) for line in raw.splitlines() if ' ' in line)
        require(values['permitlisten'] == '127.0.0.1:' + str(port) and values['maxsessions'] == '0'
                and values['authenticationmethods'] == 'publickey' and values['allowtcpforwarding'] == 'remote', 'Separate policy invalid')
    run('systemd-analyze', 'verify', str(UNIT)); run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', UNIT.name)
    require(run('/usr/sbin/sshd', '-T').decode() == read('before')['sshd'], 'Primary SSH policy changed')
    save('installed', {'time': time.time(), 'unit_sha256': sha(text)})
    return {'separate_sshd_started': True, 'primary_sshd_unchanged': True, 'port': PORT}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['snapshot', 'backup', 'install', 'firewall'])
    try: print(json.dumps(globals()[parser.parse_args().action]()))
    except Exception as e:
        print(json.dumps({'failed': True, 'error': str(e) if isinstance(e, RuntimeError) else type(e).__name__})); sys.exit(1)
