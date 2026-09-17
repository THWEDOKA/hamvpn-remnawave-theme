"""Scoped controller for udp_probe; secrets cross pinned SSH stdin, never argv.

Panel prepare/export-secret/cleanup-secret use --id entry-to-kz2|kz2-to-entry
and --port 54433|54434. launch-server/client also require --role entry|kz2.
firewall-prepare/firewall-rollback run only on kz2 and require --sha256 of this
published script. Existing firewall state is never adopted or overwritten.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time

import udp_probe as probe

ROOT = Path('/root/hamvpn-cloud140-repair-20260918/udp')
PANEL = '64.225.109.248'
PAIRS = {'entry-to-kz2': ('entry', 'kz2'), 'kz2-to-entry': ('kz2', 'entry')}
CHAIN = 'HAM_C140_UDPTEST'
UNIT = 'ham-cloud140-udp-rollback'
SOURCE, DESTINATION = probe.IPS['entry'], probe.IPS['kz2']
JUMP = ['-s', SOURCE + '/32', '-d', DESTINATION + '/32', '-p', 'udp', '-m', 'multiport',
        '--dports', '54433,54434', '-j', CHAIN]
RULES = [['-s', SOURCE + '/32', '-d', DESTINATION + '/32', '-p', 'udp', '-m', 'udp',
          '--dport', str(port), '-j', 'ACCEPT'] for port in probe.PORTS]


class ControlError(Exception):
    pass


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ControlError('command_failed:' + Path(args[0]).name)
    return result.stdout


def guard_host(role):
    if os.geteuid() != 0:
        raise ControlError('root_required')
    expected = PANEL if role == 'panel' else probe.IPS.get(role)
    if not expected:
        raise ControlError('role_outside_scope')
    addresses = {item.get('local') for interface in json.loads(run('ip', '-j', '-4', 'addr', 'show'))
                 for item in interface.get('addr_info', []) if item.get('family') == 'inet'}
    if expected not in addresses:
        raise ControlError('physical_host_mismatch')


def protected(path, directory=False):
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & 0o077 or
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ControlError('unsafe_private_state')
    return info


def state_dir():
    protected(Path('/root'), True)
    for path in (ROOT.parent, ROOT):
        path.mkdir(mode=0o700, exist_ok=True)
        protected(path, True)
    return ROOT


def private_open(path, flags):
    descriptor = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise ControlError('unsafe_private_file')
    return descriptor


def save(name, value):
    path = state_dir() / name
    with os.fdopen(private_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL), 'w') as handle:
        handle.write(json.dumps(value, sort_keys=True) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    return path


def read(name):
    path = state_dir() / name
    with os.fdopen(private_open(path, os.O_RDONLY), 'r') as handle:
        return json.load(handle)


def pair(identifier, port):
    if identifier not in PAIRS or type(port) is not int or port not in probe.PORTS:
        raise ControlError('pair_outside_scope')
    return PAIRS[identifier]


def basename(identifier, port):
    pair(identifier, port)
    return identifier + '-' + str(port)


def prepare(identifier, port):
    guard_host('panel')
    name = basename(identifier, port)
    value = {'id': identifier, 'port': port, 'created_at': time.time(),
             'key_hex': secrets.token_hex(32), 'nonce_hex': secrets.token_hex(16)}
    save(name + '.json', value)
    return {'prepared': True, 'id': identifier, 'port': port}


def credential_record(identifier, port):
    value = read(basename(identifier, port) + '.json')
    if value.get('id') != identifier or value.get('port') != port:
        raise ControlError('credential_record_mismatch')
    credentials = {'key_hex': value['key_hex'], 'nonce_hex': value['nonce_hex']}
    probe.read_credentials(io.StringIO(json.dumps(credentials)))
    return credentials


def export_secret(identifier, port):
    guard_host('panel')
    return credential_record(identifier, port)


def cleanup_secret(identifier, port):
    guard_host('panel')
    credential_record(identifier, port)
    # Exact validated single file only, never a glob or recursive deletion.
    (ROOT / (basename(identifier, port) + '.json')).unlink()
    return {'secret_removed': True, 'id': identifier, 'port': port}


def release_paths(expected_sha=None):
    path = Path(__file__).absolute()
    pattern = r'/opt/hamvpn-cloud140-kz245/releases/[0-9a-f]{12}/ops/cloud140-kz245-20260917/udp_control\.py'
    if not re.fullmatch(pattern, str(path)) or path.resolve() != path:
        raise ControlError('not_a_verified_release_path')
    for ancestor in [path, *path.parents[:-1]]:
        info = ancestor.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ControlError('unsafe_release_path')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected_sha is not None and not secrets.compare_digest(digest, expected_sha):
        raise ControlError('release_hash_mismatch')
    child = path.with_name('udp_probe.py')
    info = child.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
        raise ControlError('unsafe_probe_release')
    return path, child, digest


def launch_server(identifier, port, role, credentials):
    client_role, server_role = pair(identifier, port)
    if role != server_role:
        raise ControlError('wrong_listener_role')
    guard_host(role)
    _, script, digest = release_paths()
    name = basename(identifier, port) + '-server'
    save(name + '-intent.json', {'timestamp': time.time(), 'role': role, 'id': identifier,
                                'port': port, 'control_sha256': digest, 'duration': 90})
    out_path, err_path = ROOT / (name + '.jsonl'), ROOT / (name + '.stderr')
    with os.fdopen(private_open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL), 'wb') as out, \
         os.fdopen(private_open(err_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL), 'wb') as err:
        process = subprocess.Popen(['/usr/bin/python3', '-B', str(script), 'serve', '--side', role,
                                    '--port', str(port), '--duration', '90'], stdin=subprocess.PIPE,
                                   stdout=out, stderr=err, start_new_session=True, close_fds=True)
        try:
            wire = json.dumps({'key_hex': credentials.key.hex(), 'nonce_hex': credentials.nonce.hex()})
            process.stdin.write((wire + '\n').encode())
            process.stdin.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with os.fdopen(private_open(out_path, os.O_RDONLY), 'r') as handle:
                    first = handle.readline(4097)
                if first.endswith('\n'):
                    ready = json.loads(first)
                    if (ready.get('event') == 'ready' and ready.get('local_ip') == probe.IPS[role]
                            and ready.get('peer_ip') == probe.IPS[client_role]
                            and ready.get('port') == port and ready.get('exclusive_bind') is True):
                        result = {'ready': True, 'pid': process.pid, 'id': identifier, 'port': port,
                                  'role': role, 'duration': 90, 'proof': str(out_path)}
                        save(name + '-started.json', result)
                        return result
                    raise ControlError('listener_ready_rejected')
                if process.poll() is not None:
                    raise ControlError('listener_exited_before_ready')
                time.sleep(0.05)
            raise ControlError('listener_ready_timeout')
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            raise


def client(identifier, port, role, credentials):
    client_role, _ = pair(identifier, port)
    if role != client_role:
        raise ControlError('wrong_client_role')
    guard_host(role)
    name = basename(identifier, port) + '-client'
    save(name + '-intent.json', {'timestamp': time.time(), 'role': role, 'id': identifier, 'port': port})
    result = probe.client(probe.Config(role, port, duration=45, count=4), credentials)
    save(name + '-proof.json', result)
    # Loss is data, not a launcher exception: retain and return all_passed=false.
    return result


@contextlib.contextmanager
def firewall_lock():
    import fcntl
    with os.fdopen(private_open(state_dir() / 'firewall.lock', os.O_RDWR | os.O_CREAT), 'a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def firewall_state(text):
    lines = [shlex.split(line) for line in text.splitlines() if line.strip()]
    chain_exists = ['-N', CHAIN] in lines
    own_rules = [line[2:] for line in lines if line[:2] == ['-A', CHAIN]]
    references = [line for line in lines if any(line[index] in ('-j', '-g') and
                  line[index + 1] == CHAIN for index in range(len(line) - 1))]
    return chain_exists, own_rules, references


def cleanup_plan(text):
    exists, rules, references = firewall_state(text)
    expected = ['-A', 'INPUT', *JUMP]
    if references not in ([], [expected]) or rules != RULES[:len(rules)]:
        raise ControlError('owned_firewall_drift')
    if not exists and (rules or references):
        raise ControlError('inconsistent_firewall_state')
    return exists, rules, references


def firewall_prepare(expected_sha):
    guard_host('kz2')
    script, _, digest = release_paths(expected_sha)
    with firewall_lock():
        before = run('iptables', '-w', '5', '-S')
        if any(firewall_state(before)):
            raise ControlError('owned_chain_already_exists')
        snapshot = run('iptables-save')
        save('firewall-before.json', {'iptables_save': snapshot,
                                     'sha256': hashlib.sha256(snapshot.encode()).hexdigest()})
        save('firewall-intent.json', {'script': str(script), 'sha256': digest, 'chain': CHAIN,
                                     'source': SOURCE, 'destination': DESTINATION,
                                     'ports': list(probe.PORTS), 'timestamp': time.time()})
        run('systemd-run', '--unit=' + UNIT, '--on-active=300s', '--timer-property=AccuracySec=1s',
            '--property=Type=oneshot', '--property=UMask=0077', '/usr/bin/python3', '-B', str(script),
            'firewall-rollback', '--sha256', digest)
        if run('systemctl', 'show', UNIT + '.timer', '-p', 'ActiveState', '--value').strip() != 'active':
            raise ControlError('rollback_timer_not_armed')
        # Timer and immutable rollback ownership exist before any firewall write.
        run('iptables', '-w', '5', '-N', CHAIN)
        for rule in RULES:
            run('iptables', '-w', '5', '-A', CHAIN, *rule)
        run('iptables', '-w', '5', '-I', 'INPUT', '1', *JUMP)
        exists, rules, refs = cleanup_plan(run('iptables', '-w', '5', '-S'))
        if not exists or rules != RULES or refs != [['-A', 'INPUT', *JUMP]]:
            raise ControlError('firewall_readback_failed')
        result = {'prepared': True, 'source': SOURCE, 'destination': DESTINATION,
                  'ports': list(probe.PORTS), 'rollback_seconds': 300, 'rollback_timer_active': True}
        save('firewall-prepared.json', result)
        return result


def firewall_rollback(expected_sha):
    guard_host('kz2')
    script, _, digest = release_paths(expected_sha)
    with firewall_lock():
        intent = read('firewall-intent.json')
        if (intent.get('script') != str(script) or intent.get('sha256') != digest or
                intent.get('chain') != CHAIN or intent.get('source') != SOURCE or
                intent.get('destination') != DESTINATION or intent.get('ports') != list(probe.PORTS)):
            raise ControlError('firewall_ownership_mismatch')
        snapshot = read('firewall-before.json')
        if hashlib.sha256(snapshot['iptables_save'].encode()).hexdigest() != snapshot['sha256']:
            raise ControlError('firewall_snapshot_hash_mismatch')
        exists, rules, refs = cleanup_plan(run('iptables', '-w', '5', '-S'))
        if refs:
            run('iptables', '-w', '5', '-D', 'INPUT', *JUMP)
        for rule in reversed(rules):
            run('iptables', '-w', '5', '-D', CHAIN, *rule)
        if exists:
            run('iptables', '-w', '5', '-X', CHAIN)
        if any(firewall_state(run('iptables', '-w', '5', '-S'))):
            raise ControlError('firewall_cleanup_readback_failed')
        run('systemctl', 'stop', UNIT + '.timer')
        if run('systemctl', 'show', UNIT + '.timer', '-p', 'ActiveState', '--value').strip() not in ('inactive', 'failed'):
            raise ControlError('rollback_timer_still_active')
        result = {'own_chain_removed': True, 'own_jump_removed': True,
                  'unrelated_rules_untouched': True, 'timer_stopped': True, 'timestamp': time.time()}
        if not (ROOT / 'firewall-cleaned.json').exists():
            save('firewall-cleaned.json', result)
        return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'export-secret', 'cleanup-secret', 'launch-server',
                                          'client', 'firewall-prepare', 'firewall-rollback'))
    parser.add_argument('--id', choices=tuple(PAIRS))
    parser.add_argument('--port', type=int, choices=probe.PORTS)
    parser.add_argument('--role', choices=tuple(probe.IPS))
    parser.add_argument('--sha256')
    args = parser.parse_args()
    if args.action.startswith('firewall-'):
        if not args.sha256 or not re.fullmatch('[0-9a-f]{64}', args.sha256):
            parser.error('firewall actions require the published control script SHA-256')
        result = (firewall_prepare if args.action == 'firewall-prepare' else firewall_rollback)(args.sha256)
    elif args.action in ('launch-server', 'client'):
        if not args.role:
            parser.error('--role is required')
        credentials = probe.read_credentials(sys.stdin)
        result = (launch_server if args.action == 'launch-server' else client)(
            args.id, args.port, args.role, credentials)
    else:
        result = {'prepare': prepare, 'export-secret': export_secret,
                  'cleanup-secret': cleanup_secret}[args.action](args.id, args.port)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ControlError, probe.ProbeError) as error:
        print(json.dumps({'error': str(error), 'completed': False}), flush=True)
        sys.exit(2)
