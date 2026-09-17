"""Scoped, reversible live capacity repair. Does not restart or edit Xray."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

IP = '196.251.107.245'
STATE = Path('/root/tls245-repair-20260917/verified')
CONF = Path('/etc/sysctl.d/99-hamvpn-tls245-capacity.conf')
MODULES = Path('/etc/modules-load.d/hamvpn-tls245-conntrack.conf')
MODULE_TEXT = '# Load before systemd-sysctl so the persistent capacity applies.\nnf_conntrack\n'
TARGET = {'net.netfilter.nf_conntrack_max': 262144,
          'net.ipv4.tcp_max_orphans': 32768,
          'net.ipv4.tcp_orphan_retries': 4}


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


def values():
    return {key: int(run('sysctl', '-n', key)) for key in TARGET}


def config_text():
    return ('# TLS245 only: measured conntrack overflow and orphan pressure.\n'
            '# Preserve established-client retry policy, firewall and VPN config.\n'
            + ''.join(f'{k} = {v}\n' for k, v in TARGET.items()))


def validate(before, memory_kib, available_kib):
    assert memory_kib >= 3 * 1024 * 1024, 'Unexpected machine memory'
    assert available_kib >= 512 * 1024, 'Insufficient memory headroom'
    assert before == {'net.netfilter.nf_conntrack_max': 65536,
                      'net.ipv4.tcp_max_orphans': 16384,
                      'net.ipv4.tcp_orphan_retries': 0}, 'Concurrent capacity change'


def save(name, data):
    path = STATE / (name + '.json')
    path.write_text(json.dumps(data, indent=2) + '\n')
    path.chmod(0o600)


def fingerprint():
    files = ['/opt/remnanode/docker-compose.yml',
             '/etc/nginx/sites-available/selfsteal-tls245',
             '/etc/letsencrypt/renewal/tls245.torcalc.ru.conf',
             '/etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245']
    rules = firewall_policy(run('iptables-save'))
    return {'files': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files},
            'started': run('docker', 'inspect', '-f', '{{.State.StartedAt}}', 'remnanode'),
            'firewall': hashlib.sha256(rules.encode()).hexdigest()}


def firewall_policy(text):
    # Built-in chain packet/byte counters change with live traffic, not policy.
    return '\n'.join(re.sub(r'\[\d+:\d+\]', '[0:0]', s)
                     for s in text.splitlines() if not s.startswith('#'))


def identity():
    assert os.getuid() == 0
    ips = json.loads(run('ip', '-j', '-4', 'addr', 'show'))
    assert IP in [a['local'] for interface in ips for a in interface.get('addr_info', [])]
    assert run('docker', 'inspect', '-f', '{{.HostConfig.NetworkMode}}', 'remnanode') == 'host'
    assert run('systemctl', 'is-active', 'nginx') == 'active'
    assert run('ss', '-lntH', 'sport = :443')
    assert run('ss', '-lntH', 'sport = :8443')


def rollback():
    before = json.loads((STATE / 'before.json').read_text())
    assert CONF.read_text() == config_text(), 'Config modified since repair'
    assert MODULES.read_text() == MODULE_TEXT, 'Module config modified since repair'
    assert values() == TARGET, 'Runtime modified since repair'
    # Restore runtime first; refuse to remove anything outside this exact file.
    for k, v in before['values'].items():
        run('sysctl', '-w', f'{k}={v}')
    CONF.unlink()
    MODULES.unlink()
    save('rollback', {'time': time.time(), 'restored': values()})
    return {'rolled_back': values() == before['values']}


def apply():
    assert not CONF.exists(), 'Existing config: inspect instead of overwrite'
    assert not MODULES.exists(), 'Existing module config: inspect first'
    assert not (STATE / 'before.json').exists(), 'Existing repair intent: inspect first'
    mem = {s.split(':')[0]: int(s.split()[1]) for s in Path('/proc/meminfo').read_text().splitlines()}
    before = values()
    validate(before, mem['MemTotal'], mem['MemAvailable'])
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    baseline = fingerprint()
    save('before', {'time': time.time(), 'values': before, 'fingerprint': baseline})
    # Narrow root-only snapshot before the only mutation; no secret output.
    run('tar', '-czf', str(STATE / 'before-configs.tar.gz'), '-C', '/',
        'etc/sysctl.conf', 'etc/sysctl.d', 'opt/remnanode/docker-compose.yml',
        'etc/nginx/sites-available/selfsteal-tls245',
        'etc/letsencrypt/renewal/tls245.torcalc.ru.conf',
        'etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245')
    run('tar', '-tzf', str(STATE / 'before-configs.tar.gz'))
    save('archive-checksum', {'sha256': hashlib.sha256((STATE / 'before-configs.tar.gz').read_bytes()).hexdigest()})
    with CONF.open('x') as file: file.write(config_text())
    CONF.chmod(0o644)
    try:
        with MODULES.open('x') as file: file.write(MODULE_TEXT)
        MODULES.chmod(0o644)
        run('sysctl', '-p', str(CONF))
        assert values() == TARGET
        assert fingerprint() == baseline, 'Unrelated target service change'
    except Exception:
        # A partially applied sysctl load still restores only this invocation.
        for k, v in before.items(): run('sysctl', '-w', f'{k}={v}')
        if CONF.read_text() == config_text(): CONF.unlink()
        if MODULES.exists() and MODULES.read_text() == MODULE_TEXT: MODULES.unlink()
        save('automatic-rollback', {'time': time.time(), 'restored': values()})
        raise
    proof = {'time': time.time(), 'before': before, 'after': values(),
             'service_and_firewall_preserved': fingerprint() == baseline,
             'no_restart': True}
    save('applied', proof)
    return proof


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['apply', 'rollback', 'status'])
    action = parser.parse_args().action
    identity()
    print(json.dumps(values() if action == 'status' else globals()[action]()))


if __name__ == '__main__': main()
