"""Raise a demonstrably exhausted connection table without flushing sessions.

Only the selected host is changed. No firewall rules, DNS, timeouts, hashsize,
VPN/container services or other sysctls are modified. Backup/intent is private.
Rollback refuses to reduce the limit below currently allocated connections.
Kernel reference: https://docs.kernel.org/networking/nf_conntrack-sysctl.html
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

import preflight as p
import forward as f

ROOT = Path('/root/hamvpn-conntrack-capacity-20260918')
FILE = Path('/etc/sysctl.d/99-hamvpn-conntrack-capacity.conf')
KEY = 'net.netfilter.nf_conntrack_max'
ALLOWED = {t['ip'] for t in p.TARGETS if t['id'] in ('at', 'pl', 'cz', 'gbpower')} | {
    '176.108.245.140', '217.60.68.182', '196.251.107.245', '161.104.90.214'}


def read_status():
    base = Path('/proc/sys/net/netfilter')
    mem = {k: int(v.split()[0]) for k, v in
           (line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())}
    return dict(timestamp=time.time(), count=int((base / 'nf_conntrack_count').read_text()),
                maximum=int((base / 'nf_conntrack_max').read_text()),
                memory_total_kib=mem['MemTotal'], memory_available_kib=mem['MemAvailable'])


def choose(status):
    old, count = status['maximum'], status['count']
    p.require(0 < old <= 65536 and count >= old * .9, 'No demonstrated low-limit exhaustion')
    desired = 65536 if old <= 16384 else 262144
    # Conservative 1 KiB per extra entry allowance plus 128 MiB spare.
    p.require(status['memory_available_kib'] >= desired - old + 131072,
              'Insufficient measured memory headroom')
    p.require(status['memory_total_kib'] >= 512 * 1024, 'Host memory below supported range')
    return desired


def content(value):
    p.require(value in (65536, 262144), 'Unreviewed capacity')
    return '# HAMVPN scoped conntrack capacity; no session flush or timeout changes\n' + KEY + ' = ' + str(value) + '\n'


def apply(ip):
    p.require(ip in ALLOWED, 'Host outside selected repair scope'); f.guard(ip)
    s = p.Store(ROOT / ip.replace('.', '-')); s.secure()
    p.require(not s.exists('intent') and not FILE.exists() and not FILE.is_symlink(), 'Existing/uncertain capacity operation')
    f.trusted_parent(FILE)
    old = read_status(); wanted = choose(old)
    p.require(subprocess.run(['sysctl', '-n', KEY], capture_output=True, text=True, check=True).stdout.strip()
              == str(old['maximum']), 'Kernel capacity changed during preparation')
    s.put('intent', dict(ip=ip, before=old, desired=wanted, file=str(FILE), text=content(wanted)))
    f.create(FILE, content(wanted).encode(), 0o644)
    # Do not run sysctl --system: apply only this single reviewed key.
    result = subprocess.run(['sysctl', '-w', KEY + '=' + str(wanted)], capture_output=True, text=True, timeout=10)
    p.require(result.returncode == 0, 'Capacity write uncertain; inspect saved intent')
    actual = read_status()
    f.secure(FILE, 0o644)
    p.require(actual['maximum'] == wanted and FILE.read_text() == content(wanted), 'Runtime/persistent readback differs')
    s.put('applied', dict(ip=ip, before_maximum=old['maximum'], **actual))
    return dict(ip=ip, before_maximum=old['maximum'], **actual, persistent=True,
                sessions_flushed=False, services_restarted=False)


def rollback(ip):
    p.require(ip in ALLOWED, 'Host outside selected repair scope'); f.guard(ip)
    s = p.Store(ROOT / ip.replace('.', '-')); intent = s.get('intent')
    p.require(intent['ip'] == ip and intent['file'] == str(FILE), 'Wrong rollback target')
    f.secure(FILE, 0o644)
    p.require(FILE.read_text() == intent['text'] == content(intent['desired']), 'Capacity file changed')
    actual = read_status(); old = intent['before']['maximum']
    p.require(actual['maximum'] == intent['desired'] and actual['count'] < old,
              'Refuse unsafe reduction or changed live value')
    p.require(not s.exists('rollback-intent'), 'Existing rollback intent; inspect first')
    s.put('rollback-intent', dict(timestamp=time.time(), before=actual))
    subprocess.run(['sysctl', '-w', KEY + '=' + str(old)], check=True, capture_output=True, timeout=10)
    p.require(read_status()['maximum'] == old, 'Runtime restoration not confirmed')
    f.create(s.path / 'retired-sysctl.conf', FILE.read_bytes())
    f.secure(FILE, 0o644); p.require(FILE.read_text() == intent['text'], 'File drift during rollback')
    FILE.unlink()
    s.put('rolled-back', dict(timestamp=time.time(), maximum=old))
    return dict(ip=ip, restored=True, previous_file_absence_restored=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'apply', 'rollback'))
    parser.add_argument('--ip', required=True, choices=sorted(ALLOWED))
    args = parser.parse_args(); os.umask(0o077); f.guard(args.ip)
    from exit_stage import RootStore
    # Use a local root-only lock; no panel access or API calls.
    lock = RootStore('cz', ROOT)
    with lock.locked():
        result = read_status() if args.action == 'status' else globals()[args.action](args.ip)
    print(json.dumps(result))


if __name__ == '__main__': main()
