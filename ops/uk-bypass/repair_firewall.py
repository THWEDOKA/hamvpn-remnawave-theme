#!/usr/bin/env python3
"""Restore the existing HAMVPN UK bridge without opening its port globally."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

TARGET = '51.194.229.165'
BRIDGE = '188.225.62.121'
PORT = '7443'
COMMENT = 'HAMVPN GB existing RU bridge'
UFW = '/usr/sbin/ufw'


def command(delete=False):
    return [UFW, *(['delete'] if delete else []), 'allow', 'proto', 'tcp',
            'from', BRIDGE, 'to', 'any', 'port', PORT, 'comment', COMMENT]


def run(args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def preflight(execute=run):
    addresses = json.loads(execute(['ip', '-j', '-4', 'address', 'show']))
    if not any(a.get('local') == TARGET for i in addresses for a in i.get('addr_info', [])):
        raise RuntimeError('Not the intended UK server; refusing changes.')
    if 'Status: active' not in execute([UFW, 'status']):
        raise RuntimeError('UFW is not active; refusing to change its state.')
    listeners = execute(['ss', '-H', '-lnt', 'sport', '=', ':' + PORT])
    if not listeners.strip():
        raise RuntimeError('Expected existing TCP listener is missing.')


def backup():
    root = Path('/root/hamvpn-uk-bypass-backups')
    root.mkdir(mode=0o700, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='firewall-20260909-', dir=root))
    for source in ['/etc/ufw/user.rules', '/etc/ufw/user6.rules',
                   '/etc/ufw/ufw.conf', '/etc/default/ufw']:
        src = Path(source)
        shutil.copy2(src, directory / source.strip('/').replace('/', '_'))
    for binary in ['iptables-save', 'ip6tables-save']:
        (directory / (binary + '.txt')).write_text(run([binary]))
    (directory / 'ufw-status.txt').write_text(run([UFW, 'status', 'verbose']))
    manifest = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                for f in directory.iterdir() if f.is_file()}
    (directory / 'SHA256SUMS.json').write_text(json.dumps(manifest, indent=2))
    for name, digest in manifest.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError('Backup verification failed.')
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('Run as root.')
    preflight()
    if not args.apply:
        print('Preflight passed. Planned command:', ' '.join(command()))
        return
    directory = backup()
    print('Verified backup:', directory)
    print(run(command()))
    print(run([UFW, 'status', 'numbered']))
    print('Rollback only this rule:', ' '.join(command(delete=True)))


if __name__ == '__main__':
    main()
