"""Optional IPv4 MSS clamp for entry244 public 443 only; no changes by default."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ENTRY, INTERFACE, TABLE = '193.233.222.244', 'enp0s3', 'ham_entry244_mss'
STATE = Path('/root/hamvpn-entry244-20260917/mss244')
UNIT = Path('/etc/systemd/system/ham-entry244-mss.service')
RULES = f'''create table ip {TABLE} {{ comment "HAMVPN-entry244-MSS1200-v2"; }}
add chain ip {TABLE} incoming {{ type filter hook input priority -150; policy accept; }}
add chain ip {TABLE} outgoing {{ type filter hook output priority -150; policy accept; }}
add rule ip {TABLE} incoming iifname "{INTERFACE}" ip daddr {ENTRY} tcp dport 443 tcp flags & syn == syn tcp option maxseg size > 1200 tcp option maxseg size set 1200
add rule ip {TABLE} outgoing oifname "{INTERFACE}" ip saddr {ENTRY} tcp sport 443 tcp flags & syn == syn tcp option maxseg size > 1200 tcp option maxseg size set 1200
'''
DELETE = f'delete table ip {TABLE}\n'


def require(ok, message):
    if not ok: raise RuntimeError(message)


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, 'Command failed (output suppressed): ' + args[0])
    return result.stdout


def guard():
    require(os.geteuid() == 0, 'Root required')
    interfaces = json.loads(run('ip', '-j', '-4', 'addr', 'show', 'dev', INTERFACE))
    require(any(a.get('local') == ENTRY for i in interfaces for a in i.get('addr_info', [])), 'Wrong entry/interface')
    if STATE.exists():
        require(not STATE.is_symlink() and STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'Unsafe state directory')


def normalized(value):
    if isinstance(value, dict): return {k: normalized(v) for k, v in value.items() if k != 'handle'}
    if isinstance(value, list): return [normalized(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    return value


def current():
    tables = json.loads(run('nft', '-j', 'list', 'tables'))['nftables']
    if not any(x.get('table', {}).get('family') == 'ip' and x['table']['name'] == TABLE for x in tables): return None
    return normalized(json.loads(run('nft', '-j', 'list', 'table', 'ip', TABLE)))


def complete_table(table):
    """nft create-table may ignore nested objects: verify actual kernel objects."""
    entries = table.get('nftables', [])
    chains = [e['chain'] for e in entries if 'chain' in e]
    rules = [e['rule'] for e in entries if 'rule' in e]
    require(len(chains) == 2 and len(rules) == 2, 'MSS chains/rules missing in kernel')
    for name, hook in [('incoming', 'input'), ('outgoing', 'output')]:
        matches = [c for c in chains if c['name'] == name]
        require(len(matches) == 1 and matches[0]['hook'] == hook and matches[0]['prio'] == -150,
                'MSS hook/priority mismatch')
        own = [r for r in rules if r['chain'] == name]
        require(len(own) == 1 and any(e.get('mangle', {}).get('value') == 1200 for e in own[0]['expr']),
                'MSS assignment missing in kernel')


def verified_current():
    table = current()
    if table is not None:
        record = STATE / 'owned.json'
        require(record.is_file() and not record.is_symlink(), 'Existing table without ownership record')
        saved = json.loads(record.read_text())
        require(saved == {'spec': hashlib.sha256(RULES.encode()).hexdigest(), 'table': table}, 'Existing table is not exactly owned')
    return table


def save(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = STATE / (name + '.pending')
    with pending.open('x', encoding='utf-8') as stream:
        os.chmod(pending, 0o600); json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    pending.replace(STATE / name)


def unit_text():
    return ('[Unit]\nDescription=HAMVPN entry244 public443 MSS1200\nAfter=network-online.target nftables.service\nWants=network-online.target\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\nExecStart=/usr/bin/python3 '
            + str(Path(__file__).resolve()) + ' apply\n[Install]\nWantedBy=multi-user.target\n')


def operate(action, check_only=False, persist=False):
    guard()
    require(action in ('apply', 'rollback') and (not persist or action == 'apply'), 'Invalid action/options')
    require(not UNIT.is_symlink() and not Path(str(UNIT) + '.d').exists(), 'Unowned systemd override')
    if UNIT.exists(): require(UNIT.read_text() == unit_text(), 'Existing unit is not exactly owned')
    table = verified_current()
    batch = (DELETE if table is not None else '') + (RULES if action == 'apply' else '')
    run('nft', '-c', '-f', '-', data=batch)
    if check_only: return {'check_only': True, 'action': action}
    os.umask(0o077)
    save('before-' + str(time.time_ns()) + '.json', json.loads(run('nft', '-j', 'list', 'ruleset')))
    if action == 'rollback':
        if UNIT.exists():
            run('systemctl', 'disable', '--now', UNIT.name)
            UNIT.unlink(); run('systemctl', 'daemon-reload')
        if table is not None:
            require(verified_current() == table, 'Table changed before rollback')
            run('nft', '-f', '-', data=DELETE)
        require(current() is None, 'Rollback verification failed')
    else:
        if table is None:
            run('nft', '-f', '-', data=RULES)
            table = current(); require(table is not None, 'Table creation failed')
            complete_table(table)
            save('owned.json', {'spec': hashlib.sha256(RULES.encode()).hexdigest(), 'table': table})
        complete_table(table)
        require(verified_current() == table, 'Apply verification failed')
        if persist:
            if not UNIT.exists():
                with UNIT.open('x') as stream: stream.write(unit_text())
                UNIT.chmod(0o644)
            run('systemd-analyze', 'verify', str(UNIT)); run('systemctl', 'daemon-reload')
            run('systemctl', 'enable', '--now', UNIT.name)
    return {'action': action, 'table': TABLE, 'persistence_requested': persist}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['apply', 'rollback'])
    parser.add_argument('--check-only', action='store_true'); parser.add_argument('--persist', action='store_true')
    args = parser.parse_args(); print(json.dumps(operate(args.action, args.check_only, args.persist)))
