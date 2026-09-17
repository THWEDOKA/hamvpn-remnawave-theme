import json
from pathlib import Path
import subprocess

from common import NODES, ROOT

STATE = Path('/root/hamvpn-entry244-20260917')
ENTRY = '193.233.222.244'
NODE = '560e38b3-6ee8-4f10-861e-e2f1eddd4caa'
OLD_PROFILE = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
OLD_INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
OLD_HOSTS = {'667c0682-bc72-43fa-b205-7a65068a2304'}
TARGET_HOSTS = {h for n in NODES for h in n['hosts']}
NAME = 'HAM-ENTRY244-FOUR-EXITS'
LEGACY_TAG = 'vless-entry244-legacy-test'


def save(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = STATE / (name + '.json')
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(target)


def read(name):
    return json.loads((STATE / (name + '.json')).read_text(encoding='utf-8'))


def exists(name):
    return (STATE / (name + '.json')).exists()


def unit_inactive(unit):
    result = subprocess.run(['systemctl', 'is-active', '--quiet', unit], capture_output=True)
    if result.returncode == 3:
        return True
    if result.returncode != 4:
        return False
    # systemd garbage-collects stopped transient timers; distinguish that from
    # a command failure instead of treating arbitrary nonzero exit codes as safe.
    state = subprocess.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState'],
                           capture_output=True, text=True)
    if state.returncode or not isinstance(state.stdout, str):
        return False
    fields = dict(line.split('=', 1) for line in state.stdout.splitlines() if '=' in line)
    return fields == {'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead'}


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True)
    if result.returncode:
        save('command-error', {'program': args[0], 'status': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Command failed; diagnostics are root-only: ' + args[0])
    return result.stdout
