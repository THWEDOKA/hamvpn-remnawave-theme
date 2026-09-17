import json
from pathlib import Path
import subprocess

from common import NODES, ROOT

STATE = Path('/root/hamvpn-entry208-20260917')
ENTRY = '162.141.185.208'
NODE = '22ac9320-4762-461d-b877-a9f33b58d492'
OLD_PROFILE = '2caa9583-8d5a-46af-93b9-d0a41bd691c4'
OLD_INBOUND = 'e28f2113-9667-4e1c-be3c-60316d30f219'
OLD_HOSTS = {'a2302256-68a3-4e3e-8213-5817b0177712', '2a69e425-fb50-4bea-aeec-868735309ff4'}
TARGET_HOSTS = {h for n in NODES for h in n['hosts']}
NAME = 'HAM-ENTRY208-FOUR-EXITS'
LEGACY_TAG = 'vless-entry208-legacy-us2'


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


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True)
    if result.returncode:
        save('command-error', {'program': args[0], 'status': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Command failed; diagnostics are root-only: ' + args[0])
    return result.stdout
