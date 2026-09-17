"""Public rollout constants and root-only runtime state."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-ru140-entry-20260917')
ENTRY = '176.108.245.140'
NODES = json.loads((ROOT / 'nodes.json').read_text(encoding='utf-8'))
DOMAIN = NODES[0]['domain']
NAME = 'HAM-RU140-ENTRY-SELFSTEAL'
IMAGE = 'remnawave/node@sha256:9d57375a8168d00252f4debe7a6ac29debd8449af60467ab26b4ee212b047525'
TIMER = 'ham-ru140-hosts-rollback'


def save(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = STATE / (name + '.json')
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temp.chmod(0o600); temp.replace(path)


def read(name): return json.loads((STATE / (name + '.json')).read_text())
def exists(name): return (STATE / (name + '.json')).exists()
def ids(s): return [i['uuid'] for i in s['inbounds']]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def run(*args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, text=True)
    if p.returncode:
        save('last-command-error', {'command': list(args), 'returncode': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr})
        raise RuntimeError('Command failed: ' + args[0] + '; details in private state')
    return p.stdout


def assert_ip(ip):
    assert ip + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong server'


def binding(n):
    p = n.get('configProfile')
    return None if not p else {'profile': p['activeConfigProfileUuid'], 'inbounds': [i['uuid'] for i in p['activeInbounds']]}
