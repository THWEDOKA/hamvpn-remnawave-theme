import hashlib
import json
import os
from pathlib import Path
import subprocess

STATE = Path('/root/ham-reverse-pl2-20260918')


def require(ok, why):
    if not ok: raise RuntimeError(why)


def sha(obj): return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def write(path, data, mode=0o600):
    path = Path(path)
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'Symlink destination')
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.pl2-pending')
    with pending.open('xb') as f:
        os.chmod(pending, mode); f.write(data.encode() if isinstance(data, str) else data); f.flush(); os.fsync(f.fileno())
    pending.replace(path)


def save(name, value):
    STATE.mkdir(mode=0o700, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'Unsafe state')
    write(STATE / (name + '.json'), json.dumps(value, ensure_ascii=False))


def read(name):
    p = STATE / (name + '.json')
    require(p.stat().st_uid == 0 and p.stat().st_mode & 0o077 == 0 and not p.is_symlink(), 'Unsafe file')
    return json.loads(p.read_text())


def run(*args, data=None, timeout=40):
    p = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        save('last-error', {'program': args[0], 'code': p.returncode,
                           'stdout': p.stdout.decode(errors='replace'), 'stderr': p.stderr.decode(errors='replace')})
        raise RuntimeError('Command failed; diagnostics restricted to state: ' + args[0])
    return p.stdout


def cli(actions):
    import argparse, sys
    os.umask(0o077)
    try:
        require(os.geteuid() == 0, 'Root required')
        p = argparse.ArgumentParser(); p.add_argument('action', choices=list(actions)); a = p.parse_args()
        print(json.dumps(actions[a.action]()))
    except Exception as e:
        print(json.dumps({'failed': True, 'type': type(e).__name__,
                          'detail': str(e) if isinstance(e, RuntimeError) else 'Private details suppressed'})); sys.exit(1)
