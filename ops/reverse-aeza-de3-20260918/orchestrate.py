"""Explicit operator steps; private JSON only through pinned SSH memory pipes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import subprocess
import sys
import transport as t
from common import sha
import model as m


def directory(revision):
    assert len(revision) >= 12 and all(c in '0123456789abcdef' for c in revision)
    return '/opt/ham-reverse-de3/releases/' + revision[:12] + '/' + t.SCOPE


def call(role, module, action, payload=None):
    raw = payload if isinstance(payload, bytes) else None if payload is None else json.dumps(payload).encode()
    return json.loads(t.remote(role, 'python3 ' + DIR + '/' + module + '.py ' + action, raw))


def get(role, name):
    assert name.replace('-', '').isalnum()
    code = 'import sys,json;sys.path.insert(0,' + repr(DIR) + ');from common import read;print(json.dumps(read(' + repr(name) + ')))'
    return json.loads(t.remote(role, 'python3 -', code.encode()))


def put(role, name, value):
    assert name.replace('-', '').isalnum()
    code = 'import sys,json,os;os.umask(0o077);sys.path.insert(0,' + repr(DIR) + ');from common import save;save(' + repr(name) + ',json.load(sys.stdin))'
    # Payload never appears in command-line arguments or stdout.
    import base64
    command = "python3 -c 'import base64;exec(base64.b64decode(\"" + base64.b64encode(code.encode()).decode() + "\"))'"
    t.remote(role, command, json.dumps(value).encode())


def backups():
    for role in ['panel', 'entry', 'exit']:
        print(t.release(role), flush=True)
    print(call('panel', 'panel', 'prepare'), flush=True)
    for role in ['entry', 'exit']: print(call(role, 'ssh_setup', 'snapshot'), flush=True)
    for source, name, dest in [('panel', 'panel-before', 'entry'), ('entry', 'snapshot-entry', 'panel'), ('exit', 'snapshot-exit', 'panel')]:
        data = get(source, name)
        proof = call(dest, 'ssh_setup', 'mirror', {'name': name, 'data': data, 'sha256': sha(data)})
        print(call(source, 'panel' if source == 'panel' else 'ssh_setup', 'accept_backup', proof), flush=True)


def frontend(baseline=False):
    print(call('panel', 'panel', 'create_probe' if baseline else 'exports'), flush=True)
    wires = get('panel', 'export-wires')
    ips = {'main': m.EXIT, 'auto-member': m.EXIT, 'neighbor-18443': '217.60.68.182', 'neighbor-18444': '31.56.188.150', 'neighbor-18445': '94.183.255.82', 'neighbor-18446': '62.60.226.94'}
    def probe(item):
        label, wire = item
        proof = call('panel', 'probe', 'probe', {'location': 'panel', 'outbound': wire,
            'expected': ips[label], 'full': not label.startswith('neighbor-')})
        print(json.dumps({'path': label, 'proof': proof}), flush=True)
        return label, proof
    with ThreadPoolExecutor(max_workers=5) as pool: proofs = dict(pool.map(probe, wires.items()))
    put('panel', 'baseline-proofs' if baseline else 'frontend-proofs', proofs)
    return proofs


def ssh():
    print(call('exit', 'ssh_setup', 'generate'), flush=True)
    public = t.remote('exit', 'cat /var/lib/' + m.ACCOUNT + '/.ssh/id_ed25519.pub')
    print(call('entry', 'ssh_setup', 'identity', public), flush=True)
    public = t.remote('entry', 'cat /etc/ssh/ssh_host_ed25519_key.pub').decode().split()
    pinned = ('[' + m.ENTRY + ']:' + str(m.SSH_PORT) + ' ' + ' '.join(public[:2])).encode()
    print(call('exit', 'ssh_setup', 'install', pinned), flush=True)
    print(call('exit', 'ssh_setup', 'verify'), flush=True)
    print(call('entry', 'ssh_setup', 'listener'), flush=True)


def stage():
    proof = call('exit', 'probe', 'test', get('panel', 'plan')['exit'])
    assert proof['tested']; print(proof, flush=True)
    print(call('panel', 'panel', 'arm'), flush=True)
    print(call('panel', 'panel', 'stage', proof), flush=True)


def backend(restart=False):
    if restart: print(call('exit', 'ssh_setup', 'restart'), flush=True)
    print(call('entry', 'ssh_setup', 'listener'), flush=True)
    wire = get('panel', 'wire')
    proof = call('entry', 'probe', 'probe', {'location': 'entry', 'outbound': wire, 'expected': m.EXIT, 'full': True})
    print(proof, flush=True)
    assert proof['passed'], 'Backend failed: no cutover'
    print(call('panel', 'panel', 'accept_probe', proof), flush=True)


def apply():
    proof = call('entry', 'probe', 'test', get('panel', 'entry-candidate'))
    assert proof['tested']; print(proof, flush=True)
    print(call('panel', 'panel', 'apply', proof), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['backups', 'baseline', 'ssh', 'stage', 'backend', 'restart-backend', 'apply', 'frontend', 'finish', 'retire', 'cleanup'])
    p.add_argument('--release'); args = p.parse_args()
    revision = args.release or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=t.ROOT, text=True).strip()
    DIR = directory(revision)
    if args.action == 'baseline': frontend(True)
    elif args.action == 'frontend': frontend()
    elif args.action == 'restart-backend': backend(True)
    elif args.action == 'finish': print(call('panel', 'panel', 'finish', get('panel', 'frontend-proofs')))
    elif args.action == 'retire': print(call('exit', 'ssh_setup', 'retire_old', get('panel', 'finished')['result']))
    elif args.action == 'cleanup': print(call('panel', 'panel', 'cleanup'))
    else: globals()[args.action]()
