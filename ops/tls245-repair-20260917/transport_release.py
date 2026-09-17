"""Local release transport: private prompt, strict known-host check, no secrets saved."""
import argparse
import getpass
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import paramiko

SCOPE = 'ops/tls245-repair-20260917'


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['deploy', 'apply', 'status', 'diagnose', 'deep_inventory', 'rollback'])
    p.add_argument('--revision', required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    revision = subprocess.check_output(['git', 'rev-parse', args.revision + '^{commit}'], cwd=root, text=True).strip()
    origin = subprocess.check_output(['git', 'rev-parse', 'origin/main'], cwd=root, text=True).strip()
    assert revision == origin, 'Release must be the verified GitHub main state'
    release = '/opt/tls245-repair-20260917/' + revision[:12]
    client = paramiko.SSHClient()
    client.load_host_keys(str(Path.home() / '.ssh/known_hosts'))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    password = getpass.getpass('Node SSH password: ')
    try:
        client.connect('196.251.107.245', username='root', password=password,
            allow_agent=False, look_for_keys=False, timeout=10)
    finally:
        password = None
    def command(value):
        _, out, err = client.exec_command(value, timeout=120)
        stdout, stderr = out.read().decode(), err.read().decode()
        code = out.channel.recv_exit_status()
        if code:
            print(stderr, file=sys.stderr)
            raise RuntimeError(f'Remote command exit {code}')
        return stdout
    try:
        if args.action == 'deploy':
            archive = subprocess.check_output(['git', '-c', 'core.autocrlf=false', 'archive', '--format=tar', revision, SCOPE], cwd=root)
            digest = hashlib.sha256(archive).hexdigest()
            command('umask 077; mkdir -p /opt/tls245-repair-20260917; mkdir ' + release)
            with client.open_sftp() as sftp:
                sftp.putfo(io.BytesIO(archive), release + '/source.tar')
                sftp.chmod(release + '/source.tar', 0o600)
            assert command('sha256sum ' + release + '/source.tar').split()[0] == digest
            command('tar -xf ' + release + '/source.tar -C ' + release)
            print(json.dumps({'release': revision, 'archive_sha256': digest, 'directory': release}))
        else:
            script = args.action if args.action in ('diagnose', 'deep_inventory') else 'capacity'
            extra = '' if script != 'capacity' else ' ' + args.action
            print(command('python3 ' + release + '/' + SCOPE + '/' + script + '.py' + extra))
    finally:
        client.close()


if __name__ == '__main__': main()
