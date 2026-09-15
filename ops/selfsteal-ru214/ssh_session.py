"""Interactive operator transport; password is read without echo, never persisted."""
import base64
import getpass
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys

import paramiko


class AcceptFirstUse(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        print(json.dumps({'first_use_host': hostname, 'key_type': key.get_name(),
                          'fingerprint': 'SHA256:' + fingerprint}), flush=True)
        client.get_host_keys().add(hostname, key.get_name(), key)


def validate_candidate(ssh):
    panel_command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
                     'hamvpn-panel-via-jump', 'python3', '-']
    code = "from pathlib import Path; import sys; sys.stdout.buffer.write(Path('/root/selfsteal-ru214-panel/candidate.json').read_bytes())"
    result = subprocess.run(panel_command, input=code.encode(), capture_output=True, check=True)
    candidate = result.stdout
    digest = hashlib.sha256(candidate).hexdigest()
    path = '/root/selfsteal-ru214-backup/xray-candidate.json'
    sftp = ssh.open_sftp()
    try:
        with sftp.file(path, 'wb') as output: output.write(candidate)
        sftp.chmod(path, 0o600)
        command = ('docker cp ' + path + ' remnanode:/tmp/ru214-candidate.json && '
                   'docker exec remnanode chmod 600 /tmp/ru214-candidate.json && '
                   'docker exec remnanode xray run -test -c /tmp/ru214-candidate.json')
        _, stdout, stderr = ssh.exec_command(command, timeout=25)
        stdout.read(); stderr.read()
        passed = stdout.channel.recv_exit_status() == 0
    finally:
        _, stdout, stderr = ssh.exec_command('docker exec remnanode rm -f /tmp/ru214-candidate.json')
        stdout.read(); stderr.read(); stdout.channel.recv_exit_status()
        sftp.remove(path)
        sftp.close()
        candidate = None
    assert passed, 'Installed Xray rejected candidate; raw diagnostics suppressed'
    proof = json.dumps({'passed': passed, 'sha256': digest})
    code = "from pathlib import Path; p=Path('/root/selfsteal-ru214-panel/xray-test.json'); p.write_text(" + repr(proof) + "); p.chmod(0o600)"
    subprocess.run(panel_command, input=code.encode(), capture_output=True, check=True)
    return {'installed_xray_test_passed': passed, 'sha256': digest, 'temporary_candidates_removed': True}


def upload_release(ssh, commit):
    assert re.fullmatch('[0-9a-f]{40}', commit)
    repository = Path(__file__).resolve().parents[2]
    release = subprocess.check_output(['git', '-c', 'core.autocrlf=false', '-C', str(repository), 'archive', commit,
                                      'ops/selfsteal-ru214', 'ops/selfsteal-us3/panel_api.py'])
    path = '/root/ru214-release-' + commit + '.tar'
    with ssh.open_sftp() as sftp:
        with sftp.file(path, 'wb') as output: output.write(release)
        sftp.chmod(path, 0o600)
    return {'release_uploaded': commit, 'archive_sha256': hashlib.sha256(release).hexdigest(), 'path': path}


def main():
    known = Path.home() / '.ssh' / 'known_hosts'
    ssh = paramiko.SSHClient()
    ssh.load_host_keys(str(known))
    ssh.set_missing_host_key_policy(AcceptFirstUse())
    password = getpass.getpass('SSH password (hidden): ')
    try:
        ssh.connect('161.104.90.214', username='root', password=password,
                    allow_agent=False, look_for_keys=False, timeout=12,
                    banner_timeout=15, auth_timeout=15)
    finally:
        password = None
    ssh.save_host_keys(str(known))
    print(json.dumps({'connected': True, 'host': '161.104.90.214'}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        if request.get('quit'):
            break
        if request.get('validate_candidate'):
            print(json.dumps(validate_candidate(ssh)), flush=True)
            continue
        if request.get('upload_release'):
            print(json.dumps(upload_release(ssh, request['upload_release'])), flush=True)
            continue
        stdin, stdout, stderr = ssh.exec_command(request['command'],
                                               timeout=request.get('timeout', 55))
        if 'input' in request:
            stdin.write(request['input'])
        stdin.channel.shutdown_write()
        try:
            output = stdout.read().decode('utf-8', errors='replace')
            errors = stderr.read().decode('utf-8', errors='replace')
            status = stdout.channel.recv_exit_status()
        except socket.timeout:
            stdout.channel.close()
            print(json.dumps({'remote_outcome_unknown': True, 'reason': 'channel_timeout',
                              'next_step': 'Inspect actual remote state before retrying'}), flush=True)
            continue
        print(json.dumps({'exit_code': status, 'stdout': output, 'stderr': errors}), flush=True)
    ssh.close()


if __name__ == '__main__':
    main()
