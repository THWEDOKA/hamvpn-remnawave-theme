"""Add the existing operator public key, preserving all authorized keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

PUBLIC = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImx4dGhMrybcEygPjrgS41p6xsDvH//6s5qVyFHOpaF HAMVPN-Codex-Bridge-Admin'


def main():
    assert os.geteuid() == 0
    addresses = subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    assert '162.141.185.208/' in addresses and '162.141.185.216/' in addresses
    assert subprocess.check_output(['hostname'], text=True).strip() == 'util-us-3'
    os.umask(0o077)
    state = Path('/root/hamvpn-entry208-20260917')
    state.mkdir(mode=0o700, exist_ok=True)
    ssh = Path('/root/.ssh')
    ssh.mkdir(mode=0o700, exist_ok=True)
    authorized = ssh / 'authorized_keys'
    old = authorized.read_bytes() if authorized.exists() else b''
    backup = state / 'authorized_keys.before'
    if not backup.exists():
        backup.write_bytes(old)
        backup.chmod(0o600)
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == hashlib.sha256(old).hexdigest()
    if PUBLIC.split()[1].encode() not in old:
        new = old + (b'\n' if old and not old.endswith(b'\n') else b'') + PUBLIC.encode() + b'\n'
        temporary = ssh / 'authorized_keys.entry208.pending'
        temporary.write_bytes(new)
        temporary.chmod(0o600)
        os.chown(temporary, 0, 0)
        temporary.replace(authorized)
    ssh.chmod(0o700)
    authorized.chmod(0o600)
    os.chown(ssh, 0, 0)
    os.chown(authorized, 0, 0)
    assert PUBLIC.split()[1].encode() in authorized.read_bytes()
    print(json.dumps({'operator_key_installed': True, 'previous_keys_preserved': True}))


if __name__ == '__main__':
    main()
