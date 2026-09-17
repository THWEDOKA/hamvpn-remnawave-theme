"""Add the already approved HAMVPN operator public key to the selected entry."""
import os
from pathlib import Path
import subprocess
from bootstrap208 import PUBLIC


def main():
    assert os.geteuid() == 0
    assert '193.233.222.244/' in subprocess.check_output(['ip', '-4', 'addr', 'show'], text=True)
    assert subprocess.check_output(['hostname'], text=True).strip() == 'piter.ptr.network'
    os.umask(0o077)
    state = Path('/root/hamvpn-entry244-20260917')
    state.mkdir(mode=0o700, exist_ok=True)
    directory = Path('/root/.ssh'); directory.mkdir(mode=0o700, exist_ok=True)
    authorized = directory / 'authorized_keys'
    before = authorized.read_bytes() if authorized.exists() else b''
    backup = state / 'authorized_keys.before'
    assert not backup.exists(), 'Previous intent exists; inspect state'
    backup.write_bytes(before); backup.chmod(0o600)
    if PUBLIC.split()[1].encode() not in before:
        after = before + (b'\n' if before and not before.endswith(b'\n') else b'') + PUBLIC.encode() + b'\n'
        temporary = directory / 'authorized_keys.entry244.pending'
        temporary.write_bytes(after); temporary.chmod(0o600); os.chown(temporary, 0, 0)
        temporary.replace(authorized)
    directory.chmod(0o700); authorized.chmod(0o600)
    os.chown(directory, 0, 0); os.chown(authorized, 0, 0)
    assert PUBLIC.split()[1].encode() in authorized.read_bytes()
    print('OPERATOR_KEY_READY_PREVIOUS_KEYS_PRESERVED')


if __name__ == '__main__': main()
