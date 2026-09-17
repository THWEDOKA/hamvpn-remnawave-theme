"""Reuse verified binary release transport with the explicitly authorized entry."""
from pathlib import Path
import transport

original_ssh = transport.ssh


def ssh(target):
    if target != 'entry':
        return original_ssh(target)
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
            '-o', 'ConnectTimeout=12', '-i', str(Path.home() / '.ssh/hamvpn-panel'),
            '-o', 'IdentitiesOnly=yes', 'root@162.141.185.208']


transport.ssh = ssh

if __name__ == '__main__':
    transport.main()
