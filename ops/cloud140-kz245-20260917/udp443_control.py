"""Port-443 diagnostic controller. NEVER modifies any firewall or VPN service.

Existing UDP443 permission and free port must be checked separately. Each
direction has a fresh secret/nonce, immutable intent and bounded listener.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from udp443_probe import load, p

c = load('cloud140_udp443_controller', 'udp_control.py')
c.probe = p
c.ROOT = Path('/root/hamvpn-cloud140-repair-20260918/udp443')
original_release = c.release_paths


def release_paths(expected_sha=None):
    original, _, _ = original_release()
    script = Path(__file__).absolute()
    child = script.with_name('udp443_probe.py')
    for file in (script, child):
        info = file.lstat()
        if (file.resolve() != file or file.parent != original.parent or info.st_uid != 0 or
                info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode)):
            raise c.ControlError('unsafe_udp443_release')
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    if expected_sha is not None and digest != expected_sha:
        raise c.ControlError('release_hash_mismatch')
    return script, child, digest


c.release_paths = release_paths


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'export-secret', 'cleanup-secret', 'launch-server', 'client'])
    parser.add_argument('--id', choices=list(c.PAIRS), required=True)
    parser.add_argument('--role', choices=list(p.IPS))
    args = parser.parse_args()
    if args.action in ('launch-server', 'client'):
        if not args.role: parser.error('--role is required')
        credentials = p.read_credentials(sys.stdin)
        result = (c.launch_server if args.action == 'launch-server' else c.client)(args.id, 443, args.role, credentials)
    else:
        result = {'prepare': c.prepare, 'export-secret': c.export_secret, 'cleanup-secret': c.cleanup_secret}[args.action](args.id, 443)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    try: main()
    except (c.ControlError, p.ProbeError) as error:
        print(json.dumps({'error': str(error), 'completed': False}), flush=True)
        sys.exit(2)
