"""Fresh KZ-only disposable baseline probe; never changes routing or hosts.

Explicit export action contains a temporary identity and must be piped through
pinned SSH stdin without logging. All other actions return safe summaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import preflight as p

p.STATE = Path('/root/hamvpn-cloud140-kz2-repair-20260918')
p.NODES = [node for node in p.NODES if node['id'] == 'kz2']
assert len(p.NODES) == 1


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'export', 'cleanup'])
    args = parser.parse_args()
    api, query = p.create_client()
    if args.action == 'prepare':
        if not p.exists('before'):
            p.snapshot(api)
        assert hashlib.sha256((p.STATE / 'before.json').read_bytes()).hexdigest() == p.read('before-sha256')['sha256']
        p.account(api)
        result = dict(disposable_probe_ready=True, exit_id='kz2', vpn_unchanged=True)
    elif args.action == 'export':
        result = p.clients(api)
    else:
        result = p.cleanup(api, query)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'error': type(error).__name__, 'detail': 'Inspect protected KZ probe state before retry'}), file=sys.stderr)
        sys.exit(1)
