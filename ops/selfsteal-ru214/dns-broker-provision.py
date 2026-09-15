"""Local operator helper: token via hidden prompt, public key via a file, SSH stdin."""
import getpass
import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    commit, public_path = sys.argv[1:]
    assert re.fullmatch('[0-9a-f]{40}', commit)
    public = Path(public_path).read_text().strip()
    token = getpass.getpass('Cloudflare token (hidden): ')
    try:
        payload = json.dumps({'token': token, 'public_key': public})
        remote = '/opt/selfsteal-ru214-release/' + commit + '/ops/selfsteal-ru214/dns-broker-install.py'
        result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
            'hamvpn-panel-via-jump', 'python3', remote], input=payload, text=True,
            capture_output=True, timeout=90)
    finally:
        token = None; payload = None
    print(result.stdout, end=''); print(result.stderr, end='', file=sys.stderr)
    raise SystemExit(result.returncode)


if __name__ == '__main__': main()
