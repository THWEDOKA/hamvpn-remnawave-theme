"""Explicit AT/NL6 operator session, approved pinned keys, passwords only RAM.

No installation on startup; safe caller-owned commands use the reviewed SSH
relay. Passwords enter hidden getpass, never arguments, files or output.
"""
import argparse
import base64
import getpass
import json
from pathlib import Path
import subprocess
import sys

import diagnose_at as d


TARGETS = {
    'at': ('147.45.71.38', 'hamvpn-cloud140-six-known_hosts'),
    'nl6': ('31.76.9.211', 'hamvpn-at-nl6-known_hosts'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('targets', nargs='+', choices=tuple(TARGETS))
    args = parser.parse_args()
    assert len(set(args.targets)) == len(args.targets)
    pins = []
    for name in args.targets:
        ip, file = TARGETS[name]
        rows = (Path.home()/'.ssh'/file).read_text().splitlines()
        rows = [line for line in rows if line.startswith(ip+' ssh-ed25519 ')]
        assert len(rows) == 1, 'Exactly one approved ed25519 pin required'
        pins.extend(rows)
    access = {name: {'ip': TARGETS[name][0],
                     'password': getpass.getpass(name+' root password (hidden): ')}
              for name in args.targets}
    process = subprocess.Popen(d.o.transport.command('panel')+[d.o.encoded_command(d.o.RELAY)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding='utf-8')
    process.stdin.write(json.dumps(dict(access=access, hostkeys='\n'.join(pins)+'\n'))+'\n')
    process.stdin.flush()
    access = None
    assert process.stdout.readline().strip() == 'READY', 'Pinned relay unavailable'
    print('PINNED_RELAY_READY '+','.join(args.targets), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request.get('quit'):
                break
            assert request.get('id') in args.targets, 'Unapproved target'
            if request.get('source'):
                request['command'] = d.o.encoded_command(request.pop('source'))
            if request.get('panel_source'):
                request['input'] = base64.b64encode(d.o.transport.remote('panel',
                    d.o.encoded_command(request.pop('panel_source')))).decode()
            elif 'input_text' in request:
                request['input'] = base64.b64encode(request.pop('input_text').encode()).decode()
            process.stdin.write(json.dumps(request)+'\n')
            process.stdin.flush()
            result = json.loads(process.stdout.readline())
            raw = base64.b64decode(result.pop('stdout'))
            # Only JSON produced by intentionally safe remote commands is shown.
            if result['exit_code'] == 0:
                try:
                    result['result'] = json.loads(raw)
                except (ValueError, UnicodeError):
                    result['result'] = {'json_output': False, 'bytes': len(raw)}
            print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        process.stdin.write('{"quit":true}\n')
        process.stdin.flush()
        process.stdin.close()
        process.wait(timeout=20)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    try:
        main()
    except Exception:
        print('Pinned access stopped; private details suppressed', file=sys.stderr)
        sys.exit(1)
