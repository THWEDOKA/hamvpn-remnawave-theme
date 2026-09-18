"""Isolated installed-core tests and actual SOCKS probes; no live daemon edits."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def sha(obj): return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['test', 'probe'])
    parser.add_argument('--role', choices=['selectal', 'mws', 'panel'], required=True)
    parser.add_argument('--expected'); a = parser.parse_args(); data = json.load(sys.stdin)
    container = {'selectal': 'remnanode', 'mws': 'remnanode-ham-mws2'}.get(a.role)
    if a.action == 'test':
        r = subprocess.run(['docker', 'exec', '-i', container, 'xray', 'run', '-test', '-c', 'stdin:'],
                           input=json.dumps(data).encode(), capture_output=True, timeout=25)
        return {'tested': r.returncode == 0, 'sha256': sha(data), 'role': a.role}
    with tempfile.TemporaryDirectory(prefix='ham-auto-probe-') as directory:
        binary = str(Path(directory) / 'xray')
        if a.role == 'panel': binary = '/root/selfsteal-us3-test/xray'
        else:
            subprocess.run(['docker', 'cp', container + ':/usr/local/bin/xray', binary], check=True, capture_output=True)
            os.chmod(binary, 0o700)
        with socket.socket() as s: s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        cfg = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
               'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [data]}
        process = subprocess.Popen([binary, 'run', '-c', 'stdin:'], stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            process.stdin.write(json.dumps(cfg).encode()); process.stdin.close()
            for _ in range(40):
                if process.poll() is not None: raise RuntimeError('Isolated core exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            checks = []
            for name, url in [('204', 'https://www.gstatic.com/generate_204'),
                              ('egress', 'https://api.ipify.org'), ('page', 'https://www.wikipedia.org/')]:
                r = subprocess.run(['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                                    '-fsSL', '--max-time', '20', '-w', '\n%{http_code}', url], capture_output=True, timeout=25)
                body, _, code = r.stdout.rpartition(b'\n'); good = r.returncode == 0
                result = {'check': name, 'curl_code': r.returncode, 'http': code.decode(errors='replace')}
                if name == '204': good = good and code == b'204'
                elif name == 'page': good = good and code == b'200' and len(body) > 10000
                else:
                    try: ip = str(ipaddress.ip_address(body.strip().decode()))
                    except ValueError: ip = ''; good = False
                    result['egress'] = ip
                    good = good and (not a.expected or ip == a.expected)
                result.update(passed=bool(good), bytes=len(body)); checks.append(result)
            return {'passed': all(c['passed'] for c in checks), 'checks': checks, 'location': a.role,
                    'wire_sha256': sha(data), 'time': time.time()}
        finally:
            process.terminate()
            try: process.wait(timeout=4)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=4)
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1', port)) == 0: raise RuntimeError('Probe listener leaked')


if __name__ == '__main__':
    os.umask(0o077)
    try: print(json.dumps(main()))
    except Exception as e: print(json.dumps({'failed': True, 'type': type(e).__name__})); sys.exit(1)
