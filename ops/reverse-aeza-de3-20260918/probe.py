"""Real core and data-plane checks; explicit curl isolation and bounded lifetime."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from common import *


def test():
    cfg = json.load(sys.stdin)
    p = subprocess.run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
                       input=json.dumps(cfg).encode(), capture_output=True, timeout=30)
    if p.returncode: save('config-test-error', {'stdout': p.stdout.decode(errors='replace'), 'stderr': p.stderr.decode(errors='replace')})
    return {'tested': p.returncode == 0, 'sha256': sha(cfg)}


def probe():
    data = json.load(sys.stdin); location = data['location']; wire = data['outbound']
    require(location in ['entry', 'exit', 'panel'], 'Unknown location')
    with tempfile.TemporaryDirectory(prefix='ham-rs633-probe-') as folder:
        if location in ['entry', 'exit']:
            import model as m
            expected_server = m.ENTRY if location == 'entry' else m.EXIT
            require(expected_server + '/' in run('ip', '-4', 'addr', 'show').decode(), 'Probe role/server mismatch')
            d = json.loads(run('docker', 'inspect', 'remnanode'))[0]
            require(d['HostConfig']['NetworkMode'] == 'host', 'Wrong namespace')
            binary = str(Path(folder) / 'xray'); run('docker', 'cp', 'remnanode:/usr/local/bin/xray', binary); os.chmod(binary, 0o700)
        else: binary = '/root/selfsteal-us3-test/xray'
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        config = {'log': {'loglevel': 'none'}, 'inbounds': [{'protocol': 'socks', 'listen': '127.0.0.1',
                  'port': port, 'settings': {'auth': 'noauth'}}], 'outbounds': [wire]}
        p = subprocess.Popen([binary, 'run', '-c', 'stdin:'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            p.stdin.write(json.dumps(config).encode()); p.stdin.close()
            for _ in range(50):
                require(p.poll() is None, 'Probe core exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('Probe port not ready')
            checks = []
            jobs = [('204-' + str(i), 'https://www.gstatic.com/generate_204') for i in range(1, 4)]
            jobs += [('egress', 'https://api.ipify.org')]
            if data.get('full', True): jobs += [('download', 'https://speed.cloudflare.com/__down?bytes=3145728')]
            for label, url in jobs:
                q = subprocess.run(['curl', '--disable', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                    '-fsSL', '--connect-timeout', '7', '--max-time', '35', '-w', '\n%{http_code}', url], capture_output=True, timeout=40)
                body, _, status = q.stdout.rpartition(b'\n')
                good = q.returncode == 0 and (status == b'204' if label.startswith('204') else
                    body.strip().decode(errors='replace') == data['expected'] if label == 'egress' else
                    status == b'200' and len(body) >= 3145728)
                checks.append({'check': label, 'passed': good, 'curl_code': q.returncode,
                               'http': status.decode(errors='replace'), 'bytes': len(body)})
                if not good: break
            return {'passed': len(checks) == len(jobs) and all(c['passed'] for c in checks), 'checks': checks,
                    'expected_egress': data['expected'], 'location': location, 'namespace': 'host',
                    'wire_sha256': sha(wire), 'time': time.time()}
        finally:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
            with socket.socket() as s: require(s.connect_ex(('127.0.0.1', port)) != 0, 'Probe listener leaked')


if __name__ == '__main__': cli({'test': test, 'probe': probe})
