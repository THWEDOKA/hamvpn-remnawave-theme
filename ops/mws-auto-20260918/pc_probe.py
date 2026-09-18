"""Actual generated mihomo subscription in an isolated Windows process."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import yaml

BINARY = Path('C:/Users/User/Documents/hamvpn/HamVPN-PC/extra/sidecar/mihomo.exe')


def probe(data):
    assert hashlib.sha256(data['raw'].encode()).hexdigest() == data['sha256']
    config = yaml.safe_load(data['raw'])
    proxies = [p for p in config['proxies'] if p['name'] == '⚡ Автовыбор Обхода']
    assert len(proxies) == 1
    proxy = proxies[0]
    assert (proxy['type'], proxy['server'], proxy['port']) == ('hysteria2', 'sc.hambot.ru', 4500)
    with socket.socket() as s: s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
    cfg = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False, 'log-level': 'silent',
           'mode': 'rule', 'tun': {'enable': False}, 'dns': {'enable': False}, 'ipv6': False,
           'proxies': [proxy], 'rules': ['MATCH,' + proxy['name']]}
    raw = json.dumps(cfg, ensure_ascii=False).encode()
    with tempfile.TemporaryDirectory(prefix='ham-auto-mihomo-') as folder:
        test = subprocess.run([str(BINARY), '-t', '-d', folder, '-f', '-'], input=raw,
                 capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=20)
        assert test.returncode == 0
        p = subprocess.Popen([str(BINARY), '-d', folder, '-f', '-'], stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            p.stdin.write(raw); p.stdin.close()
            for _ in range(60):
                assert p.poll() is None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            checks = []
            for name, url in [('204', 'https://www.gstatic.com/generate_204'),
                              ('egress', 'https://api.ipify.org'), ('page', 'https://www.wikipedia.org/')]:
                q = subprocess.run(['curl.exe', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                    '-fsSL', '--max-time', '20', '-w', '\n%{http_code}', url], capture_output=True,
                    timeout=25, creationflags=subprocess.CREATE_NO_WINDOW)
                body, _, status = q.stdout.rpartition(b'\n')
                good = q.returncode == 0 and (status == b'204' if name == '204' else
                       body.strip() == b'72.56.101.218' if name == 'egress' else status == b'200' and len(body) > 10000)
                checks.append({'check': name, 'passed': good, 'curl_code': q.returncode,
                               'http': status.decode(), 'bytes': len(body)})
            return {'client': 'mihomo', 'passed': all(c['passed'] for c in checks), 'checks': checks,
                    'subscription_sha256': data['sha256'], 'binary_sha256': hashlib.sha256(BINARY.read_bytes()).hexdigest(),
                    'expected_egress': '72.56.101.218', 'time': time.time()}
        finally:
            p.terminate(); p.wait(timeout=5)
            with socket.socket() as s: assert s.connect_ex(('127.0.0.1', port)) != 0


if __name__ == '__main__':
    try: print(json.dumps(probe(json.load(sys.stdin))))
    except Exception as e: print(json.dumps({'failed': True, 'type': type(e).__name__})); sys.exit(1)
