"""Fresh real mihomo subscription; isolated temporary core, never the active VPN."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import yaml
import orchestrate as op
import transport as t
import model as m

CORE = Path('C:/Users/User/Documents/hamvpn/HamVPN-PC/extra/sidecar/mihomo.exe')


def check(revision):
    op.DIR = op.directory(revision)
    code = '''import sys,json,urllib.request
sys.path.insert(0,DIR)
from panel import client,read
api,_=client();u=read('probe');s=api('GET','/api/subscriptions/by-uuid/'+u['uuid'])
req=urllib.request.Request(s['subscriptionUrl'],headers={'User-Agent':'mihomo/1.19.29','X-Hwid':'ham-rs633-de3-owned-probe','X-Device-Os':'iOS','X-Device-Model':'Deployment probe','X-Ver-Os':'18'})
with urllib.request.urlopen(req,timeout=25) as r:sys.stdout.buffer.write(r.read())
'''.replace('DIR', repr(op.DIR))
    exported = yaml.safe_load(t.remote('panel', 'python3 -', code.encode()))
    matches = [p for p in exported['proxies'] if p.get('server') == '193.233.222.244' and p.get('port') == m.CLIENT_PORT]
    assert matches and all(p.get('client-fingerprint') == 'firefox' for p in matches)
    proxy = next(p for p in matches if m.MAIN_LABEL in p['name'])
    proofs = []
    with tempfile.TemporaryDirectory(prefix='ham-de3-mihomo-') as folder:
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        cfg = {'mixed-port': port, 'allow-lan': False, 'bind-address': '127.0.0.1',
               'mode': 'rule', 'log-level': 'silent', 'ipv6': False, 'tun': {'enable': False},
               'dns': {'enable': False}, 'proxies': [proxy], 'rules': ['MATCH,' + proxy['name']]}
        config = Path(folder) / 'probe.json'
        config.write_text(json.dumps(cfg, ensure_ascii=False), encoding='utf-8')
        proc = subprocess.Popen([str(CORE), '-d', folder, '-f', str(config)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            for _ in range(100):
                assert proc.poll() is None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2): break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('Mihomo startup timeout')
            jobs = [('204-' + str(i), 'https://www.gstatic.com/generate_204') for i in range(3)]
            jobs += [('egress', 'https://api.ipify.org'), ('download', 'https://speed.cloudflare.com/__down?bytes=3145728')]
            for label, url in jobs:
                q = subprocess.run(['curl.exe', '--disable', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                    '-fsSL', '--connect-timeout', '7', '--max-time', '35', '-w', '\n%{http_code}', url], capture_output=True, timeout=40)
                body, _, status = q.stdout.rpartition(b'\n')
                passed = q.returncode == 0 and (status == b'204' if label.startswith('204') else
                    body.strip() == m.EXIT.encode() if label == 'egress' else status == b'200' and len(body) >= 3145728)
                proofs.append({'check': label, 'passed': passed, 'code': q.returncode, 'bytes': len(body)})
                if not passed: break
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
            with socket.socket() as sock: assert sock.connect_ex(('127.0.0.1', port)) != 0
    result = {'passed': len(proofs) == 5 and all(p['passed'] for p in proofs), 'checks': proofs,
              'location': 'operator-windows-isolated-mihomo', 'time': time.time(),
              'core_sha256': hashlib.sha256(CORE.read_bytes()).hexdigest(), 'fingerprint': 'firefox',
              'proxy_sha256': hashlib.sha256(json.dumps(proxy, sort_keys=True).encode()).hexdigest()}
    op.put('panel', 'pc-proof', result)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('--release', required=True); a = p.parse_args()
    print(json.dumps(check(a.release)))
