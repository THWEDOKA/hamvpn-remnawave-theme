"""Actual installed Xray probe without persistent client config or public proxy."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from preflight import STATE, save


def test(item, binary):
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
    config = dict(log=dict(loglevel='none'), inbounds=[dict(listen='127.0.0.1', port=port,
                  protocol='socks', settings=dict(auth='noauth', udp=False))], outbounds=[item['outbound']])
    # Host-network node: the disposable instance uses the SAME installed binary and namespace.
    proc = subprocess.Popen([str(binary), 'run', '-c', 'stdin:'],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.stdin.write(json.dumps(config).encode()); proc.stdin.close()
        for _ in range(60):
            if proc.poll() is not None: raise RuntimeError('Installed probe failed to start')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2): break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('Probe listener unavailable')
        base = ['curl', '-4', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                '-fsS', '--connect-timeout', '6', '--max-time', '12']
        code = subprocess.run(base + ['-o', '/dev/null', '-w', '%{http_code}', 'https://www.gstatic.com/generate_204'], capture_output=True, text=True)
        egress = subprocess.run(base + ['https://ifconfig.me/ip'], capture_output=True, text=True)
        return dict(id=item['id'], passed=code.returncode == egress.returncode == 0 and code.stdout == '204' and egress.stdout.strip() == item['ip'],
                    http=code.stdout, exit_ip=egress.stdout.strip() if egress.returncode == 0 else None,
                    curl_codes=[code.returncode, egress.returncode])
    finally:
        proc.terminate()
        try: proc.wait(timeout=4)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=4)
        with socket.socket() as verify:
            assert verify.connect_ex(('127.0.0.1', port)) != 0, 'Temporary probe still listening'


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('label'); args = p.parse_args()
    assert args.label.replace('-', '').isalnum()
    inspection = json.loads(subprocess.check_output(['docker', 'inspect', 'remnanode']))[0]
    assert inspection['HostConfig']['NetworkMode'] == 'host'
    items = json.load(sys.stdin); assert items
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='client-', dir=STATE) as directory:
        binary = Path(directory) / 'xray'
        subprocess.run(['docker', 'cp', '-L', 'remnanode:/usr/local/bin/xray', str(binary)], check=True, capture_output=True)
        binary.chmod(0o700)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda item: test(item, binary), items))
    proof = dict(timestamp=time.time(), tests=results, all_passed=all(r['passed'] for r in results))
    save('probe-' + args.label, proof)
    print(json.dumps(proof))


if __name__ == '__main__': main()
