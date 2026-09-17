"""Scoped node inventory and stdin-only installed-core checks; no VPN mutation.

Normal output contains only health/proof fields. Private diagnostics, when
needed, remain in root-only records. Disposable SOCKS listeners bind loopback.
The active container/application is never restarted or reconfigured.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time

import preflight as p

TARGETS = {t['id']: t for t in p.TARGETS}
TARGETS['entry'] = dict(id='entry', ip=p.ENTRY, node=p.ENTRY_ID)


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=kwargs.pop('timeout', 25), **kwargs)


def context(identifier):
    p.require(identifier in TARGETS and os.geteuid() == 0, 'Approved node and root required')
    target = TARGETS[identifier]
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show']))
    p.require(target['ip'] in {a['local'] for i in addresses for a in i.get('addr_info', [])}, 'Node IP mismatch')
    container = json.loads(subprocess.check_output(['docker', 'inspect', 'remnanode']))[0]
    p.require(container['HostConfig']['NetworkMode'] == 'host' and container['State']['Running'], 'Running host-network node required')
    result = run(['docker', 'exec', 'remnanode', 'xray', 'version'])
    match = re.search(rb'Xray\s+([0-9][A-Za-z0-9.+_-]*)', result.stdout)
    p.require(result.returncode == 0 and match, 'Installed version unavailable')
    return dict(id=identifier, ip=target['ip'], node=target['node'], version=match.group(1).decode(), host_network=True)


def runtime(identifier):
    result = context(identifier)
    tcp = subprocess.check_output(['ss', '-H', '-lnt'], text=True)
    udp = subprocess.check_output(['ss', '-H', '-lnu'], text=True)
    endpoints = [line.split()[3] for line in (tcp + udp).splitlines() if len(line.split()) >= 4]
    ports = sorted({int(endpoint.rsplit(':', 1)[1]) for endpoint in endpoints
                    if endpoint.rsplit(':', 1)[-1].isdigit()})
    egress = run(['curl', '-4', '--noproxy', '*', '-fsS', '--connect-timeout', '5', '--max-time', '12', 'https://api.ipify.org'])
    exit_ip = egress.stdout.decode().strip() if egress.returncode == 0 else None
    if exit_ip is not None: ipaddress.IPv4Address(exit_ip)
    result.update(timestamp=time.time(), listening_ports=ports, backend_port=15444,
                  backend_port_free=15444 not in ports, egress_ip=exit_ip, egress_curl_code=egress.returncode)
    return result


def installed(identifier, request):
    result = context(identifier)
    config = request['config']
    p.require(request['sha256'] == p.digest(config), 'Candidate hash mismatch')
    check = run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
                input=p.encoded(config), timeout=40)
    result.update(sha256=request['sha256'], timestamp=time.time(), passed=check.returncode == 0,
                  returncode=check.returncode)
    if check.returncode:
        state = p.Store(Path('/root/hamvpn-cloud140-six-20260918/node-checks') / identifier)
        state.put('installed-failure-' + str(time.time_ns()), dict(stdout=check.stdout.decode(errors='replace'),
                  stderr=check.stderr.decode(errors='replace'), sha256=request['sha256']))
    return result


def validate_request(request):
    p.require(isinstance(request, dict) and re.fullmatch('[0-9a-f]{64}', request.get('sha256', '')), 'Proof hash required')
    items = request.get('items')
    p.require(isinstance(items, list) and 1 <= len(items) <= 16 and len({i['id'] for i in items}) == len(items), 'Nonempty unique probes required')
    for item in items:
        p.require(isinstance(item['id'], str) and re.fullmatch('[a-zA-Z0-9_-]{1,100}', item['id']), 'Invalid probe ID')
        ipaddress.IPv4Address(item['expected_egress'])
        outbound = item['outbound']
        p.require(outbound.get('protocol') == 'vless', 'Explicit VLESS probe required')
        destinations = outbound['settings']['vnext']
        p.require(len(destinations) == 1, 'Exactly one destination required')
        destination = destinations[0]
        p.require(destination['address'] in {t['ip'] for t in TARGETS.values()} | {'127.0.0.1'}, 'Foreign probe target')
        p.require(type(destination['port']) is int and 1 <= destination['port'] <= 65535, 'Invalid port')
        stream = outbound['streamSettings']
        p.require(stream.get('network') in ('raw', 'tcp'), 'Unsupported transport')
        security = stream.get('security')
        p.require(security in ('tls', 'reality', 'none'), 'Explicit security required')
        p.require(security != 'none' or destination['address'] == '127.0.0.1', 'Public unencrypted probe prohibited')
        p.require(not stream.get('tlsSettings', {}).get('allowInsecure', False), 'TLS verification required')
    return items


def listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.2): return True
    except OSError: return False


def one_probe(item, binary):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    config = dict(log=dict(loglevel='none'), inbounds=[dict(listen='127.0.0.1', port=port,
                  protocol='socks', settings=dict(auth='noauth', udp=False))], outbounds=[item['outbound']])
    result = dict(id=item['id'], started_at=time.time(),
                  wire_sha256=p.digest({k:v for k,v in item['outbound'].items() if k!='tag'}))
    process = subprocess.Popen([str(binary), 'run', '-c', 'stdin:'], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        process.stdin.write(p.encoded(config)); process.stdin.close()
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('Isolated core exited')
            if listening(port): break
            time.sleep(.1)
        else: raise RuntimeError('Isolated listener unavailable')
        base = ['curl', '-4', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                '-fsS', '--connect-timeout', '6', '--max-time', '14']
        http = run(base + ['-o', '/dev/null', '-w', '%{http_code}', 'https://www.gstatic.com/generate_204'])
        egress = run(base + ['https://api.ipify.org'])
        exit_ip = egress.stdout.decode().strip() if egress.returncode == 0 else None
        if exit_ip is not None: ipaddress.IPv4Address(exit_ip)
        result.update(http=http.stdout.decode().strip(), exit_ip=exit_ip, curl_codes=[http.returncode, egress.returncode])
        result['passed'] = result['http'] == '204' and result['curl_codes'] == [0, 0] and exit_ip == item['expected_egress']
    except Exception as error:
        result.update(passed=False, error=type(error).__name__)
    finally:
        process.terminate()
        try: process.wait(timeout=4)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=4)
        result['listener_removed'] = not listening(port)
        p.require(result['listener_removed'], 'Temporary listener did not close')
    result['timestamp'] = time.time()
    return result


def traffic(identifier, request):
    result = context(identifier)
    items = validate_request(request)
    state = p.Store(Path('/root/hamvpn-cloud140-six-20260918/node-checks') / identifier)
    state.secure()
    with tempfile.TemporaryDirectory(prefix='traffic-', dir=state.path) as directory:
        binary = Path(directory) / 'xray'
        copied = run(['docker', 'cp', '-L', 'remnanode:/usr/local/bin/xray', str(binary)])
        p.require(copied.returncode == 0, 'Cannot stage installed binary')
        binary.chmod(0o700)
        with ThreadPoolExecutor(max_workers=2) as pool:
            tests = list(pool.map(lambda item: one_probe(item, binary), items))
    result.update(sha256=request['sha256'], timestamp=time.time(), tests=tests,
                  passed=all(item['passed'] for item in tests))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['runtime', 'installed', 'traffic'])
    parser.add_argument('--id', required=True, choices=sorted(TARGETS))
    args = parser.parse_args()
    result = runtime(args.id) if args.action == 'runtime' else globals()[args.action](args.id, json.load(sys.stdin))
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__, message='Node check stopped; configuration was not changed')), file=sys.stderr)
        sys.exit(1)
