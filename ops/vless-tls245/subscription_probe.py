"""Verify actual public Happ output using only the disposable deployment user."""
import json
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import panel_deploy as rollout


def main():
    api, _ = rollout.create_client()
    intent = rollout.read('test-user')
    sub = api('GET', '/api/subscriptions/by-uuid/' + intent['uuid'])
    assert sub['isFound']
    headers = {'User-Agent': 'Happ/3.11.0', 'X-Hwid': 'hamvpn-tls245-deployment-probe',
        'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'}
    request = urllib.request.Request(sub['subscriptionUrl'], headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        configs = json.load(response)
        assert response.status == 200 and isinstance(configs, list)
    matches = [c for c in configs if c.get('remarks') == rollout.NAME]
    assert len(matches) == 1, 'Host missing or duplicated in public subscription'
    config = matches[0]
    targets = [o for o in config['outbounds'] if o.get('protocol') == 'vless'
        and any(v.get('address') == rollout.DOMAIN for v in o.get('settings', {}).get('vnext', []))]
    assert len(targets) == 1
    outbound = targets[0]
    server, = outbound['settings']['vnext']
    assert server['port'] == 443
    assert server['users'][0]['id'] and server['users'][0]['flow'] == 'xtls-rprx-vision'
    stream = outbound['streamSettings']
    assert stream['security'] == 'tls' and stream['network'] in ('tcp', 'raw')
    assert stream['tlsSettings']['serverName'] == rollout.DOMAIN
    assert not stream['tlsSettings'].get('allowInsecure', False)
    assert 'realitySettings' not in stream
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    # Retain the exact subscription's protocol, user, flow and TLS settings.
    # Only local test ingress/routing are simplified to make egress deterministic.
    probe = {'log': {'loglevel': 'warning'}, 'inbounds': [{
        'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
        'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [outbound]}
    with tempfile.TemporaryDirectory(prefix='subscription-', dir=rollout.STATE) as directory:
        path = Path(directory) / 'client.json'
        path.write_text(json.dumps(probe))
        path.chmod(0o600)
        proc = subprocess.Popen([rollout.XRAY, 'run', '-c', str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):
                assert proc.poll() is None
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            curl = ['curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:' + str(port),
                '-fsS', '--connect-timeout', '10', '--max-time', '20']
            response = subprocess.run(curl + ['-o', '/dev/null', '-w', '%{http_code}',
                'https://www.gstatic.com/generate_204'], capture_output=True, text=True)
            egress = subprocess.run(curl + ['https://api.ipify.org'], capture_output=True, text=True)
            assert response.returncode == 0 and response.stdout == '204'
            assert egress.returncode == 0 and egress.stdout.strip() == rollout.IP
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    result = {'public_subscription_http': 200, 'configs': len(configs), 'host_count': 1,
        'host': rollout.NAME, 'security': 'tls', 'flow': 'xtls-rprx-vision',
        'certificate_verification': True, 'exact_subscription_outbound_probe': True,
        'egress_http': 204, 'exit_ip': rollout.IP, 'timestamp': time.time()}
    rollout.save('subscription-proof', result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
