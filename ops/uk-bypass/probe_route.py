#!/usr/bin/env python3
"""Short-lived authenticated check through the unchanged Russian ingress.

No panel user is created. A random runtime-only VLESS user is removed in finally.
Credentials and the internal config URL are never printed or persisted in Git.
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


def run(args, input=None):
    result = subprocess.run(args, input=input, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Diagnostic subprocess failed; output suppressed to protect credentials.')
    return result.stdout


def probe():
    os.umask(0o077)
    processes = run(['docker', 'top', 'remnanode', '-eo', 'pid,comm']).decode().splitlines()[1:]
    candidates = [line.split()[0] for line in processes if line.split()[1] in ('rw-core', 'xray')]
    if len(candidates) != 1:
        raise RuntimeError('Expected exactly one existing Xray core.')
    pid = candidates[0]
    binary = '/proc/' + pid + '/exe'
    node_pid = json.loads(run(['docker', 'inspect', 'remnanode']))[0]['State']['Pid']
    argv = Path('/proc/' + pid + '/cmdline').read_bytes().decode().split('\0')
    url = next(v for v in argv if v.startswith('http+unix://'))
    unix_path, route = url[len('http+unix://'):].split('/internal/', 1)
    config = json.loads(run(['curl', '-fsS', '--max-time', '10', '--unix-socket',
                             '/proc/' + str(node_pid) + '/root' + unix_path,
                             'http://localhost/internal/' + route]))
    inbound = next(i for i in config['inbounds'] if i['tag'] == 'VLESS_TCP_REALITY_GBD')
    if inbound['port'] != 7443:
        raise RuntimeError('Unexpected inbound; refusing to test a different route.')
    reality = inbound['streamSettings']['realitySettings']
    private = base64.urlsafe_b64decode(reality['privateKey'] + '===')
    der = bytes.fromhex('302e020100300506032b656e04220420') + private
    public = run(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], der)[-32:]
    public_key = base64.urlsafe_b64encode(public).decode().rstrip('=')
    canary_id = str(uuid.uuid4())
    canary_email = 'ham-uk-probe-' + uuid.uuid4().hex + '@local.invalid'
    flow = inbound['settings']['clients'][0].get('flow', '')
    with socket.socket() as selected:
        selected.bind(('127.0.0.1', 0))
        socks_port = selected.getsockname()[1]
    user = {'id': canary_id, 'email': canary_email, 'flow': flow}
    add_config = {'inbounds': [{'tag': inbound['tag'], 'protocol': 'vless',
                               'settings': {'clients': [user], 'decryption': 'none'}}]}
    client_config = {
        'log': {'loglevel': 'none'},
        'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                      'settings': {'auth': 'noauth'}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
            'address': '188.225.62.121', 'port': 9443,
            'users': [{'id': canary_id, 'encryption': 'none', 'flow': flow}]}]},
            'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                'serverName': reality['serverNames'][0], 'fingerprint': 'firefox',
                'publicKey': public_key, 'shortId': reality['shortIds'][0]}}}],
    }
    with tempfile.TemporaryDirectory(prefix='ham-uk-route-probe-', dir='/root') as temporary:
        add_file = Path(temporary) / 'add.json'
        client_file = Path(temporary) / 'client.json'
        add_file.write_text(json.dumps(add_config))
        client_file.write_text(json.dumps(client_config))
        run([binary, 'run', '-test', '-config', str(client_file)])
        client = None
        added = False
        try:
            run([binary, 'api', 'adu', '--server=127.0.0.1:61000', str(add_file)])
            added = True
            client = subprocess.Popen([binary, 'run', '-config', str(client_file)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(40):
                if client.poll() is not None:
                    raise RuntimeError('Diagnostic client stopped before the probe.')
                try:
                    with socket.create_connection(('127.0.0.1', socks_port), 0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            base = ['curl', '-fsS', '--max-time', '12', '--socks5-hostname',
                    '127.0.0.1:' + str(socks_port)]
            checks = []
            for url in ['https://www.google.com/generate_204', 'https://www.gstatic.com/generate_204']:
                code = run([*base, '-o', '/dev/null', '-w', '%{http_code}', url]).decode()
                checks.append({'url': url, 'status': int(code)})
                if code != '204':
                    raise RuntimeError('Unexpected HTTP status from authenticated route.')
            trace = run([*base, 'https://www.cloudflare.com/cdn-cgi/trace']).decode()
            fields = dict(line.split('=', 1) for line in trace.splitlines() if '=' in line)
            print(json.dumps({'checks': checks, 'egress_ip': fields.get('ip'),
                              'egress_country': fields.get('loc'), 'runtime_only_user': True}), flush=True)
            if fields.get('ip') != '51.194.229.165':
                raise RuntimeError('Unexpected exit IP.')
        finally:
            if client is not None:
                client.terminate()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait(timeout=5)
            cleanup = subprocess.run([binary, 'api', 'rmu', '--server=127.0.0.1:61000',
                                      '-tag=' + inbound['tag'], canary_email],
                                     capture_output=True, timeout=15)
            print(json.dumps({'runtime_user_removed': cleanup.returncode == 0,
                              'diagnostic_client_stopped': client is None or client.poll() is not None}), flush=True)
            if added and cleanup.returncode:
                raise RuntimeError('Runtime test user cleanup failed; manual removal required.')


if __name__ == '__main__':
    probe()
