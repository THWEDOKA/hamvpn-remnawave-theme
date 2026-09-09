#!/usr/bin/env python3
"""Authenticated check using a pre-existing active diagnostic account.

Supply {"test_client_uuid": "..."} on stdin; the ID must already be loaded on
this inbound. No API/user mutation or mTLS bypass is performed. Credentials
and the internal config URL are never printed or persisted in Git.
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


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
    supplied = json.load(sys.stdin)
    test_id = supplied['test_client_uuid']
    matches = [c for c in inbound['settings']['clients'] if c.get('id') == test_id]
    if len(matches) != 1:
        raise RuntimeError('The selected existing test account is not loaded exactly once.')
    flow = matches[0].get('flow', '')
    with socket.socket() as selected:
        selected.bind(('127.0.0.1', 0))
        socks_port = selected.getsockname()[1]
    client_config = {
        'log': {'loglevel': 'none'},
        'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                      'settings': {'auth': 'noauth'}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
            'address': '188.225.62.121', 'port': 9443,
            'users': [{'id': test_id, 'encryption': 'none', 'flow': flow}]}]},
            'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
                'serverName': reality['serverNames'][0], 'fingerprint': 'firefox',
                'publicKey': public_key, 'shortId': reality['shortIds'][0]}}}],
    }
    with tempfile.TemporaryDirectory(prefix='ham-uk-route-probe-', dir='/root') as temporary:
        client_file = Path(temporary) / 'client.json'
        client_file.write_text(json.dumps(client_config))
        run([binary, 'run', '-test', '-config', str(client_file)])
        client = None
        try:
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
                              'egress_country': fields.get('loc'), 'existing_test_account': True}), flush=True)
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
            print(json.dumps({'users_modified': False,
                              'diagnostic_client_stopped': client is None or client.poll() is not None}), flush=True)


if __name__ == '__main__':
    probe()
