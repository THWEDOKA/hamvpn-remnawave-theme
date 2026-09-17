"""Read-only, password-in-memory independent SSH/TLS preflight for entry244."""
import getpass
import argparse
import importlib.util
import json
from pathlib import Path
import ssl
import time
import paramiko

from common import NODES

spec = importlib.util.spec_from_file_location('diagnostic_transport', Path(__file__).resolve().parent.parent / 'ru137-entry-20260917/transport.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


def compact_connection(address, sock):
    def factory(connection, *args, **kwargs):
        transport = paramiko.Transport(connection, *args, **kwargs)
        options = transport.get_security_options()
        options.kex = ('curve25519-sha256@libssh.org',)
        options.key_types = ('ssh-ed25519',)
        options.ciphers = ('aes128-ctr',)
        options.digests = ('hmac-sha2-256-etm@openssh.com',)
        return transport
    client = paramiko.SSHClient()
    client.load_host_keys(str(Path.home() / '.ssh/known_hosts'))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(address, username='root', sock=sock, key_filename=str(Path.home() / '.ssh/hamvpn-panel'),
                   allow_agent=False, look_for_keys=False, timeout=12, banner_timeout=12,
                   auth_timeout=12, transport_factory=factory)
    return client


def check(entry, node, compact=False):
    channel = entry.get_transport().open_channel('direct-tcpip', (node['ip'], 22), ('127.0.0.1', 0), timeout=12)
    client = None
    stream = None
    try:
        client = compact_connection(node['ip'], channel) if compact else diagnostic.connection(node['ip'], sock=channel)
        data = diagnostic.command(client, "python3 -c 'import sys;sys.stdout.write(chr(65)*262144)'", timeout=20)
        assert data == b'A' * 262144
        stream = client.get_transport().open_channel('direct-tcpip', ('127.0.0.1', 443), ('127.0.0.1', 0), timeout=12)
        stream.settimeout(12)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_side=False, server_hostname=node['exit_sni'])
        deadline = time.monotonic() + 25
        while True:
            assert time.monotonic() < deadline
            try:
                tls.do_handshake()
                pending = outgoing.read()
                if pending: stream.sendall(pending)
                break
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending: stream.sendall(pending)
                data = stream.recv(65536)
                assert data
                incoming.write(data)
        tls.write(('GET / HTTP/1.1\r\nHost: ' + node['exit_sni'] + '\r\nConnection: close\r\n\r\n').encode())
        stream.sendall(outgoing.read())
        response = b''
        while b'\r\n' not in response:
            assert time.monotonic() < deadline
            try: response += tls.read(8192)
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending: stream.sendall(pending)
                data = stream.recv(65536)
                assert data
                incoming.write(data)
        return {'id': node['id'], 'ssh_authenticated': True, 'transfer_256kib': True,
                'trusted_tls': tls.version(), 'http': response.split(b'\r\n')[0].decode('ascii')}
    finally:
        if stream: stream.close()
        if client: client.close()
        channel.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--reverse', action='store_true')
    args = parser.parse_args()
    password = getpass.getpass('Entry244 SSH password (hidden): ')
    if args.reverse:
        try:
            for node in NODES:
                exit_client = incoming = reverse = None
                try:
                    exit_client = diagnostic.connection(node['ip'])
                    incoming = exit_client.get_transport().open_channel('direct-tcpip', ('193.233.222.244', 22), ('127.0.0.1', 0), timeout=12)
                    reverse = diagnostic.connection('193.233.222.244', password=password, sock=incoming)
                    data = diagnostic.command(reverse, "python3 -c 'import sys;sys.stdout.write(chr(65)*262144)'", timeout=20)
                    assert data == b'A' * 262144
                    print(json.dumps({'id': node['id'], 'reverse_ssh_authenticated': True, 'transfer_256kib': True}), flush=True)
                except Exception as exc:
                    print(json.dumps({'id': node['id'], 'reverse_ssh_authenticated': False, 'error': type(exc).__name__, 'detail': str(exc)[:160]}), flush=True)
                finally:
                    if reverse: reverse.close()
                    if incoming: incoming.close()
                    if exit_client: exit_client.close()
        finally: password = None
        return
    try: entry = diagnostic.connection('193.233.222.244', password=password)
    finally: password = None
    try:
        for node in NODES:
            try: result = check(entry, node, args.compact)
            except Exception as exc: result = {'id': node['id'], 'passed': False, 'error': type(exc).__name__, 'detail': str(exc)[:160]}
            print(json.dumps(result), flush=True)
    finally: entry.close()


if __name__ == '__main__': main()
