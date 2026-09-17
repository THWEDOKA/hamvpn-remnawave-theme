"""Operator transport; credentials stay in memory, host keys are always checked."""
import argparse
import getpass
import json
from pathlib import Path
import socket
import ssl
import sys
import time

import paramiko

ENTRY = '193.233.90.137'
EXITS = ['217.60.68.182', '31.56.188.150', '94.183.255.82', '62.60.226.94']


def connection(address, password=None, sock=None):
    client = paramiko.SSHClient()
    client.load_host_keys(str(Path.home() / '.ssh/known_hosts'))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(address, username='root', password=password, sock=sock,
        key_filename=None if password else str(Path.home() / '.ssh/hamvpn-panel'),
        allow_agent=False, look_for_keys=False, timeout=12, banner_timeout=12, auth_timeout=12)
    return client


def command(client, value, data=None, timeout=55):
    stdin, out, err = client.exec_command(value, timeout=timeout)
    if data is not None: stdin.write(data)
    stdin.channel.shutdown_write()
    try:
        stdout, stderr = out.read(), err.read()
        code = out.channel.recv_exit_status()
    except socket.timeout:
        out.channel.close()
        raise RuntimeError('Unknown remote outcome; inspect actual state before retry') from None
    if code: raise RuntimeError('Remote command failed, exit ' + str(code))
    return stdout


def preflight(entry):
    for address in EXITS:
        channel = None
        client = None
        try:
            channel = entry.get_transport().open_channel('direct-tcpip', (address, 22), ('127.0.0.1', 0), timeout=12)
            client = connection(address, sock=channel)
            result = command(client, 'printf SSH_AUTHENTICATED', timeout=15)
            print(json.dumps({'exit': address, 'entry_to_exit_ssh_authenticated': result == b'SSH_AUTHENTICATED'}), flush=True)
        except Exception as error:
            print(json.dumps({'exit': address, 'entry_to_exit_ssh_authenticated': False, 'error': type(error).__name__, 'detail': str(error)[:200]}), flush=True)
        finally:
            if client: client.close()
            if channel: channel.close()


def relay_preflight(entry):
    """Read-only trial of the owner's DE94 as a transport hop; no keys copied."""
    channel = entry.get_transport().open_channel('direct-tcpip', (EXITS[-1], 22), ('127.0.0.1', 0), timeout=12)
    relay = connection(EXITS[-1], sock=channel)
    try:
        data = command(relay, "python3 -c 'import sys;sys.stdout.write(chr(65)*262144)'", timeout=15)
        assert len(data) == 262144 and data == b'A' * len(data)
        print(json.dumps({'entry_relay_256kib_transfer_verified': True}), flush=True)
        domains = ['de182.torcalc.ru', 'pl150.torcalc.ru', 'google.com', 'de94.torcalc.ru']
        for address, name in zip(EXITS, domains):
            stream = None
            try:
                stream = relay.get_transport().open_channel('direct-tcpip', (address, 443), ('127.0.0.1', 0), timeout=10)
                stream.settimeout(10)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_side=False, server_hostname=name)
                deadline = time.monotonic() + 20
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
                        assert data, 'Unexpected EOF'
                        incoming.write(data)
                tls.write(('GET / HTTP/1.1\r\nHost: ' + name + '\r\nConnection: close\r\n\r\n').encode())
                stream.sendall(outgoing.read())
                response = b''
                while b'\r\n' not in response:
                    assert time.monotonic() < deadline
                    try: response += tls.read(8192)
                    except ssl.SSLWantReadError:
                        pending = outgoing.read()
                        if pending: stream.sendall(pending)
                        data = stream.recv(65536)
                        assert data, 'Unexpected EOF'
                        incoming.write(data)
                print(json.dumps({'exit': address, 'via_entry_and_de94': True, 'tls': tls.version(), 'certificate_verified': True, 'http': response.split(b'\r\n')[0].decode('ascii')}), flush=True)
            except Exception as error:
                print(json.dumps({'exit': address, 'via_entry_and_de94': False, 'error': type(error).__name__, 'detail': str(error)[:200]}), flush=True)
            finally:
                if stream: stream.close()
    finally:
        relay.close()
        channel.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['preflight', 'relay-preflight'])
    args = parser.parse_args()
    password = getpass.getpass('Entry SSH password (hidden): ')
    try: entry = connection(ENTRY, password=password)
    finally: password = None
    try:
        if args.action == 'preflight': preflight(entry)
        else: relay_preflight(entry)
    finally: entry.close()


if __name__ == '__main__': main()
