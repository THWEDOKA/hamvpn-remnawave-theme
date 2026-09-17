"""Bounded loopback echo, not a proxy; prove the entire encrypted SSH channel."""
import argparse
import hashlib
import json
import os
import socket
import struct
import time
from preflight import save

SIZE = 262144
PORTS = {'kz2': 27443, 'de245': 28443}


def receive(sock, length):
    result = bytearray()
    while len(result) < length:
        data = sock.recv(min(65536, length - len(result)))
        if not data: raise RuntimeError('Incomplete transport probe')
        result.extend(data)
    return bytes(result)


def serve():
    deadline = time.monotonic() + 120
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 15443)); listener.listen(2); listener.settimeout(1)
        print('BOUNDED_LOOPBACK_ECHO_READY', flush=True)
        while time.monotonic() < deadline:
            try: connection, _ = listener.accept()
            except TimeoutError: continue
            with connection:
                connection.settimeout(12)
                try:
                    if receive(connection, 8) != b'HAMC140!': continue
                    if struct.unpack('!I', receive(connection, 4))[0] != SIZE: continue
                    data = receive(connection, SIZE)
                    connection.sendall(hashlib.sha256(data).digest() + data)
                except (OSError, RuntimeError): pass


def test(identifier):
    data = os.urandom(SIZE)
    started = time.monotonic()
    with socket.create_connection(('127.0.0.1', PORTS[identifier]), timeout=10) as connection:
        connection.settimeout(20)
        connection.sendall(b'HAMC140!' + struct.pack('!I', SIZE) + data)
        result = receive(connection, SIZE + 32)
        assert result[:32] == hashlib.sha256(data).digest() and result[32:] == data
    proof = dict(id=identifier, bidirectional_bytes=SIZE * 2, verified=True,
                 seconds=round(time.monotonic() - started, 3), timestamp=time.time())
    save('transport-' + identifier, proof)
    return proof


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['serve', 'test'])
    parser.add_argument('--id', choices=list(PORTS))
    args = parser.parse_args()
    if args.action == 'serve': serve()
    else:
        assert args.id
        print(json.dumps(test(args.id)))
