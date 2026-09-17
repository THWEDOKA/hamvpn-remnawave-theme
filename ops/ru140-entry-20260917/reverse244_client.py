"""One restricted reverse SSH listener; traffic can reach only this exit's 443."""
import argparse
import logging
import select
import socket
import threading
import time
import paramiko
from entry244_common import ENTRY, NODES

TARGET = ('127.0.0.1', 443)


def relay(channel, slots):
    target = None
    try:
        target = socket.create_connection(TARGET, timeout=10)
        target.settimeout(30); channel.settimeout(30)
        active = [target, channel]
        while active and not channel.closed:
            readers, _, _ = select.select(active, [], [], 15)
            for source in readers:
                data = source.recv(65536)
                if not data:
                    active.remove(source)
                    # Preserve the response tail after a TCP half-close in either direction.
                    if source is target: channel.shutdown_write()
                    else: target.shutdown(socket.SHUT_WR)
                    continue
                (channel if source is target else target).sendall(data)
    except (OSError, EOFError, ValueError, paramiko.SSHException): pass
    finally:
        try:
            if target: target.close()
        finally:
            try: channel.close()
            finally: slots.release()


def incoming_handler(node, slots):
    def incoming(channel, origin, destination):
        if destination != ('127.0.0.1', node['link']):
            channel.close(); return
        if not slots.acquire(blocking=False):
            channel.close(); return
        try:
            threading.Thread(target=relay, args=(channel, slots), daemon=True).start()
        except Exception:
            try: channel.close()
            finally: slots.release()
    return incoming


def connect_and_forward(node):
    client = paramiko.SSHClient(); client.load_host_keys('/etc/hamvpn-entry244/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    raw = None
    try:
        raw = socket.create_connection((ENTRY, 22), timeout=10)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in [('TCP_KEEPIDLE', 15), ('TCP_KEEPINTVL', 5), ('TCP_KEEPCNT', 3), ('TCP_USER_TIMEOUT', 45000)]:
            if hasattr(socket, name): raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)
        client.connect(ENTRY, username='ham-exits244', sock=raw,
                       key_filename='/etc/hamvpn-entry244/reverse_key', allow_agent=False, look_for_keys=False,
                       timeout=10, banner_timeout=12, auth_timeout=15)
        transport = client.get_transport()
        if transport is None or not transport.is_authenticated():
            raise RuntimeError('Reverse SSH authentication failed')
        transport.set_keepalive(15)
        slots = threading.BoundedSemaphore(1024)
        actual = transport.request_port_forward('127.0.0.1', node['link'], handler=incoming_handler(node, slots))
        if actual != node['link']: raise RuntimeError('Unexpected reverse listener port')
        print('Restricted reverse exit channel authenticated', flush=True)
        while transport.is_active(): time.sleep(1)
        raise RuntimeError('SSH transport disconnected; supervisor will reconnect')
    finally:
        try: client.close()
        finally:
            if raw: raw.close()


def main():
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(); parser.add_argument('--id', required=True, choices=[n['id'] for n in NODES])
    args = parser.parse_args()
    connect_and_forward(next(n for n in NODES if n['id'] == args.id))


if __name__ == '__main__': main()
