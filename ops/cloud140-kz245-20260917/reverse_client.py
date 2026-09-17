"""One pinned SSH identity/listener, fixed local target; no shell or exec."""
import argparse
import logging
import select
import socket
import threading
import time
import paramiko
from reverse import ENTRY, NODES, KEY_DIR, TARGET, guard, require

MAX_CHANNELS = 256
IDLE_TIMEOUT = 300
HALF_CLOSE_TIMEOUT = 30


def relay(channel, slots):
    target = None
    try:
        target = socket.create_connection(TARGET, timeout=10)
        target.settimeout(30); channel.settimeout(30)
        active = [target, channel]; last_data = time.monotonic(); half_closed = None
        while active and not channel.closed:
            now = time.monotonic()
            if now - last_data >= IDLE_TIMEOUT or (half_closed is not None and now - half_closed >= HALF_CLOSE_TIMEOUT): break
            readers, _, _ = select.select(active, [], [], 5)
            for source in readers:
                data = source.recv(65536)
                if not data:
                    active.remove(source)
                    if half_closed is None: half_closed = time.monotonic()
                    if source is target: channel.shutdown_write()
                    else: target.shutdown(socket.SHUT_WR)
                    continue
                (channel if source is target else target).sendall(data)
                last_data = time.monotonic()
    except (OSError, EOFError, ValueError, paramiko.SSHException): pass
    finally:
        try:
            if target: target.close()
        finally:
            try: channel.close()
            finally: slots.release()


def incoming_handler(node, slots):
    def incoming(channel, origin, destination):
        if destination != ('127.0.0.1', node['link']): channel.close(); return
        if not slots.acquire(blocking=False): channel.close(); return
        try: threading.Thread(target=relay, args=(channel, slots), daemon=True).start()
        except Exception:
            try: channel.close()
            finally: slots.release()
    return incoming


def connect_and_forward(node):
    client = paramiko.SSHClient(); raw = None
    try:
        client.load_host_keys(str(KEY_DIR / 'known_hosts'))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        raw = socket.create_connection((ENTRY, 22), timeout=10)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in [('TCP_KEEPIDLE', 15), ('TCP_KEEPINTVL', 5), ('TCP_KEEPCNT', 3), ('TCP_USER_TIMEOUT', 45000)]:
            if hasattr(socket, name): raw.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)
        client.connect(ENTRY, username=node['user'], sock=raw,
                       key_filename=str(KEY_DIR / 'reverse_key'), allow_agent=False, look_for_keys=False,
                       timeout=10, banner_timeout=12, auth_timeout=15)
        transport = client.get_transport()
        require(transport is not None and transport.is_authenticated(), 'SSH authentication failed')
        transport.set_keepalive(15)
        # Paramiko's global forwarding request otherwise has no reply deadline.
        deadline = threading.Timer(20, transport.close); deadline.daemon = True; deadline.start()
        try:
            actual = transport.request_port_forward('127.0.0.1', node['link'],
                handler=incoming_handler(node, threading.BoundedSemaphore(MAX_CHANNELS)))
        finally: deadline.cancel()
        require(actual == node['link'] and transport.is_active(), 'Reverse listener request failed')
        print('Restricted reverse channel authenticated', flush=True)
        while transport.is_active(): time.sleep(1)
        raise RuntimeError('SSH disconnected; supervisor will reconnect')
    finally:
        try: client.close()
        finally:
            if raw: raw.close()


def main():
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(); parser.add_argument('--id', required=True, choices=[n['id'] for n in NODES])
    args = parser.parse_args(); node = next(n for n in NODES if n['id'] == args.id)
    guard(node['ip'])
    require(paramiko.__file__.startswith('/usr/lib/python3/dist-packages/paramiko/'), 'Non-apt Paramiko runtime')
    connect_and_forward(node)


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print('Reverse channel stopped: ' + type(error).__name__, flush=True)
        raise SystemExit(1)
