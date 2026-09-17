"""Restricted loopback forward for DE182's verified Paramiko-compatible path."""
import argparse
import logging
from pathlib import Path
import select
import socket
import threading
import time
import paramiko
from common import NODES


def forward(local,transport,slots):
    channel=None
    try:
        local.settimeout(30)
        channel=transport.open_channel('direct-tcpip',('127.0.0.1',443),local.getpeername(),timeout=15)
        channel.settimeout(30)
        while transport.is_active():
            readers,_,_=select.select([local,channel],[],[],15)
            if not readers and channel.closed:break
            for source in readers:
                data=source.recv(65536)
                if not data:return
                (channel if source is local else local).sendall(data)
    except (OSError,EOFError,paramiko.SSHException):pass
    finally:
        if channel:channel.close()
        local.close();slots.release()


def main():
    logging.getLogger('paramiko').setLevel(logging.CRITICAL)
    p=argparse.ArgumentParser();p.add_argument('--id',choices=['de182'],required=True);a=p.parse_args()
    n=next(n for n in NODES if n['id']==a.id)
    client=paramiko.SSHClient();client.load_host_keys('/etc/hamvpn-entry140/known_hosts')
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    sock=socket.create_connection((n['ip'],22),timeout=10)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_KEEPALIVE,1)
    for key,value in [(socket.TCP_KEEPIDLE,15),(socket.TCP_KEEPINTVL,5),(socket.TCP_KEEPCNT,3)]:
        sock.setsockopt(socket.IPPROTO_TCP,key,value)
    if hasattr(socket,'TCP_USER_TIMEOUT'):sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_USER_TIMEOUT,45000)
    try:
        client.connect(n['ip'],username='ham-entry140',key_filename='/etc/hamvpn-entry140/'+n['id'],
            sock=sock,look_for_keys=False,allow_agent=False,timeout=10,banner_timeout=10,auth_timeout=15)
        transport=client.get_transport();transport.set_keepalive(15)
        slots=threading.BoundedSemaphore(1024)
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            listener.bind(('127.0.0.1',n['link']));listener.listen(256);listener.settimeout(3)
            print('Authenticated restricted DE182 link ready',flush=True)
            while transport.is_active():
                try:local,_=listener.accept()
                except socket.timeout:continue
                if not slots.acquire(blocking=False):local.close();continue
                threading.Thread(target=forward,args=(local,transport,slots),daemon=True).start()
        raise RuntimeError('Exit transport disconnected; supervisor will reconnect')
    finally:client.close();sock.close()


if __name__=='__main__':main()
