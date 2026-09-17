"""Add self-steal sites and SNI passthrough while preserving the legacy TLS site."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time

from entry208_common import ROOT, STATE, ENTRY, NODES, save, read, exists, run

STREAM = Path('/etc/nginx/modules-enabled/90-ham-entry208-stream.conf')
SITE = Path('/etc/nginx/sites-available/ham-entry208.conf')
DOMAIN = NODES[0]['domain']
TIMER = 'ham-entry208-nginx-rollback'


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.pending')
    temp.write_text(text, encoding='utf-8'); temp.chmod(mode); temp.replace(path)


def prepare():
    assert ENTRY + '/' in run('ip', '-4', 'addr', 'show')
    assert not exists('prepared') and not SITE.exists() and not STREAM.exists()
    STATE.mkdir(mode=0o700, exist_ok=True)
    assert not (STATE / 'before.tar').exists()
    run('tar', '-C', '/', '-czf', str(STATE / 'before.tar'), 'etc/nginx', 'etc/letsencrypt', 'opt/remnanode/docker-compose.yml')
    (STATE / 'before.tar').chmod(0o600)
    save('backup', {'sha256': hashlib.sha256((STATE / 'before.tar').read_bytes()).hexdigest(),
                    'firewall': run('iptables-save')})
    run('tar', '-tzf', str(STATE / 'before.tar'))
    run('env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', '--no-install-recommends', 'libnginx-mod-stream')
    assert 'host' == run('docker', 'inspect', '--format', '{{.HostConfig.NetworkMode}}', 'remnanode').strip()
    for port in (9443, 11443, 12443, 13443, 14443, 15443):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    web = Path('/var/www/ham-entry208'); web.mkdir(mode=0o755, exist_ok=True); web.chmod(0o755)
    for source in (ROOT / 'site').iterdir():
        if source.is_file():
            shutil.copyfile(source, web / source.name); (web / source.name).chmod(0o644)
    http = 'server {\n listen 80;\n server_name ' + ' '.join(n['domain'] for n in NODES) + ';\n'
    http += ' location ^~ /.well-known/acme-challenge/ { root /var/www/acme; default_type text/plain; try_files $uri =404; }\n'
    http += ' location / { return 301 https://$host$request_uri; }\n}\n'
    write(SITE, http)
    Path('/etc/nginx/sites-enabled/ham-entry208.conf').symlink_to(SITE)
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    save('prepared', {'http': http, 'timestamp': time.time()})
    return {'backup_verified': True, 'http_ready': True, 'legacy_443_unchanged': True}


def certificate():
    assert exists('prepared') and not exists('certificate')
    args = ['certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
            '--webroot', '-w', '/var/www/acme', '--cert-name', DOMAIN, '--key-type', 'ecdsa']
    for n in NODES:
        args += ['-d', n['domain']]
    run(*args)
    tls = (ROOT / 'nginx-tls.conf').read_text().replace('127.0.0.1:8443', '127.0.0.1:9443')
    # That template includes its own HTTP server; use its TLS block only.
    start = tls.index('server {', tls.index('server {') + 1) if tls.count('server {') > 1 else 0
    tls = tls[start:].replace('/var/www/hamvpn-entry140', '/var/www/ham-entry208')
    tls = tls.replace('/var/www/ham-entry140', '/var/www/ham-entry208')
    tls = tls.replace('/var/www/in-de3.torcalc.ru', '/var/www/ham-entry208')
    write(SITE, read('prepared')['http'] + tls)
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    save('certificate', {'details': run('openssl', 'x509', '-in', '/etc/letsencrypt/live/' + DOMAIN + '/fullchain.pem', '-noout', '-dates', '-ext', 'subjectAltName')})
    for n in NODES:
        context = ssl.create_default_context(); context.set_alpn_protocols(['h2'])
        with socket.create_connection(('127.0.0.1', 9443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=n['domain']) as secure:
                assert secure.version() == 'TLSv1.3' and secure.selected_alpn_protocol() == 'h2'
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/ham-entry208-nginx')
    write(hook, '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/bin/systemctl reload nginx\n', 0o755)
    run('systemctl', 'enable', '--now', 'certbot.timer')
    return {'certificate_valid': True, 'tls13_h2_all_four': True, **read('certificate')}


def renew():
    run('certbot', 'renew', '--cert-name', DOMAIN, '--dry-run', '--run-deploy-hooks')
    save('renewal', {'passed': True, 'timestamp': time.time()})
    return {'renewal_dry_run_passed': True}


def test():
    config = json.load(sys.stdin); save('candidate', config)
    result = subprocess.run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
                             input=json.dumps(config), text=True, capture_output=True)
    save('xray-config-test', {'passed': result.returncode == 0, 'output': result.stdout + result.stderr})
    assert result.returncode == 0
    return {'installed_xray_test_passed': True, 'sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()}


def arm():
    assert exists('certificate') and read('xray-config-test')['passed']
    run('systemd-run', '--unit=' + TIMER, '--on-active=30m', 'python3', str(ROOT / 'node208.py'), 'rollback')
    return {'entry_rollback_armed': True}


def wait_listeners():
    deadline = time.monotonic() + 20
    while True:
        try:
            for port in (11443, 12443, 13443, 14443, 15443):
                with socket.create_connection(('127.0.0.1', port), timeout=0.5): pass
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError('New listeners not ready; router not written') from None
            time.sleep(0.25)


def activate():
    assert not STREAM.exists()
    wait_listeners()
    stream = 'stream {\n map $ssl_preread_server_name $entry208_backend {\n default 127.0.0.1:15443;\n'
    stream += ''.join(' ' + n['domain'] + ' 127.0.0.1:' + str(n['port']) + ';\n' for n in NODES)
    stream += ' }\n server { listen 443; listen [::]:443; ssl_preread on; proxy_pass $entry208_backend; proxy_connect_timeout 10s; proxy_timeout 1h; tcp_nodelay on; }\n}\n'
    save('stream-intent', {'sha256': hashlib.sha256(stream.encode()).hexdigest()})
    write(STREAM, stream)
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    return {'public_443_sni_router_active': True, 'legacy_default_preserved': True}


def rollback():
    if STREAM.exists():
        assert hashlib.sha256(STREAM.read_bytes()).hexdigest() == read('stream-intent')['sha256']
        STREAM.rename(STATE / 'rolled-back-stream.conf')
        run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    save('nginx-rolled-back', {'timestamp': time.time()})
    return {'router_removed': True, 'legacy_site_preserved': True}


def finish():
    assert read('renewal')['passed'] and STREAM.exists()
    run('systemctl', 'stop', TIMER + '.timer')
    assert subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer']).returncode != 0
    return {'entry_rollback_timer_inactive': True}


def probes():
    import probe
    probe.STATE = STATE
    probe.save = save
    items = json.load(sys.stdin)
    results = []
    for item in items:
        result = probe.test(item); results.append(result); print(json.dumps(result), flush=True)
    save('backend-probes', {'all_passed': all(r['passed'] for r in results), 'tests': results, 'timestamp': time.time()})
    return {'all_passed': all(r['passed'] for r in results)}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'certificate', 'renew', 'test', 'arm', 'activate', 'rollback', 'finish', 'probes'])
    args = parser.parse_args()
    print(json.dumps(globals()[args.action](), ensure_ascii=False))


if __name__ == '__main__': main()
