"""Stage entry244 HTTP/local TLS without disturbing Xray; activation is separate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time

from entry244_common import ROOT, STATE, ENTRY, NODES, save, read, exists, run

STREAM = Path('/etc/nginx/modules-enabled/90-ham-entry244-stream.conf')
SITE = Path('/etc/nginx/sites-available/ham-entry244.conf')
DOMAIN = NODES[0]['domain']
TIMER = 'ham-entry244-nginx-rollback'
WEB = Path('/var/www/ham-entry244')
ENABLED = Path('/etc/nginx/sites-enabled/ham-entry244.conf')
FIREWALL = Path('/usr/local/sbin/ham-entry244-api-firewall')
FIREWALL_UNIT = Path('/etc/systemd/system/ham-entry244-api-firewall.service')
POLICY = Path('/usr/sbin/policy-rc.d')
PACKAGES = ('nginx', 'libnginx-mod-stream', 'certbot')
DOMAINS = tuple(n['domain'] for n in NODES)
PROOF_MAX_AGE = 1800


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def vpn_identity():
    return run('docker', 'inspect', '--format',
               '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}} {{.State.Running}} {{.HostConfig.NetworkMode}}',
               'remnanode').strip()


def public_443():
    result = run('ss', '-H', '-ltnp', 'sport = :443').strip()
    require(result and 'nginx' not in result, 'Existing VPN must own 443 before staging')
    return result


def check_staging_unchanged(identity, listener):
    require(vpn_identity() == identity, 'VPN identity changed; inspect before continuing')
    require(public_443() == listener, 'Public 443 listener changed during staging')


def local_tls():
    results = []
    for domain in DOMAINS:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2'])
        with socket.create_connection(('127.0.0.1', 9443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as secure:
                require(secure.version() == 'TLSv1.3' and secure.selected_alpn_protocol() == 'h2',
                        'Local TLS/ALPN validation failed')
                results.append({'sni': domain, 'tls': secure.version(), 'alpn': secure.selected_alpn_protocol()})
    return results


def site_config(tls=False):
    # Public selfsteal/render.py template, adapted to the verified four-name cert.
    names = ' '.join(DOMAINS)
    http = ('server {\n listen 80;\n server_name ' + names + ';\n'
            ' root /var/www/ham-entry244;\n index index.html;\n charset utf-8;\n server_tokens off;\n'
            ' location ^~ /.well-known/acme-challenge/ { root /var/www/acme; default_type text/plain; try_files $uri =404; }\n'
            ' location / { try_files $uri $uri/ =404; }\n location ~ /\\. { deny all; }\n}\n')
    if not tls:
        return http
    return http + ('server {\n listen 127.0.0.1:9443 ssl http2;\n server_name ' + names + ';\n'
                   ' root /var/www/ham-entry244;\n index index.html;\n charset utf-8;\n server_tokens off;\n'
                   ' ssl_certificate /etc/letsencrypt/live/' + DOMAIN + '/fullchain.pem;\n'
                   ' ssl_certificate_key /etc/letsencrypt/live/' + DOMAIN + '/privkey.pem;\n'
                   ' ssl_protocols TLSv1.2 TLSv1.3;\n ssl_session_cache shared:HAM244TLS:10m;\n'
                   ' ssl_session_timeout 1d;\n ssl_session_tickets off;\n'
                   ' add_header X-Content-Type-Options nosniff always;\n'
                   ' add_header Referrer-Policy no-referrer always;\n'
                   ' add_header Content-Security-Policy "default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'" always;\n'
                   ' location / { try_files $uri $uri/ =404; }\n location ~ /\\. { deny all; }\n}\n')


def install_packages():
    require(not POLICY.exists() and not POLICY.is_symlink(), 'Existing service policy; do not overwrite it')
    # Prevent package maintainer scripts from starting nginx or restarting services.
    policy = '#!/bin/sh\n# ham-entry244 staged package installation\nexit 101\n'
    write(POLICY, policy, 0o755)
    try:
        env = ('env', 'DEBIAN_FRONTEND=noninteractive', 'NEEDRESTART_MODE=l', 'NEEDRESTART_SUSPEND=1', 'LC_ALL=C')
        run(*env, 'apt-get', 'update')
        args = ('apt-get', '--no-upgrade', '--no-install-recommends', 'install', *PACKAGES)
        simulation = run(*env, *args, '--simulate')
        require(not re.search(r'^Inst \S+ \[|^Remv ', simulation, re.M), 'Package plan changes existing packages')
        run(*env, *args, '-y')
        run('systemctl', 'disable', '--now', 'certbot.timer')
    finally:
        require(POLICY.is_file() and POLICY.read_text() == policy, 'Service policy changed concurrently')
        POLICY.unlink()


def install_firewall():
    write(FIREWALL, (ROOT / 'firewall244.sh').read_text(), 0o700)
    unit = ('[Unit]\nDescription=Scoped HAM entry244 API restriction (TCP 2222 only)\n'
            'Before=docker.service nginx.service\nAfter=local-fs.target\n\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUMask=0077\n'
            'ExecStart=/usr/local/sbin/ham-entry244-api-firewall apply\n'
            'ExecStartPost=/usr/local/sbin/ham-entry244-api-firewall check\n'
            'ExecReload=/usr/local/sbin/ham-entry244-api-firewall apply\n\n'
            '[Install]\nWantedBy=multi-user.target\n')
    write(FIREWALL_UNIT, unit)
    run('systemd-analyze', 'verify', str(FIREWALL_UNIT))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', FIREWALL_UNIT.name)
    run(str(FIREWALL), 'check')
    run('systemctl', 'is-enabled', FIREWALL_UNIT.name)
    run('systemctl', 'is-active', FIREWALL_UNIT.name)


def write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.pending')
    require(not path.is_symlink() and not temp.exists() and not temp.is_symlink(), 'Unsafe or pending destination')
    with temp.open('x', encoding='utf-8', newline='\n') as handle:
        os.chmod(temp, mode)
        handle.write(text)
    temp.replace(path)


def prepare():
    require(ENTRY + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong entry server')
    require(not exists('prepared'), 'Already prepared; inspect state instead of repeating')
    for target in (SITE, STREAM, WEB, ENABLED, FIREWALL, FIREWALL_UNIT, POLICY):
        require(not target.exists() and not target.is_symlink(), 'Existing staging path; refusing to overwrite')
    require(not Path('/etc/nginx').exists(), 'Existing nginx installation needs a separate integration review')
    identity, listener = vpn_identity(), public_443()
    require(identity.endswith('true host'), 'Existing running remnanode must use host networking')
    for port, address in ((80, '0.0.0.0'), (9443, '127.0.0.1')):
        with socket.socket() as sock:
            sock.bind((address, port))
    require((ROOT / 'site/index.html').is_file() and (ROOT / 'firewall244.sh').is_file(), 'Release incomplete')
    require(not STATE.is_symlink(), 'Unsafe backup state directory')
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    require(not (STATE / 'before.tar').exists(), 'Previous backup exists; inspect interrupted preparation')
    paths = [p for p in ('etc/nginx', 'etc/letsencrypt', 'etc/ssh', 'opt/remnanode') if Path('/' + p).exists()]
    require('etc/ssh' in paths and 'opt/remnanode' in paths, 'Expected node paths missing')
    with (STATE / 'before.tar').open('xb'):
        (STATE / 'before.tar').chmod(0o600)
    run('tar', '-C', '/', '-czf', str(STATE / 'before.tar'), *paths)
    checksum = digest(STATE / 'before.tar')
    save('backup', {'sha256': checksum, 'firewall4': run('iptables-save'), 'firewall6': run('ip6tables-save'),
                    'vpn_identity': identity, 'public_443': listener, 'timestamp': time.time()})
    run('tar', '-tzf', str(STATE / 'before.tar'))
    require(digest(STATE / 'before.tar') == checksum, 'Backup integrity verification failed')
    install_packages()
    check_staging_unchanged(identity, listener)
    install_firewall()
    WEB.mkdir(mode=0o755); WEB.chmod(0o755)
    acme = Path('/var/www/acme')
    require(not acme.is_symlink(), 'Unexpected ACME webroot symlink')
    if not acme.exists():
        acme.mkdir(mode=0o755)
        acme.chmod(0o755)  # main's restrictive umask must not block HTTP-01 reads.
    require(acme.is_dir() and acme.stat().st_mode & 0o005 == 0o005, 'ACME webroot is not publicly readable/traversable')
    for source in (ROOT / 'site').iterdir():
        if source.is_file():
            shutil.copyfile(source, WEB / source.name); (WEB / source.name).chmod(0o644)
    http = site_config()
    write(SITE, http)
    ENABLED.symlink_to(SITE)
    # Keep the distro/default site (and any unrelated files) intact.
    run('nginx', '-t'); run('systemctl', 'enable', '--now', 'nginx')
    import http.client
    for domain in DOMAINS:
        connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
        try:
            connection.request('GET', '/', headers={'Host': domain})
            response = connection.getresponse()
            require(response.status == 200 and response.read(), 'HTTP website check failed')
        finally:
            connection.close()
    check_staging_unchanged(identity, listener)
    save('prepared', {'http': http, 'timestamp': time.time(), 'site_sha256': digest(SITE)})
    return {'backup_verified': True, 'backup_sha256': checksum, 'http_ready': True,
            'api_firewall_persistent': True, 'legacy_443_unchanged': True}


def certificate():
    require(ENTRY + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong entry server')
    require(exists('prepared') and not exists('certificate'), 'Preparation required or TLS already completed')
    require(exists('imported-certificate'), 'Transfer the existing four-name certificate securely first')
    require(digest(SITE) == read('prepared')['site_sha256'], 'Staged site changed concurrently')
    identity, listener = vpn_identity(), public_443()
    from cert244 import certificate_details
    details = certificate_details(Path('/etc/letsencrypt'))
    before = SITE.read_text()
    candidate = site_config(tls=True)
    write(SITE, candidate)
    try:
        run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
        checks = local_tls()
        check_staging_unchanged(identity, listener)
    except Exception:
        require(SITE.read_text() == candidate, 'TLS site changed concurrently; rollback refused')
        write(SITE, before)
        run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
        raise
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/ham-entry244-nginx')
    require(not hook.exists() and not hook.is_symlink(), 'Existing deploy hook; inspect before overwriting')
    write(hook, '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n', 0o755)
    run('sh', '-n', str(hook))
    run('sh', str(hook))
    # Do not start certbot before the coordinator has moved and checked DNS.
    save('certificate', {'details': details, 'tls_checks': checks, 'renewal_deferred_until_dns': True,
                         'site_sha256': digest(SITE), 'timestamp': time.time()})
    return {'certificate_valid': True, 'tls13_h2_all_four': True, 'legacy_443_unchanged': True, **read('certificate')}


def renew():
    require(exists('certificate'), 'Local TLS setup must pass first')
    # This action remains separate and is only called after coordinator DNS cutover.
    for domain in DOMAINS:
        for resolver in ('1.1.1.1', '8.8.8.8'):
            answers = run('dig', '@' + resolver, domain, 'A', '+short').split()
            require(answers == [ENTRY], 'Public DNS has not converged; no ACME request sent')
            require(not run('dig', '@' + resolver, domain, 'AAAA', '+short').strip(),
                    'Unexpected AAAA; no ACME request sent')
    require('--no-random-sleep-on-renew' in run('certbot', '--help', 'all'), 'Installed certbot lacks no-random-sleep option')
    run('certbot', 'renew', '--cert-name', DOMAIN, '--dry-run', '--run-deploy-hooks', '--no-random-sleep-on-renew')
    run('systemctl', 'enable', '--now', 'certbot.timer')
    save('renewal', {'passed': True, 'timestamp': time.time()})
    return {'renewal_dry_run_passed': True}


def test():
    config = json.load(sys.stdin); save('candidate', config)
    checksum = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    result = subprocess.run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
                             input=json.dumps(config), text=True, capture_output=True)
    save('xray-config-test', {'passed': result.returncode == 0, 'output': result.stdout + result.stderr,
                             'sha256': checksum, 'timestamp': time.time()})
    assert result.returncode == 0
    return {'installed_xray_test_passed': True, 'sha256': checksum}


def arm():
    require(exists('certificate') and not exists('nginx-rolled-back'), 'TLS required; previous rollback forbids arming')
    tested = read('xray-config-test')
    checksum = hashlib.sha256(json.dumps(read('candidate'), sort_keys=True).encode()).hexdigest()
    require(tested.get('passed') is True and tested.get('sha256') == checksum, 'Candidate does not match installed Xray test')
    proof = read('backend-probes')
    require(proof.get('all_passed') is True and 0 <= time.time() - proof.get('timestamp', 0) < PROOF_MAX_AGE,
            'Fresh successful backend probes required')
    results = proof.get('tests', [])
    require(len(results) == len(NODES) and {r.get('id') for r in results} == {n['id'] for n in NODES}
            and all(r.get('passed') is True for r in results), 'Every selected backend must pass')
    require(proof.get('candidate_sha256') == checksum, 'Backend proof does not match candidate')
    require(digest(SITE) == read('certificate')['site_sha256'], 'TLS site changed after validation')
    local_tls()
    run('systemd-run', '--unit=' + TIMER, '--on-active=30m', 'python3', str(ROOT / 'node244.py'), 'rollback')
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
    stream = 'stream {\n map $ssl_preread_server_name $entry244_backend {\n default 127.0.0.1:15443;\n'
    stream += ''.join(' ' + n['domain'] + ' 127.0.0.1:' + str(n['port']) + ';\n' for n in NODES)
    stream += ' }\n server { listen 443; listen [::]:443; ssl_preread on; proxy_pass $entry244_backend; proxy_connect_timeout 10s; proxy_timeout 1h; tcp_nodelay on; }\n}\n'
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
    require(read('renewal')['passed'] and not exists('nginx-rolled-back'), 'Renewal required; rollback must not have occurred')
    require(STREAM.is_file() and digest(STREAM) == read('stream-intent')['sha256'], 'Stream config changed or missing')
    run('systemctl', 'stop', TIMER + '.timer')
    for suffix in ('.timer', '.service'):
        status = subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + suffix], capture_output=True).returncode
        require(status == 3, 'Rollback unit not confirmed inactive; finish refused')
    require(not exists('nginx-rolled-back'), 'Rollback raced with finish')
    require(STREAM.is_file() and digest(STREAM) == read('stream-intent')['sha256'], 'Stream changed during finish')
    require(digest(SITE) == read('certificate')['site_sha256'], 'TLS site changed during finish')
    run('nginx', '-t')
    checks = local_tls()
    require(not exists('nginx-rolled-back') and STREAM.is_file()
            and digest(STREAM) == read('stream-intent')['sha256'], 'Rollback detected after final TLS checks')
    save('nginx-finished', {'timestamp': time.time(), 'tls_checks': checks})
    return {'entry_rollback_timer_inactive': True, 'entry_rollback_service_inactive': True, 'tls13_h2_all_four': True}


def probes():
    import probe
    probe.STATE = STATE
    probe.save = save
    items = json.load(sys.stdin)
    config = read('candidate')
    require(len(items) == len(NODES) and {i.get('id') for i in items} == {n['id'] for n in NODES},
            'Exactly four selected backend probes required')
    for item in items:
        selected = next(n for n in NODES if n['id'] == item['id'])
        outbound = next(o for o in config['outbounds'] if o['tag'] == 'exit-' + item['id'])
        require(item.get('ip') == selected['ip'] and item.get('outbound') == outbound, 'Probe does not match candidate backend')
    results = []
    for item in items:
        result = probe.test(item); results.append(result); print(json.dumps(result), flush=True)
    passed = (len(results) == len(NODES) and {r.get('id') for r in results} == {n['id'] for n in NODES}
              and all(r.get('passed') is True for r in results))
    checksum = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    save('backend-probes', {'all_passed': passed, 'tests': results, 'timestamp': time.time(), 'candidate_sha256': checksum})
    return {'all_passed': passed}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'certificate', 'renew', 'test', 'arm', 'activate', 'rollback', 'finish', 'probes'])
    args = parser.parse_args()
    print(json.dumps(globals()[args.action](), ensure_ascii=False))


if __name__ == '__main__': main()
