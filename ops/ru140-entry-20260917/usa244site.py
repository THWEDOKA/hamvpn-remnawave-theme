"""USA2-only DNS/HTTP-01/local TLS sidecar. Run DNS actions on the panel.

Order: dns; http; externally fetch returned challenge and hash its body;
certificate --external-proof SHA256; tls; verify. No automatic ACME retries.
Existing four-name TLS, public VPN listeners, shared site files are never edited.
"""
import argparse
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

DOMAIN, ENTRY, PORT = 'in-us2.torcalc.ru', '193.233.222.244', 19443
STATE = Path('/root/hamvpn-usa244-20260917')
SITE = Path('/etc/nginx/sites-available/ham-usa244.conf')
ENABLED = Path('/etc/nginx/sites-enabled/ham-usa244.conf')
WEB, ACME = Path('/var/www/ham-entry244'), Path('/var/www/acme')
LE = Path('/etc/letsencrypt')
CREDENTIALS = Path('/etc/hamvpn-dns-ru214/credentials.json')
HOOK = LE / 'renewal-hooks/deploy/ham-entry244-nginx'
HOOK_TEXT = '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n'


def require(ok, message):
    if not ok: raise RuntimeError(message)


def digest(data): return hashlib.sha256(data).hexdigest()
def exists(name): return (STATE / (name + '.json')).is_file()
def read(name): return json.loads((STATE / (name + '.json')).read_text())


def save(name, value):
    require(not STATE.is_symlink(), 'Unsafe state directory')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'State must be root-only')
    target = STATE / (name + '.json'); pending = target.with_suffix('.pending')
    with pending.open('x', encoding='utf-8') as stream:
        os.chmod(pending, 0o600); json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
    pending.replace(target)


def run(*args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        save('command-error', {'program': args[0], 'status': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Command failed; inspect private command-error.json')
    return result.stdout


def guard(entry=True):
    require(os.geteuid() == 0, 'Root required')
    if STATE.exists():
        require(not STATE.is_symlink() and STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0,
                'Unsafe private state')
    if entry: require(ENTRY + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong entry server')


def client():
    require(not CREDENTIALS.is_symlink() and CREDENTIALS.stat().st_uid == 0
            and CREDENTIALS.stat().st_mode & 0o077 == 0, 'Unsafe DNS credentials')
    credentials = json.loads(CREDENTIALS.read_text())
    require(re.fullmatch(r'[a-f0-9]{32}', credentials['zone_id']), 'Invalid DNS zone')
    base = 'https://api.cloudflare.com/client/v4/zones/' + credentials['zone_id'] + '/dns_records'
    def request(method, suffix='', body=None):
        req = urllib.request.Request(base + suffix, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + credentials['token'], 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=25) as response: value = json.load(response)
            require(value.get('success') is True, 'DNS provider rejected request')
            return value['result']
        except Exception:
            raise RuntimeError('DNS response failed/uncertain; read state before retry') from None
    return request


def dns_rows(request):
    return request('GET', '?' + urllib.parse.urlencode({'name': DOMAIN, 'per_page': 100}))


def wanted_record(marker):
    return {'name': DOMAIN, 'type': 'A', 'content': ENTRY, 'ttl': 300, 'proxied': False, 'comment': marker}


def matching(row, wanted): return all(row.get(k) == v for k, v in wanted.items())


def dns():
    guard(False); request = client(); rows = dns_rows(request)
    if exists('dns-intent'):
        intent = read('dns-intent')
        require(len(rows) == 1 and matching(rows[0], intent['wanted']),
                'Uncertain DNS intent: no blind repeat or adoption')
        if exists('dns-created'): require(rows[0]['id'] == read('dns-created')['created_id'], 'DNS record ID changed')
    else:
        require(not rows, 'Existing record at exact USA hostname; refusing creation')
        intent = {'before': [], 'wanted': wanted_record('ham-usa244-' + uuid.uuid4().hex), 'timestamp': time.time()}
        save('dns-intent', intent)  # Durable BEFORE POST; lost responses are reconciled only by GET.
        row = request('POST', body=intent['wanted'])
        require(matching(row, intent['wanted']) and row.get('id'), 'Unexpected created DNS record')
        save('dns-created', {'created_id': row['id']})
        rows = dns_rows(request)
        require(len(rows) == 1 and rows[0]['id'] == row['id'] and matching(rows[0], intent['wanted']), 'DNS readback failed')
    save('dns-created', {'created_id': rows[0]['id']})
    return {'domain': DOMAIN, 'address': ENTRY, 'dns_only': True, 'ttl': 300}


def dns_rollback():
    guard(False); request = client(); rows = dns_rows(request)
    require(exists('dns-created') and exists('dns-intent'), 'No confirmed owned DNS record')
    if rows:
        require(len(rows) == 1 and rows[0]['id'] == read('dns-created')['created_id']
                and matching(rows[0], read('dns-intent')['wanted']), 'Changed DNS record; rollback refused')
        request('DELETE', '/' + rows[0]['id'])
    require(not dns_rows(request), 'DNS rollback not confirmed')
    return {'owned_dns_removed': True}


def converged():
    for resolver in ('1.1.1.1', '8.8.8.8'):
        for kind in ('A', 'AAAA'):
            answer = run('dig', '@' + resolver, DOMAIN, kind, '+time=3', '+tries=1', '+noall', '+answer', '+comments')
            require('status: NOERROR,' in answer, 'DNS resolver response not successful')
            rows = [line.split() for line in answer.splitlines() if line and not line.startswith(';')]
            require((len(rows) == 1 and rows[0][-2:] == ['A', ENTRY]) if kind == 'A' else not rows,
                    'DNS not converged or unexpected AAAA/CNAME; no ACME request')


def site_config(tls=False):
    # Adapted from selfsteal renderer; reuse existing static files without rewriting them.
    config = (f'server {{\n listen 80;\n server_name {DOMAIN};\n root /var/www/ham-entry244;\n'
              ' index index.html; charset utf-8; server_tokens off;\n'
              ' location ^~ /.well-known/acme-challenge/ { root /var/www/acme; default_type text/plain; try_files $uri =404; }\n'
              ' location / { try_files $uri $uri/ =404; }\n location ~ /\\. { deny all; }\n}\n')
    if tls:
        config += (f'server {{\n listen 127.0.0.1:{PORT} ssl http2;\n server_name {DOMAIN};\n'
                   ' root /var/www/ham-entry244; index index.html; charset utf-8; server_tokens off;\n'
                   f' ssl_certificate /etc/letsencrypt/live/{DOMAIN}/fullchain.pem;\n'
                   f' ssl_certificate_key /etc/letsencrypt/live/{DOMAIN}/privkey.pem;\n'
                   ' ssl_protocols TLSv1.2 TLSv1.3; ssl_session_cache shared:HAMUSA244TLS:10m; ssl_session_tickets off;\n'
                   ' add_header X-Content-Type-Options nosniff always;\n'
                   ' location / { try_files $uri $uri/ =404; }\n location ~ /\\. { deny all; }\n}\n')
    return config


def write(path, text):
    require(not path.is_symlink(), 'Unexpected destination symlink')
    pending = path.with_suffix(path.suffix + '.usa-pending')
    with pending.open('x', encoding='utf-8', newline='\n') as stream:
        os.chmod(pending, 0o644); stream.write(text); stream.flush(); os.fsync(stream.fileno())
    pending.replace(path)


def baseline():
    files = {str(p): digest(p.read_bytes()) for p in Path('/etc/nginx').rglob('*')
             if p.is_file() and p not in (SITE, ENABLED)}
    return {'nginx_files': files, 'vpn': run('docker', 'inspect', '--format',
        '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Running}} {{.HostConfig.NetworkMode}}', 'remnanode').strip(),
        'public443': run('ss', '-H', '-ltnp', 'sport = :443').strip()}


def reload_checked(before):
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    require(baseline() == before, 'Unrelated nginx/VPN state changed')


def http_get(path='/'):
    connection = HTTPConnection('127.0.0.1', 80, timeout=8)
    try:
        connection.request('GET', path, headers={'Host': DOMAIN})
        response = connection.getresponse(); body = response.read(65536)
        require(response.status == 200 and body, 'Local HTTP proof failed')
        return body
    finally: connection.close()


def http():
    guard(); require((WEB / 'index.html').is_file() and ACME.is_dir() and not ACME.is_symlink(), 'Existing webroots required')
    if not exists('http-intent'):
        require(not SITE.exists() and not SITE.is_symlink() and not ENABLED.exists() and not ENABLED.is_symlink(), 'Existing USA site')
        require(not (LE / 'live' / DOMAIN).exists() and not (LE / 'live' / DOMAIN).is_symlink(), 'Existing USA certificate; inspect before adoption')
        with socket.socket() as listener: listener.bind(('127.0.0.1', PORT))
        save('http-intent', {'token': 'ham-usa244-' + uuid.uuid4().hex, 'timestamp': time.time(), 'before': baseline()})
        with (STATE / 'nginx-before.tar.gz').open('xb') as stream:
            os.chmod(stream.name, 0o600)
            with tarfile.open(fileobj=stream, mode='w:gz') as archive: archive.add('/etc/nginx', arcname='etc/nginx')
            stream.flush(); os.fsync(stream.fileno())
        save('http-backup', {'sha256': digest((STATE / 'nginx-before.tar.gz').read_bytes())})
    intent = read('http-intent'); before = baseline()
    require((STATE / 'nginx-before.tar.gz').is_file(), 'Before-archive missing; inspect interrupted HTTP preparation')
    require(exists('http-backup') and digest((STATE / 'nginx-before.tar.gz').read_bytes()) == read('http-backup')['sha256'], 'Before-archive integrity failed')
    require(not SITE.is_symlink() and (not SITE.exists() or SITE.read_text() == site_config()), 'USA HTTP site changed')
    require(not ENABLED.exists() and not ENABLED.is_symlink() or ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Unexpected enabled site')
    challenge = ACME / '.well-known/acme-challenge' / intent['token']
    for folder in (ACME / '.well-known', challenge.parent):
        require(not folder.is_symlink(), 'Unsafe challenge directory')
        if not folder.exists(): folder.mkdir(mode=0o755); folder.chmod(0o755)
    body = intent['token'] + '\n'
    require(not challenge.exists() or challenge.read_text() == body, 'Challenge file changed')
    write(challenge, body); write(SITE, site_config())
    if not ENABLED.is_symlink(): ENABLED.symlink_to(SITE)
    try:
        reload_checked(before)
        require(http_get('/.well-known/acme-challenge/' + intent['token']) == body.encode(), 'Challenge mismatch')
        http_get()
    except Exception:
        require(SITE.read_text() == site_config(), 'Site changed concurrently; rollback refused')
        ENABLED.unlink(); SITE.unlink(); reload_checked(before); raise
    save('http-ready', {'token': intent['token'], 'sha256': digest(body.encode()), 'timestamp': time.time()})
    return {'http_ready': True, 'challenge_url': 'http://' + DOMAIN + '/.well-known/acme-challenge/' + intent['token'],
            'external_proof_required': 'sha256 of externally fetched response body'}


def certificate_details():
    live = LE / 'live' / DOMAIN
    private = live / 'privkey.pem'
    require(private.resolve().is_relative_to((LE / 'archive' / DOMAIN).resolve())
            and private.stat().st_uid == 0 and private.stat().st_mode & 0o077 == 0, 'Unsafe certificate private key')
    details = run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-noout', '-dates', '-ext', 'subjectAltName')
    require(set(re.findall(r'DNS:([^,\s]+)', details)) == {DOMAIN}, 'Certificate SAN mismatch')
    run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-checkend', '86400', '-noout')
    run('openssl', 'verify', '-CApath', '/etc/ssl/certs', '-untrusted', str(live / 'chain.pem'), str(live / 'cert.pem'))
    require(run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-pubkey', '-noout').strip()
            == run('openssl', 'pkey', '-in', str(live / 'privkey.pem'), '-pubout').strip(), 'Certificate/key mismatch')
    return {'san': DOMAIN, 'expires': next(line.split('=', 1)[1] for line in details.splitlines() if line.startswith('notAfter='))}


def certificate(external_proof):
    guard(); proof = read('http-ready')
    require(external_proof == proof['sha256'] and 0 <= time.time() - proof['timestamp'] < 1800, 'Fresh external HTTP proof required')
    require(SITE.read_text() == site_config() and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'HTTP bootstrap changed')
    converged(); run('certbot', '--no-random-sleep-on-renew', '--version')
    live = LE / 'live' / DOMAIN
    if not exists('cert-intent'):
        require(not live.exists() and not live.is_symlink() and not (LE / 'renewal' / (DOMAIN + '.conf')).exists(), 'Existing USA lineage')
        account = re.findall(r'^account\s*=\s*([a-f0-9]{32})\s*$', (LE / 'renewal/in-de3.torcalc.ru.conf').read_text(), re.M)
        require(len(account) == 1, 'Expected existing production ACME account')
        save('cert-intent', {'domain': DOMAIN, 'timestamp': time.time(), 'external_proof': external_proof})
        run('certbot', 'certonly', '--non-interactive', '--webroot', '-w', str(ACME), '--preferred-challenges', 'http',
            '--cert-name', DOMAIN, '-d', DOMAIN, '--account', account[0], '--server', 'https://acme-v02.api.letsencrypt.org/directory',
            '--no-random-sleep-on-renew', timeout=180)
    require((live / 'cert.pem').is_file(), 'ACME intent exists without certificate; do not repeat issuance')
    details = certificate_details(); save('certificate', details)
    return {'certificate_valid': True, **details}


def local_tls():
    listeners = run('ss', '-H', '-ltn', 'sport = :' + str(PORT)).splitlines()
    require(listeners and all(line.split()[3] == '127.0.0.1:' + str(PORT) for line in listeners), 'TLS must be loopback-only')
    context = ssl.create_default_context(); context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    with socket.create_connection(('127.0.0.1', PORT), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=DOMAIN) as secure:
            require(secure.version() == 'TLSv1.3' and secure.selected_alpn_protocol() == 'h2', 'TLS1.3/h2 check failed')
    return {'tls': 'TLSv1.3', 'alpn': 'h2', 'loopback_port': PORT}


def tls():
    guard(); require(exists('certificate'), 'Verified certificate required'); certificate_details(); converged()
    require(not HOOK.is_symlink() and HOOK.stat().st_uid == 0 and HOOK.stat().st_mode & 0o022 == 0
            and HOOK.read_text() == HOOK_TEXT, 'Existing deploy hook differs from trusted reload-only hook')
    require(not SITE.is_symlink() and SITE.read_text() in (site_config(), site_config(True)), 'USA site changed')
    require(ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'USA site not enabled')
    before = baseline(); previous = SITE.read_text(); candidate = site_config(True)
    if previous == site_config():
        require(not run('ss', '-H', '-ltn', 'sport = :' + str(PORT)).strip(), 'USA local TLS port already occupied')
    save('tls-intent', {'before': previous, 'candidate_sha256': digest(candidate.encode())})
    write(SITE, candidate)
    try: reload_checked(before); result = local_tls()
    except Exception:
        require(SITE.read_text() == candidate, 'Concurrent site change; rollback refused')
        write(SITE, previous); reload_checked(before); raise
    run('sh', '-n', str(HOOK)); run('systemctl', 'enable', '--now', 'certbot.timer')
    save('tls-ready', result)
    return {**result, 'renewal_timer_enabled': True, 'renewal_dry_run': 'not_run_staging_busy'}


def verify():
    guard(); require(SITE.read_text() == site_config(True), 'USA TLS site changed'); run('nginx', '-t')
    return {**certificate_details(), **local_tls()}


def rollback_site():
    guard(); require(exists('http-intent'), 'No owned USA site')
    require(SITE.is_file() and not SITE.is_symlink() and SITE.read_text() in (site_config(), site_config(True)), 'Changed USA site')
    require(ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Changed enabled USA site')
    before = baseline(); previous = SITE.read_text()
    save('site-rollback', {'site': previous, 'certificate_retained': True})
    ENABLED.unlink(); SITE.unlink()
    try: reload_checked(before)
    except Exception:
        write(SITE, previous); ENABLED.symlink_to(SITE); reload_checked(before); raise
    return {'owned_site_removed': True, 'certificates_and_shared_timer_retained': True}


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['dns', 'dns-rollback', 'http', 'certificate', 'tls', 'verify', 'rollback-site'])
    parser.add_argument('--external-proof'); args = parser.parse_args()
    try:
        result = certificate(args.external_proof) if args.action == 'certificate' else globals()[args.action.replace('-', '_')]()
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'diagnostics': 'private state on this host'})); raise SystemExit(1)
