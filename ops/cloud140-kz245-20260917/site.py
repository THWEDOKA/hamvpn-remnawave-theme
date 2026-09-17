"""Two-name HTTP/loopback TLS sidecar, no panel/VPN/profile mutations.

After publication, run dns/dns-verify on the credential-holding panel. On entry
(sudo as needed): http -> certificate -> tls -> renew -> verify. certificate
and renew read an external HTTP proof JSON on stdin. To obtain it, pipe the
public JSON from http (or challenge) into external-proof on a different host.
No certificate issuance is repeated after an uncertain cert-intent.
"""
import argparse
import configparser
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
ENTRY = '176.108.245.140'
DOMAINS = ('in-kz2.torcalc.ru', 'in-de245.torcalc.ru')
DOMAIN, PORT = DOMAINS[0], 9443
STATE = Path('/root/hamvpn-cloud140-kz245-20260917/site')
NGINX = Path('/etc/nginx')
SITE = NGINX / 'sites-available/ham-cloud140-kz245.conf'
ENABLED = NGINX / 'sites-enabled/ham-cloud140-kz245.conf'
WEB = Path('/var/www/ham-cloud140-kz245')
ACME = Path('/var/www/acme')
LE = Path('/etc/letsencrypt')
BACKUP = STATE / 'nginx-before.tar.gz'
CREDENTIALS = Path('/etc/hamvpn-dns-ru214/credentials.json')
HOOK = LE / 'renewal-hooks/deploy/ham-cloud140-kz245-nginx'
HOOK_TEXT = ('#!/bin/sh\nset -eu\n'
             'test "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/in-kz2.torcalc.ru || exit 0\n'
             '/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n')
ACME_SERVER = 'https://acme-v02.api.letsencrypt.org/directory'
ASSETS = ('index.html', 'style.css')
MAX_AGE = 1800


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_ancestors(path):
    for parent in [*reversed(path.parents), path.parent]:
        require(not parent.is_symlink(), 'Symlink ancestor rejected')


def private_file(path):
    safe_ancestors(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0
            and path.stat().st_mode & 0o077 == 0, 'Expected root-only regular file')


def write(path, text, mode=0o644):
    safe_ancestors(path)
    require(not path.is_symlink(), 'Unexpected destination symlink')
    pending = path.with_name(path.name + '.cloud140-pending')
    with pending.open('x', encoding='utf-8', newline='\n') as stream:
        os.chmod(pending, mode)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)
    if os.name == 'posix':
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def state_path(name):
    require(re.fullmatch(r'[a-z0-9-]+', name), 'Invalid state name')
    return STATE / (name + '.json')


def exists(name):
    return state_path(name).exists()


def read(name):
    path = state_path(name)
    private_file(path)
    return json.loads(path.read_text(encoding='utf-8'))


def save(name, value):
    safe_ancestors(STATE)
    require(not STATE.is_symlink(), 'Unsafe state directory')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0, 'State must be root-only')
    path = state_path(name)
    if path.exists():
        private_file(path)
    write(path, json.dumps(value, ensure_ascii=False), 0o600)


def run(*args, timeout=30):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Command timed out; inspect state before retry') from None
    if result.returncode:
        save('command-error', {'program': args[0], 'status': result.returncode,
                               'stdout': result.stdout, 'stderr': result.stderr})
        raise RuntimeError('Command failed; diagnostics are in private state')
    return result.stdout


def guard(entry=True):
    require(os.geteuid() == 0, 'Run as root (entry access may use sudo)')
    os.umask(0o077)
    safe_ancestors(STATE)
    if STATE.exists() or STATE.is_symlink():
        require(STATE.is_dir() and not STATE.is_symlink() and STATE.stat().st_uid == 0
                and STATE.stat().st_mode & 0o077 == 0, 'Unsafe state directory')
    if entry:
        require(ENTRY + '/' in run('ip', '-4', 'addr', 'show'), 'Wrong entry server')


def client():
    private_file(CREDENTIALS)
    credentials = json.loads(CREDENTIALS.read_text(encoding='utf-8'))
    require(re.fullmatch(r'[a-f0-9]{32}', credentials['zone_id']), 'Invalid DNS zone')
    base = 'https://api.cloudflare.com/client/v4/zones/' + credentials['zone_id'] + '/dns_records'

    def request(method, suffix='', body=None):
        req = urllib.request.Request(base + suffix, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + credentials['token'], 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                value = json.load(response)
            require(value.get('success') is True, 'DNS request rejected')
            return value['result']
        except Exception:
            raise RuntimeError('DNS response failed/uncertain; read back before retry') from None
    return request


def dns_rows(request, domain):
    require(domain in DOMAINS, 'Out-of-scope DNS name')
    return request('GET', '?' + urllib.parse.urlencode({'name': domain, 'per_page': 100}))


def matching(row, wanted):
    return all(row.get(key) == value for key, value in wanted.items())


def dns():
    guard(False)
    request = client()
    rows = {d: dns_rows(request, d) for d in DOMAINS}
    if not exists('dns-intent'):
        require(not any(rows.values()), 'Existing exact-name records; no adoption or overwrite')
        marker = 'ham-cloud140-kz245-' + uuid.uuid4().hex
        save('dns-intent', {'before': rows, 'wanted': {d: {'type': 'A', 'name': d, 'content': ENTRY,
              'ttl': 300, 'proxied': False, 'comment': marker} for d in DOMAINS}, 'timestamp': time.time()})
    wanted = read('dns-intent')['wanted']
    # Preflight both names before any creation, including resumed operations.
    for index, domain in enumerate(DOMAINS):
        found = rows[domain]
        if found:
            require(len(found) == 1 and matching(found[0], wanted[domain]), 'Changed or foreign DNS record')
            if exists('dns-owned-' + str(index)):
                require(found[0]['id'] == read('dns-owned-' + str(index))['id'], 'DNS record ID changed')
        else:
            require(not exists('dns-attempt-' + str(index)), 'Uncertain DNS POST: do not repeat blindly')
    for index, domain in enumerate(DOMAINS):
        if not rows[domain]:
            save('dns-attempt-' + str(index), {'wanted': wanted[domain], 'timestamp': time.time()})
            row = request('POST', body=wanted[domain])
            require(matching(row, wanted[domain]) and row.get('id'), 'Unexpected created record')
            save('dns-owned-' + str(index), {'id': row['id']})
        found = dns_rows(request, domain)
        require(len(found) == 1 and matching(found[0], wanted[domain]), 'DNS readback failed')
        if exists('dns-owned-' + str(index)):
            require(found[0]['id'] == read('dns-owned-' + str(index))['id'], 'DNS ID changed after POST')
        save('dns-owned-' + str(index), {'id': found[0]['id']})
    return {'dns_only': True, 'domains': list(DOMAINS), 'entry': ENTRY, 'public_dns_check_required': True}


def converged():
    for domain in DOMAINS:
        for resolver in ('1.1.1.1', '8.8.8.8'):
            for kind in ('A', 'AAAA'):
                answer = run('dig', '@' + resolver, domain, kind, '+time=3', '+tries=1', '+noall', '+answer', '+comments')
                require('status: NOERROR,' in answer, 'DNS resolver did not return NOERROR')
                rows = [line.split() for line in answer.splitlines() if line and not line.startswith(';')]
                require((len(rows) == 1 and len(rows[0]) == 5 and rows[0][0].rstrip('.') == domain
                         and rows[0][-2:] == ['A', ENTRY]) if kind == 'A' else not rows,
                        'DNS not converged or unexpected AAAA/CNAME; no ACME request')


def dns_verify():
    guard(False)
    request = client()
    wanted = read('dns-intent')['wanted']
    for index, domain in enumerate(DOMAINS):
        rows = dns_rows(request, domain)
        require(len(rows) == 1 and rows[0]['id'] == read('dns-owned-' + str(index))['id']
                and matching(rows[0], wanted[domain]), 'DNS ownership/readback changed')
    converged()
    return {'dns_readback_and_two_resolvers_passed': True, 'domains': list(DOMAINS)}


def dns_rollback():
    guard(False)
    request = client()
    wanted = read('dns-intent')['wanted']
    pending = []
    for index, domain in enumerate(DOMAINS):
        rows = dns_rows(request, domain)
        if rows:
            require(len(rows) == 1 and exists('dns-owned-' + str(index))
                    and rows[0]['id'] == read('dns-owned-' + str(index))['id']
                    and matching(rows[0], wanted[domain]), 'Changed DNS; no deletions performed')
            pending.append(rows[0]['id'])
    save('dns-rollback-intent', {'ids': pending, 'timestamp': time.time()})
    for identifier in pending:
        request('DELETE', '/' + identifier)
    require(not any(dns_rows(request, d) for d in DOMAINS), 'DNS rollback readback failed')
    save('dns-rolled-back', {'timestamp': time.time()})
    return {'owned_dns_removed': True}


def site_config(tls=False):
    # Adapted from installed selfsteal/scripts/render.py; no shared vhost edits.
    names = ' '.join(DOMAINS)
    common = (f' server_name {names};\n root {WEB.as_posix()};\n index index.html; charset utf-8; server_tokens off;\n')
    locations = ' location / { try_files $uri $uri/ =404; }\n location ~ /\\. { deny all; }\n}\n'
    text = ('server {\n listen 80;\n' + common
            + f' location ^~ /.well-known/acme-challenge/ {{ root {ACME.as_posix()}; default_type text/plain; try_files $uri =404; }}\n'
            + locations)
    if tls:
        text += ('server {\n' + f' listen 127.0.0.1:{PORT} ssl http2;\n' + common
                 + f' ssl_certificate {LE.as_posix()}/live/{DOMAIN}/fullchain.pem;\n'
                 + f' ssl_certificate_key {LE.as_posix()}/live/{DOMAIN}/privkey.pem;\n'
                 + ' ssl_protocols TLSv1.2 TLSv1.3; ssl_session_cache shared:HAMCloud140KZ245:10m;\n'
                 + ' ssl_session_timeout 1d; ssl_session_tickets off;\n'
                 + ' add_header X-Content-Type-Options nosniff always;\n'
                 + ' add_header Referrer-Policy no-referrer always;\n'
                 + ' add_header Content-Security-Policy "default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'; frame-ancestors \'none\'" always;\n'
                 + locations)
    return text


def listeners(port):
    return sorted(line.split()[3] for line in run('ss', '-H', '-ltn', 'sport = :' + str(port)).splitlines())


def baseline():
    files = {}
    for path in sorted(NGINX.rglob('*')):
        if path in (SITE, ENABLED):
            continue
        if path.is_symlink():
            files[str(path)] = {'link': os.readlink(path), 'target_sha256': digest(path.read_bytes()) if path.is_file() else None}
        elif path.is_file():
            st = path.stat()
            files[str(path)] = {'sha256': digest(path.read_bytes()), 'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid}
    return {'nginx_files': files, 'nginx_master': run('systemctl', 'show', 'nginx', '-p', 'MainPID', '--value').strip(),
            'legacy_listeners': {str(p): listeners(p) for p in (80, 443, 8443)},
            'vpn': run('docker', 'inspect', '--format',
                      '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}} {{.State.Running}} {{.HostConfig.NetworkMode}}',
                      'remnanode').strip()}


def preserved():
    require(baseline() == read('http-intent')['before'], 'Existing nginx/listeners/VPN changed; inspect drift')


def reload_checked(before):
    run('nginx', '-t')
    run('systemctl', 'reload', 'nginx')
    require(baseline() == before, 'Unrelated nginx/listeners/VPN changed during reload')


def verify_backup():
    private_file(BACKUP)
    require(digest(BACKUP.read_bytes()) == read('http-backup')['sha256'], 'Before-archive integrity failed')
    with tarfile.open(BACKUP, 'r:gz') as archive:
        require(any(m.name == 'etc/nginx/nginx.conf' for m in archive.getmembers()), 'Before-archive is incomplete')


def asset_manifest():
    return {name: digest((ROOT / 'assets' / name).read_bytes()) for name in ASSETS}


def verify_web():
    require(WEB.is_dir() and not WEB.is_symlink(), 'Unsafe owned webroot')
    require({p.name for p in WEB.iterdir()} == set(ASSETS), 'Owned webroot contains unexpected files')
    for name, checksum in read('http-intent')['assets'].items():
        path = WEB / name
        require(path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == checksum,
                'Owned public asset changed')


def http_get(domain, path='/', address='127.0.0.1'):
    connection = HTTPConnection(address, 80, timeout=8)
    try:
        connection.request('GET', path, headers={'Host': domain})
        response = connection.getresponse()
        body = response.read(65536)
        require(response.status == 200 and body, 'HTTP proof failed')
        return body
    finally:
        connection.close()


def wait_http_ready():
    # nginx reload returns before the new workers necessarily accept connections.
    # Old workers can briefly answer with the previous default virtual host.
    last = None
    for attempt in range(30):
        try:
            return challenge()
        except (RuntimeError, OSError) as error:
            last = error
            if attempt < 29:
                time.sleep(.2)
    raise last


def challenge():
    guard()
    verify_backup()
    preserved()
    verify_web()
    require(not exists('site-rolled-back') and not SITE.is_symlink() and SITE.read_text() in (site_config(), site_config(True))
            and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Owned site changed or disabled')
    token = read('http-intent')['token']
    body = (token + '\n').encode()
    for domain in DOMAINS:
        require(http_get(domain, '/.well-known/acme-challenge/' + token) == body, 'HTTP challenge mismatch')
        require(http_get(domain) == (WEB / 'index.html').read_bytes(), 'HTTP site body mismatch')
    proof = {'entry': ENTRY, 'domains': list(DOMAINS), 'token': token, 'sha256': digest(body), 'timestamp': time.time()}
    save('http-ready', proof)
    return {**proof, 'http_ready': True, 'urls': ['http://' + d + '/.well-known/acme-challenge/' + token for d in DOMAINS]}


def http():
    guard()
    require(NGINX.is_dir() and ACME.is_dir() and not ACME.is_symlink(), 'Existing nginx and ACME webroot required')
    require(not exists('site-rolled-back'), 'Prior rollback; inspect before reuse')
    if not exists('http-intent'):
        for path in (SITE, ENABLED, WEB, HOOK, BACKUP, LE / 'live' / DOMAIN, LE / 'archive' / DOMAIN,
                     LE / 'renewal' / (DOMAIN + '.conf')):
            require(not path.exists() and not path.is_symlink(), 'Existing operation-owned destination')
        require(not listeners(PORT), 'New local TLS port is occupied')
        before = baseline()
        require(before['vpn'].endswith('true host') and all(before['legacy_listeners'].values()), 'Expected existing host-network VPN/listeners')
        run('nginx', '-t')
        effective = run('nginx', '-T')  # Capture only; never print the effective configuration.
        require(not any(re.search(r'(?<![\w.-])' + re.escape(d) + r'(?![\w.-])', effective) for d in DOMAINS),
                'One of the new names already occurs in the existing nginx configuration')
        save('http-intent', {'token': 'ham-cloud140-' + uuid.uuid4().hex, 'before': before,
                             'assets': asset_manifest(), 'timestamp': time.time()})
        with BACKUP.open('xb') as stream:
            os.chmod(BACKUP, 0o600)
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                archive.add(NGINX, arcname='etc/nginx')
            stream.flush()
            os.fsync(stream.fileno())
        save('http-backup', {'sha256': digest(BACKUP.read_bytes())})
    verify_backup()
    preserved()
    intent = read('http-intent')
    require(intent['assets'] == asset_manifest(), 'Public assets differ from original intent')
    require(not SITE.is_symlink() and (not SITE.exists() or SITE.read_text() == site_config()), 'HTTP site changed')
    require((not ENABLED.exists() and not ENABLED.is_symlink())
            or ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Unexpected enabled site')
    require(not WEB.is_symlink(), 'Unsafe owned webroot')
    if not WEB.exists():
        WEB.mkdir(mode=0o755)
        WEB.chmod(0o755)
    require(not {p.name for p in WEB.iterdir()} - set(ASSETS), 'Unexpected files in new webroot')
    for name in ASSETS:
        target = WEB / name
        require(not target.is_symlink() and (not target.exists() or digest(target.read_bytes()) == intent['assets'][name]), 'Asset changed on resume')
        if not target.exists():
            write(target, (ROOT / 'assets' / name).read_text(encoding='utf-8'))
    folder = ACME / '.well-known' / 'acme-challenge'
    for directory in (folder.parent, folder):
        safe_ancestors(directory)
        require(not directory.is_symlink(), 'Unsafe ACME directory')
        if not directory.exists():
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
    target = folder / intent['token']
    body = intent['token'] + '\n'
    require(not target.is_symlink() and (not target.exists() or target.read_text() == body), 'Challenge changed')
    if not target.exists():
        write(target, body)
    write(SITE, site_config())
    if not ENABLED.is_symlink():
        ENABLED.symlink_to(SITE)
    try:
        reload_checked(intent['before'])
        return wait_http_ready()
    except Exception:
        require(not SITE.is_symlink() and SITE.read_text() == site_config()
                and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Concurrent site change; rollback refused')
        ENABLED.unlink()
        SITE.unlink()
        reload_checked(intent['before'])
        raise


def external_proof(request):
    # Run on a genuinely different host, never infer external reachability locally.
    addresses = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, check=True).stdout
    require(ENTRY + '/' not in addresses, 'External HTTP probe must not run on entry')
    require(request['entry'] == ENTRY and request['domains'] == list(DOMAINS)
            and re.fullmatch(r'ham-cloud140-[a-f0-9]{32}', request['token']), 'Unexpected external probe request')
    body = (request['token'] + '\n').encode()
    require(request['sha256'] == digest(body), 'Challenge request hash mismatch')
    converged()
    checks = []
    for domain in DOMAINS:
        response = http_get(domain, '/.well-known/acme-challenge/' + request['token'], ENTRY)
        require(response == body, 'External challenge mismatch')
        checks.append({'domain': domain, 'status': 200, 'sha256': digest(response)})
    return {'entry': ENTRY, 'token': request['token'], 'observed_at': time.time(), 'checks': checks}


def check_external(proof):
    ready = read('http-ready')
    require(proof is not None and proof.get('entry') == ENTRY and proof.get('token') == ready['token'], 'External HTTP proof required')
    stamp = proof.get('observed_at', 0)
    require(ready['timestamp'] <= stamp <= time.time() and 0 <= time.time() - stamp < MAX_AGE, 'External HTTP proof is stale/future')
    checks = proof.get('checks', [])
    require(len(checks) == len(DOMAINS) and {c.get('domain') for c in checks} == set(DOMAINS)
            and all(c.get('status') == 200 and c.get('sha256') == ready['sha256'] for c in checks), 'External proof must cover both names')


def certbot_features():
    # Parse-only capability check: --version prevents ACME/network actions.
    version = run('certbot', '--version').strip()
    require(re.fullmatch(r'certbot \d+\.\d+(?:\.\d+)?', version), 'Unrecognized certbot version')
    run('certbot', '--no-random-sleep-on-renew', '--run-deploy-hooks', '--no-directory-hooks', '--version')
    return version


def account_for_issue(account=None):
    base = LE / 'accounts/acme-v02.api.letsencrypt.org/directory'
    safe_ancestors(base)
    require(base.is_dir() and not base.is_symlink(), 'Existing production ACME account required')
    choices = [p for p in base.iterdir() if re.fullmatch(r'[a-f0-9]{32}', p.name) and p.is_dir() and not p.is_symlink()]
    if account is not None:
        choices = [p for p in choices if p.name == account]
    require(len(choices) == 1, 'Specify one existing ACME account; no registration guessed')
    private_file(choices[0] / 'private_key.json')
    return choices[0].name


def certificate_details():
    live, archive = LE / 'live' / DOMAIN, LE / 'archive' / DOMAIN
    safe_ancestors(archive)
    safe_ancestors(live)
    require(archive.is_dir() and not archive.is_symlink() and not live.is_symlink(), 'Unsafe certificate lineage')
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        target = live / name
        require(target.is_file() and target.resolve().is_relative_to(archive.resolve()), 'Certificate escapes its archive')
    private_file((live / 'privkey.pem').resolve())
    details = run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-noout', '-dates', '-ext', 'subjectAltName')
    require(set(re.findall(r'DNS:([^,\s]+)', details)) == set(DOMAINS), 'Certificate SAN must match both names exactly')
    run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-checkend', '86400', '-noout')
    run('openssl', 'verify', '-CApath', '/etc/ssl/certs', '-untrusted', str(live / 'chain.pem'), str(live / 'cert.pem'))
    require(run('openssl', 'x509', '-in', str(live / 'cert.pem'), '-pubkey', '-noout').strip()
            == run('openssl', 'pkey', '-in', str(live / 'privkey.pem'), '-pubout').strip(), 'Certificate/private key mismatch')
    require((live / 'fullchain.pem').read_bytes() == (live / 'cert.pem').read_bytes() + (live / 'chain.pem').read_bytes(), 'Fullchain mismatch')
    dates = dict(line.split('=', 1) for line in details.splitlines() if line.startswith(('notBefore=', 'notAfter=')))
    require(set(dates) == {'notBefore', 'notAfter'}, 'Certificate dates missing')
    return {'domains': list(DOMAINS), **dates}


def certificate(proof=None, account=None):
    guard()
    verify_backup()
    preserved()
    require(not SITE.is_symlink() and SITE.read_text() == site_config()
            and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'HTTP bootstrap changed')
    if not exists('cert-intent'):
        check_external(proof)
        converged()
        version = certbot_features()
        selected = account_for_issue(account)
        for path in (LE / 'live' / DOMAIN, LE / 'archive' / DOMAIN, LE / 'renewal' / (DOMAIN + '.conf')):
            require(not path.exists() and not path.is_symlink(), 'Existing certificate lineage; no adoption')
        save('cert-intent', {'domains': list(DOMAINS), 'account': selected, 'certbot': version, 'proof': proof, 'timestamp': time.time()})
        run('certbot', 'certonly', '--non-interactive', '--webroot', '-w', str(ACME), '--preferred-challenges', 'http',
            '--cert-name', DOMAIN, *[arg for d in DOMAINS for arg in ('-d', d)], '--account', selected,
            '--server', ACME_SERVER, '--no-directory-hooks', '--no-random-sleep-on-renew', timeout=240)
    require(read('cert-intent')['domains'] == list(DOMAINS), 'Certificate intent differs')
    require((LE / 'live' / DOMAIN / 'cert.pem').is_file(), 'ACME intent exists without certificate; do not repeat issuance')
    details = certificate_details()
    preserved()
    save('certificate', details)
    return {'certificate_valid': True, **details}


def local_tls():
    require(listeners(PORT) == ['127.0.0.1:' + str(PORT)], 'TLS must listen only on the selected loopback port')
    results = []
    for domain in DOMAINS:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['h2'])
        with socket.create_connection(('127.0.0.1', PORT), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as secure:
                require(secure.version() == 'TLSv1.3' and secure.selected_alpn_protocol() == 'h2', 'TLS1.3/h2 check failed')
        results.append({'sni': domain, 'tls': 'TLSv1.3', 'alpn': 'h2'})
    return {'loopback_port': PORT, 'checks': results}


def hook_check():
    safe_ancestors(HOOK)
    require(HOOK.is_file() and not HOOK.is_symlink() and HOOK.stat().st_uid == 0
            and HOOK.stat().st_mode & 0o022 == 0 and HOOK.read_text() == HOOK_TEXT, 'Owned reload hook changed')
    run('sh', '-n', str(HOOK))


def tls():
    guard()
    require(exists('certificate'), 'Verified certificate required')
    verify_backup()
    preserved()
    certificate_details()
    require(not SITE.is_symlink() and SITE.read_text() in (site_config(), site_config(True))
            and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Owned site changed')
    if not exists('tls-intent'):
        require(SITE.read_text() == site_config() and not listeners(PORT), 'Unexpected existing TLS stage')
        require(not HOOK.exists() and not HOOK.is_symlink(), 'Existing reload hook; no overwrite')
        save('tls-intent', {'before': site_config(), 'sha256': digest(site_config(True).encode()), 'timestamp': time.time()})
    intent = read('tls-intent')
    require(intent['before'] == site_config() and intent['sha256'] == digest(site_config(True).encode()), 'TLS intent changed')
    before = baseline()
    write(SITE, site_config(True))
    try:
        reload_checked(before)
        result = local_tls()
        safe_ancestors(HOOK)
        if not HOOK.exists() and not HOOK.is_symlink():
            HOOK.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            write(HOOK, HOOK_TEXT, 0o755)
        hook_check()
        run('env', 'RENEWED_LINEAGE=' + str(LE / 'live' / DOMAIN), 'sh', str(HOOK))
        preserved()
    except Exception:
        require(not SITE.is_symlink() and SITE.read_text() == site_config(True), 'Concurrent TLS edit; rollback refused')
        write(SITE, intent['before'])
        reload_checked(before)
        raise
    save('tls-ready', {**result, 'timestamp': time.time()})
    return {**result, 'renewal_dry_run': 'not_run', 'legacy_80_443_8443_preserved': True}


def renew(proof):
    guard()
    require(exists('tls-ready') and not exists('renew-intent'), 'TLS required; renewal attempt already exists, inspect before retry')
    verify()
    check_external(proof)
    converged()
    version = certbot_features()
    renewal = LE / 'renewal' / (DOMAIN + '.conf')
    private_file(renewal)
    config = configparser.RawConfigParser()
    config.read_string('[certificate]\n' + renewal.read_text())
    params = config['renewalparams']
    require(params.get('authenticator') == 'webroot' and params.get('server') == ACME_SERVER
            and params.get('webroot_path', '').rstrip(', ') == str(ACME), 'Unexpected renewal method')
    require(not any('hook' in key or 'credential' in key for key in params), 'Unexpected renewal hooks/credentials')
    require(dict(config['[webroot_map]']) == {d: str(ACME) for d in DOMAINS}, 'Renewal webroots differ')
    save('renew-intent', {'timestamp': time.time(), 'certbot': version, 'proof': proof})
    run('certbot', 'renew', '--cert-name', DOMAIN, '--dry-run', '--run-deploy-hooks',
        '--deploy-hook', str(HOOK), '--no-directory-hooks', '--no-random-sleep-on-renew', timeout=300)
    verify()
    run('systemctl', 'enable', '--now', 'certbot.timer')
    run('systemctl', 'is-enabled', 'certbot.timer')
    run('systemctl', 'is-active', 'certbot.timer')
    save('renewal', {'passed': True, 'timestamp': time.time(), 'certbot': version})
    return {'renewal_dry_run_passed': True, 'renewal_timer_enabled': True}


def verify():
    guard()
    require(not exists('site-rolled-back') and not SITE.is_symlink() and SITE.read_text() == site_config(True)
            and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Owned TLS site changed')
    verify_backup()
    preserved()
    verify_web()
    hook_check()
    run('nginx', '-t')
    return {**certificate_details(), **local_tls(), 'legacy_80_443_8443_preserved': True}


def rollback_site(confirm_unused=False):
    guard()
    require(confirm_unused, 'Coordinator must detach the new TLS target before site rollback')
    verify_backup()
    preserved()
    require(not SITE.is_symlink() and SITE.read_text() in (site_config(), site_config(True))
            and ENABLED.is_symlink() and ENABLED.resolve() == SITE, 'Changed owned site; rollback refused')
    previous, before = SITE.read_text(), baseline()
    save('site-rollback-intent', {'site_sha256': digest(previous.encode()), 'timestamp': time.time()})
    ENABLED.unlink()
    SITE.unlink()
    try:
        reload_checked(before)
    except Exception:
        require(not SITE.exists() and not ENABLED.exists() and not ENABLED.is_symlink(), 'Concurrent rollback edit')
        write(SITE, previous)
        ENABLED.symlink_to(SITE)
        reload_checked(before)
        raise
    save('site-rolled-back', {'timestamp': time.time()})
    return {'owned_vhost_removed': True, 'certificates_webroot_hook_shared_timer_retained': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['dns', 'dns-verify', 'dns-rollback', 'http', 'challenge', 'external-proof',
                                          'certificate', 'tls', 'renew', 'verify', 'rollback-site'])
    parser.add_argument('--account', help='Select an existing production ACME account if several exist')
    parser.add_argument('--confirm-unused-target', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'certificate':
            result = certificate(json.load(sys.stdin), args.account)
        elif args.action in ('renew', 'external-proof'):
            result = globals()[args.action.replace('-', '_')](json.load(sys.stdin))
        elif args.action == 'rollback-site':
            result = rollback_site(args.confirm_unused_target)
        else:
            result = globals()[args.action.replace('-', '_')]()
        print(json.dumps(result, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'ok': False, 'error': type(error).__name__, 'diagnostics': 'private state only'}))
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
