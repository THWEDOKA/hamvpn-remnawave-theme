"""Four-name, isolated self-steal website preparation. No VPN routing changes.

Scope reduced before deployment to AT, PL, CZ and GBpower. GB216 and US1 are
withdrawn: never create DNS or request certificates for their former names.
Historical cloud140-six paths/ownership prefix stay stable for the coordinator.

Deploy this directory AND ../cloud140-kz245-20260917/site.py from the same
verified Git release. Shared implementation is hash-pinned (LF-normalized).

Panel CLI: site.py dns; site.py dns-verify.
Entry CLI: site.py http -> certificate -> tls -> challenge -> renew -> verify.
Pipe http/challenge JSON to `site.py external-proof` on a different server;
pipe that result back into certificate/renew stdin. Use --account only to
select an existing ACME account. Never repeat uncertain issuance/renewal.
Rollback: site.py rollback-site --confirm-unused-target, only after the
coordinator verifies no VPN inbound targets 127.0.0.1:9444. DNS rollback is
site.py dns-rollback and deletes only exact, operation-owned record IDs.

This wrapper never imports inventory.py or the old entry's VPN coordinator.
Import and --help are offline; DNS and production actions require explicit CLI.
"""
import hashlib
from http.client import HTTPResponse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SHARED_PATH = ROOT.parent / 'cloud140-kz245-20260917/site.py'
SHARED_SHA256 = '21a790cbc75e5aa199f028ebf6c0d2f15d4f09bbb4ea6093083c36c0ae67cf37'


def load_shared():
    source = SHARED_PATH.read_text(encoding='utf-8')
    if hashlib.sha256(source.encode()).hexdigest() != SHARED_SHA256:
        raise RuntimeError('Shared site helper changed; review before deployment')
    spec = importlib.util.spec_from_file_location('cloud140_six_site_engine', SHARED_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


s = load_shared()
# Every scope-bearing constant is explicit, including intentionally shared paths.
s.__doc__ = __doc__
s.ROOT = ROOT
s.ENTRY = '176.108.245.140'
s.DOMAINS = ('in-at38.torcalc.ru', 'in-pl141.torcalc.ru', 'in-cz85.torcalc.ru',
             'in-gb225.torcalc.ru')
s.DOMAIN, s.PORT = s.DOMAINS[0], 9444
s.STATE = Path('/root/hamvpn-cloud140-six-20260918/site')
s.NGINX = Path('/etc/nginx')
s.SITE = s.NGINX / 'sites-available/ham-cloud140-six.conf'
s.ENABLED = s.NGINX / 'sites-enabled/ham-cloud140-six.conf'
s.WEB = Path('/var/www/ham-cloud140-six')
s.ACME = Path('/var/www/acme')
s.LE = Path('/etc/letsencrypt')
s.BACKUP = s.STATE / 'nginx-before.tar.gz'
s.CREDENTIALS = Path('/etc/hamvpn-dns-ru214/credentials.json')
s.HOOK = s.LE / 'renewal-hooks/deploy/ham-cloud140-six-nginx'
s.HOOK_TEXT = ('#!/bin/sh\nset -eu\n'
               'test "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/in-at38.torcalc.ru || exit 0\n'
               '/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n')
s.ACME_SERVER = 'https://acme-v02.api.letsencrypt.org/directory'
s.ASSETS = ('index.html', 'style.css')
s.MAX_AGE = 1800

_base_config, _base_baseline = s.site_config, s.baseline
_base_dns, _base_verify, _base_tls = s.dns, s.verify, s.tls
_base_local_tls = s.local_tls


def site_config(tls=False):
    text = _base_config(tls)
    s.require(text.count('HAMCloud140KZ245') == int(tls), 'Unexpected shared TLS template')
    return text.replace('HAMCloud140KZ245', 'HAMCloud140Six')


def baseline():
    result = _base_baseline()
    result['legacy_listeners']['9443'] = s.listeners(9443)
    # The whole other site's nginx file/link is already in nginx_files. Its
    # active listener is an additional invariant; our only TLS port is 9444.
    return result


def https_site(domain):
    """Check the actual HTTPS page, not just a successful TLS handshake.

    Connect only to this operation's loopback port; SNI, certificate/hostname
    validation and Host all use the approved name. Never follow redirects.
    The intended public asset hash bounds and validates the response body.
    """
    s.require(domain in s.DOMAINS, 'Out-of-scope HTTPS name')
    expected = (s.WEB / 'index.html').read_bytes()
    s.require(0 < len(expected) <= 65536 and
              s.digest(expected) == s.read('http-intent')['assets']['index.html'],
              'Expected public page changed or is oversized')
    context = s.ssl.create_default_context()
    context.minimum_version = s.ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    with s.socket.create_connection(('127.0.0.1', s.PORT), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as secure:
            s.require(secure.version() == 'TLSv1.3' and
                      secure.selected_alpn_protocol() == 'http/1.1', 'HTTPS negotiation failed')
            secure.sendall(('GET / HTTP/1.1\r\nHost: ' + domain +
                            '\r\nConnection: close\r\n\r\n').encode('ascii'))
            response = HTTPResponse(secure)
            try:
                response.begin()
                body = response.read(len(expected) + 1)
                s.require(response.status == 200 and body == expected, 'HTTPS page mismatch')
            finally:
                response.close()
    return {'sni': domain, 'status': 200, 'sha256': s.digest(expected)}


def local_tls():
    result = _base_local_tls()
    # All four h2 handshakes must succeed before checking the HTTP/1.1 bodies.
    result['https_sites'] = [https_site(domain) for domain in s.DOMAINS]
    return result


def dns():
    # Seed the exact four-name intent with our historical ownership prefix.
    # Old six-name intents fail below before any provider request or mutation.
    # All uncertain-POST/readback/rollback logic stays shared.
    s.guard(False)
    if not s.exists('dns-intent'):
        request = s.client()
        rows = {d: s.dns_rows(request, d) for d in s.DOMAINS}
        s.require(not any(rows.values()), 'Existing exact-name records; no adoption or overwrite')
        marker = 'ham-cloud140-six-' + s.uuid.uuid4().hex
        s.save('dns-intent', {'before': rows,
            'wanted': {d: {'type': 'A', 'name': d, 'content': s.ENTRY, 'ttl': 300,
                          'proxied': False, 'comment': marker} for d in s.DOMAINS},
            'timestamp': s.time.time()})
    intent = s.read('dns-intent')
    s.require(set(intent['before']) == set(s.DOMAINS)
              and not any(intent['before'].values())
              and set(intent['wanted']) == set(s.DOMAINS), 'DNS intent scope changed')
    markers = {row.get('comment', '') for row in intent['wanted'].values()}
    s.require(len(markers) == 1 and s.re.fullmatch(r'ham-cloud140-six-[a-f0-9]{32}', next(iter(markers))),
              'DNS ownership marker changed')
    for domain, row in intent['wanted'].items():
        s.require(row == {'type': 'A', 'name': domain, 'content': s.ENTRY, 'ttl': 300,
                          'proxied': False, 'comment': next(iter(markers))}, 'DNS intent values changed')
    return _base_dns()


def verify():
    result = _base_verify()
    result['legacy_9443_preserved'] = True
    return result


def tls():
    result = _base_tls()
    result['legacy_9443_preserved'] = True
    return result


# Functions defined in the shared module resolve globals in its own isolated
# namespace. No sys.modules replacement or mutation of the original helper.
s.site_config, s.baseline, s.dns, s.verify, s.tls = site_config, baseline, dns, verify, tls
s.local_tls = local_tls


def main():
    s.main()


if __name__ == '__main__':
    main()
