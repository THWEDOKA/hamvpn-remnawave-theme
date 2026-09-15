"""Certbot DNS-01 hook: fixed domain, token-free SSH broker, verified propagation."""
import argparse
import json
import os
import re
import subprocess
import sys
import time

DOMAIN = 'ru214.torcalc.ru'
RECORD = '_acme-challenge.' + DOMAIN
# Independently verified reachable from this node (Cloudflare/Quad9 UDP timed out).
RESOLVERS = ('8.8.8.8', '208.67.222.222')
SSH = ['ssh', '-F', '/dev/null', '-T', '-i', '/etc/hamvpn-acme-ru214/dns_ed25519',
       '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'UserKnownHostsFile=/etc/hamvpn-acme-ru214/known_hosts',
       '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ClearAllForwardings=yes',
       '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
       '-o', 'LogLevel=ERROR', 'hamvpn-dns-ru214@64.225.109.248']


def validate(environment):
    assert environment.get('CERTBOT_DOMAIN') == DOMAIN, 'Unexpected certificate domain'
    value = environment.get('CERTBOT_VALIDATION', '')
    assert re.fullmatch(r'[A-Za-z0-9_-]{43}', value), 'Invalid ACME TXT value'
    return value


def broker(action, validation):
    assert action in ('present', 'cleanup')
    result = subprocess.run(SSH, input=json.dumps({'action': action, 'validation': validation}),
                            capture_output=True, text=True, timeout=480)
    assert result.returncode == 0, 'Restricted DNS broker failed; raw response suppressed'
    response = json.loads(result.stdout)
    assert response.get('ok') is True, 'DNS broker did not confirm operation'
    return response


def resolver(address):
    import dns.resolver
    instance = dns.resolver.Resolver(configure=False)
    instance.nameservers = [address]
    instance.timeout, instance.lifetime = 2, 4
    return instance


def visible(address, validation):
    import dns.exception
    try:
        answer = resolver(address).resolve(RECORD, 'TXT', search=False)
        return any(b''.join(record.strings).decode('ascii') == validation for record in answer)
    except (dns.exception.DNSException, UnicodeError, OSError):
        return False


def propagate(validation, timeout=420):
    deadline = time.monotonic() + timeout
    last_notice = 0
    while time.monotonic() < deadline:
        try:
            public_ok = all(visible(address, validation) for address in RESOLVERS)
            if public_ok:
                print('DNS-01 TXT verified from the node by both public resolvers.', file=sys.stderr)
                return
        except Exception as error:
            # Resolver outages are bounded; never log the TXT challenge or account data.
            if not isinstance(error, (OSError, ValueError)) and error.__class__.__module__.split('.')[0] != 'dns': raise
        if time.monotonic() - last_notice >= 30:
            print('Waiting for DNS-01 propagation (challenge value suppressed).', file=sys.stderr)
            last_notice = time.monotonic()
        time.sleep(5)
    raise RuntimeError('DNS-01 propagation not verified before timeout')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('present', 'cleanup'))
    action = parser.parse_args().action
    validation = validate(os.environ)
    if action == 'present':
        try:
            response = broker(action, validation)
            assert response.get('propagated') is True, 'Panel did not verify authoritative DNS propagation'
            propagate(validation)
        except Exception:
            try: broker('cleanup', validation)
            except Exception: print('DNS challenge cleanup requires operator verification.', file=sys.stderr)
            raise
    else:
        response = broker(action, validation)
    print(json.dumps({'ok': True, 'action': action, 'record_id': response.get('record_id')}))


if __name__ == '__main__': main()
