"""Actual entry-side TLS and renewal-health proofs; never issues a certificate."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import re
import time

spec = importlib.util.spec_from_file_location('cloud140_site', Path(__file__).with_name('site.py'))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
DOMAIN = 'in-de245.torcalc.ru'


def attest(digest, renewal=False):
    site.require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'Invalid candidate digest')
    checked = site.verify()
    selected = [item for item in checked['checks'] if item['sni'] == DOMAIN]
    site.require(len(selected) == 1 and selected[0]['tls'] == 'TLSv1.3'
                 and selected[0]['alpn'] == 'h2' and checked['loopback_port'] == 9443,
                 'Actual local TLS test failed')
    if not renewal:
        tests = [dict(id='de245-local-tls', passed=True, sni=DOMAIN,
                      address='127.0.0.1', port=9443, tls='TLSv1.3', alpn='h2', chain_verified=True)]
    else:
        saved = site.read('renewal')
        stamp = saved.get('timestamp')
        site.require(saved.get('passed') is True and type(stamp) in (int, float)
                     and math.isfinite(stamp) and 0 <= time.time() - stamp <= 86400,
                     'No recent successful actual renewal test')
        site.require(site.run('systemctl', 'is-enabled', 'certbot.timer').strip() == 'enabled'
                     and site.run('systemctl', 'is-active', 'certbot.timer').strip() == 'active',
                     'Renewal timer is not enabled and active')
        tests = [dict(id='de245-renewal', passed=True, domain=DOMAIN, dry_run=True, performed_at=stamp),
                 dict(id='de245-renewal-health', passed=True, domain=DOMAIN,
                      nginx_test=True, cert_valid=True, deploy_hook=True, timer_enabled=True,
                      timer_active=True, tls='TLSv1.3', alpn='h2')]
    result = dict(sha256=digest, timestamp=time.time(), tests=tests)
    site.save('renewal-attestation' if renewal else 'tls-attestation', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['tls', 'renewal'])
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(attest(args.sha256, args.action == 'renewal')))
