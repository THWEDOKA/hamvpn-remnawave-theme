"""Bounded readiness gate for certbot; validates end-to-end ACME TLS through SOCKS."""
import sys
import time

import requests

PROXY = 'socks5h://127.0.0.1:18089'
URL = 'https://acme-v02.api.letsencrypt.org/directory'


def main():
    session = requests.Session()
    session.trust_env = False
    for attempt in range(6):
        try:
            response = session.get(URL, proxies={'https': PROXY}, timeout=(8, 10))
            response.raise_for_status()
            assert 'newOrder' in response.json()
            print('Certificate-only ACME relay ready; upstream TLS verified.')
            return 0
        except (requests.RequestException, ValueError, AssertionError):
            if attempt < 5: time.sleep(5)
    print('ACME relay unavailable; refusing certificate renewal without verified egress.', file=sys.stderr)
    return 1


if __name__ == '__main__': raise SystemExit(main())
