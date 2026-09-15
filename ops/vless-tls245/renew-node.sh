#!/usr/bin/env bash
set -euo pipefail
test "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/tls245.torcalc.ru || exit 0
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -checkend 86400
test -s "$RENEWED_LINEAGE/privkey.pem"
docker inspect remnanode >/dev/null 2>&1 || exit 0
docker restart remnanode >/dev/null
for attempt in {1..30}; do
  if ss -lntH 'sport = :443' | grep -q .; then
    echo 'HAMVPN TLS245 renewed certificate loaded.'
    exit 0
  fi
  sleep 2
done
echo 'TLS245 did not restore port 443 after certificate renewal' >&2
exit 1
