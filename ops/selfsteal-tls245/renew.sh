#!/usr/bin/env bash
set -euo pipefail
test "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/tls245.torcalc.ru || exit 0
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -checkend 86400
nginx -t
systemctl reload nginx
docker restart remnanode >/dev/null
for attempt in {1..30}; do
    if ss -lntH 'sport = :443' | grep -q .; then exit 0; fi
    sleep 2
done
echo 'TLS245 VPN failed to restore its listener after renewal' >&2
exit 1
