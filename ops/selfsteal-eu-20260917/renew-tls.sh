#!/bin/sh
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
/usr/bin/docker restart remnanode >/dev/null
attempt=0
while [ "$attempt" -lt 30 ]; do
    if ss -lntH 'sport = :443' | grep -q . && ss -lnuH 'sport = :443' | grep -q .; then exit 0; fi
    attempt=$((attempt + 1))
    sleep 2
done
echo 'VPN listeners did not return after certificate renewal' >&2
exit 1
