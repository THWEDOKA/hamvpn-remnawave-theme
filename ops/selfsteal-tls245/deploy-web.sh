#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
ip -4 addr show | grep -q '196.251.107.245/'
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' remnanode)" = host
test ! -e /root/selfsteal-tls245-backup
for port in 80 8080 8081 8443; do test -z "$(ss -lntH "sport = :$port")"; done
install -d -m 700 /root/selfsteal-tls245-backup
tar -czf /root/selfsteal-tls245-backup/before.tar.gz -C / \
    opt/remnanode/docker-compose.yml etc/letsencrypt/renewal/tls245.torcalc.ru.conf \
    etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245 etc/systemd/system/hamvpn-tls245-firewall.service
tar -tzf /root/selfsteal-tls245-backup/before.tar.gz >/dev/null
sha256sum /root/selfsteal-tls245-backup/before.tar.gz > /root/selfsteal-tls245-backup/SHA256SUMS
iptables-save > /root/selfsteal-tls245-backup/firewall.v4
ip6tables-save > /root/selfsteal-tls245-backup/firewall.v6
test ! -d /etc/nginx || { echo 'Unexpected nginx installation: stop'; exit 1; }
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
apt-get update -qq
apt-get install -y --no-install-recommends nginx
SOURCE=$(cd "$(dirname "$0")" && pwd)
install -d -m 755 /var/www/tls245.torcalc.ru /var/www/acme/.well-known/acme-challenge
install -m 644 "$SOURCE/site/index.html" /var/www/tls245.torcalc.ru/index.html
install -m 644 "$SOURCE/site/style.css" /var/www/tls245.torcalc.ru/style.css
# This is the package-created default on a verified nginx-free server; retain it.
if test -L /etc/nginx/sites-enabled/default; then
    mv /etc/nginx/sites-enabled/default /root/selfsteal-tls245-backup/nginx-default-link
fi
install -m 644 "$SOURCE/nginx.conf" /etc/nginx/sites-available/selfsteal-tls245
ln -s /etc/nginx/sites-available/selfsteal-tls245 /etc/nginx/sites-enabled/selfsteal-tls245
nginx -t
systemctl enable --now nginx
systemctl reload nginx
curl -fsS -H 'Host: tls245.torcalc.ru' http://127.0.0.1:8080/ >/dev/null
curl -fsS --http2-prior-knowledge -H 'Host: tls245.torcalc.ru' http://127.0.0.1:8081/ >/dev/null
# Reconfigure performs a staging validation before saving the new authenticator.
certbot reconfigure --cert-name tls245.torcalc.ru --webroot -w /var/www/acme --non-interactive
install -m 700 "$SOURCE/renew.sh" /etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245
systemctl enable --now certbot.timer
echo 'Self-steal site prepared, existing TLS VPN unchanged.'
