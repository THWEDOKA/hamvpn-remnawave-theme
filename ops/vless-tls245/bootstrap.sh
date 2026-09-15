#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(id -u)" = 0
ip -4 addr show | grep -q '196.251.107.245/'
test ! -e /opt/remnanode/docker-compose.yml
test -z "$(ss -lntH 'sport = :443')"
test -z "$(ss -lntH 'sport = :80')"
test -z "$(ss -lntH 'sport = :2222')"
install -d -m 700 /root/tls245-backup /opt/hamvpn-tls245
iptables-save > /root/tls245-backup/iptables-before.v4
ip6tables-save > /root/tls245-backup/iptables-before.v6
dpkg-query -W > /root/tls245-backup/packages-before.txt
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
apt-get update -qq
apt-get install -y --no-install-recommends docker.io docker-compose-v2 certbot ca-certificates curl iptables
systemctl enable --now docker
test "$(curl -4fsS --max-time 15 https://api.ipify.org)" = 196.251.107.245
certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email \
  --key-type ecdsa --cert-name tls245.torcalc.ru -d tls245.torcalc.ru
openssl x509 -in /etc/letsencrypt/live/tls245.torcalc.ru/fullchain.pem -noout -checkend 2592000
install -m 700 "$(dirname "$0")/renew-node.sh" /etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245
systemctl enable --now certbot.timer
docker pull remnawave/node:2.7.0
docker image inspect remnawave/node:2.7.0 --format '{{index .RepoDigests 0}}' > /opt/hamvpn-tls245/node-image.txt
echo 'Bootstrap and certificate complete; node not yet published.'
