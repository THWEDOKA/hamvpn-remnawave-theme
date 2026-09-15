#!/usr/bin/env bash
# Apply only the verified release to the inspected RU214 server.
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
test "$(id -u)" = 0
ip -4 addr show | grep -Fq '161.104.90.214/'
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' remnanode)" = host
phase=${1:?Use http or tls}
backup=/root/selfsteal-ru214-backup
before=$(docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}' remnanode)
case "$phase" in
  http)
    test ! -e "$backup"
    test ! -d /etc/nginx
    test ! -d /etc/letsencrypt
    test -z "$(ss -lntH 'sport = :80')"
    test -z "$(ss -lntH 'sport = :8443')"
    install -d -m 700 "$backup"
    docker inspect remnanode > "$backup/remnanode-inspect.json"
    tar -czf "$backup/before.tar.gz" -C / opt/remnanode etc/ufw
    tar -tzf "$backup/before.tar.gz" >/dev/null
    iptables-save > "$backup/firewall.v4"
    ip6tables-save > "$backup/firewall.v6"
    dpkg-query -W > "$backup/packages.txt"
    (cd "$backup" && sha256sum before.tar.gz firewall.v4 firewall.v6 remnanode-inspect.json > SHA256SUMS && sha256sum -c SHA256SUMS)
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-install-recommends nginx certbot
    if test -L /etc/nginx/sites-enabled/default; then
      mv /etc/nginx/sites-enabled/default "$backup/nginx-default-link"
    fi
    install -d -m 755 /var/www/ru214.torcalc.ru /var/www/acme/.well-known/acme-challenge
    install -m 644 site/index.html site/style.css /var/www/ru214.torcalc.ru/
    install -m 644 nginx-http.conf /etc/nginx/sites-available/selfsteal-ru214
    ln -s /etc/nginx/sites-available/selfsteal-ru214 /etc/nginx/sites-enabled/selfsteal-ru214
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    ufw allow 80/tcp comment 'ru214 web ACME HTTP-01'
    curl --noproxy '*' -fsS -H 'Host: ru214.torcalc.ru' http://127.0.0.1/ -o /dev/null
    ;;
  tls)
    test -d "$backup"
    test -f /etc/nginx/sites-available/selfsteal-ru214
    test -z "$(ss -lntH 'sport = :8443')"
    systemctl is-active --quiet hamvpn-acme-ru214.service
    python3 /usr/local/lib/hamvpn-acme-ru214/acme-ready.py
    HTTPS_PROXY=socks5h://127.0.0.1:18089 certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
      --webroot -w /var/www/acme --preferred-challenges http \
      --key-type ecdsa --elliptic-curve secp256r1 --cert-name ru214.torcalc.ru -d ru214.torcalc.ru
    install -m 644 nginx-tls.conf /etc/nginx/sites-available/selfsteal-ru214
    if ! nginx -t; then
      install -m 644 nginx-http.conf /etc/nginx/sites-available/selfsteal-ru214
      exit 1
    fi
    systemctl reload nginx
    install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
    install -m 755 renew-nginx.sh /etc/letsencrypt/renewal-hooks/deploy/ru214-nginx
    systemctl enable --now certbot.timer
    curl --noproxy '*' -fsS --resolve ru214.torcalc.ru:8443:127.0.0.1 https://ru214.torcalc.ru:8443/ -o /dev/null
    ;;
  *) exit 2 ;;
esac
after=$(docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}' remnanode)
test "$before" = "$after"
echo "Web phase $phase passed; VPN container unchanged."
