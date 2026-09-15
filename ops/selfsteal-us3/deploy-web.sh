#!/bin/bash
# Run the verified Git release on util-us-3. Never modifies panel or Xray.
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
[[ $(id -u) == 0 && $(hostname) == util-us-3 ]] || { echo 'Wrong user/host'; exit 1; }
ip -4 addr show | grep -Fq '162.141.185.216/' || { echo 'Wrong address'; exit 1; }
phase=${1:?Use http or tls}
before=$(docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}' remnanode)
case "$phase" in
  http)
    [[ ! -e /etc/nginx/sites-available/us3.torcalc.ru ]] || { echo 'Already prepared; inspect first'; exit 1; }
    [[ -z $(ss -H -ltn 'sport = :80') ]] || { echo 'Port 80 occupied'; exit 1; }
    [[ ! -d /etc/nginx ]] || { echo 'Existing nginx installation; inspect first'; exit 1; }
    backup=$(mktemp -d /root/selfsteal-us3-backup-XXXXXXXX)
    docker inspect remnanode > "$backup/remnanode-inspect.json"
    tar -czf "$backup/remnanode.tar.gz" -C /opt remnanode
    tar -czf "$backup/ufw.tar.gz" -C /etc ufw
    iptables-save > "$backup/iptables.v4"
    ip6tables-save > "$backup/iptables.v6"
    dpkg-query -W > "$backup/packages.txt"
    sha256sum "$backup"/*.gz > "$backup/SHA256SUMS"
    (cd "$backup" && sha256sum -c SHA256SUMS)
    printf 'Protected backup: %s\n' "$backup"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-install-recommends nginx certbot
    if [[ -L /etc/nginx/sites-enabled/default ]]; then
      mv /etc/nginx/sites-enabled/default "$backup/nginx-default-link"
    fi
    install -d -m 755 /var/www/us3.torcalc.ru /var/www/acme/.well-known/acme-challenge
    install -m 644 site/index.html site/style.css /var/www/us3.torcalc.ru/
    install -m 644 nginx-http.conf /etc/nginx/sites-available/us3.torcalc.ru
    ln -s /etc/nginx/sites-available/us3.torcalc.ru /etc/nginx/sites-enabled/us3.torcalc.ru
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    ufw allow 80/tcp comment 'us3 web ACME HTTP-01'
    curl --noproxy '*' -fsS -H 'Host: us3.torcalc.ru' http://127.0.0.1/ -o /dev/null
    ;;
  tls)
    [[ -f /etc/nginx/sites-available/us3.torcalc.ru ]] || exit 1
    [[ -z $(ss -H -ltn 'sport = :8443') ]] || { echo 'Port 8443 occupied'; exit 1; }
    certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
      --webroot -w /var/www/acme --preferred-challenges http \
      --key-type ecdsa --elliptic-curve secp256r1 --cert-name us3.torcalc.ru -d us3.torcalc.ru
    install -m 644 nginx-tls.conf /etc/nginx/sites-available/us3.torcalc.ru
    if ! nginx -t; then
      install -m 644 nginx-http.conf /etc/nginx/sites-available/us3.torcalc.ru
      exit 1
    fi
    systemctl reload nginx
    install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
    install -m 755 renew-nginx.sh /etc/letsencrypt/renewal-hooks/deploy/us3-nginx
    systemctl enable --now certbot.timer
    curl --noproxy '*' -fsS --resolve us3.torcalc.ru:8443:127.0.0.1 https://us3.torcalc.ru:8443/ -o /dev/null
    ;;
  *) echo 'Use http or tls'; exit 1 ;;
esac
after=$(docker inspect -f '{{.Id}} {{.State.Pid}} {{.State.StartedAt}} {{.RestartCount}}' remnanode)
[[ "$before" == "$after" ]] || { echo 'ERROR: VPN container state changed'; exit 1; }
printf 'Web phase %s passed; VPN container unchanged.\n' "$phase"
