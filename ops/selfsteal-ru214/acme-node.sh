#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "$0")"
test "$(id -u)" = 0
ip -4 addr show | grep -Fq '161.104.90.214/'
phase=${1:?Use key or activate}
case "$phase" in
  key)
    test ! -e /etc/hamvpn-acme-ru214
    install -d -m 700 /etc/hamvpn-acme-ru214
    ssh-keygen -q -t ed25519 -N '' -C hamvpn-acme-ru214 -f /etc/hamvpn-acme-ru214/id_ed25519
    # Only the public half may leave the node.
    cat /etc/hamvpn-acme-ru214/id_ed25519.pub
    ;;
  activate)
    test -s /etc/hamvpn-acme-ru214/id_ed25519
    test -s /etc/hamvpn-acme-ru214/known_hosts
    test ! -e /etc/systemd/system/hamvpn-acme-ru214.service
    test ! -e /etc/systemd/system/certbot.service.d/ru214-acme.conf
    test -z "$(ss -lntH 'sport = :18089')"
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y --no-install-recommends python3-socks
    python3 -c 'import requests, socks; from urllib3.contrib.socks import SOCKSProxyManager'
    install -d -m 755 /usr/local/lib/hamvpn-acme-ru214
    install -m 644 acme-ready.py /usr/local/lib/hamvpn-acme-ru214/acme-ready.py
    install -m 644 acme-relay.service /etc/systemd/system/hamvpn-acme-ru214.service
    install -d -m 755 /etc/systemd/system/certbot.service.d
    install -m 644 acme-certbot.conf /etc/systemd/system/certbot.service.d/ru214-acme.conf
    systemctl daemon-reload
    systemctl enable --now hamvpn-acme-ru214.service
    ;;
  *) exit 2 ;;
esac
