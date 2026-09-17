#!/bin/sh
set -eu
if ! iptables -nL HAM_ENTRY140_API >/dev/null 2>&1; then
  iptables -N HAM_ENTRY140_API
  iptables -A HAM_ENTRY140_API -s 127.0.0.1/32 -j ACCEPT
  iptables -A HAM_ENTRY140_API -s 64.225.109.248/32 -j ACCEPT
  iptables -A HAM_ENTRY140_API -j DROP
fi
iptables -C INPUT -p tcp --dport 2222 -j HAM_ENTRY140_API 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 2222 -j HAM_ENTRY140_API
ip6tables -C INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || ip6tables -I INPUT 1 -p tcp --dport 2222 -j DROP
