#!/usr/bin/env bash
set -euo pipefail
# Own only the node-management port. Do not change SSH, global policies or other rules.
if ! iptables -nL HAM_TLS245 >/dev/null 2>&1; then
  iptables -N HAM_TLS245
  iptables -A HAM_TLS245 -s 127.0.0.1/32 -j ACCEPT
  iptables -A HAM_TLS245 -s 64.225.109.248/32 -j ACCEPT
  iptables -A HAM_TLS245 -j DROP
fi
iptables -C INPUT -p tcp --dport 2222 -j HAM_TLS245 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 2222 -j HAM_TLS245
ip6tables -C INPUT -p tcp --dport 2222 -j DROP 2>/dev/null || ip6tables -I INPUT 1 -p tcp --dport 2222 -j DROP
