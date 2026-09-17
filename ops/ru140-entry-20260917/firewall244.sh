#!/bin/sh
# Only TCP/2222 on this entry. Never flush INPUT or touch SSH/VPN/web rules.
set -eu
export LC_ALL=C
[ "$(id -u)" = 0 ]
ip -o -4 addr show | grep -Fq '193.233.222.244/'
exec 9>/run/lock/ham-entry244-api-firewall.lock
flock -x 9
chain=HAM_ENTRY244_API
marker=ham-entry244-api-20260917

check_chain() {
    tool=$1
    "$tool" -w 10 -C "$chain" -i lo -m comment --comment "$marker" -j ACCEPT
    if [ "$tool" = iptables ]; then
        "$tool" -w 10 -C "$chain" -s 64.225.109.248/32 -m comment --comment "$marker" -j ACCEPT
        expected=3
    else
        expected=2
    fi
    "$tool" -w 10 -C "$chain" -m comment --comment "$marker" -j DROP
    [ "$("$tool" -w 10 -S "$chain" | grep -c '^-A ')" = "$expected" ]
}

check_jump() {
    tool=$1
    "$tool" -w 10 -C INPUT -p tcp --dport 2222 -m comment --comment "$marker" -j "$chain"
    # An earlier broad ACCEPT must not bypass the API restriction.
    first=$("$tool" -w 10 -S INPUT | sed -n '/^-A /{p;q;}')
    case "$first" in
        "-A INPUT -p tcp -m tcp --dport 2222 -m comment --comment "*"$marker"*" -j $chain") ;;
        *) return 1 ;;
    esac
}

apply_family() {
    tool=$1
    if "$tool" -w 10 -S "$chain" >/dev/null 2>&1; then
        # Refuse to replace an unknown/incomplete chain under our name.
        check_chain "$tool"
    else
        "$tool" -w 10 -N "$chain"
        "$tool" -w 10 -A "$chain" -i lo -m comment --comment "$marker" -j ACCEPT
        if [ "$tool" = iptables ]; then
            "$tool" -w 10 -A "$chain" -s 64.225.109.248/32 -m comment --comment "$marker" -j ACCEPT
        fi
        "$tool" -w 10 -A "$chain" -m comment --comment "$marker" -j DROP
    fi
    if ! "$tool" -w 10 -C INPUT -p tcp --dport 2222 -m comment --comment "$marker" -j "$chain" 2>/dev/null; then
        "$tool" -w 10 -I INPUT 1 -p tcp --dport 2222 -m comment --comment "$marker" -j "$chain"
    fi
    check_chain "$tool"
    check_jump "$tool"
}

case "${1:-apply}" in
    apply) apply_family ip6tables; apply_family iptables ;;
    check) check_chain ip6tables; check_jump ip6tables; check_chain iptables; check_jump iptables ;;
    rollback)
        # Only remove our exact rules; never restore a whole firewall snapshot.
        for tool in iptables ip6tables; do
            check_chain "$tool"
            "$tool" -w 10 -D INPUT -p tcp --dport 2222 -m comment --comment "$marker" -j "$chain"
            "$tool" -w 10 -F "$chain"
            "$tool" -w 10 -X "$chain"
        done
        ;;
    *) exit 2 ;;
esac
