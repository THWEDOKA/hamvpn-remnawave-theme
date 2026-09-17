"""Read-only aggregate connection/pressure diagnostics; no peer addresses."""
import collections
import json
from pathlib import Path
import subprocess


def run(*args):
    return subprocess.check_output(args, text=True)


def main():
    result = {}
    for name in ('nf_conntrack_count', 'nf_conntrack_max', 'nf_conntrack_buckets'):
        result[name] = Path('/proc/sys/net/netfilter/' + name).read_text().strip()
    for name in ('tcp_max_orphans', 'tcp_orphan_retries', 'tcp_fin_timeout', 'tcp_mem',
                 'tcp_max_tw_buckets', 'ip_local_port_range'):
        result[name] = Path('/proc/sys/net/ipv4/' + name).read_text().strip()
    result['pressure'] = {p.name: p.read_text() for p in Path('/proc/pressure').iterdir()}
    result['sockstat'] = Path('/proc/net/sockstat').read_text()
    sockets = run('ss', '-Hant').splitlines()
    result['states'] = dict(collections.Counter(s.split()[0] for s in sockets))
    result['local_ports'] = dict(collections.Counter(
        s.split()[3].rsplit(':', 1)[-1] if s.split()[3].rsplit(':', 1)[-1] in
        ('443', '8443', '80', '22', '2222') else 'other' for s in sockets))
    result['ct_slab'] = [s for s in Path('/proc/slabinfo').read_text().splitlines()
        if s.startswith('nf_conntrack ') or s.startswith('tw_sock_TCP ') or s.startswith('TCP ')]
    result['renewal'] = '\n'.join(s for s in Path('/etc/letsencrypt/renewal/tls245.torcalc.ru.conf').read_text().splitlines()
        if s.startswith(('authenticator =', 'webroot_path =')))
    result['renew_hook_sha256'] = run('sha256sum', '/etc/letsencrypt/renewal-hooks/deploy/hamvpn-tls245').split()[0]
    result['kernel_ct_log_summary'] = run('journalctl', '-k', '--since', '2026-09-17', '--no-pager').count('table full, dropping packet')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
