"""Read-only, secret-safe health inventory for the existing TLS245 node."""
import collections
import json
import re
import subprocess


def run(*args):
    p = subprocess.run(args, text=True, capture_output=True, timeout=45)
    return p.returncode, p.stdout + p.stderr


def main():
    result = {}
    data = json.loads(run('docker', 'inspect', 'remnanode')[1])[0]
    result['container'] = {k: data.get(k) for k in ('Name', 'RestartCount', 'Created')}
    result['container']['state'] = {k: data['State'].get(k) for k in
        ('Status', 'Running', 'OOMKilled', 'Dead', 'StartedAt', 'FinishedAt', 'ExitCode')}
    result['container']['limits'] = {k: data['HostConfig'].get(k) for k in
        ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'NetworkMode')}
    result['container']['image'] = data['Config']['Image']
    for name, args in {
        'stats': ['docker', 'stats', '--no-stream', '--format', '{{.Name}} {{.CPUPerc}} {{.MemUsage}} {{.NetIO}} {{.PIDs}}'],
        'processes': ['ps', '-eo', 'pid,ppid,comm,%cpu,%mem,rss,etimes', '--sort=-rss'],
        'nginx': ['nginx', '-t'],
        'cert': ['openssl', 'x509', '-in', '/etc/letsencrypt/live/tls245.torcalc.ru/fullchain.pem', '-noout', '-dates', '-subject', '-issuer'],
        'timers': ['systemctl', 'list-timers', '--all', '--no-pager'],
        'network': ['ip', '-s', 'link'],
        'sockets': ['ss', '-s'],
        'tcp_stats': ['nstat', '-az'],
        'conntrack': ['sysctl', 'net.netfilter.nf_conntrack_count', 'net.netfilter.nf_conntrack_max', 'net.ipv4.tcp_congestion_control'],
        'firewall': ['iptables', '-nvL', 'HAM_TLS245'],
        'renewals': ['journalctl', '-u', 'certbot.service', '--since', '2026-09-15', '--no-pager', '-n', '35'],
    }.items():
        code, value = run(*args)
        if name == 'processes': value = '\n'.join(value.splitlines()[:12])
        if name == 'tcp_stats':
            value = '\n'.join(s for s in value.splitlines() if any(t in s for t in
                ('Retrans', 'Timeout', 'Listen', 'Abort', 'Memory', 'Backlog', 'OutSegs', 'InSegs', 'InErrs', 'OutRsts')))
        result[name] = {'exit': code, 'text': value.strip()}
    logs = run('docker', 'logs', '--since', '36h', '--tail', '30000', 'remnanode')[1]
    result['log_counts'] = {word: logs.lower().count(word) for word in
        ('error', 'fatal', 'panic', 'out of memory', 'started', 'stopped', 'restart', 'timeout', 'failed')}
    # Never publish raw node log lines (may include client IDs/configuration).
    result['error_categories'] = dict(collections.Counter(re.findall(
        r'(?:E[A-Z]{3,20}|context deadline exceeded|connection refused|connection reset by peer|too many open files|out of memory|i/o timeout)', logs)))
    kernel = run('journalctl', '-k', '--since', '2026-09-15', '--no-pager')[1]
    faults = [s for s in kernel.splitlines() if re.search(
        r'oom-kill|Out of memory|Killed process|nf_conntrack.*full|segfault|watchdog.*lockup', s, re.I)]
    result['kernel_faults'] = {'count': len(faults), 'first': faults[:2], 'last': faults[-2:]}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
