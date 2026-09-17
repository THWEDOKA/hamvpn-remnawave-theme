"""Three-minute, source-restricted alternate SSH listener; existing SSH unchanged."""
import argparse
import json
import os
import subprocess
from preflight import save, read, exists, ENTRY

SOURCE = '206.223.240.179'
PORT = 22023
CHAIN = 'HAM_C140_KZSSH'
UNIT = 'ham-cloud140-kz-ssh-probe.service'


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if p.returncode: raise RuntimeError('Command failed: ' + args[0])
    return p.stdout


def start():
    assert ENTRY + '/' in run('ip', '-4', 'addr', 'show')
    assert not exists('ssh-alternate-intent'), 'Inspect previous intent'
    assert not run('ss', '-H', '-lnt', 'sport = :' + str(PORT)).strip()
    assert '-N ' + CHAIN not in run('iptables', '-S')
    args = ['/usr/sbin/sshd', '-D', '-e', '-p', str(PORT), '-o', 'ListenAddress=' + ENTRY,
            '-o', 'AllowUsers=ham-cloud140-kz2', '-o', 'PermitRootLogin=no',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'PidFile=/run/ham-cloud140-kz-ssh-probe.pid']
    run(*[x for x in args if x not in ('-D', '-e')], '-t')
    save('ssh-alternate-intent', dict(port=PORT, source=SOURCE, firewall=run('iptables-save')))
    run('iptables', '-N', CHAIN)
    run('iptables', '-A', CHAIN, '-s', SOURCE, '-j', 'ACCEPT')
    run('iptables', '-A', CHAIN, '-j', 'DROP')
    run('iptables', '-I', 'INPUT', '1', '-p', 'tcp', '--dport', str(PORT), '-j', CHAIN)
    run('systemd-run', '--unit=' + UNIT, '--property=RuntimeMaxSec=180', '--property=UMask=0077', *args)
    return dict(temporary_ssh_port=PORT, only_source=SOURCE, expires_seconds=180, existing_ssh_untouched=True)


def cleanup():
    intent = read('ssh-alternate-intent'); assert intent['port'] == PORT and intent['source'] == SOURCE
    expected = ['-N ' + CHAIN, '-A ' + CHAIN + ' -s ' + SOURCE + '/32 -j ACCEPT', '-A ' + CHAIN + ' -j DROP']
    assert run('iptables', '-S', CHAIN).strip().splitlines() == expected, 'Own chain changed'
    rules = run('iptables', '-S', 'INPUT').strip().splitlines()
    own = '-A INPUT -p tcp -m tcp --dport ' + str(PORT) + ' -j ' + CHAIN
    assert rules.count(own) == 1, 'Own INPUT rule changed'
    run('systemctl', 'stop', UNIT)
    state = run('systemctl', 'show', UNIT, '-p', 'ActiveState', '--value').strip()
    assert state in ('inactive', 'failed'), 'Probe still running'
    run('iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', str(PORT), '-j', CHAIN)
    run('iptables', '-D', CHAIN, '-s', SOURCE, '-j', 'ACCEPT')
    run('iptables', '-D', CHAIN, '-j', 'DROP')
    run('iptables', '-X', CHAIN)
    assert not run('ss', '-H', '-lnt', 'sport = :' + str(PORT)).strip()
    save('ssh-alternate-cleanup', dict(own_listener_stopped=True, own_firewall_rules_removed=True))
    return dict(own_probe_removed=True, existing_ssh_untouched=True)


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['start', 'cleanup']); a=p.parse_args()
    print(json.dumps(globals()[a.action]()))
