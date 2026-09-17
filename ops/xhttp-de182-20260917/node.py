"""Add only one local nginx route, with timed and compare-before-restore rollback."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from common import ROOT, STATE, IP, PORT, candidate, save, read, exists

CONF = Path('/etc/nginx/conf.d/hamvpn-fallback.conf')
TIMER = 'ham-xhttp-de182-node-rollback'


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()


def hashes():
    paths = ['/opt/remnanode/docker-compose.yml',
        '/etc/letsencrypt/renewal/de182.torcalc.ru.conf',
        '/etc/letsencrypt/renewal-hooks/deploy/hamvpn-selfsteal-nginx',
        '/usr/local/sbin/hamvpn-selfsteal-firewall']
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths}


def prepare():
    assert not exists('node-before'), 'Existing intent: inspect instead of overwriting'
    original = (ROOT.parent / 'selfsteal-eu-20260917/de182/nginx-fallback.conf').read_text()
    assert CONF.read_text() == original, 'Unexpected existing fallback config'
    assert not run('ss', '-H', '-lnt', 'sport = :' + str(PORT)), 'Local port occupied'
    before = {'config': original, 'hashes': hashes(), 'time': time.time()}
    save('node-before', before)
    config = candidate(json.loads((ROOT.parent / 'selfsteal-eu-20260917/de182/tls-hy2-config.json').read_text()))
    save('node-candidate', config)
    run('docker', 'cp', str(STATE / 'node-candidate.json'), 'remnanode:/tmp/ham-xhttp-pilot-test.json')
    result = run('docker', 'exec', 'remnanode', 'xray', 'run', '-test', '-c', '/tmp/ham-xhttp-pilot-test.json')
    save('xray-test', {'passed': True, 'output': result})
    return {'installed_xray_test': True, 'backed_up': True, 'no_runtime_change': True}


def expected():
    before = read('node-before')['config']
    marker = '    location / { try_files $uri $uri/ =404; }'
    assert before.count(marker) == 1
    return before.replace(marker, (ROOT / 'nginx-location.conf').read_text() + marker)


def apply():
    assert read('xray-test')['passed']
    assert CONF.read_text() == read('node-before')['config']
    assert hashes() == read('node-before')['hashes']
    run('systemd-run', '--unit', TIMER, '--on-active=30m', '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback')
    CONF.write_text(expected()); CONF.chmod(0o644)
    try:
        run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    except Exception:
        rollback()
        raise
    save('node-applied', {'time': time.time(), 'config_sha256': hashlib.sha256(CONF.read_bytes()).hexdigest()})
    return {'nginx_route_added': True, 'timer_armed': True, 'vpn_not_restarted_by_node_script': True}


def rollback():
    assert CONF.read_text() in (expected(), read('node-before')['config']), 'Concurrent nginx edit'
    CONF.write_text(read('node-before')['config']); CONF.chmod(0o644)
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    save('node-rollback', {'time': time.time(), 'restored': True})
    return {'nginx_route_removed': True}


def finish():
    assert CONF.read_text() == expected()
    assert hashes() == read('node-before')['hashes']
    listener = run('ss', '-H', '-lnt', 'sport = :' + str(PORT))
    assert '127.0.0.1:' + str(PORT) in listener and '*:' + str(PORT) not in listener
    assert run('ss', '-H', '-lnt', 'sport = :443') and run('ss', '-H', '-lnu', 'sport = :443')
    for service in ('nginx', 'certbot.timer', 'hamvpn-selfsteal-firewall.service'):
        assert run('systemctl', 'is-active', service) == 'active'
    run('systemctl', 'stop', TIMER + '.timer')
    assert subprocess.run(['systemctl', 'is-active', '--quiet', TIMER + '.timer']).returncode != 0
    proof = {'time': time.time(), 'loopback_only': True, 'tcp_udp_443': True,
        'renewal_compose_firewall_preserved': True, 'rollback_disarmed': True}
    save('node-finished', proof)
    return proof


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['prepare', 'apply', 'rollback', 'finish'])
    args = p.parse_args()
    assert os.getuid() == 0 and IP + '/' in run('ip', '-4', 'addr', 'show')
    print(json.dumps(globals()[args.action]()))
