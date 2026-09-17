"""Fresh-node-only installer for the four owner-approved EU hosts. No secrets in argv."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def run(*args, capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture)


def spec(identifier):
    return next(n for n in json.loads((ROOT / 'nodes.json').read_text()) if n['id'] == identifier)


def backup(n):
    destination = Path('/root/hamvpn-selfsteal-' + n['id'] + '-backup')
    assert not destination.exists(), 'Existing preparation: inspect, do not overwrite backup'
    destination.mkdir(mode=0o700)
    for command, filename in [('iptables-save', 'iptables.v4'), ('ip6tables-save', 'iptables.v6'),
                              ('nft', 'nft.txt')]:
        if shutil.which(command):
            args = [command, 'list', 'ruleset'] if command == 'nft' else [command]
            (destination / filename).write_text(run(*args, capture=True).stdout)
    (destination / 'packages.txt').write_text(run('dpkg-query', '-W', capture=True).stdout)
    selected = [p for p in ['etc/ssh', 'etc/ufw', 'etc/nftables.conf', 'etc/systemd/system'] if Path('/' + p).exists()]
    run('tar', '-czf', str(destination / 'configuration.tgz'), '-C', '/', *selected)
    checks = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in destination.iterdir() if p.is_file()}
    (destination / 'checksums.json').write_text(json.dumps(checks))
    assert all(hashlib.sha256((destination / name).read_bytes()).hexdigest() == value for name, value in checks.items())
    return destination


def install(n):
    assert not Path('/opt/remnanode').exists() and not Path('/etc/nginx').exists()
    for port in (80, 443, 8443, 2222):
        assert not run('ss', '-H', '-lnt', 'sport = :' + str(port), capture=True).stdout.strip(), 'Occupied port'
    destination = backup(n)
    os.environ.update(DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    run('apt-get', 'update', '-qq')
    run('apt-get', 'install', '-y', '--no-install-recommends', 'docker.io', 'nginx', 'certbot',
        'ca-certificates', 'curl', 'iptables')
    candidate = run('apt-cache', 'policy', 'docker-compose-v2', capture=True).stdout
    package = 'docker-compose-v2' if 'Candidate:' in candidate and 'Candidate: (none)' not in candidate else 'docker-compose'
    run('apt-get', 'install', '-y', '--no-install-recommends', package)
    run('systemctl', 'enable', '--now', 'docker')
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink(): default.rename(destination / 'nginx-default-link')
    site = Path('/var/www/' + n['domain']); site.mkdir(mode=0o755, parents=True); site.chmod(0o755)
    challenge = Path('/var/www/acme/.well-known/acme-challenge')
    challenge.mkdir(mode=0o755, parents=True, exist_ok=True)
    for directory in (challenge, challenge.parent, challenge.parent.parent): directory.chmod(0o755)
    for name in ('index.html', 'style.css'):
        shutil.copyfile(ROOT / n['id'] / 'site' / name, site / name); (site / name).chmod(0o644)
    conf = Path('/etc/nginx/sites-available/' + n['domain'])
    shutil.copyfile(ROOT / n['id'] / 'nginx-http.conf', conf); conf.chmod(0o644)
    Path('/etc/nginx/sites-enabled/' + n['domain']).symlink_to(conf)
    run('nginx', '-t'); run('systemctl', 'enable', '--now', 'nginx'); run('systemctl', 'reload', 'nginx')
    run('docker', 'pull', 'remnawave/node:2.7.0')
    image = run('docker', 'image', 'inspect', 'remnawave/node:2.7.0', '--format', '{{index .RepoDigests 0}}', capture=True).stdout.strip()
    assert image.startswith('remnawave/node@sha256:') and len(image.rsplit(':', 1)[1]) == 64
    (destination / 'node-image.txt').write_text(image)
    print(json.dumps({'prepared': n['id'], 'backup': str(destination), 'image': image}))


def certificate(n):
    assert not Path('/etc/letsencrypt/live/' + n['domain']).exists(), 'Inspect existing certificate first'
    run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
        '--webroot', '-w', '/var/www/acme', '--preferred-challenges', 'http', '--key-type', 'ecdsa',
        '--elliptic-curve', 'secp256r1', '--cert-name', n['domain'], '-d', n['domain'])
    fullchain = '/etc/letsencrypt/live/' + n['domain'] + '/fullchain.pem'
    run('openssl', 'x509', '-in', fullchain, '-noout', '-checkend', '2592000')
    conf = Path('/etc/nginx/sites-available/' + n['domain'])
    shutil.copyfile(ROOT / n['id'] / 'nginx-tls.conf', conf); conf.chmod(0o644)
    try: run('nginx', '-t')
    except Exception:
        shutil.copyfile(ROOT / n['id'] / 'nginx-http.conf', conf)
        raise
    run('systemctl', 'reload', 'nginx')
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/hamvpn-selfsteal-nginx')
    shutil.copyfile(ROOT / n['id'] / 'renew-nginx.sh', hook); hook.chmod(0o755)
    run('systemctl', 'enable', '--now', 'certbot.timer')
    run('curl', '--noproxy', '*', '-fsS', '--resolve', n['domain'] + ':8443:127.0.0.1',
        'https://' + n['domain'] + ':8443/', '-o', '/dev/null')
    run('openssl', 'x509', '-in', fullchain, '-noout', '-dates', '-issuer')


def start(n):
    secret = json.load(sys.stdin)['pubKey']
    assert isinstance(secret, str) and len(secret) > 40
    destination = Path('/root/hamvpn-selfsteal-' + n['id'] + '-backup')
    image = (destination / 'node-image.txt').read_text().strip()
    compose = Path('/opt/remnanode/docker-compose.yml')
    assert not compose.exists()
    compose.parent.mkdir(mode=0o700)
    compose.write_text(json.dumps({'services': {'remnanode': {'image': image, 'container_name': 'remnanode',
        'hostname': 'remnanode', 'network_mode': 'host', 'restart': 'always',
        'environment': {'NODE_PORT': '2222', 'SECRET_KEY': secret},
        'ulimits': {'nofile': {'soft': 1048576, 'hard': 1048576}},
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}}}))
    compose.chmod(0o600)
    script = Path('/usr/local/sbin/hamvpn-selfsteal-firewall')
    assert not script.exists()
    shutil.copyfile(ROOT / 'firewall.sh', script); script.chmod(0o700)
    unit = Path('/etc/systemd/system/hamvpn-selfsteal-firewall.service')
    assert not unit.exists()
    unit.write_text('[Unit]\nDescription=HAMVPN node management isolation\nBefore=docker.service\nAfter=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/hamvpn-selfsteal-firewall\n\n[Install]\nWantedBy=multi-user.target\n')
    run('systemctl', 'daemon-reload'); run('systemctl', 'enable', '--now', unit.name)
    command = ['docker', 'compose'] if subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode == 0 else ['docker-compose']
    run(*command, '-f', str(compose), 'up', '-d')
    print(json.dumps({'started': n['id'], 'management_panel_only': True, 'host_network': True}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('id', choices=[n['id'] for n in json.loads((ROOT / 'nodes.json').read_text())])
    parser.add_argument('action', choices=['install', 'certificate', 'start'])
    args = parser.parse_args(); n = spec(args.id)
    assert os.geteuid() == 0
    assert n['ip'] + '/' in run('ip', '-4', 'addr', 'show', capture=True).stdout, 'Wrong target IP'
    globals()[args.action](n)


if __name__ == '__main__': main()
