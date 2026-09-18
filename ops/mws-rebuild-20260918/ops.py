"""Scoped MWS rebuild preparation; credentials never belong in this repository.

Run only the explicit action on the matching machine. Does not remove old VPN,
change host bindings or touch remnanode-gas/remnanode-friend.
"""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-mws-rebuild-20260918')
TARGETS = {
    'entry': {'ip': '176.109.85.244', 'domain': 'mws.torcalc.ru'},
    'exit': {'ip': '72.56.101.218', 'domain': 'mws-exit.torcalc.ru'},
}
OLD_NODE = '48854cc2-e603-439a-a401-c2aa68ff30ed'
OLD_PROFILE = '9f6bf3a4-7107-4e01-a4e1-9a022fe97ac7'
OLD_HOST = '3381a72d-522a-4fbf-878b-532f00ff1ba5'
OLD_CONTAINER = 'remnanode-ham-shared'
TLS_PORT = 9444
IMAGE = 'remnawave/node@sha256:9d57375a8168d00252f4debe7a6ac29debd8449af60467ab26b4ee212b047525'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data, mode=0o600):
    path = Path(path)
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'Symlink destination refused')
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.mws-pending')
    with pending.open('xb') as f:
        os.chmod(pending, mode)
        f.write(data.encode() if isinstance(data, str) else data)
        f.flush(); os.fsync(f.fileno())
    pending.replace(path)


def save(name, value):
    require('/' not in name and '..' not in name, 'Unsafe state name')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and stat.S_IMODE(STATE.stat().st_mode) == 0o700,
            'State must be root-only')
    write(STATE / (name + '.json'), json.dumps(value, ensure_ascii=False))


def read(name):
    p = STATE / (name + '.json')
    require(p.is_file() and not p.is_symlink() and p.stat().st_uid == 0 and p.stat().st_mode & 0o077 == 0,
            'Private state required')
    return json.loads(p.read_text())


def run(*args, data=None, timeout=90):
    r = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
    if r.returncode:
        save('last-error', {'program': args[0], 'returncode': r.returncode,
                            'stdout': r.stdout.decode(errors='replace'), 'stderr': r.stderr.decode(errors='replace')})
        raise RuntimeError('Command failed; details restricted to operation state')
    return r.stdout


def guard(role):
    require(os.geteuid() == 0, 'Root required')
    os.umask(0o077)
    if role in TARGETS:
        require((TARGETS[role]['ip'] + '/').encode() in run('ip', '-4', 'addr', 'show'), 'Wrong server')


def api_client():
    p = ROOT.parent / 'selfsteal-us3/panel_api.py'
    spec = importlib.util.spec_from_file_location('mws_api', p)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.create_client()[0]


def panel_snapshot():
    require(not (STATE / 'panel-before.json').exists(), 'Snapshot exists; do not overwrite')
    api = api_client()
    nodes, hosts = api('GET', '/api/nodes/'), api('GET', '/api/hosts/')
    node = next(n for n in nodes if n['uuid'] == OLD_NODE)
    require(node['name'] == 'MWS' and node['address'] == 'hw-mws.flowceo.ai', 'Node identity changed')
    require(node['configProfile']['activeConfigProfileUuid'] == OLD_PROFILE, 'Profile changed')
    consumers = [n['uuid'] for n in nodes if (n.get('configProfile') or {}).get('activeConfigProfileUuid') == OLD_PROFILE]
    require(consumers == [OLD_NODE], 'Profile now shared with another node')
    linked = [h for h in hosts if OLD_NODE in (h.get('nodes') or [])]
    require([h['uuid'] for h in linked] == [OLD_HOST], 'Host scope changed')
    require(linked[0]['nodes'] == [OLD_NODE], 'Host is shared')
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    before = {'node': node, 'profile': api('GET', '/api/config-profiles/' + OLD_PROFILE),
              'hosts': linked, 'squads': squads, 'all_nodes': nodes, 'all_hosts': hosts,
              'time': time.time()}
    save('panel-before', before)
    sha = digest((STATE / 'panel-before.json').read_bytes())
    require(read('panel-before') == before, 'Snapshot readback failed')
    save('panel-before-checksum', {'sha256': sha})
    return {'panel_snapshot_verified': True, 'sha256': sha, 'target_hosts': len(linked)}


def node_snapshot(role):
    guard(role)
    if (STATE / 'node-before.json').exists():
        b = read('node-before')
        require(digest((STATE / 'node-before.tar.gz').read_bytes()) == b['archive_sha256'], 'Backup mismatch')
        return {'node_snapshot_verified': True, 'already_exists': True, 'role': role}
    STATE.mkdir(mode=0o700, exist_ok=True)
    paths = ['/etc/ssh', '/etc/nginx', '/etc/letsencrypt', '/etc/ufw', '/etc/systemd/system', '/root/.ssh',
             '/opt/remnanode-ham-shared']
    archive = STATE / 'node-before.tar.gz'
    require(not archive.exists(), 'Partial archive found; inspect before retry')
    with tarfile.open(archive, 'w:gz') as t:
        for p in paths:
            if Path(p).exists():
                t.add(p, arcname=p.lstrip('/'))
    archive.chmod(0o600)
    with tarfile.open(archive) as t:
        require(len(t.getmembers()) > 0, 'Empty snapshot')
    before = {'role': role, 'time': time.time(), 'archive_sha256': digest(archive.read_bytes()),
              'listeners': run('ss', '-lntup').decode(), 'packages': run('dpkg-query', '-W').decode()}
    for tool in ('iptables-save', 'ip6tables-save', 'nft'):
        if shutil.which(tool):
            before[tool] = run(tool, *(['list', 'ruleset'] if tool == 'nft' else [])).decode()
    if shutil.which('docker'):
        before['containers'] = json.loads(run('docker', 'inspect', *run('docker', 'ps', '-q').decode().split()))
    save('node-before', before)
    return {'node_snapshot_verified': True, 'sha256': before['archive_sha256'], 'role': role}


def admin_key(role):
    require(role == 'exit', 'Bootstrap is limited to the new bridge')
    node_snapshot(role)
    key = sys.stdin.read().strip()
    parts = key.split()
    require(len(parts) in (2, 3) and parts[0] == 'ssh-ed25519' and '\n' not in key, 'Expected one public key')
    require(len(base64.b64decode(parts[1])) == 51, 'Invalid Ed25519 key')
    folder = Path('/root/.ssh'); folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / 'authorized_keys'
    require(not folder.is_symlink() and not path.is_symlink(), 'Symlink key store refused')
    old = path.read_text() if path.exists() else ''
    if not any(parts[1] in row.split() for row in old.splitlines()):
        write(path, old.rstrip('\n')+'\n'+key+'\n')
    folder.chmod(0o700); path.chmod(0o600)
    return {'existing_operator_public_key_installed': True, 'backup_retained': True}


def dns_client():
    p = Path('/etc/hamvpn-dns-ru214/credentials.json')
    require(p.is_file() and p.stat().st_uid == 0 and p.stat().st_mode & 0o077 == 0, 'Protected DNS credentials required')
    c = json.loads(p.read_text())
    base = 'https://api.cloudflare.com/client/v4/zones/' + c['zone_id'] + '/dns_records'
    def request(method, path='', body=None):
        req = urllib.request.Request(base+path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer '+c['token'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as r: value = json.load(r)
        require(value.get('success') is True, 'DNS request rejected')
        return value['result']
    return request


def dns_prepare():
    read('panel-before')
    request = dns_client()
    results = []
    for role, target in TARGETS.items():
        name = 'dns-'+role
        wanted = json.loads((ROOT / role / 'dns-record.json').read_text())
        rows = request('GET', '?'+urllib.parse.urlencode({'name': target['domain']}))
        if not (STATE / (name+'.json')).exists():
            require(not rows, 'Existing DNS record conflicts with fresh installation')
            save(name, {'wanted': wanted, 'before': [], 'intent': True})
            # On uncertainty never POST again: subsequent run only reconciles.
            row = request('POST', body=wanted)
            save(name, {'wanted': wanted, 'before': [], 'id': row['id']})
        rows = request('GET', '?'+urllib.parse.urlencode({'name': target['domain']}))
        require(len(rows) == 1 and all(rows[0].get(k) == v for k, v in wanted.items()), 'DNS readback mismatch')
        saved = read(name)
        if saved.get('id'):
            require(saved['id'] == rows[0]['id'], 'DNS ownership changed')
        else:
            saved['id'] = rows[0]['id']; save(name, saved)
        results.append({'domain': target['domain'], 'address': target['ip'], 'dns_only': True})
    return {'dns_verified': results}


def prepare_site(role):
    guard(role); node_snapshot(role)
    marker = STATE / 'http-prepared.json'
    require(not marker.exists(), 'HTTP preparation already complete')
    for port in [80, TLS_PORT]:
        require(not run('ss', '-H', '-lnt', 'sport = :'+str(port)).strip(), 'Required HTTP/TLS port occupied')
    os.environ.update(DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    run('apt-get', 'update', '-qq', timeout=240)
    packages = ['nginx', 'certbot', 'ca-certificates', 'curl']
    if role == 'exit': packages += ['docker.io', 'docker-compose-v2']
    run('apt-get', 'install', '-y', '--no-install-recommends', *packages, timeout=360)
    # The installer may have started only the newly installed web service.
    domain = TARGETS[role]['domain']
    web = Path('/var/www') / domain; web.mkdir(mode=0o755, exist_ok=True); web.chmod(0o755)
    for name in ('index.html', 'style.css'):
        write(web / name, (ROOT / role / 'site' / name).read_bytes(), 0o644)
    acme = Path('/var/www/acme/.well-known/acme-challenge')
    acme.mkdir(parents=True, exist_ok=True)
    for p in [acme, acme.parent, acme.parent.parent]: p.chmod(0o755)
    token = 'ham-mws-20260918-'+role
    write(acme / token, token+'\n', 0o644)
    vhost = Path('/etc/nginx/sites-available/ham-mws-selfsteal')
    enabled = Path('/etc/nginx/sites-enabled/ham-mws-selfsteal')
    require(not vhost.exists() and not enabled.exists(), 'Existing owned vhost requires reconciliation')
    write(vhost, (ROOT / role / 'nginx-http.conf').read_bytes(), 0o644)
    enabled.symlink_to(vhost)
    run('nginx', '-t'); run('systemctl', 'enable', '--now', 'nginx'); run('systemctl', 'reload', 'nginx')
    result = {'role': role, 'domain': domain, 'address': TARGETS[role]['ip'], 'token': token,
              'time': time.time(), 'vhost_sha256': digest(vhost.read_bytes())}
    save('http-prepared', result)
    return result


def certificate(role):
    guard(role); prepared = read('http-prepared')
    require(prepared['role'] == role, 'Wrong preparation')
    external = json.load(sys.stdin)
    require(external.get('domain') == TARGETS[role]['domain'] and external.get('http_challenge_verified') is True
            and 0 <= time.time()-external.get('time', 0) < 1800, 'Fresh external HTTP proof required')
    domain = TARGETS[role]['domain']; cert = Path('/etc/letsencrypt/live') / domain / 'fullchain.pem'
    if not cert.exists():
        require(not (STATE / 'cert-intent.json').exists(), 'Uncertain certificate attempt; inspect before retry')
        save('cert-intent', {'domain': domain, 'time': time.time()})
        run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--register-unsafely-without-email',
            '--webroot', '-w', '/var/www/acme', '--preferred-challenges', 'http', '--key-type', 'ecdsa',
            '--cert-name', domain, '-d', domain, timeout=180)
    run('openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '2592000')
    vhost = Path('/etc/nginx/sites-available/ham-mws-selfsteal')
    require(digest(vhost.read_bytes()) == prepared['vhost_sha256'], 'HTTP vhost drift')
    write(vhost, (ROOT / role / 'nginx-tls.conf').read_bytes(), 0o644)
    try: run('nginx', '-t')
    except Exception:
        write(vhost, (ROOT / role / 'nginx-http.conf').read_bytes(), 0o644)
        raise
    run('systemctl', 'reload', 'nginx')
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/ham-mws-nginx')
    require(not hook.exists(), 'Existing renewal hook requires reconciliation')
    write(hook, (ROOT / role / 'renew-nginx.sh').read_bytes(), 0o755)
    run('systemctl', 'enable', '--now', 'certbot.timer')
    context = ssl.create_default_context(); context.set_alpn_protocols(['h2', 'http/1.1'])
    with socket.create_connection(('127.0.0.1', TLS_PORT), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            require(tls.version() == 'TLSv1.3' and tls.selected_alpn_protocol() == 'h2', 'TLS 1.3/h2 required')
    run('curl', '--noproxy', '*', '-fsS', '--resolve', domain+':9444:127.0.0.1',
        'https://'+domain+':9444/', '-o', '/dev/null')
    result = {'local_tls_verified': True, 'role': role, 'domain': domain,
              'details': run('openssl', 'x509', '-in', str(cert), '-noout', '-dates').decode(),
              'time': time.time(), 'vhost_sha256': digest(vhost.read_bytes())}
    save('certificate', result)
    return result


def renew(role):
    guard(role); read('certificate')
    args = ['certbot', 'renew', '--cert-name', TARGETS[role]['domain'], '--dry-run', '--run-deploy-hooks']
    help_text = run('certbot', '--help', 'all').decode()
    if '--no-random-sleep-on-renew' in help_text: args.append('--no-random-sleep-on-renew')
    run(*args, timeout=240)
    require(run('systemctl', 'is-active', 'certbot.timer').strip() == b'active', 'Renewal timer inactive')
    save('renewal', {'passed': True, 'time': time.time()})
    return {'renewal_dry_run_passed': True, 'role': role}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['panel-snapshot','node-snapshot','admin-key','dns-prepare','prepare-site','certificate','renew'])
    parser.add_argument('--role', choices=['entry','exit','panel'], required=True)
    args = parser.parse_args(); guard(args.role)
    if args.action in ('panel-snapshot', 'dns-prepare'):
        require(args.role == 'panel', 'Panel-only action')
        result = globals()[args.action.replace('-', '_')]()
    else:
        require(args.role in TARGETS, 'Node-only action')
        result = globals()[args.action.replace('-', '_')](args.role)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        # Do not expose secret API/config contents in exception representations.
        print(json.dumps({'failed': True, 'error':type(error).__name__,
                          'detail':str(error) if isinstance(error, RuntimeError) else 'Inspect operation state'}))
        sys.exit(1)
