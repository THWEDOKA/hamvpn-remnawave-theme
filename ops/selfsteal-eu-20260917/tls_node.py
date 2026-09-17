"""Prepare the owner's revised TLS + HY2 template on only these new hosts."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from node import run, spec, ROOT


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('id'); args = parser.parse_args()
    n = spec(args.id)
    assert n['ip'] + '/' in run('ip', '-4', 'addr', 'show', capture=True).stdout
    for port in (9443, 9444): assert not run('ss', '-H', '-lnt', 'sport = :' + str(port), capture=True).stdout.strip()
    backup = Path('/root/hamvpn-selfsteal-' + n['id'] + '-backup/tls-hy2')
    assert not backup.exists(), 'Existing revision preparation: inspect rather than repeat'
    backup.mkdir(mode=0o700)
    compose = Path('/opt/remnanode/docker-compose.yml')
    shutil.copyfile(compose, backup / 'docker-compose.before.json')
    hook = Path('/etc/letsencrypt/renewal-hooks/deploy/hamvpn-selfsteal-nginx')
    shutil.copyfile(hook, backup / 'renew.before.sh')
    conf = Path('/etc/nginx/conf.d/hamvpn-fallback.conf'); assert not conf.exists()
    shutil.copyfile(ROOT / n['id'] / 'nginx-fallback.conf', conf); conf.chmod(0o644)
    run('nginx', '-t'); run('systemctl', 'reload', 'nginx')
    content = json.loads(compose.read_text())
    service = content['services']['remnanode']; assert service['network_mode'] == 'host'
    assert 'volumes' not in service, 'Unexpected existing mount'
    service['volumes'] = ['/etc/letsencrypt:/etc/letsencrypt:ro']
    compose.write_text(json.dumps(content)); compose.chmod(0o600)
    run('systemctl', 'is-active', '--quiet', 'hamvpn-selfsteal-firewall.service')
    run('docker', 'compose', '-f', str(compose), 'up', '-d')
    run('docker', 'cp', str(ROOT / n['id'] / 'tls-hy2-config.json'), 'remnanode:/tmp/hamvpn-tls-hy2-test.json')
    result = run('docker', 'exec', 'remnanode', 'xray', 'run', '-test', '-c', '/tmp/hamvpn-tls-hy2-test.json', capture=True)
    (backup / 'xray-test.txt').write_text(result.stdout + result.stderr)
    shutil.copyfile(ROOT / 'renew-tls.sh', hook); hook.chmod(0o755)
    print(json.dumps({'id': n['id'], 'certificate_readonly_mount': True, 'fallback_http1_h2': True,
                      'installed_xray_config_test': True, 'renewal_hook_updated': True}))


if __name__ == '__main__': main()
