"""Run on the new node. A private one-shot relay supplies the panel node key."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/opt/hamvpn-tls245')


def main():
    os.umask(0o077)
    compose = Path('/opt/remnanode/docker-compose.yml')
    assert not compose.exists(), 'Existing node must not be overwritten'
    secret_path = ROOT / 'node-key.json'
    secret = json.loads(secret_path.read_text())['pubKey']
    assert isinstance(secret, str) and len(secret) > 40
    image = (ROOT / 'node-image.txt').read_text().strip()
    assert image.startswith('remnawave/node@sha256:') and len(image.rsplit(':', 1)[1]) == 64
    compose.parent.mkdir(mode=0o700, exist_ok=True)
    compose.write_text(json.dumps({'services': {'remnanode': {
        'image': image, 'container_name': 'remnanode', 'hostname': 'remnanode',
        'network_mode': 'host', 'restart': 'always',
        'environment': {'NODE_PORT': '2222', 'SECRET_KEY': secret},
        'volumes': ['/etc/letsencrypt:/etc/letsencrypt:ro'],
        'ulimits': {'nofile': {'soft': 1048576, 'hard': 1048576}},
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}
    }}}))
    compose.chmod(0o600)
    secret_path.unlink()
    firewall = ROOT / 'node_firewall.sh'
    firewall.chmod(0o700)
    unit = Path('/etc/systemd/system/hamvpn-tls245-firewall.service')
    assert not unit.exists()
    unit.write_text('[Unit]\nDescription=HAMVPN TLS245 management firewall\nBefore=docker.service\nAfter=network-pre.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/opt/hamvpn-tls245/node_firewall.sh\n\n[Install]\nWantedBy=multi-user.target\n')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', unit.name], check=True)
    subprocess.run(['docker', 'compose', '-f', str(compose), 'up', '-d'], check=True)
    print(json.dumps({'node_started': True, 'image': image, 'management_restricted': True}))


if __name__ == '__main__':
    main()
