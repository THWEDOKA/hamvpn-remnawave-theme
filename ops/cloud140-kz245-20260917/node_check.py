"""Installed-Xray validation and authenticated probes, input secrets on stdin only."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import preflight as p
import probe


def checksum(config): return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def installed(config, identifier):
    n = next(n for n in p.NODES if n['id'] == identifier) if identifier != 'entry' else dict(ip=p.ENTRY, node=p.ENTRY_ID)
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show']))
    assert n['ip'] in {a['local'] for i in addresses for a in i.get('addr_info', [])}
    container = json.loads(subprocess.check_output(['docker', 'inspect', 'remnanode']))[0]
    assert container['HostConfig']['NetworkMode'] == 'host'
    version_text = subprocess.check_output(['docker', 'exec', 'remnanode', 'xray', 'version'], text=True)
    version = re.search(r'Xray\s+([0-9][A-Za-z0-9.+_-]*)', version_text).group(1)
    result = subprocess.run(['docker', 'exec', '-i', 'remnanode', 'xray', 'run', '-test', '-c', 'stdin:'],
                            input=json.dumps(config), capture_output=True, text=True, timeout=30)
    p.save('installed-diagnostics-' + identifier, dict(returncode=result.returncode, output=result.stdout + result.stderr))
    assert result.returncode == 0, 'Installed Xray rejected candidate; inspect private diagnostics'
    proof = dict(id=identifier, node=n['node'], ip=n['ip'], sha256=checksum(config), timestamp=time.time(),
                 tests=[dict(kind='installed-xray', passed=True, returncode=0, version=version)])
    p.save('installed-' + identifier, proof)
    return proof


def traffic(request, label, on_entry=False):
    assert isinstance(request, dict) and re.fullmatch('[0-9a-f]{64}', request['sha256'])
    items = request['items']; assert items and len(items) <= 16 and len({i['id'] for i in items}) == len(items)
    assert all(i['ip'] in {n['ip'] for n in p.NODES} for i in items)
    p.STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='traffic-', dir=p.STATE) as directory:
        if on_entry:
            config = json.loads(subprocess.check_output(['docker', 'inspect', 'remnanode']))[0]
            assert config['HostConfig']['NetworkMode'] == 'host'
            for item in items:
                endpoint = item['outbound']['settings']['vnext'][0]
                assert endpoint['address'] == '127.0.0.1' and endpoint['port'] in (27443, 28443)
            binary = Path(directory) / 'xray'
            subprocess.run(['docker','cp','-L','remnanode:/usr/local/bin/xray',str(binary)],check=True,capture_output=True)
            binary.chmod(0o700)
        else:
            binary = Path('/root/selfsteal-us3-test/xray')
            assert binary.is_file() and binary.stat().st_uid == 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda item: probe.test(item, binary), items))
    proof = dict(sha256=request['sha256'], timestamp=time.time(), tests=results,
                 all_passed=bool(results) and all(i['passed'] for i in results))
    p.save(label, proof)
    return proof


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['installed', 'backend', 'public'])
    parser.add_argument('--id', choices=['entry','de245','kz2'])
    parser.add_argument('--label', choices=['candidate-probes', 'subscription-probes', 'backend-probes'])
    args = parser.parse_args(); data=json.load(sys.stdin)
    if args.action == 'installed':
        assert args.id; result=installed(data,args.id)
    else:
        assert args.label; result=traffic(data,args.label,args.action=='backend')
    print(json.dumps(result))
