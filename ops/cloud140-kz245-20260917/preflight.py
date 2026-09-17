"""Scoped panel snapshot and disposable authenticated probes; no routing writes."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-cloud140-kz245-20260917')
sys.path.insert(0, str(ROOT.parent / 'selfsteal-us3'))
from panel_api import create_client

ENTRY = '176.108.245.140'
ENTRY_ID = 'f67527b4-9685-41a3-8bd1-c1538724b4a1'
NODES = [
    dict(id='kz2', ip='206.223.240.179', node='cfacbcaf-3c26-48ab-a321-826a9fc0137b',
         profile='d354e2ac-4b86-40a7-a0b3-ef9499d329b1', inbound='41b6c310-32dd-4845-acc6-816ed48e2ff9',
         sni='google.com', domain='in-kz2.torcalc.ru', port=18443,
         hosts=['4d2a011b-94de-4364-8e87-0d1fff8b9cb7', '2f7af907-559a-4b5e-85a8-73360a1ed908']),
    dict(id='de245', ip='196.251.107.245', node='dd62f99f-0464-413f-915e-05bb075098bd',
         profile='b4572f94-d216-471f-8824-d793b4eb53bd', inbound='af7d5f27-dd52-4e34-bc3d-666c46b3c2e2',
         sni='tls245.torcalc.ru', domain='in-de245.torcalc.ru', port=18444,
         hosts=['f9e8c4e3-24f4-4771-8e09-69d366c8f5b6', 'a12de64e-77ad-4265-b47d-d4bf3f61fd34']),
]


def save(name, value):
    if STATE.exists():
        assert not STATE.is_symlink() and STATE.stat().st_uid == 0 and STATE.stat().st_mode & 0o077 == 0
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = STATE / (name + '.json')
    pending = target.with_suffix('.pending')
    with pending.open('x', encoding='utf-8') as f:
        os.chmod(pending, 0o600)
        json.dump(value, f)
        f.flush(); os.fsync(f.fileno())
    pending.replace(target)


def read(name): return json.loads((STATE / (name + '.json')).read_text())
def exists(name): return (STATE / (name + '.json')).exists()


def snapshot(api):
    assert not exists('before'), 'Snapshot exists; inspect before resuming'
    nodes = api('GET', '/api/nodes/')
    hosts = api('GET', '/api/hosts/')
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    indexed = {n['uuid']: n for n in nodes}
    assert indexed[ENTRY_ID]['address'] == ENTRY and indexed[ENTRY_ID]['isConnected']
    profiles = {indexed[ENTRY_ID]['configProfile']['activeConfigProfileUuid']}
    for n in NODES:
        found = indexed[n['node']]
        assert found['address'] == n['ip'] and found['isConnected'] and not found['isDisabled']
        assert found['configProfile']['activeConfigProfileUuid'] == n['profile']
        assert n['inbound'] in {i['uuid'] for i in found['configProfile']['activeInbounds']}
        profiles.add(n['profile'])
        for hid in n['hosts']:
            h = next(h for h in hosts if h['uuid'] == hid)
            assert h['nodes'] == [n['node']] and not h['isDisabled']
            assert h['inbound'] == dict(configProfileUuid=n['profile'], configProfileInboundUuid=n['inbound'])
    value = dict(nodes=nodes, hosts=hosts, squads=squads,
                 profiles={p: api('GET', '/api/config-profiles/' + p) for p in profiles})
    save('before', value)
    digest = hashlib.sha256((STATE / 'before.json').read_bytes()).hexdigest()
    save('before-sha256', dict(sha256=digest))
    return dict(snapshot_verified=True, nodes=3, hosts=4, sha256=digest)


def account(api):
    if exists('test-intent'):
        intent = read('test-intent')
        user = api('GET', '/api/users/' + intent['uuid'])
        assert user['username'] == intent['username'] and user['tag'] == intent['tag']
        assert not exists('test-cleanup'), 'Previous probe finished; do not reuse'
        return user
    squad = next(s for s in read('before')['squads'] if s['name'] == 'BASE')
    assert {n['inbound'] for n in NODES} <= {i['uuid'] for i in squad['inbounds']}
    identifier = str(uuid.uuid4())
    body = dict(uuid=identifier, username='cloud140_probe_' + identifier[:8],
                expireAt=(datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(),
                trafficLimitBytes=536870912, trafficLimitStrategy='NO_RESET',
                tag='CLOUD140_PROBE', description='Temporary CLOUD140 KZ245 route verification',
                activeInternalSquads=[squad['uuid']])
    save('test-intent', body)
    user = api('POST', '/api/users/', body)
    assert user['uuid'] == identifier and user['username'] == body['username']
    save('test-created', dict(uuid=identifier))
    return user


def public_key(private):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private + '='))
    return base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')


def clients(api):
    user = account(api)
    before = read('before')
    result = []
    for n in NODES:
        profile = before['profiles'][n['profile']]
        assert api('GET', '/api/config-profiles/' + n['profile'])['config'] == profile['config'], 'Profile drift'
        meta = next(i for i in profile['inbounds'] if i['uuid'] == n['inbound'])
        inbound = next(i for i in profile['config']['inbounds'] if i['tag'] == meta['tag'])
        rs = inbound['streamSettings']['realitySettings']
        out = dict(protocol='vless', settings={'vnext': [dict(address=n['ip'], port=443,
                   users=[dict(id=user['vlessUuid'], encryption='none', flow='xtls-rprx-vision')])]},
                   streamSettings=dict(network='raw', security='reality', realitySettings=dict(
                       serverName=n['sni'], fingerprint='chrome', publicKey=public_key(rs['privateKey']), shortId=rs['shortIds'][0])))
        result.append(dict(id=n['id'], ip=n['ip'], outbound=out))
    return result


def cleanup(api):
    intent = read('test-intent')
    user = api('GET', '/api/users/' + intent['uuid'])
    for key in ('username', 'tag', 'description'):
        assert user[key] == intent[key], 'Not our disposable account'
    result = api('DELETE', '/api/users/' + intent['uuid'])
    assert result.get('isDeleted') is True
    save('test-cleanup', dict(deleted=True))
    return dict(disposable_user_deleted=True)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(); p.add_argument('action', choices=['snapshot', 'account', 'export-clients', 'cleanup'])
    args = p.parse_args(); api, _ = create_client()
    if args.action == 'snapshot': result = snapshot(api)
    elif args.action == 'account': account(api); result = dict(disposable_probe_ready=True)
    elif args.action == 'export-clients': result = clients(api)
    else: result = cleanup(api)
    print(json.dumps(result))


if __name__ == '__main__': main()
