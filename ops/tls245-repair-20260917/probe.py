"""Run on HAM panel: isolated short-lived user, legacy/REALITY/subscription."""
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.request
import uuid

sys.path.insert(0, '/opt/hamvpn-tls245-release/ops/selfsteal-tls245')
import panel as existing

STATE = Path('/root/tls245-repair-20260917-probes')
NODE = 'dd62f99f-0464-413f-915e-05bb075098bd'
HOST = 'f9e8c4e3-24f4-4771-8e09-69d366c8f5b6'
PROFILE = 'b4572f94-d216-471f-8824-d793b4eb53bd'
DOMAIN = 'tls245.torcalc.ru'
IP = '196.251.107.245'


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False))
    path.chmod(0o600)


def main():
    os.umask(0o077)
    api, query = existing.common.create_client()
    node = api('GET', '/api/nodes/' + NODE)
    host = api('GET', '/api/hosts/' + HOST)
    assert node['address'] == IP and node['configProfile']['activeConfigProfileUuid'] == PROFILE
    assert host['nodes'] == [NODE] and host['address'] == DOMAIN and not host['isDisabled']
    profile = api('GET', '/api/config-profiles/' + PROFILE)
    inbound = next(i for i in profile['config']['inbounds'] if i['tag'] == 'tls245-selfsteal')
    reality = inbound['streamSettings']['realitySettings']
    assert inbound['port'] == 443 and reality['target'] == '127.0.0.1:8443'
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['privateKey'] + '==='))
    public = base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')
    inbounds = {i['uuid'] for i in node['configProfile']['activeInbounds']}
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    selected = [s for s in squads if inbounds <= set(existing.ids(s))]
    squad = next(s for s in selected if s['name'] == 'BASE')
    STATE.mkdir(mode=0o700, exist_ok=True)
    uid = str(uuid.uuid4())
    directory = STATE / uid
    directory.mkdir(mode=0o700)
    existing.STATE = directory
    body = {'uuid': uid, 'username': 'repair245_' + uid[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        'trafficLimitBytes': 134217728, 'trafficLimitStrategy': 'NO_RESET',
        'tag': 'TLS245_REPAIR', 'description': 'Disposable capacity-repair verification',
        'activeInternalSquads': [squad['uuid']]}
    save(directory / 'intent.json', body)
    results = {'timestamp': time.time(), 'tests': [], 'cleanup_verified': False}
    try:
        # Intent is persisted before the write; finally also handles uncertain POSTs.
        user = api('POST', '/api/users/', body)
        assert user['uuid'] == uid
        for label, address, security, fp in [('legacy-tls-ip', IP, 'tls', 'chrome'),
            ('legacy-tls-domain', DOMAIN, 'tls', 'chrome'),
            ('reality-chrome', DOMAIN, 'reality', 'chrome'),
            ('reality-firefox', IP, 'reality', 'firefox')]:
            stream = {'network': 'raw', 'security': security}
            if security == 'tls':
                stream['tlsSettings'] = {'serverName': DOMAIN, 'fingerprint': fp,
                    'alpn': ['h2', 'http/1.1'], 'allowInsecure': False}
            else:
                stream['realitySettings'] = {'serverName': DOMAIN, 'fingerprint': fp,
                    'publicKey': public, 'shortId': reality['shortIds'][0]}
            outbound = {'protocol': 'vless', 'settings': {'vnext': [{'address': address, 'port': 443,
                'users': [{'id': user['vlessUuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
                'streamSettings': stream}
            result = existing.test_outbound(outbound)
            results['tests'].append({'scenario': label, **result})
        sub = api('GET', '/api/subscriptions/by-uuid/' + uid)
        req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/3.11.0',
            'X-Hwid': 'tls245-repair-20260917', 'X-Device-Os': 'iOS',
            'X-Device-Model': 'Repair verification', 'X-Ver-Os': '18'})
        with urllib.request.urlopen(req, timeout=30) as response:
            configs = json.load(response)
            assert response.status == 200
        matching = [c for c in configs if c.get('remarks') == host['remark']]
        assert len(matching) == 1
        outs = [o for o in matching[0]['outbounds'] if o.get('protocol') == 'vless' and
            any(s.get('address') == DOMAIN for s in o.get('settings', {}).get('vnext', []))]
        assert len(outs) == 1
        assert outs[0]['streamSettings']['security'] == 'reality'
        result = existing.test_outbound(outs[0])
        results['tests'].append({'scenario': 'actual-happ-subscription', 'target_count': 1, **result})
        assert existing.connection_fields(api('GET', '/api/hosts/' + HOST)) == existing.connection_fields(host), 'Target host concurrent change'
        assert api('GET', '/api/config-profiles/' + PROFILE)['config'] == profile['config']
        current = api('GET', '/api/nodes/' + NODE)
        assert current['isConnected'] and current['configProfile'] == node['configProfile']
        results['target_preserved_connected'] = True
        results['users_online'] = current.get('usersOnline')
    finally:
        # Never delete by a guessed identity; verify exact operation-owned user.
        count = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(uid)) + "'")
        if count['remaining']:
            current = api('GET', '/api/users/' + uid)
            assert current['username'] == body['username'] and current['tag'] == body['tag']
            api('DELETE', '/api/users/' + uid)
        count = query("SELECT json_build_object('remaining',count(*)) FROM users WHERE uuid='" + str(uuid.UUID(uid)) + "'")
        results['cleanup_verified'] = count['remaining'] == 0
        save(directory / 'proof.json', results)
    results['all_passed'] = len(results['tests']) == 5 and all(t['passed'] for t in results['tests']) and results['cleanup_verified']
    print(json.dumps(results, ensure_ascii=False))
    assert results['all_passed'], 'VPN verification failed; no config rollback needed (probe does not change configuration)'


if __name__ == '__main__': main()
