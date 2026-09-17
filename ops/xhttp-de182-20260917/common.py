"""One-node XHTTP pilot; public constants only, no runtime credentials."""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-xhttp-de182-20260917')
IP, DOMAIN = '217.60.68.182', 'de182.torcalc.ru'
NODE = '2c0f93bf-ec0a-4dff-b0f1-b57badd920e1'
PROFILE = '597b8c2d-65a6-40a5-bb97-2fb633157812'
OLD_IDS = ['b05fdb37-106a-4fd3-b4b9-dae955942c1f', '57e27143-2f5a-424d-a801-54df192c163b']
TAG, PATH = 'ham-de182-xhttp-pilot', '/ham-xhttp-pilot/'
NAME = '🇩🇪 Германия — 3 · XHTTP TLS'
PORT = 10080
XRAY = '/root/selfsteal-us3-test/xray'


def added_inbound():
    return {'tag': TAG, 'listen': '127.0.0.1', 'port': PORT, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']},
        'streamSettings': {'network': 'xhttp', 'security': 'none',
            'xhttpSettings': {'host': DOMAIN, 'path': PATH, 'mode': 'packet-up'}}}


def candidate(original):
    assert [i['tag'] for i in original['inbounds']] == ['ham-de182-vless-tls', 'ham-de182-hy2']
    assert all(i['port'] == 443 for i in original['inbounds'])
    assert all(i['streamSettings']['security'] == 'tls' for i in original['inbounds'])
    result = copy.deepcopy(original)
    result['inbounds'].append(added_inbound())
    return result


def save(name, value):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = STATE / (name + '.json')
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(path)


def read(name):
    return json.loads((STATE / (name + '.json')).read_text(encoding='utf-8'))


def exists(name):
    return (STATE / (name + '.json')).exists()


def binding(node):
    profile = node.get('configProfile')
    return None if not profile else {'activeConfigProfileUuid': profile['activeConfigProfileUuid'],
        'activeInbounds': [i['uuid'] for i in profile['activeInbounds']]}


def ids(squad):
    return [i['uuid'] for i in squad['inbounds']]


def host_body(inbound):
    return {'remark': NAME, 'address': DOMAIN, 'port': 443, 'host': DOMAIN, 'sni': DOMAIN,
        'path': PATH, 'alpn': 'http/1.1', 'fingerprint': 'chrome', 'securityLayer': 'TLS',
        'isDisabled': True, 'isHidden': False, 'tags': [], 'nodes': [NODE],
        'excludedInternalSquads': [],
        'inbound': {'configProfileUuid': PROFILE, 'configProfileInboundUuid': inbound}}


def outbound(user, protocol='xhttp'):
    tls = {'serverName': DOMAIN, 'allowInsecure': False}
    if protocol == 'hysteria':
        return {'protocol': 'hysteria', 'settings': {'address': DOMAIN, 'port': 443, 'version': 2},
            'streamSettings': {'network': 'hysteria', 'security': 'tls',
                'tlsSettings': {**tls, 'alpn': ['h3']},
                'hysteriaSettings': {'version': 2, 'auth': user['vlessUuid']}}}
    account = {'id': user['vlessUuid'], 'encryption': 'none'}
    stream = {'network': 'xhttp' if protocol == 'xhttp' else 'raw', 'security': 'tls',
        'tlsSettings': {**tls, 'alpn': ['h2', 'http/1.1'], 'fingerprint': 'chrome'}}
    if protocol == 'xhttp':
        # This unchanged TLS frontend prefers HTTP/1.1. Pin the pilot's HTTP
        # version to avoid an H2 dialer receiving an HTTP/1.1 fallback response.
        stream['tlsSettings']['alpn'] = ['http/1.1']
        stream['xhttpSettings'] = {'host': DOMAIN, 'path': PATH, 'mode': 'packet-up'}
    else:
        account['flow'] = 'xtls-rprx-vision'
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': DOMAIN, 'port': 443,
        'users': [account]}]}, 'streamSettings': stream}
