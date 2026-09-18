"""Additive MWS route; no changes to existing balancer policy or client hosts."""
from copy import deepcopy

TAG = 'BS3_AUTO_MWS2'
BACKEND = 'HAM-MWS2-AUTO-BACKEND'
PORT = 28443


def backend(config, private, short):
    out = deepcopy(config)
    assert not any(i['tag'] == BACKEND or i.get('port') == PORT for i in out['inbounds'])
    inbound = deepcopy(next(i for i in out['inbounds'] if i['tag'] == 'HAM-MWS2-REALITY'))
    inbound.update(tag=BACKEND, port=PORT, listen='0.0.0.0')
    inbound['settings']['clients'] = []
    inbound['streamSettings']['realitySettings'].update(privateKey=private, shortIds=[short])
    out['inbounds'].append(inbound)
    # Only the fixed Selectal source may use this private service identity.
    # Its normal Russian DIRECT rules remain on Selectal; the new leg is foreign.
    out['routing']['rules'] = [
        {'type': 'field', 'inboundTag': [BACKEND], 'source': ['5.188.115.106'], 'outboundTag': 'FOREIGN'},
        {'type': 'field', 'inboundTag': [BACKEND], 'outboundTag': 'BLOCK'},
    ] + out['routing']['rules']
    return out


def wire(identity, public, short):
    return {'tag': TAG, 'protocol': 'vless', 'settings': {'vnext': [{
        'address': 'mws.torcalc.ru', 'port': PORT,
        'users': [{'id': identity, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'serverName': 'mws.torcalc.ru', 'fingerprint': 'firefox',
            'publicKey': public, 'shortId': short}}}


def candidate(config, outbound):
    out = deepcopy(config)
    assert not any(o['tag'] == TAG for o in out['outbounds'])
    balancer = next(b for b in out['routing']['balancers'] if b['tag'] == 'BS3_AUTO')
    assert 'BS3_AUTO_' in balancer['selector']
    assert 'BS3_AUTO_' in out['observatory']['subjectSelector']
    assert outbound['tag'] == TAG
    assert outbound['streamSettings']['realitySettings']['fingerprint'] == 'firefox'
    out['outbounds'].append(deepcopy(outbound))
    return out
