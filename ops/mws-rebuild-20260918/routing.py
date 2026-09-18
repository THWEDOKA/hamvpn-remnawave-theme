"""Pure split-routing builders. Private keys and user identities are runtime inputs.

No direct fallback for unclassified/international traffic. Keep the foreign
outbound first and omit an unconditional catch-all rule: IPIfNonMatch needs
the second pass for IP geolocation of destinations supplied as domains.
"""
from copy import deepcopy
from uuid import UUID
import ipaddress

ENTRY_TAG = 'HAM-MWS2-REALITY'
LEGACY_TAG = 'HAM-MWS2-LEGACY-XHTTP'
BACKEND_TAG = 'HAM-MWS2-EXIT-REALITY'
RUSSIAN_DOMAINS = ['geosite:category-ru', 'domain:ru', 'domain:su', 'domain:xn--p1ai']


def outbound(address, domain, port, user, public_key, short_id):
    ipaddress.ip_address(address)
    UUID(user)
    assert public_key and short_id and domain
    return {'tag': 'FOREIGN', 'protocol': 'vless', 'settings': {'vnext': [{
        'address': address, 'port': port, 'users': [{
            'id': user, 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
        'streamSettings': {'network': 'raw', 'security': 'reality',
            'realitySettings': {'serverName': domain, 'fingerprint': 'chrome',
                                'publicKey': public_key, 'shortId': short_id}}}


def inbound(tag, port, domain, private_key, short_id):
    assert private_key and short_id
    return {'tag': tag, 'listen': '0.0.0.0', 'port': port, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True},
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'show': False, 'target': '127.0.0.1:9444', 'xver': 0,
            'serverNames': [domain], 'privateKey': private_key, 'shortIds': [short_id],
            'minClientVer': '1.8.2'}}}


def entry_config(foreign, private_key, short_id, legacy=None, port=18443):
    assert foreign['tag'] == 'FOREIGN' and foreign['protocol'] == 'vless'
    assert foreign['streamSettings']['security'] == 'reality'
    front = inbound(ENTRY_TAG, port, 'mws.torcalc.ru', private_key, short_id)
    inbounds = [front]
    if legacy is not None:
        old = deepcopy(legacy)
        assert old['protocol'] == 'vless' and old['port'] == 2083
        assert old['streamSettings']['network'] == 'xhttp' and old['streamSettings']['security'] == 'tls'
        old['tag'] = LEGACY_TAG
        old['settings']['clients'] = []
        old['sniffing'] = {'enabled': True, 'destOverride': ['http','tls','quic'], 'routeOnly': True}
        inbounds.append(old)
    return {
        'log': {'loglevel': 'warning'},
        'dns': {'servers': [
            {'address':'77.88.8.8', 'domains':RUSSIAN_DOMAINS, 'skipFallback':True},
            'https://1.1.1.1/dns-query'], 'queryStrategy':'UseIPv4', 'tag':'MWS2-DNS'},
        'inbounds':inbounds,
        'outbounds':[deepcopy(foreign), {'tag':'RU-DIRECT','protocol':'freedom'}, {'tag':'BLOCK','protocol':'blackhole'}],
        'routing': {'domainStrategy':'IPIfNonMatch', 'rules':[
            {'type':'field','ip':['geoip:private'],'outboundTag':'BLOCK'},
            {'type':'field','domain':['geosite:private'],'outboundTag':'BLOCK'},
            {'type':'field','protocol':['bittorrent'],'outboundTag':'BLOCK'},
            {'type':'field','inboundTag':['MWS2-DNS'],'ip':['77.88.8.8/32'],'outboundTag':'RU-DIRECT'},
            {'type':'field','inboundTag':['MWS2-DNS'],'outboundTag':'FOREIGN'},
            {'type':'field','domain':list(RUSSIAN_DOMAINS),'outboundTag':'RU-DIRECT'},
            {'type':'field','ip':['geoip:ru'],'outboundTag':'RU-DIRECT'},
        ]}}


def exit_config(private_key, short_id):
    return {'log':{'loglevel':'warning'},
        'inbounds':[inbound(BACKEND_TAG,443,'mws-exit.torcalc.ru',private_key,short_id)],
        'outbounds':[{'tag':'DIRECT','protocol':'freedom'}, {'tag':'BLOCK','protocol':'blackhole'}],
        'routing':{'domainStrategy':'IPIfNonMatch','rules':[
            {'type':'field','ip':['geoip:private'],'outboundTag':'BLOCK'},
            {'type':'field','domain':['geosite:private'],'outboundTag':'BLOCK'},
            {'type':'field','protocol':['bittorrent'],'outboundTag':'BLOCK'}]}}
