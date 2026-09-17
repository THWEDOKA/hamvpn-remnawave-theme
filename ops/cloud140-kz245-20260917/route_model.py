"""Pure candidate builders; never apply, log, persist or certify a deployment.

Inputs/outputs contain private configuration: keep both in protected panel state.
Canonical target identities come from preflight; this module calls no API.
Plain VLESS is restricted to loopback and REQUIRES separately verified reverse
SSH (including authenticated 204/egress probes) before activating a candidate.
All panel bindings, service-user/squad rights, installed-Xray tests, TLS/SNI
checks and rollback protection belong to the caller, not to these builders.
"""

import base64
from copy import deepcopy
import ipaddress
import re
from uuid import UUID

from preflight import ENTRY, NODES


BACKEND_PORT = 15443
TLS_TARGET = '127.0.0.1:9443'
REVERSE_PORTS = {'kz2': 27443, 'de245': 28443}
LEGACY_PREFIXES = {key: 'cloud140-' + key + '-legacy-' for key in REVERSE_PORTS}


def _require(condition, message):
    if not condition:
        # Never interpolate configuration, identities or user values here.
        raise ValueError(message)


def _node(exit_id):
    _require(isinstance(exit_id, str) and exit_id in REVERSE_PORTS,
             'Unknown route ID')
    matches = [node for node in NODES if node['id'] == exit_id]
    _require(len(matches) == 1, 'Canonical route inventory is ambiguous')
    return matches[0]


def route_tags(exit_id):
    """Return only this operation's public tags (no configuration/credentials)."""
    _node(exit_id)
    return {kind: 'cloud140-' + exit_id + '-' + kind
            for kind in ('front', 'backend', 'exit')}


def _tags(items):
    _require(isinstance(items, list) and all(isinstance(item, dict) for item in items),
             'Expected a list of configuration objects')
    result = [item.get('tag') for item in items]
    _require(all(isinstance(tag, str) and bool(tag.strip()) for tag in result),
             'All inbound/outbound tags must be explicit')
    _require(len(result) == len(set(result)), 'Duplicate configuration tags')
    return set(result)


def _clone(source):
    _require(isinstance(source, dict), 'Expected an Xray configuration object')
    _tags(source.get('inbounds'))
    _tags(source.get('outbounds'))
    routing = source.get('routing', {})
    _require(isinstance(routing, dict), 'Invalid routing object')
    rules = routing.get('rules', [])
    _require(isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules),
             'Invalid routing rules')
    for rule in rules:
        for field in ('inboundTag', 'ip', 'domain', 'protocol'):
            if field in rule:
                _require(isinstance(rule[field], list)
                         and all(isinstance(value, str) for value in rule[field]),
                         'Invalid routing selector')
    return deepcopy(source)


def _assert_free_port(config, port):
    """Fail closed on conflicting port/range, even for a different bind address.

This is a configuration check only; the caller must inspect real listeners too.
"""
    for inbound in config['inbounds']:
        value = inbound.get('port')
        if value is None:
            continue
        _require(type(value) is int or isinstance(value, str), 'Unsupported inbound port')
        for part in str(value).split(','):
            match = re.fullmatch(r'(\d+)(?:-(\d+))?', part.strip())
            _require(match is not None, 'Unsupported inbound port')
            lower, upper = int(match[1]), int(match[2] or match[1])
            _require(1 <= lower <= upper <= 65535, 'Invalid inbound port range')
            _require(not lower <= port <= upper, 'Required port overlaps an existing inbound')


def _assert_new_tags(config, tags):
    occupied = _tags(config['inbounds']) | _tags(config['outbounds'])
    # Dangling rules must not silently acquire a newly added inbound/outbound.
    for rule in config.get('routing', {}).get('rules', []):
        occupied.update(rule.get('inboundTag', []))
        if isinstance(rule.get('outboundTag'), str):
            occupied.add(rule['outboundTag'])
    _require(not occupied.intersection(tags), 'Operation tags already present or referenced')


def legacy_tag_map(source_config, exit_id='kz2'):
    """Map EVERY source inbound tag to the chosen exit's isolated namespace.

Use the same map when remapping panel inbound metadata and squad rights.
Only config tags and routing.inboundTag references are rewritten here.
The default exit ID retains compatibility with the original KZ-only helper.
"""
    _node(exit_id)
    config = _clone(source_config)
    prefixes = tuple('cloud140-' + key + '-' for key in REVERSE_PORTS)
    _require(not any(item['tag'].startswith(prefixes) for item in config['inbounds']),
             'Exit source is already operation-scoped')
    result = {item['tag']: LEGACY_PREFIXES[exit_id] + item['tag'] for item in config['inbounds']}
    _assert_new_tags(config, set(result.values()))
    return result


def _is_security_block(rule, block_tags):
    if rule.get('outboundTag') not in block_tags:
        return False
    if 'bittorrent' in rule.get('protocol', []) or 'geosite:private' in rule.get('domain', []):
        return True
    for value in rule.get('ip', []):
        if value == 'geoip:private':
            return True
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.is_private:
            return True
    return False


def _insert_routes(config, new_rules):
    routing = config.setdefault('routing', {})
    rules = routing.setdefault('rules', [])
    blocks = {item['tag'] for item in config['outbounds'] if item.get('protocol') == 'blackhole'}
    protected = [index for index, rule in enumerate(rules) if _is_security_block(rule, blocks)]
    position = max(protected, default=-1) + 1
    # An earlier unscoped rule could steal new traffic before the mandatory
    # security blocks. There is no safe insertion preserving the old ordering.
    _require(all(rule.get('inboundTag') or _is_security_block(rule, blocks)
                 for rule in rules[:position]),
             'Existing broad route precedes a security block; explicit review required')
    rules[position:position] = new_rules


def _direct_tag(config, selected):
    freedom = [item['tag'] for item in config['outbounds'] if item.get('protocol') == 'freedom']
    if selected is None:
        _require(len(freedom) == 1, 'Select one existing freedom outbound explicitly')
        return freedom[0]
    _require(isinstance(selected, str) and selected in freedom,
             'Exit destination must be an existing freedom outbound')
    return selected


def build_exit_config(source_config, exit_id, *, clone=True, direct_tag=None):
    """Clone either exit with unique legacy tags; add one loopback backend.

Return an Xray config, not an API profile wrapper. For BOTH exits the caller
MUST create a new dedicated profile, copy precise original->clone legacy rights
and change only the target node binding after its installed-Xray test. Never
PATCH either original profile. clone=False is forbidden in this operation.
Only tags/references change on legacy inbounds; keys, SNI and all other fields
remain unchanged. clients=[] on the new backend is intentional: only a separate
backend service squad may inject its service user.
The explicit backend->freedom rule avoids inheriting a legacy proxy/catch-all.
"""
    _require(clone is True, 'Both exits require dedicated clones; original profiles must remain untouched')
    tags = route_tags(exit_id)
    config = _clone(source_config)
    _assert_new_tags(config, {tags['backend']})
    _assert_free_port(config, BACKEND_PORT)
    outbound = _direct_tag(config, direct_tag)
    renamed = legacy_tag_map(source_config, exit_id)
    for inbound in config['inbounds']:
        inbound['tag'] = renamed[inbound['tag']]
    for rule in config.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            rule['inboundTag'] = [renamed.get(tag, tag) for tag in rule['inboundTag']]
    config['inbounds'].append(dict(
        tag=tags['backend'], listen='127.0.0.1', port=BACKEND_PORT, protocol='vless',
        settings=dict(clients=[], decryption='none'),
        streamSettings=dict(network='raw', security='none'),
        sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)))
    _insert_routes(config, [dict(type='field', inboundTag=[tags['backend']], outboundTag=outbound)])
    return config


def _identity(value):
    _require(isinstance(value, dict) and set(value) == {'privateKey', 'shortIds'},
             'Identity requires only privateKey and shortIds')
    key, short_ids = value['privateKey'], value['shortIds']
    _require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', key) is not None,
             'Invalid REALITY private key encoding')
    decoded = base64.urlsafe_b64decode(key + '=')
    _require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip('=') == key
             and any(decoded), 'Invalid REALITY private key encoding')
    _require(isinstance(short_ids, list) and bool(short_ids)
             and all(isinstance(sid, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', sid)
                     for sid in short_ids), 'Invalid REALITY short IDs')
    _require(len({sid.lower() for sid in short_ids}) == len(short_ids), 'Duplicate REALITY short IDs')
    return deepcopy(value)


def _service_uuid(value):
    _require(isinstance(value, str), 'Invalid backend service UUID')
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError('Invalid backend service UUID') from None
    _require(str(parsed) == value and parsed.int != 0, 'Invalid backend service UUID')
    return value


def build_entry_config(source_config, identities, service_uuids, *, include_cached_snis=False):
    """Append two fresh frontends, two SSH-loopback outbounds and scoped routes.

identities = {route_id: {'privateKey': <new X25519 key>, 'shortIds': [<hex>]}}
service_uuids = {route_id: <separate backend service user's UUID>}
Both mappings must cover exactly the canonical exits. No source exit key is
copied. Optional cached SNIs are only extra names, NOT migration of cached
identities: old direct endpoints must remain available. A TLS probe for every
extra SNI is required before opting in; the model cannot certify its target.
"""
    _require(type(include_cached_snis) is bool, 'Cached SNI option must be boolean')
    ids = set(REVERSE_PORTS)
    _require({node['id'] for node in NODES} == ids, 'Canonical route inventory changed')
    _require(isinstance(identities, dict) and set(identities) == ids,
             'Provide an explicit identity for each route')
    _require(isinstance(service_uuids, dict) and set(service_uuids) == ids,
             'Provide an explicit backend service UUID for each route')
    checked = {key: _identity(identities[key]) for key in REVERSE_PORTS}
    services = {key: _service_uuid(service_uuids[key]) for key in REVERSE_PORTS}
    _require(len({item['privateKey'] for item in checked.values()}) == len(ids),
             'Frontend identities must be independent')
    config = _clone(source_config)
    rules = []
    for node in NODES:
        key = node['id']
        tags = route_tags(key)
        _assert_new_tags(config, {tags['front'], tags['exit']})
        _assert_free_port(config, node['port'])
        names = [node['domain']]
        if include_cached_snis and node['sni'] not in names:
            names.append(node['sni'])
        reality = dict(show=False, xver=0, target=TLS_TARGET, serverNames=names, **checked[key])
        config['inbounds'].append(dict(
            tag=tags['front'], listen=ENTRY, port=node['port'], protocol='vless',
            settings=dict(clients=[], decryption='none'),
            streamSettings=dict(network='raw', security='reality', realitySettings=reality),
            sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)))
        config['outbounds'].append(dict(
            tag=tags['exit'], protocol='vless',
            settings=dict(vnext=[dict(address='127.0.0.1', port=REVERSE_PORTS[key],
                                      users=[dict(id=services[key], encryption='none')])]),
            streamSettings=dict(network='raw', security='none')))
        rules.append(dict(type='field', inboundTag=[tags['front']], outboundTag=tags['exit']))
    _insert_routes(config, rules)
    return config
