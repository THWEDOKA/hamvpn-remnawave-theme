"""Pure six-exit candidate builders. No I/O, credentials, API or deployment.

Inputs and returned dictionaries can contain secrets; the caller must keep them
private. This self-contained adaptation intentionally imports no earlier scope.
These functions validate configuration SHAPE, not operational verification.
The coordinator owns current inventory, fresh authenticated 204/egress evidence,
installed-Xray tests, free runtime ports, dedicated service-user/squad bindings,
firewall, isolated profile creation and rollback before any activation.
REALITY identities/SNIs/targets must be explicitly checked by that coordinator.
Plain loopback VLESS additionally requires a verified, restricted SSH tunnel.
"""

import base64
from copy import deepcopy
import ipaddress
import re
from uuid import UUID


ENTRY = '176.108.245.140'
TLS_TARGET = '127.0.0.1:9444'
BACKEND_PORT = 15444
TARGETS = {
    'at': {'ip': '147.45.71.38', 'domain': 'in-at38.torcalc.ru'},
    'pl': {'ip': '31.77.59.141', 'domain': 'in-pl141.torcalc.ru'},
    'cz': {'ip': '45.151.180.85', 'domain': 'in-cz85.torcalc.ru'},
    'gb': {'ip': '51.194.240.216', 'domain': 'in-gb216.torcalc.ru'},
    'us1': {'ip': '162.141.185.231', 'domain': 'in-us1.torcalc.ru'},
    'gbpower': {'ip': '51.194.240.225', 'domain': 'in-gb225.torcalc.ru'},
}
DOMAINS = {key: value['domain'] for key, value in TARGETS.items()}
PREFIX = 'cloud140-six-'


def _require(condition, message):
    if not condition:
        # Deliberately never interpolate caller values (including secrets).
        raise ValueError(message)


def _node(exit_id):
    _require(isinstance(exit_id, str) and exit_id in TARGETS, 'Unknown route ID')
    return TARGETS[exit_id]


def route_tags(exit_id):
    """Return the operation-owned public tag names for one approved route."""
    _node(exit_id)
    return {kind: PREFIX + exit_id + '-' + kind for kind in ('front', 'backend', 'exit')}


def _tags(items):
    _require(isinstance(items, list) and all(isinstance(item, dict) for item in items),
             'Expected a list of configuration objects')
    tags = [item.get('tag') for item in items]
    _require(all(isinstance(tag, str) and bool(tag.strip()) for tag in tags),
             'All inbound/outbound tags must be explicit')
    _require(len(set(tags)) == len(tags), 'Duplicate configuration tags')
    return set(tags)


def _clone(source):
    _require(isinstance(source, dict), 'Expected an Xray configuration object')
    inbound_tags, outbound_tags = _tags(source.get('inbounds')), _tags(source.get('outbounds'))
    _require(not inbound_tags & outbound_tags, 'Ambiguous inbound/outbound tags')
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
    balancers = routing.get('balancers', [])
    _require(isinstance(balancers, list) and all(isinstance(b, dict) for b in balancers),
             'Invalid balancers')
    for balancer in balancers:
        selectors = balancer.get('selector', [])
        _require(isinstance(selectors, list) and all(isinstance(s, str) for s in selectors),
                 'Invalid balancer selectors')
    return deepcopy(source)


def _port(value):
    _require(type(value) is int and 1 <= value <= 65535, 'Invalid requested port')
    return value


def _assert_free_port(config, port):
    """Conservative across all protocols/bind addresses; runtime check is separate."""
    _port(port)
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


def _assert_new_tags(config, tags, *, outbound_tags=()):
    occupied = _tags(config['inbounds']) | _tags(config['outbounds'])
    for rule in config.get('routing', {}).get('rules', []):
        occupied.update(rule.get('inboundTag', []))
        if isinstance(rule.get('outboundTag'), str):
            occupied.add(rule['outboundTag'])
    _require(not occupied.intersection(tags), 'Operation tags already present or referenced')
    # Xray balancer selectors are prefixes. An additive outbound must not
    # silently change the membership/behavior of a pre-existing balancer.
    for balancer in config.get('routing', {}).get('balancers', []):
        _require(not any(tag.startswith(selector) for tag in outbound_tags
                         for selector in balancer.get('selector', [])),
                 'New outbound would join an existing balancer')


def legacy_tag_map(source_config, exit_id):
    """Map ALL legacy inbounds; caller must also map panel metadata/squad rights."""
    _node(exit_id)
    config = _clone(source_config)
    _require(not any(item['tag'].startswith(PREFIX) for item in config['inbounds']),
             'Exit source is already operation-scoped')
    result = {item['tag']: PREFIX + exit_id + '-legacy-' + item['tag']
              for item in config['inbounds']}
    _assert_new_tags(config, set(result.values()))
    return result


def _insert_routes(config, new_rules):
    routing = config.setdefault('routing', {})
    rules = routing.setdefault('rules', [])
    blocks = {item['tag'] for item in config['outbounds'] if item.get('protocol') == 'blackhole'}
    # Preserve ALL blackhole security rules, not only known geoip spellings.
    protected = [i for i, rule in enumerate(rules) if rule.get('outboundTag') in blocks]
    position = max(protected, default=-1) + 1
    _require(all(rule.get('inboundTag') or rule.get('outboundTag') in blocks
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


def _key(value):
    _require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is not None,
             'Invalid REALITY key encoding')
    decoded = base64.urlsafe_b64decode(value + '=')
    _require(len(decoded) == 32 and any(decoded)
             and base64.urlsafe_b64encode(decoded).decode().rstrip('=') == value,
             'Invalid REALITY key encoding')
    return value


def _short_id(value):
    _require(isinstance(value, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', value),
             'Invalid REALITY short ID')
    return value


def _identity(value):
    _require(isinstance(value, dict) and set(value) == {'privateKey', 'shortIds'},
             'Identity requires only privateKey and shortIds')
    _key(value['privateKey'])
    short_ids = value['shortIds']
    _require(isinstance(short_ids, list) and bool(short_ids), 'Invalid REALITY short IDs')
    for short_id in short_ids:
        _short_id(short_id)
    _require(len({s.lower() for s in short_ids}) == len(short_ids), 'Duplicate REALITY short IDs')
    return deepcopy(value)


def _fresh_identity(source, value):
    identity = _identity(value)
    for inbound in source['inbounds']:
        stream = inbound.get('streamSettings', {})
        _require(isinstance(stream, dict), 'Invalid existing stream settings')
        reality = stream.get('realitySettings', {})
        _require(isinstance(reality, dict), 'Invalid existing REALITY settings')
        _require(reality.get('privateKey') != identity['privateKey'],
                 'New identity must not reuse a legacy or another route private key')
    return identity


def _domain(value):
    _require(isinstance(value, str) and len(value) <= 253 and '.' in value
             and value == value.lower() and all(re.fullmatch(
                 r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                 for label in value.split('.')), 'Invalid explicit server name')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Server name must be a DNS name')


def _server_names(values):
    _require(isinstance(values, list) and bool(values), 'Explicit server names are required')
    for value in values:
        _domain(value)
    _require(len(set(values)) == len(values), 'Duplicate server names')
    return deepcopy(values)


def _target(value):
    _require(isinstance(value, str), 'Explicit REALITY target is required')
    # Deliberately require host:port, no implicit 443, Unix socket or URL.
    match = re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[a-z0-9.-]+):([0-9]{1,5})', value)
    _require(match is not None, 'Invalid explicit REALITY target')
    host, port = match[1], int(match[2])
    _port(port)
    try:
        address = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        _domain(host)
    else:
        _require(not address.is_unspecified and not address.is_multicast,
                 'Invalid explicit REALITY target')
    return value


def build_exit_config(source_config, exit_id, backend_port=BACKEND_PORT, *,
                      mode='reality', identity=None, server_names=None, target=None,
                      direct_tag=None, clone=True):
    """Return a dedicated exit clone; never modify a shared/original profile.

Every old inbound is preserved except its globally isolated tag; ONLY routing
inboundTag references are rewritten. clients=[] on the dedicated backend is
intentional: the caller binds a SEPARATE backend-only service user/squad.
mode='reality' requires explicit fresh identity and checked target/server_names;
its listener is the selected exit IP. mode='ssh' requires all three omitted and
binds unencrypted VLESS ONLY to 127.0.0.1. No automatic transport fallback.
"""
    node, tags = _node(exit_id), route_tags(exit_id)
    _require(clone is True, 'Dedicated exit clones are mandatory')
    _require(isinstance(mode, str) and mode in ('reality', 'ssh'), 'Explicit supported transport required')
    config = _clone(source_config)
    _assert_new_tags(config, {tags['backend']})
    _assert_free_port(config, backend_port)
    outbound = _direct_tag(config, direct_tag)
    if mode == 'reality':
        reality = dict(show=False, xver=0, target=_target(target),
                       serverNames=_server_names(server_names), **_fresh_identity(config, identity))
        stream, listen = dict(network='raw', security='reality', realitySettings=reality), node['ip']
    else:
        _require(identity is None and server_names is None and target is None,
                 'SSH mode must not silently ignore REALITY parameters')
        stream, listen = dict(network='raw', security='none'), '127.0.0.1'
    renamed = legacy_tag_map(source_config, exit_id)
    for inbound in config['inbounds']:
        inbound['tag'] = renamed[inbound['tag']]
    for rule in config.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            rule['inboundTag'] = [renamed.get(tag, tag) for tag in rule['inboundTag']]
    config['inbounds'].append(dict(
        tag=tags['backend'], listen=listen, port=backend_port, protocol='vless',
        settings=dict(clients=[], decryption='none'), streamSettings=stream,
        sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)))
    _insert_routes(config, [dict(type='field', inboundTag=[tags['backend']], outboundTag=outbound)])
    return config


def _service_uuid(value):
    _require(isinstance(value, str), 'Invalid backend service UUID')
    try:
        parsed = UUID(value)
    except ValueError:
        raise ValueError('Invalid backend service UUID') from None
    _require(str(parsed) == value and parsed.int != 0, 'Invalid backend service UUID')
    return value


def _backend_outbound(value, exit_id, source):
    """Accept a coordinator-verified final VLESS client object; retag only.

This is not a proof validator. Its narrow accepted shape prevents hidden proxy
chains, multiplexing/transport rewrites or a public plain-VLESS path. The caller
must pass the exact transport that passed authenticated entry-namespace probes.
"""
    node = _node(exit_id)
    _require(isinstance(value, dict) and value.get('protocol') == 'vless',
             'Backend outbound must be VLESS')
    _require(set(value) <= {'tag', 'protocol', 'settings', 'streamSettings'},
             'Unsupported backend outbound field; explicit review required')
    settings, stream = value.get('settings'), value.get('streamSettings')
    _require(isinstance(settings, dict) and set(settings) == {'vnext'}, 'Invalid backend settings')
    destinations = settings['vnext']
    _require(isinstance(destinations, list) and len(destinations) == 1
             and isinstance(destinations[0], dict), 'Exactly one backend destination is required')
    destination = destinations[0]
    _require(set(destination) == {'address', 'port', 'users'}, 'Invalid backend destination')
    _port(destination['port'])
    users = destination['users']
    _require(isinstance(users, list) and len(users) == 1 and isinstance(users[0], dict),
             'Exactly one dedicated backend identity is required')
    user = users[0]
    _require(set(user) <= {'id', 'encryption', 'flow'} and user.get('encryption') == 'none',
             'Invalid backend VLESS identity settings')
    service_uuid = _service_uuid(user.get('id'))
    _require(user.get('flow', '') in ('', 'xtls-rprx-vision'), 'Unsupported backend flow')
    for inbound in source['inbounds']:
        current_settings = inbound.get('settings', {})
        _require(isinstance(current_settings, dict), 'Invalid existing inbound settings')
        clients = current_settings.get('clients', [])
        _require(isinstance(clients, list) and all(isinstance(c, dict) for c in clients),
                 'Invalid existing clients')
        _require(all(client.get('id') != service_uuid for client in clients),
                 'Backend service identity must not reuse a client UUID')
    _require(isinstance(stream, dict) and stream.get('network') in ('raw', 'tcp'),
             'Only an explicitly checked raw/TCP backend transport is supported')
    security = stream.get('security')
    _require(isinstance(security, str) and security in ('none', 'reality', 'tls'),
             'Backend security must be explicit')
    security_key = {'none': None, 'reality': 'realitySettings', 'tls': 'tlsSettings'}[security]
    _require(set(stream) <= {'network', 'security'} | ({security_key} if security_key else set()),
             'Unsupported backend stream field; explicit review required')
    if security == 'none':
        _require(destination['address'] == '127.0.0.1', 'Plain VLESS backend is loopback-only')
        _require(not user.get('flow'), 'Plain SSH backend must not request TLS Vision flow')
    else:
        _require(destination['address'] == node['ip'], 'Encrypted backend must target selected exit IP')
        options = stream.get(security_key)
        _require(isinstance(options, dict), 'Missing explicit backend security settings')
        _domain(options.get('serverName'))
        fingerprint = options.get('fingerprint')
        _require(isinstance(fingerprint, str) and bool(re.fullmatch(r'[a-zA-Z0-9_-]+', fingerprint)),
                 'Explicit backend fingerprint is required')
        if security == 'reality':
            _require(set(options) <= {'serverName', 'fingerprint', 'publicKey', 'password',
                                     'shortId', 'spiderX', 'show'},
                     'Unsupported backend REALITY field')
            keys = [name for name in ('publicKey', 'password') if name in options]
            _require(len(keys) == 1, 'Exactly one explicit REALITY public key field is required')
            _key(options[keys[0]])
            _short_id(options.get('shortId'))
            if 'show' in options:
                _require(options['show'] is False, 'REALITY debug output must be disabled')
            if 'spiderX' in options:
                _require(isinstance(options['spiderX'], str) and options['spiderX'].startswith('/'),
                         'Invalid backend REALITY spider path')
        else:
            _require(set(options) <= {'serverName', 'fingerprint', 'alpn', 'allowInsecure'},
                     'Unsupported backend TLS field')
            _require(options.get('allowInsecure', False) is False, 'TLS verification cannot be disabled')
            if 'alpn' in options:
                _require(isinstance(options['alpn'], list) and bool(options['alpn'])
                         and all(v in ('h2', 'http/1.1') for v in options['alpn']),
                         'Invalid backend TLS ALPN')
    result = deepcopy(value)
    result['tag'] = route_tags(exit_id)['exit']
    return result


def build_entry_config(source_config, exit_id, port, domain, identity, backend_outbound):
    """Append ONE frontend, exact verified backend transport and scoped route.

No port allocation or transport fallback is performed. All old fields stay
unchanged. The approved domain must match the route exactly. New frontend keys
must be fresh, clients remain empty for panel injection, and the self-steal
target is the separately verified loopback TLS site on 9444. Returned backend
outbound is a deep copy of the supplied object with ONLY its tag replaced.
"""
    node, tags = _node(exit_id), route_tags(exit_id)
    _require(isinstance(domain, str) and domain == node['domain'], 'Domain does not match approved route')
    _require(port != 9444, 'Frontend cannot occupy the self-steal TLS target port')
    config = _clone(source_config)
    _assert_new_tags(config, {tags['front'], tags['exit']}, outbound_tags={tags['exit']})
    _assert_free_port(config, port)
    checked = _fresh_identity(config, identity)
    outbound = _backend_outbound(backend_outbound, exit_id, config)
    reality = dict(show=False, xver=0, target=TLS_TARGET, serverNames=[domain], minClientVer='1.8.2', **checked)
    config['inbounds'].append(dict(
        tag=tags['front'], listen=ENTRY, port=port, protocol='vless',
        settings=dict(clients=[], decryption='none'),
        streamSettings=dict(network='raw', security='reality', realitySettings=reality),
        sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=True)))
    config['outbounds'].append(outbound)
    _insert_routes(config, [dict(type='field', inboundTag=[tags['front']], outboundTag=tags['exit'])])
    return config
