"""Read-only, secret-whitelisted inventory for six explicitly selected exits.

Run on the panel with its existing protected adapter via PYTHONPATH, or pass the
sanitized panel JSON to `entry` on CLOUDru. Does not write local/remote state,
mutate panel objects, authenticate VPN clients, or accept SSH host keys.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import ssl
import sys
import time


ENTRY = '176.108.245.140'
TARGETS = [
    {'id': 'at', 'ip': '147.45.71.38', 'node': '7f9b7a9d-fee8-4f64-ac6e-dceb59afe715',
     'host': '8a734066-a484-4b17-b1ac-c02f52f62c06'},
    {'id': 'pl', 'ip': '31.77.59.141', 'node': 'e7cb39c6-81b5-419c-bf3c-ca07a0237674',
     'host': '64f97c2b-0c9d-4a09-8909-08f8c15e3219'},
    {'id': 'cz', 'ip': '45.151.180.85', 'node': 'efb5048a-7e25-427e-94bd-de469e7bca1e',
     'host': '5de1d4d2-9bd7-42f3-993c-d218bc6bd98a'},
    {'id': 'gb', 'ip': '51.194.240.216', 'node': 'a456b92a-8372-45fa-b007-117ef785abc5',
     'host': '75133919-61a5-47ba-929e-3a27c9a361cf'},
    {'id': 'us1', 'ip': '162.141.185.231', 'node': 'f6e49f98-3d96-46aa-b79e-0b636f625a61',
     'host': '762610b7-944a-4ed1-ae25-55f0d906cb15'},
    {'id': 'gbpower', 'ip': '51.194.240.225', 'node': 'a101da45-16eb-4eb1-807a-a49ac956add6',
     'host': '439b1267-ef6e-4ca0-8509-567879863d1d'},
]


def pick(value, keys):
    return {key: value.get(key) for key in keys}


def safe_inbound(meta, profile):
    raw = next((i for i in profile['config']['inbounds'] if i['tag'] == meta['tag']), {})
    stream = raw.get('streamSettings', {})
    reality = stream.get('realitySettings', {})
    tls = stream.get('tlsSettings', {})
    return dict(pick(meta, ('uuid', 'tag')), **pick(raw, ('listen', 'port', 'protocol')),
                network=stream.get('network'), security=stream.get('security'),
                server_names=reality.get('serverNames', []), tls_server_name=tls.get('serverName'),
                target=reality.get('target', reality.get('dest')))


def panel_inventory(api):
    nodes = api('GET', '/api/nodes/')
    hosts = api('GET', '/api/hosts/')
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    indexed = {n['uuid']: n for n in nodes}
    hindex = {h['uuid']: h for h in hosts}
    profiles = {}
    routes = []
    probes = []
    for target in TARGETS:
        node = indexed[target['node']]
        assert node['address'] == target['ip'], 'Selected node address changed'
        assert target['node'] in hindex[target['host']]['nodes'], 'Selected host binding changed'
        profile_id = node['configProfile']['activeConfigProfileUuid']
        if profile_id not in profiles:
            profiles[profile_id] = api('GET', '/api/config-profiles/' + profile_id)
        profile = profiles[profile_id]
        active = node['configProfile']['activeInbounds']
        active_ids = {i['uuid'] for i in active}
        safe_active = [safe_inbound(i, profile) for i in active]
        linked_hosts = []
        for host in hosts:
            if target['node'] not in host.get('nodes', []):
                continue
            binding = host.get('inbound') or {}
            linked_hosts.append(dict(
                pick(host, ('uuid', 'remark', 'address', 'port', 'sni', 'host',
                            'fingerprint', 'isHidden', 'isDisabled', 'viewPosition', 'nodes')),
                inbound=pick(binding, ('configProfileUuid', 'configProfileInboundUuid')),
                binding_matches_active=(binding.get('configProfileUuid') == profile_id and
                                        binding.get('configProfileInboundUuid') in active_ids)))
        relevant_ids = active_ids | {h['inbound']['configProfileInboundUuid'] for h in linked_hosts}
        rights = []
        for squad in squads:
            matches = sorted(relevant_ids & {i['uuid'] for i in squad.get('inbounds', [])})
            if matches:
                rights.append(dict(pick(squad, ('uuid', 'name')), relevant_inbounds=matches,
                                   customer_name_hint=squad['name'] in ('BASE', 'WHITE', 'OLD', 'site')))
        consumers = [pick(n, ('uuid', 'name', 'address', 'isConnected', 'isDisabled')) for n in nodes
                     if (n.get('configProfile') or {}).get('activeConfigProfileUuid') == profile_id]
        indirect_hosts = []
        for host in hosts:
            binding = host.get('inbound') or {}
            if target['node'] not in host.get('nodes', []) and (
                    host.get('address') == target['ip'] or
                    binding.get('configProfileInboundUuid') in active_ids):
                indirect_hosts.append(dict(
                    pick(host, ('uuid', 'remark', 'address', 'port', 'isHidden', 'isDisabled', 'nodes')),
                    inbound=pick(binding, ('configProfileUuid', 'configProfileInboundUuid'))))
        auth_candidates = []
        for inbound in safe_active:
            if inbound['protocol'] != 'vless' or inbound['security'] != 'reality':
                continue
            auth_candidates.append(dict(
                node_uuid=target['node'], profile_uuid=profile_id,
                inbound_uuid=inbound['uuid'], inbound_tag=inbound['tag'],
                address=target['ip'], port=inbound['port'],
                network=inbound['network'], security=inbound['security'],
                allowed_server_names=inbound['server_names'],
                customer_squad_uuids=[s['uuid'] for s in rights if s['customer_name_hint']
                                      and inbound['uuid'] in s['relevant_inbounds']],
                credential_resolution='Read profile and disposable identity privately on panel at test time',
                authenticated_test_performed=False, expected_egress=None))
        routes.append(dict(id=target['id'], management_ip=target['ip'],
                           node=pick(node, ('uuid', 'name', 'address', 'isConnected', 'isDisabled',
                                            'version', 'xrayVersion', 'usersOnline')),
                           profile=dict(uuid=profile_id, name=profile.get('name'), consumers=consumers),
                           active_inbounds=safe_active, hosts=linked_hosts, squads=rights,
                           other_hosts_using_active_inbounds=indirect_hosts,
                           authentication_candidates=auth_candidates))
        for inbound in safe_active:
            if inbound['network'] == 'hysteria' or inbound['protocol'] == 'hysteria':
                continue
            names = inbound.get('server_names') or []
            sni = names[0] if names else inbound.get('tls_server_name')
            candidate = dict(id=target['id'], ip=target['ip'], port=int(inbound['port']), sni=sni,
                             purpose='active-tcp-inbound-cover-tls')
            if candidate not in probes:
                probes.append(candidate)
        # An advertised UDP-only endpoint is not diagnosed by a TCP probe.
        # Its possible web listener is only a site-preparation observation.
        if not any(p['id'] == target['id'] for p in probes):
            host = next(h for h in linked_hosts if h['uuid'] == target['host'])
            probes.append(dict(id=target['id'], ip=target['ip'], port=443, sni=host.get('sni'),
                               purpose='website-only-not-udp-health'))
    return dict(timestamp=time.time(), readonly=True, routes=routes, probe_targets=probes)


def connection_probe(item):
    allowed = {t['id']: t['ip'] for t in TARGETS}
    assert allowed.get(item['id']) == item['ip'], 'Probe target outside scope'
    assert isinstance(item['port'], int) and 1 <= item['port'] <= 65535
    sni = item.get('sni')
    assert sni is None or (isinstance(sni, str) and len(sni) <= 253 and '\n' not in sni)
    result = dict(pick(item, ('id', 'ip', 'port', 'sni', 'purpose')),
                  tcp_connect=False, trusted_tls=False)
    start = time.monotonic()
    try:
        with socket.create_connection((item['ip'], item['port']), timeout=5) as conn:
            result['tcp_connect'] = True
            result['tcp_ms'] = round((time.monotonic() - start) * 1000, 1)
            if sni:
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2', 'http/1.1'])
                with context.wrap_socket(conn, server_hostname=sni) as tls:
                    result.update(trusted_tls=True, tls_version=tls.version(),
                                  alpn=tls.selected_alpn_protocol())
    except Exception as error:
        result['error_type'] = type(error).__name__
    result['elapsed_ms'] = round((time.monotonic() - start) * 1000, 1)
    return result


def self_test():
    """Offline reproducible tests; no adapter, SSH, socket or file writes."""
    import copy
    import unittest
    from unittest.mock import patch

    class InventoryTests(unittest.TestCase):
        def setUp(self):
            self.nodes, self.hosts, self.squads, self.profiles, self.calls = [], [], [], {}, []
            for n, t in enumerate(TARGETS):
                pid, iid, tag = 'profile-' + str(n), 'inbound-' + str(n), 'tag-' + str(n)
                meta = dict(uuid=iid, tag=tag, rawInbound={'privateKey': 'REDACTION_SENTINEL'})
                self.nodes.append(dict(uuid=t['node'], address=t['ip'], name=t['id'],
                    configProfile=dict(activeConfigProfileUuid=pid, activeInbounds=[meta])))
                self.hosts.append(dict(uuid=t['host'], nodes=[t['node']], port=443,
                    address=t['ip'], isDisabled=False, inbound=dict(
                        configProfileUuid=pid, configProfileInboundUuid=iid)))
                self.profiles[pid] = dict(name=pid, config=dict(inbounds=[dict(tag=tag,
                    protocol='vless', port=443, settings={'clients': [{'id': 'REDACTION_SENTINEL'}]},
                    streamSettings=dict(network='raw', security='reality', realitySettings=dict(
                        privateKey='REDACTION_SENTINEL', shortIds=['REDACTION_SENTINEL'],
                        serverNames=['example.com'], target='example.com:443')))]))
                self.squads.append(dict(uuid='squad-' + str(n), name='BASE', inbounds=[meta]))

        def api(self, method, path):
            self.calls.append((method, path))
            self.assertEqual(method, 'GET')
            if path == '/api/nodes/': return self.nodes
            if path == '/api/hosts/': return self.hosts
            if path == '/api/internal-squads/': return {'internalSquads': self.squads}
            return self.profiles[path.rsplit('/', 1)[-1]]

        def test_whitelist_get_and_six_candidates(self):
            result = panel_inventory(self.api)
            self.assertEqual(len(result['routes']), 6)
            self.assertEqual(len(result['probe_targets']), 6)
            self.assertNotIn('REDACTION_SENTINEL', json.dumps(result))
            self.assertNotIn('rawInbound', json.dumps(result))
            for route in result['routes']:
                self.assertTrue(route['hosts'][0]['binding_matches_active'])
                candidate = route['authentication_candidates'][0]
                self.assertIsNone(candidate['expected_egress'])
                self.assertFalse(candidate['authenticated_test_performed'])
                self.assertEqual(len(candidate['customer_squad_uuids']), 1)

        def test_binding_mismatch(self):
            self.hosts[3]['inbound'] = dict(configProfileUuid='other', configProfileInboundUuid='other')
            self.assertFalse(panel_inventory(self.api)['routes'][3]['hosts'][0]['binding_matches_active'])

        def test_node_drift(self):
            self.nodes[0]['address'] = '127.0.0.1'
            with self.assertRaises(AssertionError): panel_inventory(self.api)

        def test_host_drift(self):
            self.hosts[0]['nodes'] = []
            with self.assertRaises(AssertionError): panel_inventory(self.api)

        def test_service_squad_excluded(self):
            service = copy.deepcopy(self.squads[0])
            service.update(uuid='service', name='HAM-RU140-BACKEND')
            self.squads.append(service)
            route = panel_inventory(self.api)['routes'][0]
            self.assertEqual(len(route['squads']), 2)
            self.assertEqual(route['authentication_candidates'][0]['customer_squad_uuids'], ['squad-0'])

        def test_udp_not_tcp_vpn(self):
            raw = self.profiles['profile-4']['config']['inbounds'][0]
            raw['protocol'] = 'hysteria'
            raw['streamSettings']['network'] = 'hysteria'
            result = panel_inventory(self.api)
            self.assertEqual(result['routes'][4]['authentication_candidates'], [])
            self.assertEqual(next(p for p in result['probe_targets'] if p['id'] == 'us1')['purpose'],
                             'website-only-not-udp-health')

        def test_probe_scope(self):
            for item in [dict(id='at', ip='127.0.0.1', port=443),
                         dict(id='at', ip=TARGETS[0]['ip'], port=0),
                         dict(id='other', ip=TARGETS[0]['ip'], port=443)]:
                with self.assertRaises(AssertionError): connection_probe(item)

        def test_probe_does_not_echo_unknown_data(self):
            with patch('socket.create_connection', side_effect=TimeoutError):
                result = connection_probe(dict(id='at', ip=TARGETS[0]['ip'], port=443,
                                               privateKey='REDACTION_SENTINEL'))
            self.assertNotIn('REDACTION_SENTINEL', json.dumps(result))
            self.assertEqual(result['error_type'], 'TimeoutError')

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful(): raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['panel', 'entry', 'self-test'])
    args = parser.parse_args()
    if args.action == 'self-test':
        self_test()
        return
    if args.action == 'panel':
        from panel_api import create_client
        api, _query = create_client()
        result = panel_inventory(api)
    else:
        data = json.load(sys.stdin)
        assert data.get('readonly') is True
        items = data['probe_targets']
        assert items and len(items) <= 24
        # Binding succeeds only on the intended physical entry, with no listener.
        with socket.socket() as check:
            check.bind((ENTRY, 0))
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(connection_probe, items))
        result = dict(timestamp=time.time(), source=ENTRY, readonly=True,
                      authenticated_vpn_test=False, results=results)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
