"""Synthetic offline tests; none of these identities are deployed credentials."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('cloud140_six_pure_model', Path(__file__).with_name('route_model.py'))
model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(model)


def identity(seed=17):
    return {'privateKey': base64.urlsafe_b64encode(bytes([seed]) * 32).decode().rstrip('='),
            'shortIds': ['1234abcd', 'aabbccdd']}


def source():
    return {
        'log': {'loglevel': 'none'}, 'dns': {'servers': ['1.1.1.1']},
        'custom': {'nested': ['untouched']},
        'inbounds': [
            {'tag': 'legacy-hy2', 'listen': '0.0.0.0', 'port': 443, 'protocol': 'hysteria',
             'settings': {'version': 2, 'clients': [{'id': '00000000-0000-4000-8000-000000000001',
                                                   'password': 'SYNTHETIC-OLD-CLIENT'}]},
             'streamSettings': {'network': 'hysteria', 'security': 'tls',
                                'tlsSettings': {'certificates': [{'keyFile': '/preserve/cert.key'}]},
                                'finalmask': {'quicParams': {'congestion': 'bbr'}}}},
            {'tag': 'legacy-gb-7443', 'listen': '0.0.0.0', 'port': 7443, 'protocol': 'vless',
             'settings': {'decryption': 'none', 'clients': [], 'fallbacks': [{'dest': 9443}]},
             'streamSettings': {'network': 'tcp', 'security': 'reality',
                                'realitySettings': {'privateKey': identity(1)['privateKey'],
                                                    'shortIds': ['ffee'], 'serverNames': ['old.example'],
                                                    'target': 'old.example:443', 'extra': [3]}},
             'sniffing': {'enabled': False}},
            {'tag': 'legacy-udp-4500', 'port': 4500, 'protocol': 'hysteria',
             'settings': {'version': 2, 'clients': []},
             'streamSettings': {'network': 'hysteria', 'security': 'tls',
                                'tlsSettings': {'alpn': ['h3']}}}],
        'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                      {'tag': 'DENY', 'protocol': 'blackhole'},
                      {'tag': 'old-proxy', 'protocol': 'socks', 'settings': {'servers': []}}],
        'routing': {'domainStrategy': 'IPIfNonMatch', 'custom': ['keep'],
                    'balancers': [{'tag': 'old-balancer', 'selector': ['old-proxy']}],
                    'rules': [
                        {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'DENY'},
                        {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'DENY'},
                        {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'DENY'},
                        {'type': 'field', 'inboundTag': ['legacy-gb-7443', 'legacy-hy2', 'unrelated-api'],
                         'network': 'tcp,udp', 'outboundTag': 'old-proxy'},
                        {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'DIRECT'}]}}


def backend(exit_id='at', security='reality', *, seed=99):
    stream = {'network': 'raw', 'security': security}
    if security == 'reality':
        stream['realitySettings'] = {'serverName': 'checked.example', 'fingerprint': 'chrome',
                                     'publicKey': identity(91)['privateKey'], 'shortId': 'aabb',
                                     'spiderX': '/', 'show': False}
    if security == 'tls':
        stream['tlsSettings'] = {'serverName': 'checked.example', 'fingerprint': 'firefox',
                                 'allowInsecure': False, 'alpn': ['h2', 'http/1.1']}
    return {'tag': 'authenticated-probe', 'protocol': 'vless',
            'settings': {'vnext': [{'address': '127.0.0.1' if security == 'none' else model.TARGETS[exit_id]['ip'],
                                    'port': 28445 if security == 'none' else 15444,
                                    'users': [{'id': '00000000-0000-4000-8000-%012d' % seed,
                                               'encryption': 'none'}]}]},
            'streamSettings': stream}


def entry(config=None, exit_id='at', **overrides):
    args = dict(port=18445, domain=model.DOMAINS[exit_id], identity=identity(),
                backend_outbound=backend(exit_id))
    args.update(overrides)
    return model.build_entry_config(source() if config is None else config, exit_id, **args)


def exit_config(config=None, exit_id='at', **overrides):
    args = dict(mode='reality', identity=identity(), server_names=['checked.example'], target='checked.example:443')
    args.update(overrides)
    return model.build_exit_config(source() if config is None else config, exit_id, **args)


class ModelTests(unittest.TestCase):
    def test_inventory_domain_contract(self):
        self.assertEqual(model.DOMAINS, {'at': 'in-at38.torcalc.ru', 'pl': 'in-pl141.torcalc.ru',
                                        'cz': 'in-cz85.torcalc.ru', 'gb': 'in-gb216.torcalc.ru',
                                        'us1': 'in-us1.torcalc.ru', 'gbpower': 'in-gb225.torcalc.ru'})
        for key, node in model.TARGETS.items():
            with self.subTest(route=key):
                self.assertEqual(exit_config(exit_id=key)['inbounds'][-1]['listen'], node['ip'])
                front = entry(exit_id=key)['inbounds'][-1]
                self.assertEqual(front['listen'], '176.108.245.140')
                self.assertEqual(front['streamSettings']['realitySettings']['serverNames'], [node['domain']])

    def test_entry_exact_additive_delta(self):
        original = source()
        result = entry(original)
        self.assertEqual(result['inbounds'][:-1], original['inbounds'])
        self.assertEqual(result['outbounds'][:-1], original['outbounds'])
        self.assertEqual(result['routing']['rules'][3], {
            'type': 'field', 'inboundTag': ['cloud140-six-at-front'], 'outboundTag': 'cloud140-six-at-exit'})
        result['inbounds'].pop()
        result['outbounds'].pop()
        result['routing']['rules'].pop(3)
        self.assertEqual(result, original)

    def test_every_exit_legacy_field_preserved_except_tags_and_inbound_references(self):
        original = source()
        for key in model.TARGETS:
            with self.subTest(route=key):
                result, expected = exit_config(original, key), deepcopy(original)
                mapping = model.legacy_tag_map(original, key)
                self.assertEqual(mapping, {i['tag']: 'cloud140-six-' + key + '-legacy-' + i['tag']
                                           for i in original['inbounds']})
                for inbound in expected['inbounds']:
                    inbound['tag'] = mapping[inbound['tag']]
                expected['routing']['rules'][3]['inboundTag'] = [
                    mapping.get(tag, tag) for tag in original['routing']['rules'][3]['inboundTag']]
                result['inbounds'].pop()
                result['routing']['rules'].pop(3)
                self.assertEqual(result, expected)

    def test_hysteria_only_us1_is_not_replaced_by_tcp(self):
        config = source()
        config['inbounds'] = config['inbounds'][:1]
        original = deepcopy(config['inbounds'][0])
        result = exit_config(config, 'us1')
        preserved = result['inbounds'][0]
        self.assertEqual(preserved.pop('tag'), 'cloud140-six-us1-legacy-legacy-hy2')
        original.pop('tag')
        self.assertEqual(preserved, original)
        self.assertEqual(result['inbounds'][-1]['protocol'], 'vless')

    def test_gb_7443_and_all_six_gbpower_legacy_ports_are_preserved(self):
        config = source()
        config['inbounds'] = [dict(deepcopy(config['inbounds'][1]), tag='legacy-' + str(port), port=port)
                              for port in (7443, 8443, 9443, 10443, 2053, 2096)]
        result = exit_config(config, 'gbpower')
        for old, new in zip(config['inbounds'], result['inbounds']):
            restored = deepcopy(new)
            restored['tag'] = old['tag']
            self.assertEqual(restored, old)

    def test_builders_and_outputs_are_independent_deep_copies(self):
        config, ident, out = source(), identity(), backend()
        before = deepcopy((config, ident, out))
        result = entry(config, identity=ident, backend_outbound=out)
        other = exit_config(config, identity=ident)
        result['inbounds'][0]['settings']['clients'].clear()
        result['inbounds'][-1]['streamSettings']['realitySettings']['shortIds'].append('ff')
        result['outbounds'][-1]['settings']['vnext'][0]['users'].clear()
        result['routing']['balancers'].clear()
        other['custom']['nested'].clear()
        self.assertEqual((config, ident, out), before)

    def test_new_frontend_empty_clients_fresh_key_and_fixed_local_tls(self):
        front = entry()['inbounds'][-1]
        self.assertEqual(front['settings'], {'clients': [], 'decryption': 'none'})
        self.assertEqual(front['streamSettings']['network'], 'raw')
        reality = front['streamSettings']['realitySettings']
        self.assertEqual(reality['privateKey'], identity()['privateKey'])
        self.assertEqual(reality['target'], '127.0.0.1:9444')
        self.assertNotIn('dest', reality)
        self.assertTrue(front['sniffing']['routeOnly'])

    def test_exit_dedicated_backend_empty_clients_and_selected_freedom(self):
        result = exit_config()
        inbound = result['inbounds'][-1]
        self.assertEqual(inbound['settings'], {'clients': [], 'decryption': 'none'})
        self.assertEqual(inbound['tag'], 'cloud140-six-at-backend')
        self.assertEqual(inbound['port'], 15444)
        self.assertEqual(result['routing']['rules'][3]['outboundTag'], 'DIRECT')
        self.assertEqual(result['outbounds'], source()['outbounds'])

    def test_explicit_ssh_only_loopback_no_reality_parameters(self):
        for key in model.TARGETS:
            result = model.build_exit_config(source(), key, backend_port=15666, mode='ssh')
            inbound = result['inbounds'][-1]
            self.assertEqual((inbound['listen'], inbound['port']), ('127.0.0.1', 15666))
            self.assertEqual(inbound['streamSettings'], {'network': 'raw', 'security': 'none'})
        for extra in ({'identity': identity()}, {'target': 'checked.example:443'}, {'server_names': ['checked.example']}):
            with self.assertRaises(ValueError):
                model.build_exit_config(source(), 'at', mode='ssh', **extra)

    def test_no_implicit_reality_identity_sni_target_or_transport_fallback(self):
        with self.assertRaises(ValueError):
            model.build_exit_config(source(), 'at')
        for missing in ('identity', 'server_names', 'target'):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                exit_config(**{missing: None})
        for mode in ('none', 'tls', 'auto', '', None, [], True):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                exit_config(mode=mode)

    def test_non_clone_mode_rejected(self):
        for clone in (False, None, 1, 'true'):
            with self.assertRaises(ValueError):
                exit_config(clone=clone)

    def test_backend_exact_supplied_transport_except_scoped_tag(self):
        for security in ('reality', 'tls', 'none'):
            with self.subTest(security=security):
                original = backend(security=security)
                result = entry(backend_outbound=original)['outbounds'][-1]
                expected = deepcopy(original)
                expected['tag'] = 'cloud140-six-at-exit'
                self.assertEqual(result, expected)
                self.assertEqual(original['tag'], 'authenticated-probe')

    def test_backend_tcp_spelling_and_vision_preserved_when_encrypted(self):
        out = backend()
        out['streamSettings']['network'] = 'tcp'
        out['settings']['vnext'][0]['users'][0]['flow'] = 'xtls-rprx-vision'
        result = entry(backend_outbound=out)['outbounds'][-1]
        self.assertEqual(result['streamSettings'], out['streamSettings'])
        self.assertEqual(result['settings'], out['settings'])

    def test_newer_xray_password_public_key_alias_supported_not_ambiguous(self):
        out = backend()
        options = out['streamSettings']['realitySettings']
        options['password'] = options.pop('publicKey')
        self.assertEqual(entry(backend_outbound=out)['outbounds'][-1]['streamSettings'], out['streamSettings'])
        options['publicKey'] = options['password']
        with self.assertRaises(ValueError):
            entry(backend_outbound=out)

    def test_reject_plain_public_hostname_other_loopback_and_unspecified(self):
        for address in ('147.45.71.38', 'example.com', 'localhost', '127.0.0.2', '::1', '0.0.0.0'):
            out = backend(security='none')
            out['settings']['vnext'][0]['address'] = address
            with self.subTest(address=address), self.assertRaises(ValueError):
                entry(backend_outbound=out)

    def test_reject_backend_wrong_exit_or_protocol(self):
        with self.assertRaises(ValueError):
            entry(backend_outbound=backend('pl'))
        for protocol in ('freedom', 'socks', 'hysteria', 'trojan', None):
            out = backend()
            out['protocol'] = protocol
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)

    def test_reject_hidden_proxy_chain_mux_transport_rewrites(self):
        for key, value in (('proxySettings', {'tag': 'old-proxy'}), ('mux', {'enabled': True}), ('sendThrough', '1.2.3.4')):
            out = backend(security='none')
            out[key] = value
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)
        for key, value in (('sockopt', {'dialerProxy': 'old-proxy'}), ('tcpSettings', {}),
                           ('tlsSettings', {'allowInsecure': True})):
            out = backend(security='none')
            out['streamSettings'][key] = value
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)
        for network in ('ws', 'grpc', 'xhttp', 'hysteria', None):
            out = backend()
            out['streamSettings']['network'] = network
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)

    def test_tls_verification_cannot_be_disabled_or_overridden(self):
        for value in (True, 1, 'false', None):
            out = backend(security='tls')
            out['streamSettings']['tlsSettings']['allowInsecure'] = value
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)
        out = backend(security='tls')
        out['streamSettings']['tlsSettings']['verifyPeerCertInNames'] = ['other.example']
        with self.assertRaises(ValueError):
            entry(backend_outbound=out)

    def test_missing_or_invalid_backend_security(self):
        for security in (None, '', 'auto', True, []):
            out = backend()
            out['streamSettings']['security'] = security
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)
        for field in ('publicKey', 'serverName', 'shortId', 'fingerprint'):
            out = backend()
            out['streamSettings']['realitySettings'].pop(field)
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)

    def test_reject_public_plain_flow_and_multiple_backends_or_users(self):
        out = backend(security='none')
        out['settings']['vnext'][0]['users'][0]['flow'] = 'xtls-rprx-vision'
        with self.assertRaises(ValueError):
            entry(backend_outbound=out)
        for multiple in ('destinations', 'users'):
            out = backend()
            items = out['settings']['vnext'] if multiple == 'destinations' else out['settings']['vnext'][0]['users']
            items.append(deepcopy(items[0]))
            with self.assertRaises(ValueError):
                entry(backend_outbound=out)

    def test_reject_reused_customer_uuid_or_invalid_service_uuid(self):
        for value in ('00000000-0000-4000-8000-000000000001', '00000000-0000-0000-0000-000000000000',
                      'PRIVATE-NOT-UUID', None):
            out = backend()
            out['settings']['vnext'][0]['users'][0]['id'] = value
            with self.assertRaises(ValueError) as error:
                entry(backend_outbound=out)
            self.assertNotIn('PRIVATE', str(error.exception))

    def test_security_blocks_precede_scoped_new_rules_and_catchall_follows(self):
        for result in (entry(), exit_config()):
            self.assertEqual(result['routing']['rules'][:3], source()['routing']['rules'][:3])
            self.assertEqual(result['routing']['rules'][-1], source()['routing']['rules'][-1])
            self.assertEqual(len(result['routing']['rules'][3]['inboundTag']), 1)

    def test_all_blackhole_rules_keep_precedence_even_unknown_security_policy(self):
        config = source()
        config['routing']['rules'].insert(3, {'type': 'field', 'domain': ['domain:malware.example'], 'outboundTag': 'DENY'})
        config['routing']['rules'].insert(1, config['routing']['rules'].pop(4))
        for build in (entry, exit_config):
            result = build(config)
            self.assertEqual(result['routing']['rules'][4], config['routing']['rules'][4])
            self.assertEqual(len(result['routing']['rules'][5]['inboundTag']), 1)

    def test_broad_route_before_security_blocks_fails_without_mutation(self):
        config = source()
        config['routing']['rules'].insert(0, config['routing']['rules'].pop())
        before = deepcopy(config)
        for build in (entry, exit_config):
            with self.assertRaisesRegex(ValueError, 'broad route'):
                build(config)
        self.assertEqual(config, before)

    def test_missing_routing_or_rules_preserves_unknown_fields(self):
        for field in ('routing', 'rules'):
            config = source()
            if field == 'routing':
                config.pop(field)
            else:
                config['routing'].pop(field)
            for build in (entry, exit_config):
                result = build(config)
                self.assertEqual(len(result['routing'].pop('rules')), 1)
                self.assertEqual(result['routing'], config.get('routing', {}))

    def test_freedom_requires_explicit_choice_when_ambiguous(self):
        config = source()
        config['outbounds'].append({'tag': 'SECOND', 'protocol': 'freedom'})
        with self.assertRaises(ValueError):
            exit_config(config)
        self.assertEqual(exit_config(config, direct_tag='SECOND')['routing']['rules'][3]['outboundTag'], 'SECOND')
        with self.assertRaises(ValueError):
            exit_config(direct_tag='old-proxy')
        config['outbounds'] = [item for item in config['outbounds'] if item['protocol'] != 'freedom']
        with self.assertRaises(ValueError):
            exit_config(config)

    def test_ports_are_caller_supplied_and_all_ranges_checked(self):
        self.assertEqual(entry(port=19876)['inbounds'][-1]['port'], 19876)
        self.assertEqual(exit_config(backend_port=15666)['inbounds'][-1]['port'], 15666)
        for conflict in (15444, '15444', '10000-20000', '443,15444,18445'):
            config = source()
            config['inbounds'][0]['port'] = conflict
            with self.assertRaises(ValueError):
                exit_config(config)
        for port in (443, 7443, 4500, 9444, True, 0, 65536, '18445', [], None):
            with self.assertRaises(ValueError):
                entry(port=port)
        for port in (True, 0, 65536, [], None):
            with self.assertRaises(ValueError):
                exit_config(backend_port=port)

    def test_malformed_existing_port_fails_closed_without_echo(self):
        for port in (True, {}, 'SECRET-PORT', '1-70000', '200-100', ''):
            config = source()
            config['inbounds'][0]['port'] = port
            with self.assertRaises(ValueError) as error:
                entry(config)
            self.assertNotIn('SECRET', str(error.exception))

    def test_domain_must_match_selected_route_not_merely_approved_set(self):
        for domain in ('in-pl141.torcalc.ru', 'IN-AT38.torcalc.ru', 'in-at38.torcalc.ru.', 'evil.example', None):
            with self.assertRaises(ValueError):
                entry(domain=domain)

    def test_explicit_names_targets_checked_without_default_or_secret_echo(self):
        for names in (None, [], [''], ['*.example'], ['UPPER.example'], ['1.2.3.4'],
                      ['a.example', 'a.example'], 'a.example', ['secret']):
            with self.assertRaises(ValueError):
                exit_config(server_names=names)
        for target in (None, '', 'checked.example', 'https://checked.example:443',
                       'checked.example:65536', '0.0.0.0:443', '224.0.0.1:443', 'SECRET-TARGET'):
            with self.assertRaises(ValueError) as error:
                exit_config(target=target)
            self.assertNotIn('SECRET', str(error.exception))
        for target in ('127.0.0.1:9443', '[::1]:9443', 'checked.example:443'):
            self.assertEqual(exit_config(target=target)['inbounds'][-1]['streamSettings']['realitySettings']['target'], target)

    def test_invalid_keys_shortids_and_legacy_identity_reuse_rejected(self):
        for change in ({'privateKey': 'SECRET'}, {'privateKey': 'A' * 43}, {'shortIds': []},
                       {'shortIds': ['abc']}, {'shortIds': ['aa', 'AA']}, {'shortIds': ['gg']},
                       {'shortIds': ['']}, {'extra': 'SECRET'}):
            ident = identity()
            ident.update(change)
            for build in (entry, exit_config):
                with self.assertRaises(ValueError) as error:
                    build(identity=ident)
                self.assertNotIn('SECRET', str(error.exception))
        for build in (entry, exit_config):
            with self.assertRaises(ValueError):
                build(identity=identity(1))

    def test_six_routes_can_append_with_distinct_identity_port_and_scope(self):
        config, original = source(), source()
        for index, key in enumerate(model.TARGETS, 30):
            config = entry(config, key, port=18400 + index, identity=identity(index),
                           backend_outbound=backend(key, seed=index))
        self.assertEqual(config['inbounds'][:3], original['inbounds'])
        self.assertEqual(config['outbounds'][:3], original['outbounds'])
        self.assertEqual(len(config['inbounds']), 9)
        self.assertEqual(len({inbound['tag'] for inbound in config['inbounds']}), 9)
        with self.assertRaises(ValueError):
            entry(config)
        with self.assertRaises(ValueError):
            entry(entry(), 'pl', port=18446, identity=identity())

    def test_no_double_clone_or_cross_clone(self):
        for key in model.TARGETS:
            with self.assertRaises(ValueError):
                exit_config(exit_config(), key)
        maps = [set(model.legacy_tag_map(source(), key).values()) for key in model.TARGETS]
        self.assertEqual(len(set.union(*maps)), sum(map(len, maps)))

    def test_dangling_tags_and_legacy_tag_collisions_fail_closed(self):
        for field, value in (('inboundTag', ['cloud140-six-at-front']), ('outboundTag', 'cloud140-six-at-exit')):
            config = source()
            config['routing']['rules'].append({field: value})
            with self.assertRaises(ValueError):
                entry(config)
        config = source()
        config['outbounds'].append({'tag': 'cloud140-six-at-legacy-legacy-hy2', 'protocol': 'freedom'})
        with self.assertRaises(ValueError):
            model.legacy_tag_map(config, 'at')

    def test_new_backend_does_not_join_old_balancer_by_prefix(self):
        for selector in ('', 'cloud140', 'cloud140-six-at-exit'):
            config = source()
            config['routing']['balancers'][0]['selector'] = [selector]
            with self.assertRaises(ValueError):
                entry(config)

    def test_invalid_config_shapes_raise_valueerror(self):
        for mutation in ('duplicate', 'no-tag', 'selector', 'routing', 'rules', 'balancers', 'cross-tag'):
            config = source()
            if mutation == 'duplicate':
                config['inbounds'][1]['tag'] = config['inbounds'][0]['tag']
            elif mutation == 'no-tag':
                config['inbounds'][0].pop('tag')
            elif mutation == 'selector':
                config['routing']['rules'][0]['ip'] = 'geoip:private'
            elif mutation == 'routing':
                config['routing'] = None
            elif mutation == 'rules':
                config['routing']['rules'] = {}
            elif mutation == 'balancers':
                config['routing']['balancers'][0]['selector'] = 'old-proxy'
            elif mutation == 'cross-tag':
                config['inbounds'][0]['tag'] = 'DIRECT'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                entry(config)

    def test_unknown_scope_rejected_without_echo(self):
        for key in ('kz2', 'de245', 'SECRET-ROUTE', None, []):
            with self.assertRaises(ValueError) as error:
                model.build_exit_config(source(), key, mode='ssh')
            self.assertNotIn('SECRET', str(error.exception))

    def test_no_process_network_file_api_or_print_side_effects(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
             patch('builtins.open', side_effect=AssertionError('file I/O forbidden')), \
             patch('subprocess.run', side_effect=AssertionError('process forbidden')), \
             patch('socket.socket', side_effect=AssertionError('network forbidden')):
            entry()
            exit_config()
            model.build_exit_config(source(), 'gb', mode='ssh')
            with self.assertRaises(ValueError):
                entry(identity={'privateKey': 'SECRET'})
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
