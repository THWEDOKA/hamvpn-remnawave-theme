"""Offline candidate tests; fixtures are synthetic, no production snapshots."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import unittest
from unittest.mock import patch

import preflight
import route_model as model


def fixture():
    return dict(
        log={'loglevel': 'warning'}, dns={'servers': ['localhost']},
        policy={'levels': {'0': {'handshake': 4}}}, stats={},
        observatory={'subjectSelector': ['legacy-out']}, custom={'nested': [1, {'keep': True}]},
        inbounds=[dict(
            tag='old-' + str(index), listen='0.0.0.0', port=443 + index, protocol='vless',
            settings={'clients': [{'id': 'legacy-fixture', 'flow': 'xtls-rprx-vision'}],
                      'decryption': 'none', 'extra': ['preserve']},
            streamSettings={'network': 'tcp', 'security': 'reality', 'realitySettings': {
                'privateKey': 'SYNTHETIC-LEGACY-KEY-' + str(index), 'shortIds': ['aabb'],
                'serverNames': ['legacy.example'], 'target': '127.0.0.1:8443', 'extra': [index]}},
            sniffing={'enabled': False}) for index in range(4)],
        outbounds=[{'tag': 'DIRECT', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}},
                   {'tag': 'BLOCK', 'protocol': 'blackhole', 'settings': {}},
                   {'tag': 'legacy-out', 'protocol': 'socks', 'settings': {'servers': []}}],
        routing={'domainStrategy': 'IPIfNonMatch', 'domainMatcher': 'hybrid',
                 'balancers': [{'tag': 'keep', 'selector': ['legacy-out']}], 'rules': [
                     {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'BLOCK'},
                     {'type': 'field', 'domain': ['geosite:private'], 'outboundTag': 'BLOCK'},
                     {'type': 'field', 'protocol': ['bittorrent'], 'outboundTag': 'BLOCK'},
                     {'type': 'field', 'inboundTag': ['old-0', 'old-2'],
                      'outboundTag': 'legacy-out', 'network': 'tcp'},
                     {'type': 'field', 'inboundTag': ['old-1', 'unrelated-internal'],
                      'outboundTag': 'DIRECT'},
                     {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'DIRECT'}]})


def identities():
    # Public deterministic test bytes, not deployed credentials.
    return {name: {'privateKey': base64.urlsafe_b64encode(bytes([index]) * 32).decode().rstrip('='),
                   'shortIds': ['1234abcd', 'aabbccdd']}
            for index, name in enumerate(('kz2', 'de245'), 1)}


def services():
    return {'kz2': '00000000-0000-4000-8000-000000000001',
            'de245': '00000000-0000-4000-8000-000000000002'}


class ModelTests(unittest.TestCase):
    def entry(self, source=None, **kwargs):
        return model.build_entry_config(fixture() if source is None else source,
                                        identities(), services(), **kwargs)

    def test_canonical_inventory(self):
        result = self.entry()
        for node, inbound in zip(preflight.NODES, result['inbounds'][-2:]):
            self.assertEqual((inbound['listen'], inbound['port']), (preflight.ENTRY, node['port']))
            self.assertEqual(inbound['streamSettings']['realitySettings']['serverNames'], [node['domain']])

    def test_entry_exact_additive_delta(self):
        source = fixture()
        result = self.entry(source)
        self.assertEqual(result['inbounds'][:4], source['inbounds'])
        self.assertEqual(result['outbounds'][:3], source['outbounds'])
        del result['inbounds'][-2:]
        del result['outbounds'][-2:]
        del result['routing']['rules'][3:5]
        self.assertEqual(result, source)

    def test_entry_never_mutates_input_or_identity(self):
        source, keys, users = fixture(), identities(), services()
        old = deepcopy((source, keys, users))
        result = model.build_entry_config(source, keys, users)
        result['inbounds'][0]['settings']['clients'].clear()
        result['inbounds'][-1]['streamSettings']['realitySettings']['shortIds'].append('ffff')
        result['routing']['balancers'].clear()
        result['custom']['nested'].clear()
        self.assertEqual((source, keys, users), old)

    def test_fronts_use_fresh_provided_identity_local_tls_and_empty_clients(self):
        result = self.entry()
        for node, inbound in zip(preflight.NODES, result['inbounds'][-2:]):
            rs = inbound['streamSettings']['realitySettings']
            self.assertEqual(inbound['streamSettings']['network'], 'raw')
            self.assertEqual(inbound['streamSettings']['security'], 'reality')
            self.assertEqual(rs['target'], '127.0.0.1:9443')
            self.assertNotIn('dest', rs)
            self.assertEqual(rs['privateKey'], identities()[node['id']]['privateKey'])
            self.assertEqual(inbound['settings'], {'clients': [], 'decryption': 'none'})
            self.assertTrue(inbound['sniffing']['routeOnly'])

    def test_backend_service_only_inside_loopback_ssh_ports(self):
        for node, outbound in zip(preflight.NODES, self.entry()['outbounds'][-2:]):
            self.assertEqual(outbound['streamSettings'], {'network': 'raw', 'security': 'none'})
            self.assertEqual(outbound['settings']['vnext'], [dict(
                address='127.0.0.1', port=model.REVERSE_PORTS[node['id']],
                users=[dict(id=services()[node['id']], encryption='none')])])
            self.assertNotIn('privateKey', str(outbound))
            self.assertNotIn('flow', str(outbound))

    def test_cached_snis_are_opt_in_without_copying_exit_keys(self):
        result = self.entry(include_cached_snis=True)
        for node, inbound in zip(preflight.NODES, result['inbounds'][-2:]):
            rs = inbound['streamSettings']['realitySettings']
            self.assertEqual(rs['serverNames'], [node['domain'], node['sni']])
            self.assertEqual(rs['privateKey'], identities()[node['id']]['privateKey'])

    def test_rules_after_all_security_blocks_before_catchall(self):
        source, result = fixture(), self.entry()
        rules = result['routing']['rules']
        self.assertEqual(rules[:3], source['routing']['rules'][:3])
        self.assertEqual(rules[5:], source['routing']['rules'][3:])
        for node, rule in zip(preflight.NODES, rules[3:5]):
            tags = model.route_tags(node['id'])
            self.assertEqual(rule, dict(type='field', inboundTag=[tags['front']], outboundTag=tags['exit']))

    def test_security_recognizes_blackhole_tag_not_its_spelling(self):
        source = fixture()
        source['outbounds'][1]['tag'] = 'deny'
        for rule in source['routing']['rules'][:3]:
            rule['outboundTag'] = 'deny'
        self.assertEqual(self.entry(source)['routing']['rules'][:3], source['routing']['rules'][:3])

    def test_explicit_private_network_blocks_keep_priority(self):
        for private in ('10.0.0.0/8', '127.0.0.0/8', 'fc00::/7', '192.168.0.0/16'):
            with self.subTest(network=private):
                source = fixture()
                source['routing']['rules'] = [{'type': 'field', 'ip': [private], 'outboundTag': 'BLOCK'}]
                self.assertEqual(self.entry(source)['routing']['rules'][0], source['routing']['rules'][0])

    def test_scoped_old_rules_keep_relative_order_around_blocks(self):
        source = fixture()
        rule = source['routing']['rules'].pop(3)
        source['routing']['rules'].insert(1, rule)
        result = self.entry(source)
        self.assertEqual(result['routing']['rules'][:4], source['routing']['rules'][:4])
        self.assertEqual(result['routing']['rules'][6:], source['routing']['rules'][4:])

    def test_impossible_security_order_fails_without_mutation(self):
        source = fixture()
        source['routing']['rules'].insert(0, source['routing']['rules'].pop())
        before = deepcopy(source)
        with self.assertRaisesRegex(ValueError, 'broad route'):
            self.entry(source)
        with self.assertRaisesRegex(ValueError, 'broad route'):
            model.build_exit_config(source, 'kz2')
        self.assertEqual(source, before)

    def test_existing_routing_without_rules_is_preserved(self):
        source = fixture()
        del source['routing']['rules']
        result = self.entry(source)
        self.assertEqual(len(result['routing'].pop('rules')), 2)
        self.assertEqual(result['routing'], source['routing'])

    def test_existing_config_without_routing(self):
        source = fixture()
        del source['routing']
        self.assertEqual(len(self.entry(source)['routing']['rules']), 2)

    def test_kz_clone_renames_every_inbound_and_every_routing_reference(self):
        source = fixture()
        result = model.build_exit_config(source, 'kz2')
        mapping = model.legacy_tag_map(source)
        self.assertEqual(mapping, {item['tag']: 'cloud140-kz2-legacy-' + item['tag'] for item in source['inbounds']})
        expected = deepcopy(source)
        for item in expected['inbounds']:
            item['tag'] = mapping[item['tag']]
        for rule in expected['routing']['rules']:
            if 'inboundTag' in rule:
                rule['inboundTag'] = [mapping.get(tag, tag) for tag in rule['inboundTag']]
        del result['inbounds'][-1]
        del result['routing']['rules'][3]
        self.assertEqual(result, expected)

    def test_de245_clone_exact_delta_preserves_all_non_tag_fields(self):
        source = fixture()
        before = deepcopy(source)
        result = model.build_exit_config(source, 'de245', clone=True)
        mapping = model.legacy_tag_map(source, 'de245')
        self.assertEqual(mapping, {item['tag']: 'cloud140-de245-legacy-' + item['tag']
                                   for item in source['inbounds']})
        expected = deepcopy(source)
        for inbound in expected['inbounds']:
            inbound['tag'] = mapping[inbound['tag']]
        for rule in expected['routing']['rules']:
            if 'inboundTag' in rule:
                rule['inboundTag'] = [mapping.get(tag, tag) for tag in rule['inboundTag']]
        del result['inbounds'][-1]
        del result['routing']['rules'][3]
        self.assertEqual(result, expected)
        self.assertEqual(source, before)

    def test_both_clone_namespaces_are_disjoint_from_each_other_and_originals(self):
        source = fixture()
        original_tags = {item['tag'] for item in source['inbounds']}
        kz = model.build_exit_config(source, 'kz2', clone=True)
        de = model.build_exit_config(source, 'de245', clone=True)
        kz_tags = {item['tag'] for item in kz['inbounds']}
        de_tags = {item['tag'] for item in de['inbounds']}
        self.assertFalse(kz_tags & de_tags or kz_tags & original_tags or de_tags & original_tags)
        self.assertEqual(model.legacy_tag_map(source), model.legacy_tag_map(source, 'kz2'))

    def test_explicit_clone_true_matches_safe_default_for_both_exits(self):
        for exit_id in model.REVERSE_PORTS:
            self.assertEqual(model.build_exit_config(fixture(), exit_id, clone=True),
                             model.build_exit_config(fixture(), exit_id))

    def test_non_clone_mode_is_forbidden_for_both_exits_without_source_changes(self):
        source = fixture()
        before = deepcopy(source)
        for exit_id in model.REVERSE_PORTS:
            for option in (False, None, 1, 'true'):
                with self.subTest(exit_id=exit_id, option=option):
                    with self.assertRaisesRegex(ValueError, 'dedicated clones'):
                        model.build_exit_config(source, exit_id, clone=option)
        self.assertEqual(source, before)

    def test_cached_keys_snis_clients_ports_preserved_in_both_exit_clones(self):
        source = fixture()
        for exit_id in model.REVERSE_PORTS:
            result = model.build_exit_config(source, exit_id, clone=True)
            for original, cloned in zip(source['inbounds'], result['inbounds'][:-1]):
                restored = deepcopy(cloned)
                restored['tag'] = original['tag']
                self.assertEqual(restored, original)

    def test_both_exit_backends_loopback_empty_clients_no_flow(self):
        for exit_id in model.REVERSE_PORTS:
            result = model.build_exit_config(fixture(), exit_id)
            backend = result['inbounds'][-1]
            self.assertEqual((backend['listen'], backend['port']), ('127.0.0.1', 15443))
            self.assertEqual(backend['tag'], 'cloud140-' + exit_id + '-backend')
            self.assertEqual(backend['protocol'], 'vless')
            self.assertEqual(backend['streamSettings'], {'network': 'raw', 'security': 'none'})
            self.assertEqual(backend['settings'], {'clients': [], 'decryption': 'none'})
            self.assertNotIn('flow', str(backend))
            self.assertEqual(result['routing']['rules'][3], dict(
                type='field', inboundTag=[backend['tag']], outboundTag='DIRECT'))

    def test_exit_results_do_not_alias_source_or_each_other(self):
        source = fixture()
        before = deepcopy(source)
        kz = model.build_exit_config(source, 'kz2')
        de = model.build_exit_config(source, 'de245')
        kz['inbounds'][0]['settings']['clients'].clear()
        kz['routing']['rules'][0]['ip'].append('changed')
        kz['outbounds'][0]['settings'].clear()
        self.assertEqual(source, before)
        restored = deepcopy(de['inbounds'][0])
        restored['tag'] = before['inbounds'][0]['tag']
        self.assertEqual(restored, before['inbounds'][0])
        self.assertEqual(de['outbounds'], before['outbounds'])

    def test_direct_outbound_is_explicit_when_ambiguous(self):
        source = fixture()
        source['outbounds'].append({'tag': 'other-freedom', 'protocol': 'freedom'})
        with self.assertRaises(ValueError):
            model.build_exit_config(source, 'de245')
        result = model.build_exit_config(source, 'de245', direct_tag='other-freedom')
        self.assertEqual(result['routing']['rules'][3]['outboundTag'], 'other-freedom')

    def test_backend_refuses_proxy_as_exit_destination(self):
        with self.assertRaises(ValueError):
            model.build_exit_config(fixture(), 'de245', direct_tag='legacy-out')

    def test_missing_freedom_is_rejected(self):
        source = fixture()
        source['outbounds'] = source['outbounds'][1:]
        with self.assertRaises(ValueError):
            model.build_exit_config(source, 'kz2')

    def test_ports_and_ranges_colliding_with_new_fronts_are_rejected(self):
        for port in (18443, '18444', '18400-18500', '443,18443'):
            with self.subTest(port=port):
                source = fixture()
                source['inbounds'][0]['port'] = port
                with self.assertRaises(ValueError):
                    self.entry(source)

    def test_backend_port_collision_is_rejected(self):
        source = fixture()
        source['inbounds'][0]['port'] = 15443
        for exit_id in model.REVERSE_PORTS:
            with self.assertRaises(ValueError):
                model.build_exit_config(source, exit_id)

    def test_port_parser_fails_closed_without_echoing_value(self):
        for port in (True, {}, 'SECRET-INVALID-PORT', '1-70000', '200-100'):
            source = fixture()
            source['inbounds'][0]['port'] = port
            with self.assertRaises(ValueError) as error:
                self.entry(source)
            self.assertNotIn('SECRET', str(error.exception))

    def test_no_double_apply_or_double_clone(self):
        with self.assertRaises(ValueError):
            self.entry(self.entry())
        for exit_id in model.REVERSE_PORTS:
            with self.assertRaises(ValueError):
                model.build_exit_config(model.build_exit_config(fixture(), exit_id), exit_id)

    def test_dangling_operation_tag_references_are_not_silently_activated(self):
        for field, value in (('inboundTag', ['cloud140-kz2-front']), ('outboundTag', 'cloud140-kz2-exit')):
            source = fixture()
            source['routing']['rules'].append({field: value})
            with self.assertRaises(ValueError):
                self.entry(source)

    def test_legacy_renaming_collision_rejected(self):
        for exit_id in model.REVERSE_PORTS:
            source = fixture()
            source['outbounds'].append({'tag': 'cloud140-' + exit_id + '-legacy-old-0', 'protocol': 'freedom'})
            with self.assertRaises(ValueError):
                model.legacy_tag_map(source, exit_id)

    def test_cross_route_reclone_rejected(self):
        kz = model.build_exit_config(fixture(), 'kz2')
        with self.assertRaises(ValueError):
            model.legacy_tag_map(kz, 'de245')
        de = model.build_exit_config(fixture(), 'de245')
        with self.assertRaises(ValueError):
            model.legacy_tag_map(de, 'kz2')

    def test_duplicate_or_missing_tags_rejected(self):
        for tag in ('old-0', '', None):
            source = fixture()
            source['inbounds'][1]['tag'] = tag
            with self.assertRaises(ValueError):
                self.entry(source)

    def test_wrong_rule_selector_shape_rejected(self):
        source = fixture()
        source['routing']['rules'][3]['inboundTag'] = 'old-0'
        with self.assertRaises(ValueError):
            model.build_exit_config(source, 'kz2')

    def test_identity_mapping_requires_exact_routes(self):
        for keys in ({}, {'kz2': identities()['kz2']}, dict(identities(), unexpected={})):
            with self.assertRaises(ValueError):
                model.build_entry_config(fixture(), keys, services())

    def test_service_mapping_requires_exact_routes(self):
        with self.assertRaises(ValueError):
            model.build_entry_config(fixture(), identities(), {'kz2': services()['kz2']})

    def test_malformed_identity_rejected_without_exposing_keys(self):
        for change in ({'privateKey': 'SECRET-NOT-A-KEY'}, {'shortIds': []}, {'shortIds': ['abc']},
                       {'shortIds': ['AA', 'aa']}, {'shortIds': ['gg']}, {'privateKey': 'A' * 43}):
            keys = identities()
            keys['kz2'].update(change)
            with self.assertRaises(ValueError) as error:
                model.build_entry_config(fixture(), keys, services())
            self.assertNotIn('SECRET', str(error.exception))
            self.assertNotIn(keys['kz2']['privateKey'], str(error.exception))

    def test_front_identity_reuse_rejected(self):
        keys = identities()
        keys['de245'] = deepcopy(keys['kz2'])
        with self.assertRaises(ValueError):
            model.build_entry_config(fixture(), keys, services())

    def test_malformed_service_uuid_never_echoed(self):
        for value in ('SECRET-ID', '00000000-0000-0000-0000-000000000000', None):
            users = services()
            users['kz2'] = value
            with self.assertRaises(ValueError) as error:
                model.build_entry_config(fixture(), identities(), users)
            self.assertNotIn('SECRET', str(error.exception))

    def test_unknown_route_rejected_without_echo(self):
        with self.assertRaises(ValueError) as error:
            model.build_exit_config(fixture(), 'SECRET-UNKNOWN')
        self.assertNotIn('SECRET', str(error.exception))

    def test_cached_sni_option_requires_actual_boolean(self):
        with self.assertRaises(ValueError):
            self.entry(include_cached_snis='false')

    def test_builders_have_no_api_process_file_or_output_side_effects(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
             patch.object(preflight, 'create_client', side_effect=AssertionError('API forbidden')), \
             patch('subprocess.run', side_effect=AssertionError('process forbidden')), \
             patch('builtins.open', side_effect=AssertionError('file IO forbidden')):
            self.entry()
            model.build_exit_config(fixture(), 'kz2')
            model.build_exit_config(fixture(), 'de245')
            try:
                model.build_entry_config(fixture(), {'kz2': 'SECRET'}, services())
            except ValueError:
                pass
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
