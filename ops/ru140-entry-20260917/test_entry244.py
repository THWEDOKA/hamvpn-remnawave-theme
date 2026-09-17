"""Offline entry244 regression tests: fake API/state, no production credentials.

Run: python -B -m unittest discover -s ops/ru140-entry-20260917 -p test_entry244.py -v
Safety regressions are ordinary failing tests, not expected failures. No SSH,
systemd, Docker, API, or production-state access is allowed by the test harness.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import entry244_common as common244
import node244
import panel244 as p
import transport


SOURCE_NODE = '22ac9320-4762-461d-b877-a9f33b58d492'
CREATED = {'profile': 'fixture-created-profile', 'legacy': 'fixture-created-legacy',
           'inbounds': {n['id']: 'fixture-created-' + n['id'] for n in p.NODES}}
SERVICE = {'uuid': 'fixture-backend-user', 'username': 'ham_entry140_backend',
           'status': 'ACTIVE', 'vlessUuid': '00000000-0000-4000-8000-000000000001'}
BACKEND_SQUAD = 'fixture-backend-squad'
NOW = 10000.0


def node(identifier, address, profile, inbounds):
    return {'uuid': identifier, 'name': identifier, 'address': address, 'port': 2222,
            'isConnected': True, 'isDisabled': False,
            'configProfile': {'activeConfigProfileUuid': profile,
                              'activeInbounds': [{'uuid': x} for x in inbounds]}}


def fixture():
    """Identifiers are public; all credential-like values are invalid sentinels."""
    legacy = {'tag': 'fixture-old', 'listen': '0.0.0.0', 'port': 443,
              'protocol': 'vless', 'settings': {'clients': [], 'decryption': 'none'},
              'streamSettings': {'network': 'raw', 'security': 'reality',
                  'realitySettings': {'privateKey': 'NOT_A_KEY_LEGACY',
                      'shortIds': ['NOT_A_SHORT_ID_LEGACY'],
                      'serverNames': list(dict.fromkeys(['google.com', *[
                          n['exit_sni'] for n in p.NODES if n['profile'] == p.OLD_PROFILE]])),
                      'target': '127.0.0.1:8443'}}}
    profiles = {}
    for n in p.NODES:
        tag = 'fixture-' + n['id']
        profiles[n['profile']] = {'uuid': n['profile'],
            'inbounds': [{'uuid': n['inbound'], 'tag': tag}],
            'config': {'inbounds': [{'tag': tag, 'protocol': 'vless',
                'streamSettings': {'network': 'raw', 'security': 'tls'}}]}}
    profiles[p.OLD_PROFILE] = {'uuid': p.OLD_PROFILE,
        'inbounds': [{'uuid': p.OLD_INBOUND, 'tag': legacy['tag']}],
        'config': {'inbounds': [legacy],
            'outbounds': [{'tag': 'DIRECT', 'protocol': 'freedom'},
                          {'tag': 'BLOCK', 'protocol': 'blackhole'}],
            'routing': {'rules': [
                {'type': 'field', 'ip': ['geoip:private'], 'outboundTag': 'BLOCK'},
                {'type': 'field', 'domain': ['geosite:ru'], 'outboundTag': 'DIRECT'},
                {'type': 'field', 'ip': ['geoip:ru'], 'outboundTag': 'DIRECT'},
                {'type': 'field', 'inboundTag': [legacy['tag']], 'outboundTag': 'DIRECT'}]}}}
    source_inbounds = []
    for n in p.NODES:
        source_inbounds.append({'tag': 'vless-entry208-' + n['id'],
            'streamSettings': {'security': 'reality', 'realitySettings': {
                'privateKey': 'NOT_A_KEY_' + n['id'],
                'shortIds': ['NOT_A_SHORT_ID_' + n['id'], 'NOT_A_SECOND_ID'],
                'serverNames': [n['domain'], 'fixture-alias.invalid'],
                'target': '127.0.0.1:9443'}}})
    profiles[p.SOURCE_PROFILE] = {'uuid': p.SOURCE_PROFILE,
        'inbounds': [{'uuid': 'fixture-source-' + n['id'], 'tag': i['tag']}
                     for n, i in zip(p.NODES, source_inbounds)],
        'config': {'inbounds': source_inbounds}}
    nodes = [node(p.NODE, p.ENTRY, p.OLD_PROFILE, [p.OLD_INBOUND]),
             node(SOURCE_NODE, '162.141.185.208', p.SOURCE_PROFILE,
                  ['fixture-source-' + n['id'] for n in p.NODES])]
    nodes.extend(node(n['node'], n['ip'], n['profile'], [n['inbound']]) for n in p.NODES)
    # An unrelated node shares OLD_PROFILE: never rewrite this profile in place.
    nodes.append(node('fixture-shared-node', '192.0.2.25', p.OLD_PROFILE, [p.OLD_INBOUND]))
    hosts = []
    for n in p.NODES:
        for hidden, identifier in enumerate(n['hosts']):
            hosts.append({'uuid': identifier, 'remark': identifier, 'nodes': [SOURCE_NODE],
                'inbound': {'configProfileUuid': p.SOURCE_PROFILE,
                            'configProfileInboundUuid': 'fixture-source-' + n['id']},
                'address': n['domain'], 'sni': n['domain'], 'host': n['domain'],
                'port': 443, 'securityLayer': 'DEFAULT', 'fingerprint': 'firefox',
                'alpn': None, 'isDisabled': False, 'isHidden': bool(hidden), 'viewPosition': hidden})
    legacy_host = {'uuid': next(iter(p.OLD_HOSTS)), 'remark': 'TEST', 'nodes': [p.NODE],
        'inbound': {'configProfileUuid': p.OLD_PROFILE, 'configProfileInboundUuid': p.OLD_INBOUND},
        'address': p.ENTRY, 'sni': 'google.com', 'host': '', 'port': 443,
        'securityLayer': 'DEFAULT', 'fingerprint': 'chrome', 'alpn': None,
        'isDisabled': False, 'isHidden': False}
    hosts.append(legacy_host)
    unrelated = copy.deepcopy(legacy_host)
    unrelated.update(uuid='fixture-unrelated-host', nodes=['fixture-shared-node'])
    hosts.append(unrelated)
    squads = [{'uuid': 'fixture-base-squad', 'name': 'BASE',
               'inbounds': [{'uuid': x} for x in dict.fromkeys(
                   [p.OLD_INBOUND, *['fixture-source-' + n['id'] for n in p.NODES], 'fixture-unrelated-right'])]},
              {'uuid': BACKEND_SQUAD, 'name': 'BACKEND',
               'inbounds': [{'uuid': n['inbound']} for n in p.NODES]}]
    return {'nodes': nodes, 'hosts': hosts, 'profiles': profiles, 'squads': squads}


class FakeAPI:
    def __init__(self, before):
        self.data = copy.deepcopy(before)
        self.writes = []

    def __call__(self, method, path, body=None):
        if method != 'GET':
            self.writes.append((method, path, copy.deepcopy(body)))
        if path.startswith('/api/users/'):
            assert method == 'GET'
            return copy.deepcopy(SERVICE)
        if path == '/api/config-profiles/' and method == 'GET':
            return {'configProfiles': [{'uuid': k, 'name': 'fixture-' + k}
                                       for k in self.data['profiles']]}
        if path == '/api/config-profiles/' and method == 'POST':
            profile = {'uuid': CREATED['profile'], 'config': copy.deepcopy(body['config']),
                'inbounds': [{'uuid': CREATED['legacy'], 'tag': p.LEGACY_TAG}, *[
                    {'uuid': CREATED['inbounds'][n['id']], 'tag': 'vless-entry244-' + n['id']}
                    for n in p.NODES]]}
            self.data['profiles'][profile['uuid']] = profile
            return copy.deepcopy(profile)
        if path.startswith('/api/config-profiles/'):
            assert method == 'GET', 'Existing profiles must never be modified'
            return copy.deepcopy(self.data['profiles'][path.rsplit('/', 1)[-1]])
        for endpoint, collection in [('nodes', 'nodes'), ('hosts', 'hosts'), ('internal-squads', 'squads')]:
            base = '/api/' + endpoint + '/'
            if not path.startswith(base):
                continue
            if method == 'GET':
                if path != base:
                    return copy.deepcopy(next(x for x in self.data[collection] if x['uuid'] == path[len(base):]))
                values = copy.deepcopy(self.data[collection])
                return {'internalSquads': values} if collection == 'squads' else values
            assert method == 'PATCH' and path == base
            value = next(x for x in self.data[collection] if x['uuid'] == body['uuid'])
            updates = copy.deepcopy(body)
            if collection == 'nodes' and 'configProfile' in updates:
                updates['configProfile']['activeInbounds'] = [
                    {'uuid': x} for x in updates['configProfile']['activeInbounds']]
            if collection == 'squads' and 'inbounds' in updates:
                updates['inbounds'] = [{'uuid': x} for x in updates['inbounds']]
            value.update(updates)
            return copy.deepcopy(value)
        raise AssertionError('Unexpected API operation')


class PanelHarness(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.before = fixture()
        self.api = FakeAPI(self.before)
        self.state = {'before': copy.deepcopy(self.before), 'created': copy.deepcopy(CREATED),
            'old-probes': {'all_passed': True, 'timestamp': NOW},
            'installed-test': {'installed_xray_test_passed': True},
            'new-probes': {'all_passed': True, 'timestamp': NOW},
            'subscription-proof': {'all_passed': True, 'timestamp': NOW}}
        self.stack.enter_context(patch.object(p.prior, 'public_key', return_value='NOT_A_PUBLIC_KEY'))
        self.stack.enter_context(patch.object(p, 'read', side_effect=lambda k: copy.deepcopy(self.state[k])))
        self.stack.enter_context(patch.object(p, 'save', side_effect=lambda k, v: self.state.__setitem__(k, copy.deepcopy(v))))
        self.stack.enter_context(patch.object(p, 'exists', side_effect=lambda k: k in self.state))
        self.stack.enter_context(patch.object(p.prior, 'read', side_effect=lambda k: copy.deepcopy({
            'backend-user': SERVICE, 'backend-squad': {'uuid': BACKEND_SQUAD}}[k])))
        self.stack.enter_context(patch.object(p.time, 'time', return_value=NOW))
        self.command = self.stack.enter_context(patch.object(p.subprocess, 'run',
            side_effect=AssertionError('Unexpected subprocess: test must remain offline')))
        state_path = MagicMock()
        (state_path / 'before.json').read_bytes.side_effect = lambda: json.dumps(self.state['before'], sort_keys=True).encode()
        self.stack.enter_context(patch.object(p, 'STATE', state_path))
        self.state['before-checksum'] = {'sha256': hashlib.sha256(
            json.dumps(self.state['before'], sort_keys=True).encode()).hexdigest()}
        self.state['candidate'] = p.candidate(self.before, SERVICE)
        self.state['installed-test']['sha256'] = hashlib.sha256(
            json.dumps(self.state['candidate'], sort_keys=True).encode()).hexdigest()

    def stage(self):
        p.stage(self.api)

    def activated(self):
        self.stage()
        self.command.side_effect = None
        self.command.return_value = subprocess.CompletedProcess([], 0)
        p.activate(self.api)

    def published(self):
        self.activated()
        p.publish(self.api)

    def snapshot(self):
        self.state.pop('before', None)
        return p.snapshot(self.api)


class ScopeAndCandidateTests(PanelHarness):
    def test_exact_scope_constants(self):
        self.assertEqual(p.NODE, '560e38b3-6ee8-4f10-861e-e2f1eddd4caa')
        self.assertEqual(p.OLD_PROFILE, 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1')
        self.assertEqual(p.OLD_INBOUND, '41b6c310-32dd-4845-acc6-816ed48e2ff9')
        self.assertEqual(p.OLD_HOSTS, {'667c0682-bc72-43fa-b205-7a65068a2304'})
        self.assertEqual(p.SOURCE_PROFILE, '75174e4f-1572-493d-a30c-96651ab0e70d')
        self.assertEqual(p.ENTRY, '193.233.222.244')
        self.assertEqual(len(p.TARGET_HOSTS), 8)
        self.assertFalse(p.OLD_HOSTS & p.TARGET_HOSTS)
        self.assertEqual({n['ip'] for n in p.NODES},
                         {'217.60.68.182', '31.56.188.150', '94.183.255.82', '62.60.226.94'})
        self.assertTrue(all(len(n['hosts']) == 2 for n in p.NODES))

    def test_candidate_preserves_shared_profile_and_legacy_exactly(self):
        original = copy.deepcopy(self.before)
        config = p.candidate(self.before, SERVICE)
        self.assertEqual(self.before, original)
        expected = copy.deepcopy(original['profiles'][p.OLD_PROFILE]['config']['inbounds'][0])
        expected.update(tag=p.LEGACY_TAG, listen='127.0.0.1', port=15443)
        self.assertEqual(config['inbounds'][0], expected)
        self.assertEqual(config['outbounds'][:2], original['profiles'][p.OLD_PROFILE]['config']['outbounds'])
        self.assertEqual(len(config['inbounds']), 5)

    def test_preserves_all_four_published_reality_identities_and_loopback_target(self):
        config = self.state['candidate']
        for n, source in zip(p.NODES, self.before['profiles'][p.SOURCE_PROFILE]['config']['inbounds']):
            inbound = next(i for i in config['inbounds'] if i['tag'] == 'vless-entry244-' + n['id'])
            self.assertEqual((inbound['listen'], inbound['port']), ('127.0.0.1', n['port']))
            reality = inbound['streamSettings']['realitySettings']
            self.assertEqual(reality['target'], '127.0.0.1:9443')
            for key in ('privateKey', 'shortIds', 'serverNames'):
                self.assertEqual(reality[key], source['streamSettings']['realitySettings'][key])
            reality['shortIds'].append('FIXTURE_MUTATION')
            self.assertNotIn('FIXTURE_MUTATION', source['streamSettings']['realitySettings']['shortIds'])

    def test_routes_precede_all_ru_direct_rules(self):
        rules = self.state['candidate']['routing']['rules']
        direct = [i for i, r in enumerate(rules) if r.get('outboundTag') == 'DIRECT']
        for n in p.NODES:
            routes = [(i, r) for i, r in enumerate(rules) if 'vless-entry244-' + n['id'] in r.get('inboundTag', [])]
            self.assertEqual(len(routes), 1)
            self.assertLess(routes[0][0], min(direct))
            self.assertEqual(routes[0][1]['outboundTag'], 'exit-' + n['id'])
        self.assertFalse(any('fixture-old' in r.get('inboundTag', []) for r in rules))

    def test_backend_vless_loopback_and_strict_tls_or_reality(self):
        self.assertEqual({n['link'] for n in p.NODES}, {21443, 22443, 23443, 24443})
        for n in p.NODES:
            outbound = next(o for o in self.state['candidate']['outbounds'] if o['tag'] == 'exit-' + n['id'])
            self.assertEqual(outbound['protocol'], 'vless')
            target = outbound['settings']['vnext'][0]
            self.assertEqual((target['address'], target['port']), ('127.0.0.1', n['link']))
            self.assertEqual(target['users'][0]['id'], SERVICE['vlessUuid'])
            stream = outbound['streamSettings']
            if stream['security'] == 'tls':
                self.assertIs(stream['tlsSettings']['allowInsecure'], False)
                self.assertEqual(stream['tlsSettings']['serverName'], n['exit_sni'])
            else:
                self.assertEqual(stream['security'], 'reality')
                self.assertEqual(stream['realitySettings']['serverName'], n['exit_sni'])

    def test_legacy_host_changes_binding_only(self):
        host = next(h for h in self.before['hosts'] if h['uuid'] in p.OLD_HOSTS)
        self.assertEqual(p.legacy_host(host), {'inbound': {
            'configProfileUuid': CREATED['profile'], 'configProfileInboundUuid': CREATED['legacy']}})

    def test_target_mapping_preserves_hidden_status_and_fingerprint(self):
        for host in self.before['hosts']:
            if host['uuid'] not in p.TARGET_HOSTS:
                continue
            fields = p.target_host(host)
            self.assertNotIn('isHidden', fields)
            self.assertNotIn('remark', fields)
            self.assertEqual(fields['nodes'], [p.NODE])
            self.assertEqual(fields['fingerprint'], host['fingerprint'])


class PreflightSafetyTests(PanelHarness):
    def test_valid_snapshot_is_read_only_on_api(self):
        self.assertTrue(self.snapshot()['snapshot_verified'])
        self.assertFalse(self.api.writes)

    def test_snapshot_rejects_unhealthy_piter(self):
        self.api.data['nodes'][0]['isConnected'] = False
        with self.assertRaises(AssertionError):
            self.snapshot()

    def test_snapshot_rejects_missing_target_host(self):
        self.api.data['hosts'].pop(0)
        with self.assertRaises(AssertionError, msg='All eight source hosts must exist before snapshot'):
            self.snapshot()

    def test_snapshot_rejects_missing_test_host(self):
        self.api.data['hosts'] = [h for h in self.api.data['hosts'] if h['uuid'] not in p.OLD_HOSTS]
        with self.assertRaises(AssertionError, msg='Legacy TEST must be explicitly found'):
            self.snapshot()

    def test_snapshot_rejects_shared_or_rebound_target_host(self):
        self.api.data['hosts'][0]['nodes'] = [SOURCE_NODE, 'fixture-unrelated-node']
        with self.assertRaises(AssertionError, msg='Refuse to overwrite a shared source host'):
            self.snapshot()

    def test_snapshot_rejects_wrong_source_profile_binding(self):
        self.api.data['hosts'][0]['inbound']['configProfileUuid'] = p.OLD_PROFILE
        with self.assertRaises(AssertionError):
            self.snapshot()

    def test_snapshot_rejects_disconnected_foreign_exit(self):
        foreign = next(n for n in self.api.data['nodes'] if n['uuid'] == p.NODES[0]['node'])
        foreign['isConnected'] = False
        with self.assertRaises(AssertionError):
            self.snapshot()

    def test_candidate_rejects_duplicate_source_tag(self):
        source = self.before['profiles'][p.SOURCE_PROFILE]['config']['inbounds']
        source.append(copy.deepcopy(source[0]))
        with self.assertRaises(AssertionError, msg='Source frontend tags must be unique'):
            p.candidate(self.before, SERVICE)

    def test_stage_requires_installed_xray_test(self):
        self.state['installed-test']['installed_xray_test_passed'] = False
        with self.assertRaises(AssertionError):
            self.stage()
        self.assertFalse(self.api.writes)

    def test_stage_rejects_candidate_changed_after_xray_test(self):
        self.state['candidate']['inbounds'][0]['port'] = 16443
        with self.assertRaises(AssertionError, msg='Installed test digest must match staged candidate'):
            self.stage()
        self.assertFalse(self.api.writes)


class LifecycleTests(PanelHarness):
    def test_rights_are_copied_from_frontend208_not_foreign_inbounds(self):
        for n in p.NODES:
            source_only = {'uuid': 'fixture-customer', 'inbounds': [{'uuid': 'fixture-source-' + n['id']}]}
            self.assertEqual(p.additions(source_only, CREATED), [CREATED['inbounds'][n['id']]])
            foreign_only = {'uuid': 'fixture-customer', 'inbounds': [{'uuid': n['inbound']}]}
            expected = [CREATED['legacy']] if n['inbound'] == p.OLD_INBOUND else []
            self.assertEqual(p.additions(foreign_only, CREATED), expected)

    def test_backend_squad_is_excluded_even_with_frontend_and_legacy_rights(self):
        squad = {'uuid': BACKEND_SQUAD, 'inbounds': [{'uuid': identifier} for identifier in
            [p.OLD_INBOUND, *['fixture-source-' + n['id'] for n in p.NODES]]]}
        self.assertEqual(p.additions(squad, CREATED), [])

    def test_stage_unions_current_rights_and_excludes_backend(self):
        squad = self.api.data['squads'][0]
        squad['inbounds'].append({'uuid': 'fixture-concurrent-right'})
        original = copy.deepcopy(self.api.data)
        self.stage()
        rights = set(p.ids(squad))
        self.assertTrue(set(p.ids(original['squads'][0])) <= rights)
        self.assertTrue({CREATED['legacy'], *CREATED['inbounds'].values()} <= rights)
        self.assertEqual(self.api.data['squads'][1], original['squads'][1])
        self.assertEqual(self.api.data['nodes'], original['nodes'])
        self.assertEqual(self.api.data['hosts'], original['hosts'])
        for identifier, profile in original['profiles'].items():
            self.assertEqual(self.api.data['profiles'][identifier], profile)

    def test_stage_refuses_removed_prior_rights(self):
        self.api.data['squads'][0]['inbounds'] = []
        with self.assertRaises(AssertionError):
            self.stage()
        self.assertFalse(any(path == '/api/internal-squads/' for _, path, _ in self.api.writes))

    def test_activate_changes_only_piter_and_test_binding(self):
        self.activated()
        changes = [(path, body['uuid']) for method, path, body in self.api.writes if method == 'PATCH']
        self.assertEqual([x for x in changes if x[0] == '/api/nodes/'], [('/api/nodes/', p.NODE)])
        self.assertEqual({uuid for path, uuid in changes if path == '/api/hosts/'}, p.OLD_HOSTS)
        self.assertTrue(p.verify(self.api)['old_rights_preserved'])

    def test_activate_rejects_piter_health_drift_before_any_write(self):
        self.stage()
        self.api.writes.clear()
        self.api.data['nodes'][0]['isDisabled'] = True
        self.command.side_effect = None
        self.command.return_value = subprocess.CompletedProcess([], 0)
        with self.assertRaises(AssertionError):
            p.activate(self.api)
        self.assertFalse(self.api.writes)

    def test_publish_migrates_exactly_eight_hosts_and_keeps_shared_profile(self):
        self.activated()
        self.api.writes.clear()
        p.publish(self.api)
        self.assertEqual(len(self.api.writes), 8)
        self.assertEqual({body['uuid'] for _, path, body in self.api.writes if path == '/api/hosts/'}, p.TARGET_HOSTS)
        self.assertEqual(self.api.data['profiles'][p.OLD_PROFILE], self.before['profiles'][p.OLD_PROFILE])
        self.assertTrue(p.verify(self.api, True)['unrelated_nodes_hosts_and_profiles_unchanged'])

    def test_publish_rejects_expired_proof(self):
        self.state['new-probes']['timestamp'] = NOW - 1801
        with self.assertRaises(AssertionError):
            p.publish(self.api)
        self.assertFalse(self.api.writes)

    def test_publish_rejects_future_proof(self):
        self.activated()
        self.api.writes.clear()
        self.state['new-probes']['timestamp'] = NOW + 3600
        with self.assertRaises(AssertionError):
            p.publish(self.api)
        self.assertFalse(self.api.writes)

    def test_publish_refuses_later_host_edit(self):
        self.activated()
        self.api.writes.clear()
        self.api.data['hosts'][0]['remark'] = 'fixture-later-edit'
        with self.assertRaises(AssertionError):
            p.publish(self.api)
        self.assertFalse(self.api.writes)

    def test_rollback_restores_only_scoped_hosts_and_piter(self):
        self.published()
        self.api.writes.clear()
        self.assertTrue(p.rollback(self.api)['old_node_and_host_bindings_restored'])
        self.assertEqual(self.api.data['hosts'], self.before['hosts'])
        self.assertEqual(self.api.data['nodes'], self.before['nodes'])
        self.assertTrue(all(path in ('/api/hosts/', '/api/nodes/') for _, path, _ in self.api.writes))

    def test_rollback_rejects_later_target_host_edit(self):
        self.published()
        self.api.data['hosts'][0]['remark'] = 'fixture-later-edit'
        with self.assertRaises(AssertionError):
            p.rollback(self.api)

    def test_rollback_rejects_later_node_inbounds_without_partial_restore(self):
        self.published()
        self.api.writes.clear()
        self.api.data['nodes'][0]['configProfile']['activeInbounds'].append({'uuid': 'fixture-later-inbound'})
        with self.assertRaises(AssertionError, msg='Rollback must not discard later node edits'):
            p.rollback(self.api)
        self.assertFalse(self.api.writes)

    def test_rollback_preflights_node_before_restoring_dns_or_hosts(self):
        import dns244
        self.published()
        self.api.writes.clear()
        self.state['dns-' + p.NODES[0]['id']] = {'before': {'id': 'fixture-dns-record'}}
        self.api.data['nodes'][0]['configProfile']['activeConfigProfileUuid'] = 'fixture-later-profile'
        with patch.object(dns244, 'rollback') as dns_rollback:
            with self.assertRaises(AssertionError):
                p.rollback(self.api)
        dns_rollback.assert_not_called()
        self.assertFalse(self.api.writes)

    def test_finish_rejects_already_running_rollback_service(self):
        self.published()
        self.command.reset_mock()
        def systemctl(args, **kwargs):
            # Timer has elapsed, but its associated rollback service is running.
            code = 0 if args[1] != 'is-active' or args[-1].endswith('.service') else 3
            return subprocess.CompletedProcess(args, code)
        self.command.side_effect = systemctl
        with self.assertRaises((AssertionError, RuntimeError), msg='A running rollback may undo finish after verify'):
            p.finish(self.api)
        self.assertNotIn('finished', self.state)

    def test_finish_does_not_treat_systemctl_error_as_inactive(self):
        self.published()
        self.command.side_effect = lambda args, **kwargs: subprocess.CompletedProcess(
            args, 1 if args[1] == 'is-active' else 0)
        with self.assertRaises((AssertionError, RuntimeError)):
            p.finish(self.api)
        self.assertNotIn('finished', self.state)


class DNSPreflightTests(unittest.TestCase):
    """All Cloudflare calls, historical ownership files and state are in memory."""
    def setUp(self):
        import dns244
        self.dns = dns244
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.records = {'fixture-dns-' + n['id']: {
            'id': 'fixture-dns-' + n['id'], 'name': n['domain'], 'type': 'A',
            'content': dns244.OLD_ENTRY, 'ttl': 300, 'proxied': False}
            for n in dns244.NODES}
        self.original = copy.deepcopy(self.records)
        self.state = {'published': {'timestamp': NOW},
                      'new-probes': {'all_passed': True, 'timestamp': NOW}}
        self.events = []
        self.failed_get = None
        self.stack.enter_context(patch.object(dns244, 'client', return_value=self.request))
        self.stack.enter_context(patch.object(dns244, 'read', side_effect=lambda name: copy.deepcopy(self.state[name])))
        self.stack.enter_context(patch.object(dns244, 'exists', side_effect=lambda name: name in self.state))
        self.stack.enter_context(patch.object(dns244, 'save', side_effect=self.save))
        self.stack.enter_context(patch.object(dns244.time, 'time', return_value=NOW))
        owners = {'dns-' + n['id'] + '.json': {'created_id': 'fixture-dns-' + n['id']}
                  for n in dns244.NODES}
        ownership_root = MagicMock()
        ownership_root.__truediv__.side_effect = lambda name: MagicMock(
            read_text=lambda: json.dumps(owners[name]))
        self.stack.enter_context(patch.object(dns244, 'Path', return_value=ownership_root))
        self.stack.enter_context(patch.object(dns244.urllib.request, 'urlopen',
            side_effect=AssertionError('DNS tests must never access the network')))

    def save(self, name, value):
        self.events.append(('SAVE', name))
        self.state[name] = copy.deepcopy(value)

    def request(self, method, suffix='', body=None):
        if suffix.startswith('?'):
            self.assertEqual(method, 'GET')
            query = self.dns.urllib.parse.parse_qs(suffix[1:])
            identifier = next('fixture-dns-' + n['id'] for n in self.dns.NODES
                              if n['domain'] == query['name'][0])
        else:
            identifier = suffix.removeprefix('/')
        self.events.append((method, identifier))
        if method == 'GET':
            if identifier == self.failed_get:
                raise RuntimeError('Fixture DNS read failed')
            row = copy.deepcopy(self.records[identifier])
            return [row] if suffix.startswith('?') else row
        self.assertEqual(method, 'PATCH')
        self.records[identifier].update(copy.deepcopy(body))
        return copy.deepcopy(self.records[identifier])

    def prepare_rollback(self):
        for n in self.dns.NODES:
            identifier = 'fixture-dns-' + n['id']
            self.state['dns-' + n['id']] = {
                'before': copy.deepcopy(self.original[identifier]), 'wanted': self.dns.ENTRY}
            self.records[identifier]['content'] = self.dns.ENTRY

    def assert_all_four_preflight_before_first_write(self):
        first_write = next(i for i, event in enumerate(self.events) if event[0] != 'GET')
        reads = {identifier for method, identifier in self.events[:first_write] if method == 'GET'}
        self.assertEqual(reads, set(self.original))

    def assert_no_writes(self):
        self.assertTrue(all(method == 'GET' for method, _ in self.events),
                        'Preflight failure must precede API writes and saved intents')

    def test_move_preflights_all_four_before_state_or_api_write(self):
        result = self.dns.move()
        self.assertTrue(result['dns_verified'])
        self.assert_all_four_preflight_before_first_write()
        self.assertEqual(sum(method == 'PATCH' for method, _ in self.events), 4)
        self.assertTrue(all(row['content'] == self.dns.ENTRY for row in self.records.values()))

    def test_move_invalid_fourth_record_never_partially_moves_first_three(self):
        identifier = 'fixture-dns-' + self.dns.NODES[-1]['id']
        for field, value in [('id', 'fixture-unowned'), ('type', 'AAAA'),
                             ('proxied', True), ('content', '192.0.2.50'), ('ttl', 600)]:
            with self.subTest(field=field):
                self.records = copy.deepcopy(self.original)
                self.events.clear()
                self.records[identifier][field] = value
                with self.assertRaises((AssertionError, RuntimeError)):
                    self.dns.move()
                self.assert_no_writes()

    def test_move_fourth_read_error_never_writes(self):
        self.failed_get = 'fixture-dns-' + self.dns.NODES[-1]['id']
        with self.assertRaises(RuntimeError):
            self.dns.move()
        self.assert_no_writes()

    def test_move_resume_checks_all_four_and_only_patches_unmoved_records(self):
        self.prepare_rollback()
        pending_ids = {'fixture-dns-' + n['id'] for n in self.dns.NODES[2:]}
        for identifier in pending_ids:
            self.records[identifier]['content'] = self.dns.OLD_ENTRY
        self.dns.move()
        self.assert_all_four_preflight_before_first_write()
        self.assertEqual({identifier for method, identifier in self.events if method == 'PATCH'}, pending_ids)

    def test_rollback_preflights_all_four_before_first_patch(self):
        self.prepare_rollback()
        self.assertEqual(self.dns.rollback()['dns_records_restored'], 4)
        self.assert_all_four_preflight_before_first_write()
        self.assertEqual(self.records, self.original)

    def test_rollback_invalid_fourth_record_never_partially_restores_first_three(self):
        identifier = 'fixture-dns-' + self.dns.NODES[-1]['id']
        for field, value in [('name', 'fixture-later-edit.invalid'), ('type', 'AAAA'),
                             ('proxied', True), ('content', '192.0.2.50'), ('ttl', 600)]:
            with self.subTest(field=field):
                self.records = copy.deepcopy(self.original)
                self.prepare_rollback()
                self.events.clear()
                self.records[identifier][field] = value
                with self.assertRaises((AssertionError, RuntimeError)):
                    self.dns.rollback()
                self.assert_no_writes()

    def test_rollback_fourth_read_error_never_writes(self):
        self.prepare_rollback()
        self.failed_get = 'fixture-dns-' + self.dns.NODES[-1]['id']
        with self.assertRaises(RuntimeError):
            self.dns.rollback()
        self.assert_no_writes()

    def test_rollback_resume_checks_all_four_and_only_patches_unrestored_records(self):
        self.prepare_rollback()
        pending_ids = {'fixture-dns-' + n['id'] for n in self.dns.NODES[2:]}
        for identifier in set(self.original) - pending_ids:
            self.records[identifier]['content'] = self.dns.OLD_ENTRY
        self.dns.rollback()
        self.assert_all_four_preflight_before_first_write()
        self.assertEqual({identifier for method, identifier in self.events if method == 'PATCH'}, pending_ids)
        self.assertEqual(self.records, self.original)


class CommonStateTests(unittest.TestCase):
    def test_atomic_save_roundtrip_utf8_without_temp_residue(self):
        with tempfile.TemporaryDirectory(prefix='ham-entry244-test-') as tmp:
            state = Path(tmp) / 'private-state'
            with patch.object(common244, 'STATE', state):
                common244.save('proof', {'label': 'только тест', 'passed': True})
                self.assertEqual(common244.read('proof'), {'label': 'только тест', 'passed': True})
                self.assertTrue(common244.exists('proof'))
                self.assertFalse((state / 'proof.tmp').exists())

    def test_command_error_does_not_expose_captured_output(self):
        result = subprocess.CompletedProcess(['fixture'], 2, 'FIXTURE_STDOUT_SENTINEL', 'FIXTURE_STDERR_SENTINEL')
        with patch.object(common244.subprocess, 'run', return_value=result), patch.object(common244, 'save'):
            with self.assertRaises(RuntimeError) as raised:
                common244.run('fixture')
        self.assertNotIn('SENTINEL', str(raised.exception))


class CertificateGateTests(unittest.TestCase):
    def test_certificate_validation_helper_is_available(self):
        import cert244
        self.assertTrue(callable(getattr(cert244, 'certificate_details', None)),
                        'node244.certificate imports cert244.certificate_details')

    def test_failed_tls_validation_never_saves_success_certificate_marker(self):
        # node244.arm() accepts exists('certificate'); a failed handshake must
        # not create this marker. No real filesystem, socket or shell calls.
        import cert244
        saved = {}
        fake_site = MagicMock()
        fake_site.read_text.side_effect = ['fixture-http', 'fixture-tls']
        with patch.object(node244, 'SITE', fake_site), \
             patch.object(node244, 'exists', side_effect=lambda name: name in ('prepared', 'imported-certificate')), \
             patch.object(node244, 'read', return_value={'http': 'fixture-http', 'site_sha256': 'fixture-digest'}), \
             patch.object(node244, 'save', side_effect=lambda name, value: saved.__setitem__(name, value)), \
             patch.object(node244, 'write') as write, \
             patch.object(node244, 'run', return_value=p.ENTRY + '/32'), \
             patch.object(node244, 'digest', return_value='fixture-digest'), \
             patch.object(node244, 'vpn_identity', return_value='fixture-container'), \
             patch.object(node244, 'public_443', return_value='fixture-listener'), \
             patch.object(node244, 'site_config', return_value='fixture-tls'), \
             patch.object(cert244, 'certificate_details', return_value={'fixture': True}, create=True), \
             patch.object(node244, 'local_tls', side_effect=OSError('fixture handshake failure')):
            with self.assertRaises(OSError):
                node244.certificate()
        self.assertNotIn('certificate', saved, 'Certificate success marker precedes verified TLS1.3/h2')
        self.assertEqual([call.args[1] for call in write.call_args_list], ['fixture-tls', 'fixture-http'])


class TransportTests(unittest.TestCase):
    def setUp(self):
        # Loading the adapter must not change other test modules' transport.
        original = transport.ssh
        spec = importlib.util.spec_from_file_location('fixture_transport244', Path(__file__).with_name('transport244.py'))
        self.adapter = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(self.adapter)
        finally:
            transport.ssh = original

    def test_strict_entry_ssh_identity(self):
        args = self.adapter.ssh('entry')
        self.assertEqual(args[-1], 'root@193.233.222.244')
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'UpdateHostKeys=no', 'IdentitiesOnly=yes'):
            self.assertIn(option, args)
        self.assertEqual(Path(args[args.index('-i') + 1]), Path.home() / '.ssh/hamvpn-panel')

    def test_panel_alias_and_foreign_exits_unchanged(self):
        self.assertEqual(self.adapter.ssh('panel'), self.adapter.original_ssh('panel'))
        self.assertEqual(self.adapter.ssh('panel')[-1], 'hamvpn-panel-via-jump')
        for n in p.NODES:
            self.assertEqual(self.adapter.ssh(n['id'])[-1], 'root@' + n['ip'])

    def test_release_refuses_commit_not_on_origin_main_before_remote(self):
        with patch.object(transport.subprocess, 'check_output', side_effect=['a' * 40, 'b' * 40]), \
             patch.object(transport, 'remote') as remote:
            with self.assertRaises(AssertionError):
                transport.release('entry', 'fixture-revision')
        remote.assert_not_called()

    def test_run_refuses_unpublished_commit_before_remote(self):
        argv = ['transport244.py', 'entry', 'run', '--revision', 'fixture-unpublished',
                '--script', 'panel244.py', '--args', 'activate']
        with patch.object(transport.sys, 'argv', argv), \
             patch.object(transport.subprocess, 'check_output', side_effect=['a' * 40, 'b' * 40]), \
             patch.object(transport, 'remote', return_value=subprocess.CompletedProcess([], 0, b'', b'')) as remote:
            with self.assertRaises(AssertionError, msg='run must verify GitHub state just like release'):
                transport.main()
        remote.assert_not_called()

    def test_checked_does_not_print_remote_secret_sentinel(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            with self.assertRaises(RuntimeError):
                transport.checked(subprocess.CompletedProcess([], 1, b'', b'FIXTURE_SECRET_SENTINEL'))
        self.assertNotIn('FIXTURE_SECRET_SENTINEL', stream.getvalue())


if __name__ == '__main__':
    unittest.main()
