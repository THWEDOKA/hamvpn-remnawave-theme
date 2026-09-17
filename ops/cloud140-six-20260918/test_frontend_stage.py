"""Offline frontend API/proof/rollback simulations; never contact production."""

import base64
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import frontend_stage as f
from test_exit_stage import Store, Timer, API
import test_exit_stage as exit_fixture
from test_preflight import SECRET


class FrontStore(Store):
    def __init__(self, route_id, registry=None):
        super().__init__()
        self.route_id = route_id
        self.registry = registry if registry is not None else {}
        self.registry[route_id] = self

    def serial(self):
        for route_id, store in self.registry.items():
            if route_id == self.route_id or not store.data: continue
            value = store.data.get('operation', {})
            f.require('finished' in value or 'rolled_back' in value, 'Another route unfinished')


class EntryAPI(API):
    def __call__(self, method, path, body=None):
        if method == 'GET' and path.startswith('/api/subscriptions/by-uuid/'):
            self.calls.append((method, path, None))
            return dict(subscriptionUrl='https://subscription.invalid/PRIVATE-FIXTURE-URL')
        before = deepcopy(self.profiles.get(body.get('uuid'), {})) if method == 'PATCH' and path == '/api/config-profiles/' else None
        try:
            return super().__call__(method, path, body)
        finally:
            if before is not None and self.profiles[body['uuid']]['config'] == body['config']:
                current = self.profiles[body['uuid']]
                old = f.c.metadata(before)
                current['inbounds'] = [dict(tag=value['tag'], uuid=old.get(value['tag'], 'front-meta-' + value['tag']))
                    for value in current['config']['inbounds']]


class FrontendTests(unittest.TestCase):
    def setUp(self): self.init('pl')

    def init(self, route_id):
        self.exit = exit_fixture.CoordinatorTests(); self.exit.init(route_id)
        self.route_id = route_id
        fixture = self.exit.fixture
        for host in fixture.hosts.values():
            host.update(host=None, sni='example.com', viewPosition=4)
        for host in self.exit.baseline.data['before']['hosts']:
            host.update(host=None, sni='example.com', viewPosition=4)
        entry = fixture.profiles['entry-profile']
        first = entry['config']['inbounds'][0]; first.update(port=11443, listen='127.0.0.1')
        for port in (12443, 13443, 14443):
            previous = deepcopy(first); previous.update(tag='entry-legacy-' + str(port), port=port)
            entry['config']['inbounds'].append(previous)
            entry['inbounds'].append(dict(tag=previous['tag'], uuid='entry-legacy-inbound-' + str(port)))
        second = deepcopy(first); second.update(tag='entry-de245', port=18444)
        entry['config']['inbounds'].append(second)
        entry['inbounds'].append(dict(tag='entry-de245', uuid='entry-de245-inbound'))
        fixture.nodes[f.p.ENTRY_ID]['configProfile']['activeInbounds'] = deepcopy(entry['inbounds'])
        # Existing owned limited probe account, not a production customer.
        user = fixture.account()
        fixture.users[user['uuid']]['vlessUuid'] = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
        self.exit.apply()
        self.exit.worker.accept_backend(route_id, self.exit.proof('backend'))
        self.exit.worker.finish(route_id)
        self.exit_record = self.exit.store.get('operation')
        self.core = self.exit.worker
        self.api = EntryAPI.__new__(EntryAPI)
        self.api.__dict__ = self.exit.api.__dict__
        self.core.api = self.api
        self.store, self.timer = FrontStore(route_id), Timer()
        self.api.store, self.api.timer = self.store, self.timer
        self.worker = f.Frontend(self.api, self.store, self.core, self.timer, self.exit.baseline,
            clock=lambda: self.exit.now, identity_factory=lambda: dict(
                privateKey=base64.urlsafe_b64encode(bytes([73]) * 32).decode().rstrip('='), shortIds=['af12']),
            subscription_fetch=self.subscription_fetch)
        self.api.writes.clear(); self.api.calls.clear()
        self.subscription_override = None
        self.fetch_calls = []

    def inputs(self):
        now = self.exit.now
        value = dict(runtime=dict(id='entry', node=f.p.ENTRY_ID, ip=f.p.ENTRY, timestamp=now,
            port=f.PORTS[self.route_id], port_free=True, namespace_verified=True, firewall_ready=True,
            legacy443listening_nginx_verified=True, xray_version='26.7.28'),
            site=dict(entry=f.p.ENTRY, timestamp=now, loopback_port=9444, chain_verified=True,
                certificate_valid=True, dns_verified=True, checks=[dict(sni=d, tls='TLSv1.3', alpn='h2') for d in sorted(f.DOMAINS)],
                https_sites=[dict(sni=d, status=200, sha256='c' * 64) for d in sorted(f.DOMAINS)],
                renewal_dry_run_passed=True, renewal_performed_at=now - 100, deploy_hook=True, timer_enabled=True, timer_active=True))
        if f.p.AUTOS[self.route_id]: value['auto_remark'] = 'EXISTING AUTO GROUP'
        return value

    def legacy_request(self):
        def wire(port):
            return dict(protocol='vless', settings=dict(vnext=[dict(address=f.p.ENTRY, port=port,
                users=[dict(id='bbbbbbbb-cccc-4ddd-8eee-ffffffffffff', encryption='none', flow='xtls-rprx-vision')])]),
                streamSettings=dict(network='raw', security='reality', realitySettings=dict(
                    serverName='old.example', publicKey='fixture-public-key', shortId='ab', fingerprint='chrome')))
        return dict(items=[dict(id='legacy-' + str(port), client='xray', wire=wire(port), expected_egress='196.251.107.245')
                           for port in (443, 18444)])

    def proof(self, phase, request=None):
        record = self.store.get('operation')
        result = dict(sha256=record['sha256'], timestamp=self.exit.now)
        if phase == 'installed':
            return dict(**result, id='entry', node=f.p.ENTRY_ID, ip=f.p.ENTRY,
                tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.7.28')])
        request = request or record['requests'][phase]['request']
        result.update(request_sha256=request['request_sha256'], tests=[dict(id=item['id'], client=item['client'],
            wire_sha256=item['wire_sha256'], passed=True, authenticated=True, http_code=204,
            exit_ip=item['expected_egress'], returncodes=[0, 0]) for item in request['items']])
        return result

    def prepare(self):
        result = self.worker.prepare(self.route_id, self.inputs())
        self.worker.accept(self.route_id, 'installed', self.proof('installed'))
        request = self.worker.export_baseline(self.route_id, self.legacy_request())
        self.worker.accept(self.route_id, 'baseline', self.proof('baseline', request))
        return result

    def stage(self):
        self.prepare(); return self.worker.stage(self.route_id)

    def publish(self):
        self.stage()
        request = self.worker.export_public(self.route_id)
        self.worker.accept(self.route_id, 'public', self.proof('public', request))
        return self.worker.publish(self.route_id)

    def subscription_fetch(self, url, headers, kind):
        self.fetch_calls.append((url, deepcopy(headers), kind))
        before, plan, _ = self.worker._load(self.route_id)
        user = self.worker._user(before)['vlessUuid']
        happ, proxies = [], []
        for host in before['hosts']:
            xray = self.worker._client(plan, user, host, 'xray'); xray['tag'] = 'arbitrary-local-tag'
            happ.append(dict(remarks=plan['auto_remark'] if host['isHidden'] else host['remark'], outbounds=[xray]))
            if not host['isHidden']:
                proxies.append(self.worker._client(plan, user, host, 'mihomo'))
        value = happ if kind == 'happ' else dict(proxies=proxies)
        if self.subscription_override: self.subscription_override(kind, value)
        return value

    def test_prepare_snapshots_current_profile_and_no_mutations(self):
        original = deepcopy(self.api.profiles['entry-profile'])
        self.prepare()
        self.assertFalse(self.api.writes)
        before, plan = self.store.get('before'), self.store.get('plan')
        self.assertEqual(before['profile'], original)
        self.assertEqual(plan['candidate']['inbounds'][:-1], original['config']['inbounds'])
        self.assertEqual(plan['candidate']['outbounds'][:-1], original['config']['outbounds'])
        self.assertEqual(plan['candidate']['inbounds'][-1]['port'], 18446)
        self.assertEqual(plan['candidate']['inbounds'][-1]['streamSettings']['realitySettings']['minClientVer'], '1.8.2')

    def test_only_four_approved_routes_have_fixed_frontend_ports(self):
        self.assertEqual(f.PORTS, dict(at=18445, pl=18446, cz=18447, gbpower=18448))
        for key in ('gb', 'us1', 'kz2'):
            with self.assertRaises(f.c.SafetyError): self.worker.prepare(key, self.inputs())
        self.assertFalse(self.api.writes)

    def test_actual_nginx443_architecture_accepts_no_xray443_and_preserves_all_five(self):
        profile = deepcopy(self.api.profiles['entry-profile'])
        self.assertNotIn(443, {i['port'] for i in profile['config']['inbounds']})
        self.assertEqual({i['port'] for i in profile['config']['inbounds']}, f.LEGACY_PORTS)
        self.stage()
        self.assertEqual(self.api.profiles['entry-profile']['config']['inbounds'][:-1], profile['config']['inbounds'])
        baseline = self.store.get('operation')['requests']['baseline']['request']['items']
        self.assertEqual({f.wire_endpoint(i['client'], i['wire'])[1] for i in baseline}, {443, 18444})

    def test_actual_nginx443_requires_runtime_and_every_old_loopback_active_unchanged(self):
        for change in ('runtime', 'missing', 'public-bind', 'inactive', 'duplicate'):
            self.init('pl'); request = self.inputs()
            profile = self.api.profiles['entry-profile']
            if change == 'runtime': request['runtime'].pop('legacy443listening_nginx_verified')
            if change == 'missing': profile['config']['inbounds'].pop(1)
            if change == 'public-bind': profile['config']['inbounds'][1]['listen'] = '0.0.0.0'
            if change == 'inactive': self.api.nodes[f.p.ENTRY_ID]['configProfile']['activeInbounds'].pop(1)
            if change == 'duplicate': profile['config']['inbounds'].append(deepcopy(profile['config']['inbounds'][1]))
            with self.assertRaises(f.c.SafetyError): self.worker.prepare(self.route_id, request)
            self.assertFalse(self.api.writes)
        self.init('pl'); self.prepare()
        self.api.profiles['entry-profile']['config']['inbounds'][1]['port'] = 12444
        with self.assertRaises(f.c.SafetyError): self.worker.stage(self.route_id)
        self.assertFalse(self.api.writes)

    def test_unfinished_other_route_prevents_preparation(self):
        other = FrontStore('at', self.store.registry); other.data['operation'] = {'staged': True}
        with self.assertRaises(f.c.SafetyError): self.prepare()
        self.assertFalse(self.api.writes)
        other.data['operation']['finished'] = self.exit.now
        self.prepare()

    def test_backend_must_be_finished_and_profile_identity_current(self):
        self.exit.store.data['operation'].pop('finished')
        with self.assertRaises(f.c.SafetyError): self.prepare()
        self.assertFalse(self.api.writes)

    def test_previous_finished_route_survives_next_route_publication_and_rollback(self):
        # Model a previously finished CZ frontend in the CURRENT dedicated
        # profile, not in the original six-exit preflight snapshot.
        previous = FrontStore('cz', self.store.registry)
        previous.data['operation'] = dict(id='cz', finished=self.exit.now - 100)
        profile = self.api.profiles['entry-profile']
        front = deepcopy(profile['config']['inbounds'][0])
        front.update(tag='previous-cz-front', port=18447)
        profile['config']['inbounds'].append(front)
        profile['config']['outbounds'].append(dict(tag='previous-cz-backend', protocol='freedom'))
        profile['config'].setdefault('routing', {}).setdefault('rules', []).append(
            dict(type='field', inboundTag=['previous-cz-front'], outboundTag='previous-cz-backend'))
        profile['inbounds'].append(dict(tag='previous-cz-front', uuid='previous-cz-inbound'))
        self.api.nodes[f.p.ENTRY_ID]['configProfile']['activeInbounds'].append(dict(uuid='previous-cz-inbound'))
        for squad in self.api.squads.values():
            if squad['name'] in f.p.CUSTOMER_NAMES:
                squad['inbounds'].append(dict(uuid='previous-cz-inbound'))
        for hid in (f.c.target('cz')['host'], f.p.AUTOS['cz']):
            self.api.hosts[hid].update(nodes=[f.p.ENTRY_ID], address=f.model.DOMAINS['cz'], port=18447,
                inbound=dict(configProfileUuid='entry-profile', configProfileInboundUuid='previous-cz-inbound'))
        config, metadata = deepcopy(profile['config']), f.c.metadata(profile)
        previous_hosts = {hid: deepcopy(self.api.hosts[hid]) for hid in (f.c.target('cz')['host'], f.p.AUTOS['cz'])}
        self.publish()
        self.assertEqual(self.store.get('before')['profile']['config'], config)
        self.assertEqual(profile['config']['inbounds'][:-1], config['inbounds'])
        self.worker.rollback(self.route_id)
        self.assertEqual(profile['config'], config)
        self.assertEqual(f.c.metadata(profile), metadata)
        for hid, host in previous_hosts.items(): self.assertEqual(self.api.hosts[hid], host)
        for squad in self.api.squads.values():
            if squad['name'] in f.p.CUSTOMER_NAMES:
                self.assertIn('previous-cz-inbound', f.c.ids(squad['inbounds']))
        self.assertEqual(previous.data['operation'], dict(id='cz', finished=self.exit.now - 100))

    def test_corrupted_owned_host_intent_blocks_rollback_before_any_write(self):
        self.publish()
        self.store.data['operation']['host_intents'][f.c.target(self.route_id)['host']] = '0' * 64
        count = len(self.api.writes)
        with self.assertRaises(f.c.SafetyError): self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count)

    def test_site_runtime_and_renewal_constraints_fail_before_writes(self):
        for change in (lambda v: v['site'].update(loopback_port=9443),
                       lambda v: v['site'].update(dns_verified=False), lambda v: v['site']['checks'].pop(),
                       lambda v: v['site']['https_sites'][0].update(status=301),
                       lambda v: v['site'].update(renewal_performed_at=self.exit.now + 1),
                       lambda v: v['site'].update(renewal_dry_run_passed=False),
                       lambda v: v['runtime'].update(port_free=False), lambda v: v['runtime'].update(port=443),
                       lambda v: v['runtime'].update(namespace_verified=False)):
            value = self.inputs(); change(value)
            with self.assertRaises(f.c.SafetyError): self.worker.prepare(self.route_id, value)
        self.assertFalse(self.api.writes)

    def test_cannot_modify_shared_entry_profile_or_missing_legacy_endpoint(self):
        old = deepcopy(self.api.nodes['other-consumer']['configProfile'])
        self.api.nodes['other-consumer']['configProfile'] = deepcopy(self.api.nodes[f.p.ENTRY_ID]['configProfile'])
        with self.assertRaises(f.c.SafetyError): self.prepare()
        self.api.nodes['other-consumer']['configProfile'] = old
        self.api.profiles['entry-profile']['config']['inbounds'][0]['port'] = 80
        with self.assertRaises(f.c.SafetyError): self.prepare()
        self.assertFalse(self.api.writes)

    def test_stage_only_entry_own_delta_no_hosts_or_exits_mutated(self):
        old_nodes, old_hosts, old_profiles = deepcopy(self.api.nodes), deepcopy(self.api.hosts), deepcopy(self.api.profiles)
        self.stage()
        self.assertEqual(self.timer.starts, [self.route_id])
        self.assertEqual(self.api.hosts, old_hosts)
        for nid, node in old_nodes.items():
            if nid != f.p.ENTRY_ID: self.assertEqual(self.api.nodes[nid], node)
        for pid, profile in old_profiles.items():
            if pid != 'entry-profile': self.assertEqual(self.api.profiles[pid], profile)
        self.assertEqual(self.exit.store.get('operation'), self.exit_record)
        record = self.store.get('operation')
        self.assertEqual(set(record['grants']), set(self.store.get('before')['customers']))
        self.assertNotIn(record['front'], f.c.ids(self.api.squads[self.exit_record['objects']['squad']]['inbounds']))

    def test_stage_requires_all_proofs_and_failed_recheck_revokes_old_success(self):
        self.prepare()
        proof = self.proof('installed'); proof['tests'][0]['returncode'] = 1
        with self.assertRaises(f.c.SafetyError): self.worker.accept(self.route_id, 'installed', proof)
        with self.assertRaises(f.c.SafetyError): self.worker.stage(self.route_id)
        self.assertFalse(self.api.writes)

    def test_baseline_exact_443_and_18444_and_no_full_random_listener_config(self):
        self.worker.prepare(self.route_id, self.inputs())
        for change in (lambda q: q['items'].pop(),
            lambda q: q['items'][0]['wire']['settings']['vnext'][0].update(address='127.0.0.1'),
            lambda q: q['items'][0]['wire']['settings']['vnext'][0].update(port=9999),
            lambda q: q['items'][0].update(wire={'inbounds': [], 'outbounds': []})):
            request = self.legacy_request(); change(request)
            with self.assertRaises(f.c.SafetyError): self.worker.export_baseline(self.route_id, request)

    def test_candidate_request_covers_both_cores_main_auto_and_legacy(self):
        self.stage()
        request = self.worker.export_public(self.route_id)
        new = [i for i in request['items'] if not i['legacy']]
        self.assertEqual({i['id'] for i in new}, {'pl-main-xray', 'pl-main-mihomo', 'pl-auto-xray', 'pl-auto-mihomo'})
        self.assertEqual(len(request['items']), 6)
        self.assertEqual({f.wire_endpoint(i['client'], i['wire'])[:2] for i in new}, {(f.model.DOMAINS['pl'], 18446)})
        self.assertEqual({i['wire_sha256'] for i in request['items'] if i['legacy']},
                         {i['wire_sha256'] for i in self.store.get('operation')['requests']['baseline']['request']['items']})

    def test_publish_requires_every_core_host_case_204_and_correct_egress(self):
        self.stage(); request = self.worker.export_public(self.route_id)
        for change in (lambda p: p['tests'].pop(), lambda p: p.update(timestamp=self.exit.now + 1),
                       lambda p: p.update(request_sha256='0' * 64),
                       lambda p: p['tests'][0].update(wire_sha256='0' * 64),
                       lambda p: p['tests'][0].update(passed=False, exit_ip=None, returncodes=[0, 28])):
            proof = self.proof('public', request); change(proof)
            with self.assertRaises(f.c.SafetyError): self.worker.accept(self.route_id, 'public', proof)
        with self.assertRaises(f.c.SafetyError): self.worker.publish(self.route_id)
        self.assertFalse(any(path == '/api/hosts/' for _, path, _ in self.api.writes))

    def test_publish_preserves_uuid_remark_order_hidden_fp_and_unknown_fields(self):
        original = deepcopy(self.api.hosts)
        result = self.publish()
        self.assertEqual(result['published_hosts'], 2)
        for hid, old in original.items():
            actual = deepcopy(self.api.hosts[hid])
            if hid in {self.exit.fixture.hosts[f.c.target(self.route_id)['host']]['uuid'], f.p.AUTOS[self.route_id]}:
                self.assertEqual(actual['nodes'], [f.p.ENTRY_ID])
                self.assertEqual(actual['address'], f.model.DOMAINS[self.route_id])
                for key in f.HOST_FIELDS: actual[key] = old[key]
            self.assertEqual(actual, old)
        self.assertFalse(any(method == 'POST' for method, _, _ in self.api.writes))

    def test_gbpower_has_only_main_no_new_auto(self):
        self.init('gbpower'); before_count = len(self.api.hosts)
        result = self.publish()
        self.assertEqual(result['published_hosts'], 1)
        self.assertEqual(len(self.api.hosts), before_count)
        request = self.worker.export_subscription(self.route_id, {'headers': {'x-hwid': 'existing-device'}})
        self.assertEqual({v['id'] for v in request['items']}, {'gbpower-sub-main-xray', 'gbpower-sub-main-mihomo'})

    def test_uncertain_applied_profile_node_and_host_patch_resume_readback_only(self):
        for path in ('/api/config-profiles/', '/api/nodes/', '/api/hosts/'):
            self.init('pl')
            if path == '/api/hosts/':
                self.stage(); q = self.worker.export_public(self.route_id); self.worker.accept(self.route_id, 'public', self.proof('public', q))
                method = self.worker.publish
            else: self.prepare(); method = self.worker.stage
            self.api.fail_after = ('PATCH', path)
            with self.assertRaises(TimeoutError): method(self.route_id)
            method(self.route_id)
            bodies = [b for m, p, b in self.api.writes if m == 'PATCH' and p == path]
            self.assertEqual(len(bodies), len({b['uuid'] for b in bodies}))

    def test_uncertain_unapplied_profile_node_host_patch_never_blindly_repeated(self):
        for path in ('/api/config-profiles/', '/api/nodes/', '/api/hosts/'):
            self.init('pl')
            if path == '/api/hosts/':
                self.stage(); q = self.worker.export_public(self.route_id); self.worker.accept(self.route_id, 'public', self.proof('public', q))
                method = self.worker.publish
            else: self.prepare(); method = self.worker.stage
            self.api.fail_before = ('PATCH', path)
            with self.assertRaises(TimeoutError): method(self.route_id)
            count = len(self.api.writes)
            with self.assertRaises(f.c.SafetyError): method(self.route_id)
            self.assertEqual(len(self.api.writes), count)
            self.worker.rollback(self.route_id)

    def test_rollback_restores_hosts_entry_and_own_grants_only_keeps_finished_exit(self):
        self.publish()
        before, record = self.store.get('before'), self.store.get('operation')
        sid = next(iter(record['grants'])); self.api.squads[sid]['inbounds'].append(dict(uuid='concurrent-grant'))
        self.worker.rollback(self.route_id)
        self.assertEqual(self.api.profiles['entry-profile']['config'], before['profile']['config'])
        self.assertEqual(f.c.metadata(self.api.profiles['entry-profile']), f.c.metadata(before['profile']))
        self.assertEqual(self.api.profiles['entry-profile']['unknown'], before['profile']['unknown'])
        self.assertEqual(f.c.binding(self.api.nodes[f.p.ENTRY_ID]), f.c.binding(before['entry']))
        for host in before['hosts']: self.assertEqual(self.api.hosts[host['uuid']], host)
        self.assertIn('concurrent-grant', f.c.ids(self.api.squads[sid]['inbounds']))
        self.assertEqual(self.exit.store.get('operation'), self.exit_record)
        self.assertTrue(self.exit_record['finished'])
        count = len(self.api.writes); self.worker.rollback(self.route_id)
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_refuses_foreign_profile_host_grant_or_new_consumer_before_write(self):
        for kind in ('profile', 'host', 'grant', 'consumer'):
            self.init('pl'); self.publish(); record = self.store.get('operation')
            if kind == 'profile': self.api.profiles['entry-profile']['config']['new-foreign-field'] = True
            if kind == 'host': self.api.hosts[f.c.target('pl')['host']]['remark'] = 'Changed'
            if kind == 'grant': self.api.squads['foreign'] = dict(uuid='foreign', name='SERVICE', inbounds=[dict(uuid=record['front'])])
            if kind == 'consumer': self.api.nodes['other-consumer']['configProfile'] = deepcopy(self.api.nodes[f.p.ENTRY_ID]['configProfile'])
            count = len(self.api.writes)
            with self.assertRaises(f.c.SafetyError): self.worker.rollback(self.route_id)
            self.assertEqual(len(self.api.writes), count)

    def test_rollback_failed_profile_restore_does_not_claim_success(self):
        self.publish(); self.api.ignore = ('PATCH', '/api/config-profiles/')
        with self.assertRaises(f.c.SafetyError): self.worker.rollback(self.route_id)
        self.assertNotIn('rolled_back', self.store.get('operation'))
        self.api.ignore = None
        self.worker.rollback(self.route_id)

    def test_actual_subscriptions_are_fetched_after_publish_and_both_formats_verified(self):
        self.publish()
        request = self.worker.export_subscription(self.route_id, {'headers': {'x-hwid': 'existing-device'}})
        self.assertEqual(len(self.fetch_calls), 2)
        self.assertEqual({kind for _, _, kind in self.fetch_calls}, {'happ', 'mihomo'})
        self.assertEqual({i['id'] for i in request['items']}, {'pl-sub-main-xray', 'pl-sub-auto-xray', 'pl-sub-main-mihomo'})
        self.assertTrue(any(path.startswith('/api/subscriptions/by-uuid/') for _, path, _ in self.api.calls))
        self.worker.accept(self.route_id, 'subscription', self.proof('subscription', request))
        result = self.worker.finish(self.route_id)
        self.assertTrue(result['actual_subscription_verified'])
        self.assertTrue(result['rollback_timer_and_service_inactive'])
        self.assertEqual(self.timer.cancels, [self.route_id])
        self.assertTrue(self.worker.rollback(self.route_id)['rollback_skipped_finished'])

    def test_fresh_subscription_wrong_uuid_key_sni_address_fp_and_missing_auto_fail(self):
        self.publish()
        mutations = [lambda k, v: v[0]['outbounds'][0]['settings']['vnext'][0]['users'][0].update(id='changed') if k == 'happ' else None,
            lambda k, v: v[0]['outbounds'][0]['streamSettings']['realitySettings'].update(publicKey='wrong') if k == 'happ' else None,
            lambda k, v: v['proxies'][0].update(servername='wrong.example') if k == 'mihomo' else None,
            lambda k, v: v['proxies'][0].update(server='127.0.0.1') if k == 'mihomo' else None,
            lambda k, v: v['proxies'][0].update({'client-fingerprint': 'changed'}) if k == 'mihomo' else None,
            lambda k, v: v.pop() if k == 'happ' else None]
        for change in mutations:
            self.subscription_override = change
            with self.assertRaises(f.c.SafetyError): self.worker.export_subscription(self.route_id, {'headers': {'x-hwid': 'existing-device'}})
            self.assertNotIn('subscription', self.store.get('operation')['proofs'])
        with self.assertRaises(f.c.SafetyError): self.worker.finish(self.route_id)
        self.assertFalse(self.timer.cancels)

    def test_old_failure_recorded_but_working_entry_legacy_cannot_regress(self):
        self.prepare()
        proof = self.proof('baseline')
        proof['tests'][0].update(passed=False, authenticated=False, http_code=0, exit_ip=None, returncodes=[28, 28])
        self.worker.accept(self.route_id, 'baseline', proof)
        self.worker.stage(self.route_id)
        request = self.worker.export_public(self.route_id); after = self.proof('public', request)
        failed = next(t for t in after['tests'] if t['id'] == proof['tests'][0]['id'])
        failed.update(passed=False, authenticated=False, http_code=0, exit_ip=None, returncodes=[28, 28])
        self.worker.accept(self.route_id, 'public', after)
        other = next(t for t in after['tests'] if t['id'] == proof['tests'][1]['id'])
        other.update(passed=False, exit_ip=None, returncodes=[0, 28])
        with self.assertRaises(f.c.SafetyError): self.worker.accept(self.route_id, 'public', after)

    def test_secret_export_is_copy_and_normal_result_never_prints_credentials(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.prepare(); cfg = self.worker.export_config(self.route_id); cfg['inbounds'].clear()
            result = self.worker.status(self.route_id)
        self.assertTrue(self.worker.export_config(self.route_id)['inbounds'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(out.getvalue(), ''); self.assertEqual(err.getvalue(), '')


class HelperTests(unittest.TestCase):
    def test_wire_hash_ignores_only_local_labels_and_keeps_uuid_sni_and_fp(self):
        value = dict(tag='random-local-label', protocol='vless', settings={'uuid': 'kept'}, streamSettings={'sni': 'kept', 'fp': 'kept'})
        changed = deepcopy(value); changed['tag'] = 'different'
        self.assertEqual(f.wire_hash('xray', value), f.wire_hash('xray', changed))
        for field in ('settings', 'streamSettings'):
            changed = deepcopy(value); changed[field]['new-wire-field'] = 'different'
            self.assertNotEqual(f.wire_hash('xray', value), f.wire_hash('xray', changed))

    def test_cli_secret_export_refuses_missing_flag_or_terminal(self):
        for args in (['export-config', '--id', 'pl'], ['export-public', '--id', 'pl', '--secret-stdout']):
            with patch.object(f.sys.stdout, 'isatty', return_value=True), patch.object(f, 'RootStore') as store:
                with self.assertRaises(f.c.SafetyError): f.main(args)
                store.assert_not_called()

    def test_fetcher_rejects_insecure_url_and_unapproved_or_invented_headers(self):
        with self.assertRaises(f.c.SafetyError): f.fetch_subscription('http://example.com/private', {'x-hwid': 'existing'}, 'happ')
        with self.assertRaises(f.c.SafetyError): f.fetch_subscription('https://example.com/private', {}, 'happ')
        with self.assertRaises(f.c.SafetyError): f.fetch_subscription('https://example.com/private', {'Authorization': 'secret'}, 'happ')
        with self.assertRaises(f.c.SafetyError): f.fetch_subscription('https://example.com/private', {'x-hwid': 'x\r\nAuthorization: secret'}, 'happ')

    def test_timer_targets_only_per_route_frontend_and_checks_both_units(self):
        calls, created = [], False
        def run(args, **kwargs):
            nonlocal created
            calls.append(args)
            self.assertNotIn('shell', kwargs)
            if args[0] == 'systemd-run': created = True; return SimpleNamespace(returncode=0, stdout='')
            if not created: return SimpleNamespace(returncode=1, stdout='LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
            is_timer = args[2].endswith('.timer')
            return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=' + ('active' if is_timer else 'inactive') +
                '\nSubState=' + ('waiting' if is_timer else 'dead') + '\nResult=success\n')
        f.Timers(run).start('pl')
        command = next(v for v in calls if v[0] == 'systemd-run')
        self.assertIn('--unit=ham-cloud140-six-pl-front-rollback', command)
        self.assertIn('--on-active=1200s', command)
        self.assertEqual(command[-3:], ['rollback', '--id', 'pl'])


if __name__ == '__main__': unittest.main()
