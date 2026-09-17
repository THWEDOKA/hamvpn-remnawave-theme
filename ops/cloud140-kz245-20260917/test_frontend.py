"""DE245 lifecycle simulations. No network, production API or systemd execution."""
from copy import deepcopy
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import coordinator as c
import frontend as f
import preflight as p
import route_model as model
from test_coordinator import API as CoreAPI, MemoryStore, Timer as CoreTimer, NOW, baseline
from test_route_model import fixture, identities, services


def snapshot():
    before = baseline()
    node = c.target('de245')
    profile = before['profiles'][node['profile']]
    profile['config']['inbounds'] = profile['config']['inbounds'][:2]
    original, compat = profile['config']['inbounds']
    original['port'] = 443
    original['streamSettings']['realitySettings'].update(
        privateKey=identities()['de245']['privateKey'], serverNames=[node['sni']], target='127.0.0.1:8443')
    compat.update(listen='127.0.0.1', port=8443)
    compat['streamSettings'] = dict(network='raw', security='tls', tlsSettings={'certificates': []})
    profile['inbounds'] = profile['inbounds'][:2]
    for host in before['hosts']:
        host['host'] = host['sni']
        if host['uuid'] in node['hosts']:
            host['remark'] = 'DE245 original auto' if host['isHidden'] else 'DE245 original main'
            host['fingerprint'] = 'chrome' if host['isHidden'] else 'firefox'
    before['squads'][0]['inbounds'].append(dict(uuid='de245-in-1'))
    for name in ('WHITE', 'OLD', 'site'):
        before['squads'].append(dict(uuid='customer-' + name, name=name,
                                    inbounds=[dict(uuid=node['inbound']), dict(uuid='de245-in-1')]))
    return before


class API(CoreAPI):
    def __call__(self, method, path, body=None):
        if method == 'GET' and path.startswith('/api/subscriptions/by-uuid/'):
            return dict(subscriptionUrl='https://fixture.invalid/private-subscription')
        if method == 'PATCH' and path == '/api/config-profiles/':
            previous = c.metadata(self.profiles[body['uuid']])
            fail = self.fail_after == (method, path)
            if fail: self.fail_after = None
            result = super().__call__(method, path, body)
            if self.ignore != (method, path):
                self.profiles[body['uuid']]['inbounds'] = [dict(tag=item['tag'],
                    uuid=previous.get(item['tag'], 'front-meta-' + item['tag'])) for item in body['config']['inbounds']]
            if fail: raise RuntimeError('Lost profile PATCH response')
            return deepcopy(self.profiles[body['uuid']])
        return super().__call__(method, path, body)


class Timers:
    def __init__(self, core_timer):
        self.core = core_timer
        self.waiting = False
        self.running = set()
        self.stopped = []
        self.fail_on = None

    def start(self, route_id):
        c.require(route_id == 'de245' and not self.waiting, 'Timer exists')
        self.waiting = True

    def armed(self, route_id):
        c.require(self.waiting and f.FRONT_TIMER not in self.running, 'Frontend timer not waiting')

    def stop(self, name):
        if name == self.fail_on: raise c.SafetyError('Stop failed')
        self.stopped.append(name)
        if name == f.FRONT_TIMER: self.waiting = False
        else: self.core.active.discard('de245')

    def service_idle(self, name): c.require(name not in self.running, 'Rollback service executing')

    def inactive(self, name):
        self.service_idle(name)
        c.require(not self.waiting if name == f.FRONT_TIMER else 'de245' not in self.core.active, 'Timer still active')


class SelectedModelTests(unittest.TestCase):
    def test_host_exclusions_order_not_access_changes(self):
        original = dict(uuid='one', excludedInternalSquads=['squad-b', 'squad-a'], remark='same')
        reordered = dict(original, excludedInternalSquads=['squad-a', 'squad-b'])
        self.assertEqual(c.stable_host(original), c.stable_host(reordered))
        self.assertNotEqual(c.stable_host(original), c.stable_host(dict(original, excludedInternalSquads=['squad-a'])))
        with self.assertRaises(c.SafetyError): c.stable_host(dict(original, excludedInternalSquads=['squad-a', 'squad-a']))

    def test_single_route_exact_addition_and_no_kz_placeholders(self):
        source = fixture()
        result = model.build_entry_config(source, {'de245': identities()['de245']},
                                          {'de245': services()['de245']}, route_ids=['de245'])
        self.assertEqual(len(result['inbounds']), 5)
        self.assertEqual(result['inbounds'][-1]['port'], 18444)
        self.assertEqual(result['outbounds'][-1]['settings']['vnext'][0]['port'], 28443)
        self.assertNotIn('cloud140-kz2', json.dumps(result))
        del result['inbounds'][-1]; del result['outbounds'][-1]; del result['routing']['rules'][3]
        self.assertEqual(result, source)

    def test_selection_rejects_empty_duplicate_unknown_and_extra_identity(self):
        for selection in ([], ['de245', 'de245'], ['missing'], 'de245', [True]):
            with self.assertRaises(ValueError):
                model.build_entry_config(fixture(), {}, {}, route_ids=selection)
        with self.assertRaises(ValueError):
            model.build_entry_config(fixture(), identities(), services(), route_ids=['de245'])

    def test_default_both_is_unchanged(self):
        self.assertEqual(model.build_entry_config(fixture(), identities(), services()),
                         model.build_entry_config(fixture(), identities(), services(), route_ids=['kz2', 'de245']))


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.now = NOW
        self.core_store = MemoryStore()
        self.core_store.snapshot = snapshot(); self.core_store.digest = c.checksum(self.core_store.snapshot)
        self.store = MemoryStore()
        self.store.snapshot = deepcopy(self.core_store.snapshot); self.store.digest = self.core_store.digest
        self.api = API(self.core_store.snapshot)
        self.core_timer = CoreTimer()
        self.core = c.Coordinator(self.api, self.core_store, self.core_timer, lambda: self.now)
        self.core.prepare('de245')
        core_record = self.core_store.read('exit-de245')
        node = c.target('de245')
        self.core.accept_test('de245', dict(id='de245', node=node['node'], ip=node['ip'],
            sha256=core_record['sha256'], timestamp=self.now,
            tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.7.28')]))
        self.core.stage('de245')
        self.timers = Timers(self.core_timer)
        self.intent = dict(uuid='technical-probe', username='cloud140_probe_fixture', tag='CLOUD140_PROBE',
                           description='Temporary CLOUD140 KZ245 route verification')
        self.api.users[self.intent['uuid']] = dict(**self.intent, status='ACTIVE',
            vlessUuid='00000000-0000-4000-8000-000000000077', activeInternalSquads=[dict(uuid='base')])
        self.subscription = []
        self.worker = f.Frontend(self.api, self.store, self.core, self.timers, lambda: self.now,
            key_factory=lambda: deepcopy(identities()['de245']), probe_intent=lambda: deepcopy(self.intent),
            subscription_fetch=lambda url: deepcopy(self.subscription))
        public = patch.object(p, 'public_key', return_value='SYNTHETIC-PUBLIC-KEY')
        public.start(); self.addCleanup(public.stop)

    def record(self): return self.store.read('state')

    def proof(self, phase):
        record = self.record()
        result = dict(sha256=record['sha256'], timestamp=self.now)
        if phase == 'installed':
            result.update(id='entry', node=p.ENTRY_ID, ip=p.ENTRY,
                tests=[dict(kind='installed-xray', passed=True, returncode=0, version='26.7.28')])
        elif phase == 'tls':
            result['tests'] = [dict(id='de245-local-tls', passed=True, sni=c.target('de245')['domain'],
                address='127.0.0.1', port=9443, tls='TLSv1.3', alpn='h2', chain_verified=True)]
        elif phase == 'renewal':
            result['tests'] = [dict(id='de245-renewal', passed=True, domain=c.target('de245')['domain'],
                performed_at=self.now-3600, dry_run=True), dict(id='de245-renewal-health', passed=True,
                domain=c.target('de245')['domain'], nginx_test=True, cert_valid=True, deploy_hook=True,
                timer_enabled=True, timer_active=True, tls='TLSv1.3', alpn='h2')]
        else:
            result.update(all_passed=True, tests=[dict(id=item['id'], passed=True, http='204',
                exit_ip=item['ip'], curl_codes=[0, 0]) for item in record['requests'][phase]['request']['items']])
        return result

    def prepared(self):
        self.worker.prepare()
        self.worker.accept('installed', self.proof('installed'))
        self.worker.accept('tls', self.proof('tls'))

    def backend(self):
        self.prepared(); self.worker.arm()
        self.core.arm('de245'); self.core.activate_exit('de245')
        self.worker.export_backend(); self.worker.accept('backend', self.proof('backend'))

    def staged(self):
        self.backend(); self.worker.stage()

    def published(self):
        self.staged(); self.worker.export_public()
        self.worker.accept('public', self.proof('public')); self.worker.publish()

    def subscription_ready(self):
        record = self.record()
        user = self.api.users[self.intent['uuid']]['vlessUuid']
        rs = record['candidate']['inbounds'][-1]['streamSettings']['realitySettings']
        self.subscription = []
        for host in record['hosts']:
            outbound = f.client(p.ENTRY, 18444, user, 'reality', rs, host['fingerprint'])
            outbound['tag'] = 'actual-subscription-out'
            self.subscription.append(dict(remarks=f.AUTO_REMARK if host['isHidden'] else host['remark'],
                                           outbounds=[outbound, dict(tag='unrelated', protocol='freedom')]))

    def final_ready(self):
        self.published(); self.subscription_ready(); self.worker.export_subscription()
        self.worker.accept('subscription', self.proof('subscription'))
        self.worker.accept('renewal', self.proof('renewal'))

    def test_prepare_needs_only_de245_core_and_writes_no_api(self):
        count = len(self.api.writes)
        self.worker.prepare()
        self.assertFalse(self.core_store.exists('exit-kz2'))
        self.assertEqual(len(self.api.writes), count)
        self.assertEqual(len(self.worker.export_config()['inbounds']), 5)
        self.assertNotIn('cloud140-kz2', json.dumps(self.worker.export_config()))

    def test_front_timer_arms_before_core_activation(self):
        self.prepared(); self.worker.arm()
        self.assertTrue(self.timers.waiting)
        self.assertNotIn('activated', self.core_store.read('exit-de245'))
        self.assertFalse(self.core_timer.active)

    def test_arm_refuses_timer_order_that_would_put_core_rollback_first(self):
        self.prepared(); self.core.arm('de245')
        self.now += 900
        with self.assertRaises(c.SafetyError): self.worker.arm()

    def test_stage_requires_all_positive_fresh_prerequisites(self):
        self.backend()
        record = self.store.values['state']; record['proofs'].pop('backend')
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.stage()
        self.assertEqual(len(self.api.writes), count)

    def test_stage_adds_one_front_preserves_old_four_and_untouched_exits(self):
        self.backend()
        before_profiles = deepcopy(self.api.profiles); before_hosts = deepcopy(self.api.hosts)
        before_kz = deepcopy(self.api.nodes[c.target('kz2')['node']])
        self.worker.stage()
        record = self.record(); profile = self.api.profiles[record['profile']]
        self.assertEqual(profile['config']['inbounds'][:4], before_profiles[record['profile']]['config']['inbounds'])
        self.assertEqual(len(c.binding(self.api.nodes[p.ENTRY_ID])['inbounds']), 5)
        for node in p.NODES:
            self.assertEqual(self.api.profiles[node['profile']], before_profiles[node['profile']])
        self.assertEqual(self.api.hosts, before_hosts)
        self.assertEqual(self.api.nodes[c.target('kz2')['node']], before_kz)
        granted = [s['name'] for s in self.api.squads.values() if record['front'] in c.ids(s['inbounds'])]
        self.assertEqual(set(granted), f.CUSTOMERS)
        backend = self.core_store.read('exit-de245')
        self.assertNotIn(record['front'], c.ids(self.api.squads[backend['objects']['squad']]['inbounds']))

    def test_existing_customer_additions_are_preserved_on_stage_and_rollback(self):
        self.backend()
        self.api.squads['base']['inbounds'].append(dict(uuid='concurrent-a'))
        self.worker.stage()
        self.api.squads['base']['inbounds'].append(dict(uuid='concurrent-b'))
        self.worker.rollback()
        actual = c.ids(self.api.squads['base']['inbounds'])
        self.assertTrue({'concurrent-a', 'concurrent-b'} <= set(actual))

    def test_backend_export_matches_helper_and_has_no_vision(self):
        self.backend()
        request = self.worker.export_backend()
        self.assertEqual(set(request), {'sha256', 'items'})
        self.assertEqual([item['id'] for item in request['items']], ['de245-backend'])
        out = request['items'][0]['outbound']; endpoint = out['settings']['vnext'][0]
        self.assertEqual((endpoint['address'], endpoint['port']), ('127.0.0.1', 28443))
        self.assertNotIn('flow', endpoint['users'][0])
        self.assertEqual(out['streamSettings'], dict(network='raw', security='none'))

    def test_public_export_exact_six_ids_and_cached_tls_proven_vision_fallback(self):
        self.staged()
        request = self.worker.export_public()
        items = {item['id']: item for item in request['items']}
        self.assertEqual(set(items), {'de245-public-chrome','de245-public-firefox','de245-host-main',
                                    'de245-host-auto','de245-legacy-reality','de245-legacy-tls'})
        tls = items['de245-legacy-tls']['outbound']
        self.assertEqual(tls['settings']['vnext'][0]['address'], c.target('de245')['ip'])
        self.assertEqual(tls['settings']['vnext'][0]['port'], 443)
        self.assertEqual(tls['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(tls['streamSettings']['security'], 'tls')
        self.assertIs(tls['streamSettings']['tlsSettings']['allowInsecure'], False)
        for role, expected in (('main', 'firefox'), ('auto', 'chrome')):
            self.assertEqual(items['de245-host-'+role]['outbound']['streamSettings']['realitySettings']['fingerprint'], expected)

    def test_traffic_proofs_require_exact_ids_not_just_boolean(self):
        self.staged(); self.worker.export_public()
        valid = self.proof('public')
        bad = []
        empty = deepcopy(valid); empty['tests'] = []; bad.append(empty)
        missing = deepcopy(valid); missing['tests'].pop(); bad.append(missing)
        duplicate = deepcopy(valid); duplicate['tests'][0] = deepcopy(duplicate['tests'][1]); bad.append(duplicate)
        for field, value in (('http', '200'), ('exit_ip', c.target('kz2')['ip']), ('curl_codes', [0, 1]),
                             ('curl_codes', [False, 0]), ('passed', False), ('id', 'unexpected')):
            proof = deepcopy(valid); proof['tests'][0][field] = value; bad.append(proof)
        for proof in bad:
            with self.assertRaises(c.SafetyError): self.worker.accept('public', proof)

    def test_proofs_reject_wrong_digest_future_stale_and_preexport_timestamp(self):
        self.backend()
        for field, value in (('sha256', 'wrong'), ('timestamp', self.now+1), ('timestamp', self.now-1801),
                             ('timestamp', float('nan')), ('timestamp', True)):
            proof = self.proof('backend'); proof[field] = value
            with self.assertRaises(c.SafetyError): self.worker.accept('backend', proof)
        self.now += 10; self.worker.export_backend()
        proof = self.proof('backend'); proof['timestamp'] -= 1
        with self.assertRaises(c.SafetyError): self.worker.accept('backend', proof)

    def test_new_failed_proof_revokes_previous_success(self):
        self.backend()
        proof = self.proof('backend'); proof['tests'][0]['passed'] = False
        with self.assertRaises(c.SafetyError): self.worker.accept('backend', proof)
        self.assertNotIn('backend', self.record()['proofs'])

    def test_saved_request_corruption_and_rehashed_incomplete_coverage_rejected(self):
        self.staged(); self.worker.export_public()
        proof = self.proof('public')
        saved = deepcopy(self.store.values['state']['requests']['public'])
        for recompute in (False, True):
            bad = deepcopy(saved); bad['request']['items'].pop()
            if recompute: bad['digest'] = c.checksum(bad['request'])
            self.store.values['state']['requests']['public'] = bad
            with self.assertRaises(c.SafetyError): self.worker.accept('public', proof)

    def test_installed_proof_must_be_actual_entry_not_exit(self):
        self.worker.prepare()
        proof = self.proof('installed'); proof.update(id='de245', node=c.target('de245')['node'], ip=c.target('de245')['ip'])
        with self.assertRaises(c.SafetyError): self.worker.accept('installed', proof)

    def test_profile_patch_response_loss_is_read_back_without_repatch(self):
        self.backend(); self.api.fail_after = ('PATCH', '/api/config-profiles/')
        with self.assertRaises(RuntimeError): self.worker.stage()
        self.worker.stage()
        writes = [w for w in self.api.writes if w[0] == 'PATCH' and w[1] == '/api/config-profiles/']
        self.assertEqual(len(writes), 1)

    def test_profile_timeout_without_apply_never_repatches(self):
        self.backend(); self.api.fail_before = ('PATCH', '/api/config-profiles/')
        with self.assertRaises(RuntimeError): self.worker.stage()
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.stage()
        self.assertEqual(len(self.api.writes), count)

    def test_partial_profile_apply_can_rollback_before_front_uuid_was_saved(self):
        self.backend(); self.api.fail_after = ('PATCH', '/api/config-profiles/')
        with self.assertRaises(RuntimeError): self.worker.stage()
        self.assertNotIn('front', self.record())
        self.assertTrue(self.worker.rollback()['exit_core_restored'])

    def test_publish_requires_public_legacy_and_host_fingerprint_coverage(self):
        self.staged()
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.publish()
        self.assertEqual(len(self.api.writes), count)

    def test_publish_changes_only_two_hosts_allowed_fields(self):
        old = deepcopy(self.api.hosts)
        self.published()
        for key, host in old.items():
            actual = self.api.hosts[key]
            if key in c.target('de245')['hosts']:
                self.assertEqual({k: v for k, v in host.items() if k not in f.HOST_FIELDS},
                                 {k: v for k, v in actual.items() if k not in f.HOST_FIELDS})
                self.assertEqual((actual['address'], actual['port'], actual['sni']), (p.ENTRY, 18444, c.target('de245')['domain']))
            else: self.assertEqual(host, actual)

    def test_publish_cannot_accept_restored_old_entry_under_mixed_host_guard(self):
        self.staged(); self.worker.export_public(); self.worker.accept('public', self.proof('public'))
        record = self.record(); before = self.store.snapshot
        self.api.profiles[record['profile']] = deepcopy(before['profiles'][record['profile']])
        self.api.nodes[p.ENTRY_ID] = deepcopy(next(n for n in before['nodes'] if n['uuid'] == p.ENTRY_ID))
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.publish()
        self.assertEqual(len(self.api.writes), count)

    def test_actual_subscription_exports_only_selected_main_auto_outbounds(self):
        self.published(); self.subscription_ready()
        request = self.worker.export_subscription()
        self.assertEqual({i['id'] for i in request['items']}, {'de245-sub-main', 'de245-sub-auto'})
        self.assertNotIn('subscriptionUrl', json.dumps(request))
        self.assertNotIn('unrelated', json.dumps(request))
        self.worker.accept('subscription', self.proof('subscription'))

    def test_subscription_rejects_wrong_wire_security_flow_identity_and_fingerprint(self):
        self.published()
        for mutation in ('flow', 'security', 'publicKey', 'shortId', 'fingerprint', 'serverName', 'id'):
            self.subscription_ready()
            out = self.subscription[0]['outbounds'][0]
            if mutation in ('flow', 'id'): out['settings']['vnext'][0]['users'][0][mutation] = 'wrong'
            elif mutation == 'security': out['streamSettings']['security'] = 'none'
            else: out['streamSettings']['realitySettings'][mutation] = 'wrong'
            with self.assertRaises(c.SafetyError): self.worker.export_subscription()

    def test_subscription_probe_must_be_after_actual_export_and_publish(self):
        self.published(); self.subscription_ready(); self.worker.export_subscription()
        proof = self.proof('subscription'); proof['timestamp'] -= 1
        with self.assertRaises(c.SafetyError): self.worker.accept('subscription', proof)

    def test_new_bad_subscription_fetch_invalidates_previous_success(self):
        self.final_ready()
        self.subscription[0]['outbounds'][0]['streamSettings']['security'] = 'none'
        with self.assertRaises(c.SafetyError): self.worker.export_subscription()
        self.assertNotIn('subscription', self.record()['proofs'])
        with self.assertRaises(c.SafetyError): self.worker.finish()
        self.assertFalse(self.timers.stopped)

    def test_new_failed_public_export_invalidates_previous_success(self):
        self.staged(); self.worker.export_public(); self.worker.accept('public', self.proof('public'))
        self.api.users[self.intent['uuid']]['status'] = 'EXPIRED'
        with self.assertRaises(c.SafetyError): self.worker.export_public()
        self.assertNotIn('public', self.record()['proofs'])

    def test_renewal_preserves_old_actual_time_but_requires_fresh_health(self):
        self.worker.prepare()
        proof = self.proof('renewal')
        self.worker.accept('renewal', proof)
        self.assertEqual(self.record()['proofs']['renewal']['tests'][0]['performed_at'], self.now-3600)
        for performed in (self.now+1, self.now-86401, True):
            proof = self.proof('renewal'); proof['tests'][0]['performed_at'] = performed
            with self.assertRaises(c.SafetyError): self.worker.accept('renewal', proof)
        proof = self.proof('renewal'); proof['timestamp'] -= 1801
        with self.assertRaises(c.SafetyError): self.worker.accept('renewal', proof)

    def test_rollback_restores_frontend_before_core_and_preserves_kz(self):
        original_kz = deepcopy(self.api.nodes[c.target('kz2')['node']])
        self.published(); record = self.record(); order = []
        original = self.core.rollback
        def checked(route_id):
            self.assertEqual(route_id, 'de245')
            self.assertEqual(self.api.profiles[record['profile']]['config'], self.store.snapshot['profiles'][record['profile']]['config'])
            for old in record['hosts']: self.assertEqual(self.api.hosts[old['uuid']], old)
            self.assertFalse(any(record['front'] in c.ids(s['inbounds']) for s in self.api.squads.values()))
            order.append('core-after-frontend')
            return original(route_id)
        self.core.rollback = checked
        self.assertTrue(self.worker.rollback()['exit_core_restored'])
        self.assertEqual(order, ['core-after-frontend'])
        self.assertEqual(self.api.nodes[c.target('kz2')['node']], original_kz)
        self.assertTrue(self.core_store.read('exit-de245')['rolled_back'])

    def test_rollback_all_scope_preflight_before_any_patch(self):
        self.published()
        self.api.squads['customer-site']['inbounds'] = []
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_refuses_foreign_core_grant_before_restoring_hosts(self):
        self.published(); core = self.core_store.read('exit-de245')
        self.api.squads['other-group']['inbounds'].append(dict(uuid=core['rights']['base']['added'][0]))
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_does_not_touch_foreign_host_edits(self):
        self.published()
        self.api.hosts[c.target('de245')['hosts'][0]]['remark'] = 'Concurrent rename'
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        self.assertEqual(len(self.api.writes), count)

    def test_rollback_fails_on_ignored_entry_restore_before_calling_core(self):
        self.published(); self.api.ignore = ('PATCH', '/api/config-profiles/')
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        self.assertNotIn('rolled_back', self.core_store.read('exit-de245'))

    def test_rollback_resumes_after_core_already_restored(self):
        self.published()
        original = self.core.rollback
        def lost_reply(route_id):
            original(route_id)
            raise RuntimeError('Lost core completion')
        self.core.rollback = lost_reply
        with self.assertRaises(RuntimeError): self.worker.rollback()
        self.core.rollback = original
        self.assertTrue(self.worker.rollback()['exit_core_restored'])

    def test_finish_requires_subscription_and_renewal_not_only_public(self):
        self.published()
        with self.assertRaises(c.SafetyError): self.worker.finish()
        self.assertFalse(self.timers.stopped)

    def test_finish_stops_both_and_checks_services_with_poststop_verification(self):
        self.final_ready()
        self.assertTrue(self.worker.finish()['both_rollback_timers_inactive'])
        self.assertEqual(self.timers.stopped, [c.SystemdTimer.name('de245'), f.FRONT_TIMER])
        self.assertIn('finished', self.record())
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        with self.assertRaises(c.SafetyError): self.worker.export_subscription()

    def test_backend_squad_cannot_gain_frontend_even_with_other_service_names(self):
        self.staged(); record = self.record()
        self.api.squads['rogue-service'] = dict(uuid='rogue-service', name='SERVICE_POOL',
                                               inbounds=[dict(uuid=record['front'])])
        count = len(self.api.writes)
        with self.assertRaises(c.SafetyError): self.worker.verify()
        with self.assertRaises(c.SafetyError): self.worker.rollback()
        self.assertEqual(len(self.api.writes), count)

    def test_finish_race_with_running_rollback_cannot_claim_success(self):
        self.final_ready(); self.timers.running.add(f.FRONT_TIMER)
        with self.assertRaises(c.SafetyError): self.worker.finish()
        self.assertNotIn('finished', self.record())

    def test_finish_resumes_after_one_timer_stop_failed(self):
        self.final_ready(); self.timers.fail_on = f.FRONT_TIMER
        with self.assertRaises(c.SafetyError): self.worker.finish()
        self.assertNotIn('finished', self.record())
        self.timers.fail_on = None
        self.assertTrue(self.worker.finish()['frontend_finalized'])

    def test_no_implicit_secret_output_or_external_processes(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch('subprocess.run', side_effect=AssertionError('No runtime execution')):
            self.final_ready(); self.worker.finish()
        self.assertEqual(out.getvalue(), ''); self.assertEqual(err.getvalue(), '')


class SystemdTests(unittest.TestCase):
    def test_frontend_start_uses_frontend_script_ten_minutes_and_no_shell(self):
        calls = []
        def runner(args, **kwargs):
            self.assertNotIn('shell', kwargs); calls.append(args)
            if args[0] == 'systemd-run': return SimpleNamespace(returncode=0, stdout='')
            created = any(x[0] == 'systemd-run' for x in calls)
            if not created: return SimpleNamespace(returncode=1, stdout='LoadState=not-found\nActiveState=inactive\nSubState=dead\n')
            timer = args[2].endswith('.timer')
            return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState='+('active' if timer else 'inactive')
                +'\nSubState='+('waiting' if timer else 'dead')+'\nResult=success\n')
        f.Timers(runner).start('de245')
        command = next(x for x in calls if x[0] == 'systemd-run')
        self.assertIn('--on-active=10m', command)
        self.assertTrue(command[-2].replace('\\','/').endswith('/frontend.py'))
        self.assertEqual(command[-1], 'rollback')

    def test_nonzero_unknown_does_not_count_as_inactive(self):
        for code in (0, 1, 4, 5):
            runner = lambda *args, **kwargs: SimpleNamespace(returncode=code, stdout='inactive\n')
            with self.assertRaises(c.SafetyError): f.Timers(runner).inactive(f.FRONT_TIMER)

    def test_inactive_requires_rc3_and_good_service_result(self):
        def runner(args, **kwargs):
            if args[1] == 'is-active': return SimpleNamespace(returncode=3, stdout='inactive\n')
            return SimpleNamespace(returncode=0, stdout='LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=exit-code\n')
        with self.assertRaises(c.SafetyError): f.Timers(runner).inactive(f.FRONT_TIMER)

    def test_subscription_fetch_refuses_http_without_network(self):
        with patch('urllib.request.build_opener', side_effect=AssertionError('No network')):
            with self.assertRaises(c.SafetyError): f.fetch_happ('http://fixture.invalid/private')


if __name__ == '__main__': unittest.main()
