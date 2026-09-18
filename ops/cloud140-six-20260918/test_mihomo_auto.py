"""Pure synthetic tests: no live API, credentials, customer profiles or writes."""
from contextlib import nullcontext
from copy import deepcopy
import base64
import unittest

import mihomo_auto as m


def fixture():
    template = {'mixed-port': 7890, 'dns': {'enable': True}, 'proxies': None,
                'proxy-groups': [{'name': 'Manual', 'type': 'select', 'proxies': None}],
                'rules': ['MATCH,Manual']}
    record = dict(uuid='template-id', name='Default', templateType='MIHOMO', templateJson=None,
                  viewPosition=1, encodedTemplateYaml=base64.b64encode(m.encoded(template)).decode())
    happ_template = dict(uuid='happ-id', templateType='XRAY_JSON', templateJson={'remnawave': {
        'injectHosts': [{'selector': {'type': 'tagRegex', 'pattern': '^AUTO_BASE_POOL$'},
                         'tagPrefix': 'basepool', 'selectFrom': 'ALL'}]}})
    def host(uid, name, hidden=False, tags=None):
        return dict(uuid=uid, remark=name, isHidden=hidden, tags=tags or [], isDisabled=False,
                    excludeFromSubscriptionTypes=[], xrayJsonTemplateUuid=None)
    catalog = [host('auto', 'Old Auto'), host('a', 'Visible [A]'),
               host('b', 'Hidden (A)+', True, [m.TAG]),
               host('c', 'Hidden B', True, [m.TAG]), host('other', 'Other Hidden', True)]
    catalog[0]['xrayJsonTemplateUuid'] = 'happ-id'
    plan = m.build_plan(record, template, catalog, 'auto', happ_template)
    def proxy(name, ip):
        return dict(name=name, type='vless', server=ip, port=443,
                    uuid='00000000-0000-4000-8000-000000000001', network='tcp', tls=True,
                    servername='example.test', extra_unknown={'must': 'remain'})
    proxies = [proxy('Old Auto', '192.0.2.1'), proxy('Visible [A]', '192.0.2.2')]
    hidden = proxy('Hidden (A)+', '192.0.2.3')
    before = deepcopy(template); before['proxies'] = deepcopy(proxies)
    before['proxy-groups'][0]['proxies'] = [p['name'] for p in proxies]
    candidate = deepcopy(plan['template']); candidate.pop('remnawave')
    for group in candidate['proxy-groups']:
        group.pop('remnawave')
    candidate['proxies'] = deepcopy(proxies + [hidden])
    all_native = deepcopy(before); all_native['proxies'] = deepcopy(candidate['proxies'])
    outbound = dict(tag='proof', protocol='vless', settings={'must': 'remain'})
    pairs = [dict(name=hidden['name'], id='b', hidden=True, tags=[m.TAG], disabled=False,
                  proxy=deepcopy(hidden), outbound=outbound)]
    happ = [{'remarks': 'Old Auto', 'routing': {'balancers': [{'selector': ['basepool']}]},
             'outbounds': [{**outbound, 'tag': 'basepool'}]}]
    native = dict(baseline=before, candidate=candidate, all_native=all_native, pairs=pairs)
    preview = m.validate_preview(plan, native, before, happ)
    return plan, catalog, happ_template, native, happ, preview


def measurement(plan, preview, phase='candidate', timestamp=100):
    return dict(phase=phase, plan_sha256=plan['sha256'], generated_sha256=preview['generated_sha256'],
        timestamp=timestamp, test_id='run-'+phase, client_version='Mihomo test', config_test_exit_code=0,
        cleanup=dict(process=True, listener=True, directory=True), groups={
          m.AUTO: {'type': 'URLTest', 'all': preview['pool_names']},
          'Manual': {'type': 'Selector', 'all': preview['main_names'], 'now': m.AUTO}},
        attempts=[dict(test_id='request-'+str(i), http=204, egress_http=200, curl_exit_codes=[0, 0],
                       selected_member=preview['pool_names'][0],
                       selected_wire_sha256=preview['pool_wire_sha256'][preview['pool_names'][0]],
                       egress_ip='203.0.113.1', selection_stable=True) for i in range(2)])


class MemoryStore:
    def __init__(self): self.data = {}
    def locked(self): return nullcontext()
    def read(self, name): return deepcopy(self.data.get(name))
    def save(self, name, value):
        if name in self.data: raise FileExistsError(name)
        self.data[name] = deepcopy(value)


class Timer:
    def __init__(self): self.armed = False
    def arm(self, sha): self.armed = True
    def active(self, sha): return self.armed
    def disarm(self, sha): self.armed = False


class AutoTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.catalog, self.happ_template, self.native, self.happ, self.preview = fixture()

    def validate(self):
        return m.validate_preview(self.plan, self.native, self.native['baseline'], self.happ)

    def transaction(self):
        self.current = deepcopy(self.plan['before']); self.writes = []
        self.store, self.timer = MemoryStore(), Timer()
        def api(method, path, body=None):
            if method == 'PATCH':
                self.assertIsNotNone(self.store.read('plan'))
                self.assertIsNotNone(self.store.read('apply-intent'))
                self.assertEqual(set(body), {'uuid', 'encodedTemplateYaml'})
                self.writes.append(deepcopy(body)); self.current.update(body)
                if getattr(self, 'lose_response', False): raise OSError('Synthetic lost response')
            return deepcopy(self.current)
        self.tx = m.Transaction(api, self.store, self.timer, lambda: (self.catalog, self.happ_template), lambda: 100)
        self.tx.prepare(self.plan)
        return self.tx

    def test_exact_authorized_subset_not_all_catalog_or_visible(self):
        self.assertEqual(self.preview['pool_names'], ['Hidden (A)+'])
        self.assertEqual(self.preview['main_names'], ['Visible [A]', m.AUTO])
        self.assertNotIn('Hidden B', self.preview['pool_names'])

    def test_regex_is_literal_re2_subset(self):
        regex = m.exact_regex(['A [B]+(C).?', 'Имя #1'])
        self.assertTrue(m.re.fullmatch(regex, 'A [B]+(C).?'))
        self.assertFalse(m.re.fullmatch(regex, 'A BBBCx'))
        self.assertNotIn('\\ ', regex)

    def test_no_static_credentials_or_host_mutation(self):
        self.assertFalse(self.plan['template']['proxies'])
        self.assertEqual(self.plan['after']['uuid'], self.plan['before']['uuid'])
        self.assertNotIn('00000000', base64.b64decode(self.plan['after']['encodedTemplateYaml']).decode())

    def test_unknown_wire_field_not_silently_discarded(self):
        self.native['candidate']['proxies'][1].pop('extra_unknown')
        with self.assertRaises(ValueError): self.validate()

    def test_happ_wire_mismatch_rejected(self):
        self.happ[0]['outbounds'][0]['settings'] = {'changed': True}
        with self.assertRaises(ValueError): self.validate()

    def test_unsupported_hidden_member_fails_not_skips(self):
        self.native['pairs'][0]['proxy'] = None
        with self.assertRaises(ValueError): self.validate()

    def test_actual_baseline_override_rejected(self):
        public = deepcopy(self.native['baseline']); public['dns']['enable'] = False
        with self.assertRaises(ValueError): m.validate_preview(self.plan, self.native, public, self.happ)

    def test_empty_or_wrong_pool_rejected(self):
        self.native['pairs'] = []
        with self.assertRaises(ValueError): self.validate()

    def test_manual_visibility_drift_rejected(self):
        self.native['candidate']['proxy-groups'][0]['exclude-filter'] = '^Old Auto$'
        with self.assertRaises(ValueError): self.validate()

    def test_duplicate_names_rejected(self):
        catalog = deepcopy(self.catalog); catalog[1]['remark'] = catalog[0]['remark']
        with self.assertRaises(ValueError):
            m.build_plan(self.plan['before'], self.plan['baseline_template'], catalog, 'auto', self.happ_template)

    def test_urltest_and_traffic_proof_gate(self):
        proof = measurement(self.plan, self.preview)
        self.assertTrue(m.validate_measurement(self.plan, self.preview, proof, 'candidate', 100))
        for field, value in [('config_test_exit_code', 1), ('timestamp', 101), ('generated_sha256', 'wrong')]:
            bad = deepcopy(proof); bad[field] = value
            with self.assertRaises(ValueError): m.validate_measurement(self.plan, self.preview, bad, 'candidate', 100)
        for mutate in (lambda x: x['attempts'][0].update(curl_exit_codes=[28, 0]),
                       lambda x: x['groups'][m.AUTO].update(all=['Old Auto']),
                       lambda x: x['attempts'][0].update(selection_stable=False),
                       lambda x: x['attempts'][0].pop('selection_stable'),
                       lambda x: x['groups']['Manual'].update(now='Old Auto'),
                       lambda x: x['cleanup'].update(process=False)):
            bad = deepcopy(proof); mutate(bad)
            with self.assertRaises(ValueError): m.validate_measurement(self.plan, self.preview, bad, 'candidate', 100)

    def test_scoped_patch_and_exact_rollback(self):
        tx = self.transaction(); tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(self.current, self.plan['after'])
        self.assertEqual(tx.rollback(), {'rolled_back': True})
        self.assertEqual(self.current, self.plan['before'])
        self.assertEqual(len(self.writes), 2)

    def test_uncertain_patch_readback_without_duplicate(self):
        tx = self.transaction(); self.lose_response = True
        tx.apply(self.preview, measurement(self.plan, self.preview))
        tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(len(self.writes), 1)

    def test_rollback_refuses_other_changes(self):
        tx = self.transaction(); tx.apply(self.preview, measurement(self.plan, self.preview))
        self.current['name'] = 'Other operator'
        with self.assertRaises(ValueError): tx.rollback()
        self.assertEqual(len(self.writes), 1)

    def test_relevant_catalog_drift_blocks_before_write(self):
        tx = self.transaction(); self.catalog[1]['remark'] = 'Changed'
        with self.assertRaises(ValueError): tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(self.writes, [])

    def test_endpoint_rollout_not_catalog_lock(self):
        tx = self.transaction(); self.catalog[1]['address'] = '192.0.2.9'
        tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(len(self.writes), 1)

    def test_independent_timer_required(self):
        tx = self.transaction(); self.timer.arm = lambda sha: None
        with self.assertRaises(ValueError): tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(self.writes, [])

    def test_finish_requires_public_readback_and_fresh_proof(self):
        tx = self.transaction(); tx.apply(self.preview, measurement(self.plan, self.preview))
        with self.assertRaises(ValueError): tx.finish(self.preview, measurement(self.plan, self.preview, 'public'))
        public = m.validate_preview(self.plan, self.native, self.native['candidate'], self.happ, published=True)
        tx.finish(public, measurement(self.plan, public, 'public'))
        self.assertFalse(self.timer.armed)
        self.assertEqual(tx.rollback(), {'skipped_finished': True})

    def test_happ_not_patched_by_transaction(self):
        before = deepcopy(self.happ_template); tx = self.transaction()
        tx.apply(self.preview, measurement(self.plan, self.preview))
        self.assertEqual(self.happ_template, before)
        self.assertTrue(all(w['uuid'] == self.plan['before']['uuid'] for w in self.writes))


if __name__ == '__main__': unittest.main()
