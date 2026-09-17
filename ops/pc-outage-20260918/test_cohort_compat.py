from copy import deepcopy
import unittest
import cohort_compat as c


class Store:
    def __init__(self): self.records = {}
    def exists(self, name): return name in self.records
    def get(self, name): return deepcopy(self.records[name])
    def put(self, name, value):
        if name in self.records: raise RuntimeError('immutable')
        self.records[name] = deepcopy(value)


class Timer:
    def __init__(self): self.armed = False
    def active(self): return self.armed
    def arm(self): self.armed = True
    def cancel(self): self.armed = False
    def verify_script(self): return True


def fixture_config():
    return {'inbounds': [dict(tag=c.TAG, port=443, protocol='vless', settings={'clients': []},
            streamSettings=dict(security='reality', network='raw', realitySettings={
                'privateKey': 'fixture-key', 'shortIds': ['aa'], 'serverNames': ['example.invalid']}))],
            'outbounds': [{'protocol': 'freedom'}], 'routing': {'rules': [dict(inboundTag=[c.TAG], outboundTag='DIRECT')]}}


class API:
    def __init__(self):
        self.profiles = {c.SOURCE: dict(uuid=c.SOURCE, name='G-CONFIG', config=fixture_config(),
                         inbounds=[dict(uuid=c.INBOUND, tag=c.TAG)])}
        self.nodes, self.hosts, self.writes = {}, {}, []
        for ip, nid, main, auto in c.TARGETS.values():
            self.nodes[nid] = dict(uuid=nid, address=ip, isConnected=True, isDisabled=False,
                                  versions={'xray': '26.7.28'}, configProfile=dict(activeConfigProfileUuid=c.SOURCE,
                                  activeInbounds=[dict(uuid=c.INBOUND, tag=c.TAG, rawInbound=deepcopy(fixture_config()['inbounds'][0]))]))
            for hid, hidden in [(main, False), (auto, True)]:
                self.hosts[hid] = dict(uuid=hid, nodes=[nid], address=ip, port=443, isHidden=hidden,
                                     isDisabled=False, remark='fixture-' + hid, fingerprint='firefox', sni=None,
                                     inbound=dict(configProfileUuid=c.SOURCE, configProfileInboundUuid=c.INBOUND))
        for i in range(5):
            self.nodes['protected-' + str(i)] = dict(uuid='protected-' + str(i), address='198.51.100.' + str(i+1),
                configProfile=dict(activeConfigProfileUuid=c.SOURCE, activeInbounds=[dict(uuid=c.INBOUND, tag=c.TAG)]))
        self.squads = {'base': dict(uuid='base', name='BASE', inbounds=[{'uuid': c.INBOUND}, {'uuid': 'existing-other'}]),
                       'white': dict(uuid='white', name='WHITE', inbounds=[{'uuid': c.INBOUND}]),
                       'unrelated': dict(uuid='unrelated', name='SERVICE', inbounds=[{'uuid': 'service'}])}
        self.fail_host_once = False

    def __call__(self, method, path, body=None):
        if method == 'GET':
            if path == '/api/nodes/': result = list(self.nodes.values())
            elif path == '/api/hosts/': result = list(self.hosts.values())
            elif path == '/api/internal-squads/': result = {'internalSquads': list(self.squads.values())}
            elif path == '/api/config-profiles/': result = {'configProfiles': list(self.profiles.values())}
            else: result = self.profiles[path.split('/')[-1]]
            return deepcopy(result)
        self.writes.append((method, path, deepcopy(body)))
        if method == 'POST' and path == '/api/config-profiles/':
            result = dict(uuid='clone-profile', name=body['name'], config=deepcopy(body['config']),
                          inbounds=[dict(uuid='clone-inbound', tag=c.NEW_TAG)])
            self.profiles[result['uuid']] = result
            return deepcopy(result)
        if path == '/api/internal-squads/':
            self.squads[body['uuid']]['inbounds'] = [{'uuid': value} for value in body['inbounds']]
        elif path == '/api/nodes/':
            requested = body['configProfile']; pid = requested['activeConfigProfileUuid']
            self.nodes[body['uuid']]['configProfile'] = dict(activeConfigProfileUuid=pid,
                activeInbounds=[dict(uuid=iid, tag=self.profiles[pid]['inbounds'][0]['tag'],
                                    rawInbound=deepcopy(self.profiles[pid]['config']['inbounds'][0]))
                                for iid in requested['activeInbounds']])
        elif path == '/api/hosts/':
            if self.fail_host_once:
                self.fail_host_once = False
                raise RuntimeError('simulated ambiguous host request')
            self.hosts[body['uuid']]['inbound'] = deepcopy(body['inbound'])
        else: raise RuntimeError('unexpected write')
        return {}


class Tests(unittest.TestCase):
    def setUp(self):
        self.api, self.store, self.timer = API(), Store(), Timer()
        self.op = c.Operation(self.api, self.store, self.timer, clock=lambda: 1000)

    def ready(self):
        self.op.plan()
        self.op.accept_installed(dict(sha256=self.op.load()['sha256'], timestamp=999,
                                     passed=True, returncode=0, version='26.7.28'))

    def proof(self):
        return dict(sha256=self.op.load()['sha256'], timestamp=1000,
                    live_mihomo_delays={key: 100 for key in c.TARGETS},
                    tests=[dict(id=key+'-'+core+'-'+fp, http='204', curl_codes=[0,0], exit_ip=value[0], listener_removed=True)
                           for key, value in c.TARGETS.items() for core in ('mihomo','xray') for fp in ('chrome','firefox')])

    def subscription(self):
        self.op.accept_subscription(dict(sha256=self.op.load()['sha256'], timestamp=1000, passed=True,
            subscription_readback=[dict(id=key,mihomo_main_unchanged=True,happ_main_unchanged=True,happ_auto_unchanged=True)
                                   for key in c.TARGETS]))

    def test_only_minversion_and_tag_references_change(self):
        original = fixture_config(); result = c.candidate(original)
        self.assertEqual(original, fixture_config())
        self.assertEqual(result['inbounds'][0]['streamSettings']['realitySettings'].pop('minClientVer'), '1.8.2')
        result['inbounds'][0]['tag'] = c.TAG; result['routing']['rules'][0]['inboundTag'] = [c.TAG]
        self.assertEqual(original, result)

    def test_explicit_policy_refused(self):
        for value in ('0.0.0', '26.3.27', '1.8.2', None, ''):
            config = fixture_config(); config['inbounds'][0]['streamSettings']['realitySettings']['minClientVer'] = value
            with self.assertRaises(RuntimeError): c.candidate(config)

    def test_profile_name_matches_installed_contract(self):
        self.assertTrue(c.valid_profile_name(c.NAME))
        self.assertTrue(c.valid_profile_name('A' * 30))
        for name in ('A', 'A'*31, 'bad/name', 'HAM-PC-MIHOMO-SIX-COMPAT-20260918'):
            self.assertFalse(c.valid_profile_name(name))

    def test_old_core_target_refused(self):
        self.api.nodes[next(iter(c.NODE_IDS))]['versions']['xray'] = '26.3.27'
        with self.assertRaises(RuntimeError): self.op.plan()
        self.assertEqual(self.api.writes, [])

    def test_unexpected_host_refused(self):
        self.api.hosts['foreign'] = deepcopy(next(iter(self.api.hosts.values())))
        self.api.hosts['foreign']['uuid'] = 'foreign'
        with self.assertRaises(RuntimeError): self.op.plan()

    def test_null_unrelated_relations_are_safe(self):
        self.api.nodes['disabled-unrelated'] = dict(uuid='disabled-unrelated', configProfile=None)
        self.api.hosts['unbound-unrelated'] = dict(uuid='unbound-unrelated', nodes=[], inbound=None)
        self.ready(); self.op.stage(); self.op.apply(); self.op.rollback()

    def test_relation_order_is_not_host_drift(self):
        hid = next(iter(c.HOST_IDS))
        self.api.hosts[hid]['excludedInternalSquads'] = [{'uuid':'b'}, {'uuid':'a'}]
        self.ready()
        self.api.hosts[hid]['excludedInternalSquads'].reverse()
        self.op.stage(); self.op.apply()

    def test_shared_profile_never_written(self):
        original = deepcopy(self.api.profiles[c.SOURCE]); self.ready(); self.op.stage(); self.op.apply()
        self.assertEqual(self.api.profiles[c.SOURCE], original)
        self.assertFalse(any(path == '/api/config-profiles/' and method == 'PATCH' for method,path,_ in self.api.writes))
        self.assertTrue(self.timer.active())

    def test_five_other_consumers_unchanged(self):
        original = {nid: deepcopy(n) for nid,n in self.api.nodes.items() if nid not in c.NODE_IDS}
        self.ready(); self.op.stage(); self.op.apply()
        self.assertEqual(original, {nid:n for nid,n in self.api.nodes.items() if nid not in c.NODE_IDS})

    def test_hosts_keep_everything_except_inbound(self):
        original = deepcopy(self.api.hosts); self.ready(); self.op.stage(); self.op.apply()
        for hid, old in original.items():
            actual = deepcopy(self.api.hosts[hid]); actual['inbound'] = old['inbound']
            self.assertEqual(old, actual)

    def test_clone_rights_preserve_existing_and_service_squad(self):
        self.ready(); self.op.stage(); self.op.apply()
        self.assertEqual({i['uuid'] for i in self.api.squads['base']['inbounds']}, {c.INBOUND,'existing-other','clone-inbound'})
        self.assertEqual(self.api.squads['unrelated']['inbounds'], [{'uuid':'service'}])

    def test_drift_blocks_before_any_stage_write(self):
        self.ready(); self.api.profiles[c.SOURCE]['config']['outbounds'].append({'protocol':'blackhole'})
        with self.assertRaises(RuntimeError): self.op.stage()
        self.assertEqual(self.api.writes, [])

    def test_stage_and_apply_are_resumable(self):
        self.ready(); self.op.stage(); self.op.stage(); self.op.apply(); self.op.apply()
        self.assertEqual(sum(method=='POST' for method,_,_ in self.api.writes),1)

    def rejected_name_intent(self):
        self.ready()
        self.store.put('stage-intent', {'timestamp': 999})
        self.timer.arm()
        self.store.put('clone-intent', dict(name='HAM-PC-MIHOMO-SIX-COMPAT-20260918',
                       sha256=self.op.load()['sha256'], timestamp=999))

    def test_rejected_old_name_one_explicit_proven_absent_retry(self):
        self.rejected_name_intent(); original = self.store.get('clone-intent')
        self.op.rearm_empty_stage()
        self.op.stage(); self.op.stage()
        self.assertEqual(sum(method=='POST' for method,_,_ in self.api.writes), 1)
        self.assertEqual(self.store.get('clone-intent'), original)
        self.assertTrue(self.store.get('clone-name-retry-intent')['old_and_new_absent'])

    def test_name_retry_never_overwrites_foreign_new_name(self):
        self.rejected_name_intent()
        self.op.rearm_empty_stage()
        self.api.profiles['foreign'] = dict(uuid='foreign', name=c.NAME, config=self.op.load()['candidate'], inbounds=[])
        with self.assertRaises(RuntimeError): self.op.stage()
        self.assertFalse(self.store.exists('clone-name-retry-intent'))
        self.assertEqual(self.api.writes, [])

    def test_uncertain_retry_never_reposts_without_created_object(self):
        self.rejected_name_intent()
        self.op.rearm_empty_stage()
        intent = self.store.get('clone-intent')
        self.store.put('clone-name-retry-intent', dict(old_name=intent['name'], name=c.NAME,
                       sha256=self.op.load()['sha256'], old_and_new_absent=True, timestamp=999))
        with self.assertRaises(RuntimeError): self.op.stage()
        self.assertEqual(self.api.writes, [])

    def test_invalid_name_stage_cannot_create_before_timer_retarget(self):
        self.rejected_name_intent()
        with self.assertRaises(RuntimeError): self.op.stage()
        self.assertEqual(self.api.writes, [])

    def test_retarget_requires_both_profile_names_absent(self):
        self.rejected_name_intent()
        self.api.profiles['foreign'] = dict(uuid='foreign',name=c.NAME)
        with self.assertRaises(RuntimeError): self.op.rearm_empty_stage()
        self.assertFalse(self.store.exists('empty-stage-rearmed'))

    def test_retarget_is_not_a_way_to_extend_active_deployment(self):
        self.ready(); self.op.stage(); self.op.apply()
        with self.assertRaises(RuntimeError): self.op.rearm_empty_stage()

    def test_partial_apply_can_rollback(self):
        original = deepcopy(self.api.hosts); self.ready(); self.op.stage(); self.api.fail_host_once = True
        with self.assertRaises(RuntimeError): self.op.apply()
        self.op.rollback()
        self.assertEqual(self.api.hosts, original)
        self.assertTrue(all(c.binding(self.api.nodes[nid])['activeConfigProfileUuid'] == c.SOURCE for nid in c.NODE_IDS))
        self.assertNotIn('clone-inbound', {i['uuid'] for i in self.api.squads['base']['inbounds']})

    def test_rollback_leaves_added_unrelated_permissions(self):
        self.ready(); self.op.stage(); self.op.apply()
        self.api.squads['base']['inbounds'].append({'uuid':'concurrent-other'})
        self.op.rollback()
        self.assertEqual({i['uuid'] for i in self.api.squads['base']['inbounds']}, {c.INBOUND,'existing-other','concurrent-other'})

    def test_rollback_refuses_foreign_clone_consumer(self):
        self.ready(); self.op.stage(); self.op.apply()
        self.api.nodes['foreign'] = deepcopy(next(self.api.nodes[nid] for nid in c.NODE_IDS))
        self.api.nodes['foreign']['uuid'] = 'foreign'
        with self.assertRaises(RuntimeError): self.op.rollback()

    def test_bad_proof_keeps_timer(self):
        self.ready(); self.op.stage(); self.op.apply(); self.subscription(); proof = self.proof(); proof['tests'][0]['exit_ip'] = '192.0.2.4'
        with self.assertRaises(RuntimeError): self.op.finish(proof)
        self.assertTrue(self.timer.active())

    def test_finish_requires_all24_and_disarms(self):
        self.ready(); self.op.stage(); self.op.apply(); self.subscription(); proof = self.proof()
        self.op.finish(proof); self.assertFalse(self.timer.active()); self.op.finish(proof)
        self.assertTrue(self.op.rollback()['rollback_skipped_finished'])

    def test_cached_traffic_alone_does_not_finish(self):
        self.ready(); self.op.stage(); self.op.apply()
        with self.assertRaises(KeyError): self.op.finish(self.proof())
        self.assertTrue(self.timer.active())

    def test_subscription_missing_auto_is_rejected(self):
        self.ready(); self.op.stage(); self.op.apply()
        with self.assertRaises(RuntimeError):
            self.op.accept_subscription(dict(sha256=self.op.load()['sha256'], timestamp=1000, passed=True,
                subscription_readback=[dict(id=key,mihomo_main_unchanged=True,happ_main_unchanged=True,happ_auto_unchanged=False)
                                       for key in c.TARGETS]))


if __name__ == '__main__': unittest.main()
