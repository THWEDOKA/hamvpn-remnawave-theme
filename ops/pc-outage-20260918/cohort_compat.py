"""Isolated compatibility clone for six new-core direct DE/NL nodes.

Never patches the shared G-CONFIG or its five non-target nodes. Existing host
UUIDs, keys, SNI, addresses, ports and user identities remain unchanged. Only
the selected node/profile assignments, host inbound bindings and equivalent
permissions to the clone are changed, under independent timed rollback.
"""
import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import reality_compat as base

require, digest = base.require, base.digest
SOURCE = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
INBOUND = '41b6c310-32dd-4845-acc6-816ed48e2ff9'
TAG = 'vless-reality-shared'
NEW_TAG = 'vless-reality-pc-six-20260918'
NAME = 'HAM-PC-SIX-COMPAT-20260918'
TARGETS = {
    'nl1': ('83.217.194.44', 'a4029bb7-a591-450a-913d-6f204d965629',
            '599df985-92a0-4865-b535-feb431ef7cb3', 'b803897d-e2fa-4698-99ce-49477a8c1bf6'),
    'nl2': ('132.243.117.133', '07d46063-d6a1-4339-94aa-91748c7f8e48',
            'a72a0060-2814-4843-8d01-50438f16cf91', 'a103c850-a930-4452-9d3b-ab478928f0b9'),
    'nl3': ('132.243.117.144', '52102a53-816a-40c2-a0fd-ab1225feefe2',
            '78f22080-0aef-4199-b518-a1b88bab828b', 'ef8410d3-6e71-4faf-9919-be86eded5689'),
    'nl4': ('83.217.194.71', '7b954bb3-72a7-4eaf-94da-08d492be5266',
            '9000eacb-4c58-465b-8a92-01a452b48e15', 'dacf8492-116a-40e4-bc78-54a15cc14dfb'),
    'de1': ('89.19.211.249', 'd6cd9021-7bcf-4917-9edd-4a637a724dcb',
            '104c5bf6-eb27-46fc-9d6c-13203c5cdf74', 'fc1916b6-2aeb-4d0a-a2e8-d3bf77247eae'),
    'de2': ('186.246.24.12', '19b6cd1d-3b69-4be7-af88-acf970496dd1',
            'f5220f4c-aad4-40e7-a5f7-c2e7d56e8e4e', '5036a874-a493-4320-b996-26f03f6c1346'),
}
NODE_IDS = {t[1] for t in TARGETS.values()}
HOST_IDS = {h for t in TARGETS.values() for h in t[2:]}


def valid_profile_name(name):
    # Installed Remnawave create-config-profile.command.js contract.
    return isinstance(name, str) and 2 <= len(name) <= 30 and re.fullmatch(r'[A-Za-z0-9_\s-]+', name) is not None


def binding(node):
    p = node['configProfile']
    return dict(activeConfigProfileUuid=p['activeConfigProfileUuid'],
                activeInbounds=sorted(i['uuid'] for i in p['activeInbounds']))


def stable_host(host):
    result = {k: v for k, v in host.items() if k not in ('createdAt', 'updatedAt')}
    if 'excludedInternalSquads' in result:
        values = [i['uuid'] if isinstance(i, dict) else i for i in result['excludedInternalSquads']]
        require(len(values) == len(set(values)), 'Duplicate host exclusions')
        result['excludedInternalSquads'] = sorted(values)
    return result


def candidate(config):
    result = deepcopy(config)
    require(len(result['inbounds']) == 1, 'Expected one source inbound')
    inbound = result['inbounds'][0]
    require(inbound['tag'] == TAG and inbound['port'] == 443 and inbound['protocol'] == 'vless',
            'Source inbound identity changed')
    stream = inbound['streamSettings']
    require(stream['security'] == 'reality', 'Expected REALITY')
    require('minClientVer' not in stream['realitySettings'], 'Refuse to overwrite explicit version policy')
    inbound['tag'] = NEW_TAG
    stream['realitySettings']['minClientVer'] = '1.8.2'
    for rule in result.get('routing', {}).get('rules', []):
        if 'inboundTag' in rule:
            require(isinstance(rule['inboundTag'], list), 'Unexpected routing tag representation')
            rule['inboundTag'] = [NEW_TAG if tag == TAG else tag for tag in rule['inboundTag']]
    return result


class Store(base.Store):
    def __init__(self):
        self.path = base.ROOT / 'gconf-six'


class Timer(base.Timer):
    def __init__(self):
        self.unit = 'ham-pc-gconf-six-rollback'

    def arm(self):
        require(not self.active(), 'Rollback timer already active')
        require(self.state('service')['ActiveState'] == 'inactive', 'Rollback service is not inactive')
        self.run(['systemd-run', '--unit=' + self.unit, '--on-active=900',
                  '--timer-property=AccuracySec=1s', '--property=UMask=0077',
                  '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback'])
        require(self.active(), 'Rollback timer was not armed')

    def verify_script(self):
        output = self.run(['systemctl', 'show', self.unit + '.service', '-p', 'ExecStart', '--value'])
        require(str(Path(__file__).resolve()) in output and 'rollback' in output,
                'Rollback service does not target the current published helper')
        return True


class Operation:
    def __init__(self, api, store, timer, clock=time.time):
        self.api, self.store, self.timer, self.clock = api, store, timer, clock

    def collect(self):
        nodes = {n['uuid']: n for n in self.api('GET', '/api/nodes/')}
        hosts = {h['uuid']: h for h in self.api('GET', '/api/hosts/')}
        squads = {s['uuid']: s for s in self.api('GET', '/api/internal-squads/')['internalSquads']}
        profile = self.api('GET', '/api/config-profiles/' + SOURCE)
        return nodes, hosts, squads, profile

    def plan(self):
        require(not self.store.exists('before'), 'Snapshot already exists')
        require(valid_profile_name(NAME), 'Clone name violates the installed API contract')
        ns, hs, ss, source = self.collect()
        require(source['uuid'] == SOURCE and {i['uuid'] for i in source['inbounds']} == {INBOUND}, 'Source metadata changed')
        for ip, nid, main, auto in TARGETS.values():
            n = ns[nid]
            require(n['address'] == ip and n['isConnected'] and not n['isDisabled'] and
                    n['versions']['xray'] == '26.7.28' and
                    binding(n) == dict(activeConfigProfileUuid=SOURCE, activeInbounds=[INBOUND]), 'Node scope changed')
            require({h['uuid'] for h in hs.values() if nid in h.get('nodes', [])} == {main, auto}, 'Unexpected target host')
            for hid, hidden in ((main, False), (auto, True)):
                h = hs[hid]
                require(h['nodes'] == [nid] and h['address'] == ip and h['port'] == 443 and
                        h['isHidden'] is hidden and not h['isDisabled'] and
                        h['inbound'] == dict(configProfileUuid=SOURCE, configProfileInboundUuid=INBOUND), 'Host scope changed')
        profiles = self.api('GET', '/api/config-profiles/')['configProfiles']
        require(not any(p['name'] == NAME for p in profiles), 'Clone name already exists')
        customers = {sid: sorted(i['uuid'] for i in s['inbounds']) for sid, s in ss.items()
                     if INBOUND in {i['uuid'] for i in s['inbounds']}}
        require(bool(customers), 'Source inbound has no permissions')
        other = {nid: dict(address=n['address'], binding=binding(n)) for nid, n in ns.items()
                 if nid not in NODE_IDS and (n.get('configProfile') or {}).get('activeConfigProfileUuid') == SOURCE}
        require(len(other) == 5, 'Unexpected shared-profile consumer set')
        new = candidate(source['config'])
        before = dict(source=source, nodes={nid: dict(address=ns[nid]['address'], binding=binding(ns[nid])) for nid in NODE_IDS},
                      others=other, hosts={hid: stable_host(hs[hid]) for hid in HOST_IDS},
                      rights=customers, initial_profiles=sorted(p['uuid'] for p in profiles),
                      candidate=new, sha256=digest(new), timestamp=self.clock())
        self.store.put('before', before)
        return dict(planned=True, nodes=6, hosts=12, protected_other_nodes=5, sha256=before['sha256'])

    def load(self):
        before = self.store.get('before')
        require(candidate(before['source']['config']) == before['candidate'] and
                digest(before['candidate']) == before['sha256'], 'Candidate integrity mismatch')
        return before

    def clone(self):
        if not self.store.exists('clone'):
            return None
        record = self.store.get('clone')
        profile = self.api('GET', '/api/config-profiles/' + record['profile'])
        require(profile['name'] == NAME and profile['config'] == self.load()['candidate'] and
                len(profile['inbounds']) == 1 and profile['inbounds'][0]['uuid'] == record['inbound'] and
                profile['inbounds'][0]['tag'] == NEW_TAG, 'Owned clone drift')
        return record

    def guard(self, complete=False, healthy=False):
        before = self.load(); ns, hs, ss, source = self.collect(); clone = self.clone()
        require(source['config'] == before['source']['config'], 'Shared profile changed')
        others = {nid: dict(address=n['address'], binding=binding(n)) for nid, n in ns.items()
                  if nid not in NODE_IDS and (n.get('configProfile') or {}).get('activeConfigProfileUuid') == SOURCE}
        require(others == before['others'], 'Protected shared consumers changed')
        newbind = dict(activeConfigProfileUuid=clone['profile'], activeInbounds=[clone['inbound']]) if clone else None
        newhost = dict(configProfileUuid=clone['profile'], configProfileInboundUuid=clone['inbound']) if clone else None
        for nid, old in before['nodes'].items():
            allowed = [newbind] if complete else [old['binding']] + ([newbind] if clone else [])
            require(ns[nid]['address'] == old['address'] and binding(ns[nid]) in allowed, 'Target binding drift')
            if healthy: require(ns[nid]['isConnected'] and not ns[nid]['isDisabled'], 'Target node unhealthy')
        for hid, old in before['hosts'].items():
            wanted = {**old, 'inbound': newhost} if clone else None
            allowed = [wanted] if complete else [old] + ([wanted] if clone else [])
            require(stable_host(hs[hid]) in allowed, 'Target host drift')
        if clone:
            require(not any(nid not in NODE_IDS and binding(n)['activeConfigProfileUuid'] == clone['profile']
                            for nid, n in ns.items() if n.get('configProfile')), 'Foreign node uses clone')
            require(not any(hid not in HOST_IDS and (h.get('inbound') or {}).get('configProfileUuid') == clone['profile']
                            for hid, h in hs.items()), 'Foreign host uses clone')
        for sid, old in before['rights'].items():
            actual = {i['uuid'] for i in ss[sid]['inbounds']}
            require(set(old) <= actual, 'Existing rights were removed')
            if complete: require(clone['inbound'] in actual, 'Clone permissions missing')
        if clone:
            require(not any(sid not in before['rights'] and clone['inbound'] in {i['uuid'] for i in s['inbounds']}
                            for sid, s in ss.items()), 'Unowned clone permission')
        return before, ns, hs, ss, clone

    def fresh(self, proof):
        require(proof.get('sha256') == self.load()['sha256'] and
                isinstance(proof.get('timestamp'), (int, float)) and 0 <= self.clock() - proof['timestamp'] < 900,
                'Stale or unrelated proof')

    def accept_installed(self, proof):
        self.guard(); self.fresh(proof)
        require(proof.get('passed') is True and proof.get('returncode') == 0 and
                proof.get('version') == '26.7.28', 'Installed Xray validation required')
        self.store.put('installed-proof', proof)
        return dict(installed_validation_accepted=True)

    def stage(self):
        before, _, _, _, clone = self.guard()
        require(not self.store.exists('finished') and not self.store.exists('rolled-back'), 'Operation is closed')
        self.fresh(self.store.get('installed-proof'))
        if not self.store.exists('stage-intent'):
            self.store.put('stage-intent', dict(timestamp=self.clock()))
            self.timer.arm()
        require(self.timer.active(), 'Rollback timer required')
        if not clone:
            if not self.store.exists('clone-intent'):
                require(valid_profile_name(NAME), 'Clone name violates the installed API contract')
                self.store.put('clone-intent', dict(name=NAME, sha256=before['sha256'], timestamp=self.clock()))
                result = self.api('POST', '/api/config-profiles/', dict(name=NAME, config=before['candidate']))
            else:
                intent = self.store.get('clone-intent')
                require(intent['sha256'] == before['sha256'], 'Original clone intent changed')
                profiles = self.api('GET', '/api/config-profiles/')['configProfiles']
                matches = [p for p in profiles if p['name'] == NAME]
                if intent['name'] != NAME:
                    require(isinstance(intent['name'], str) and len(intent['name']) > 30 and
                            valid_profile_name(NAME) and not any(p['name'] == intent['name'] for p in profiles),
                            'Old-name retry is not a proven rejected-name request')
                    require(self.store.exists('empty-stage-rearmed'), 'Retarget the old-version rollback before name retry')
                    rearmed = self.store.get('empty-stage-rearmed')
                    require(rearmed['name'] == NAME and rearmed['sha256'] == before['sha256'] and
                            rearmed['rollback_script_verified'] is True, 'Invalid retargeted rollback proof')
                    if not self.store.exists('clone-name-retry-intent'):
                        require(not matches, 'Retry target already exists without ownership intent')
                        self.store.put('clone-name-retry-intent', dict(old_name=intent['name'], name=NAME,
                            sha256=before['sha256'], old_and_new_absent=True, timestamp=self.clock()))
                        result = self.api('POST', '/api/config-profiles/', dict(name=NAME, config=before['candidate']))
                    else:
                        retry = self.store.get('clone-name-retry-intent')
                        require(retry['name'] == NAME and retry['old_name'] == intent['name'] and
                                retry['sha256'] == before['sha256'] and retry['old_and_new_absent'] is True and
                                len(matches) == 1, 'Uncertain name retry requires operator review')
                        result = self.api('GET', '/api/config-profiles/' + matches[0]['uuid'])
                else:
                    require(len(matches) == 1, 'Uncertain clone creation requires operator review')
                    result = self.api('GET', '/api/config-profiles/' + matches[0]['uuid'])
            require(result['name'] == NAME and result['config'] == before['candidate'] and
                    len(result['inbounds']) == 1 and result['inbounds'][0]['tag'] == NEW_TAG and
                    result['uuid'] not in before['initial_profiles'], 'Clone readback differs')
            self.store.put('clone', dict(profile=result['uuid'], inbound=result['inbounds'][0]['uuid']))
            clone = self.clone()
        for sid in before['rights']:
            _, _, _, ss, _ = self.guard()
            actual = {i['uuid'] for i in ss[sid]['inbounds']}
            marker = 'grant-' + sid
            if not self.store.exists(marker): self.store.put(marker, dict(added=clone['inbound']))
            if clone['inbound'] not in actual:
                self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=sorted(actual | {clone['inbound']})))
        self.guard()
        if not self.store.exists('staged'): self.store.put('staged', dict(timestamp=self.clock()))
        return dict(staged=True, sha256=before['sha256'])

    def rearm_empty_stage(self):
        before, ns, hs, _, clone = self.guard()
        require(clone is None and self.store.exists('stage-intent') and self.store.exists('clone-intent') and
                not any(self.store.exists(k) for k in ('clone', 'clone-name-retry-intent', 'staged', 'apply-intent',
                                                      'applied', 'finished', 'rolled-back', 'empty-stage-rearmed')),
                'Only the unmutated rejected-name stage can be retargeted')
        require(all(binding(ns[nid]) == old['binding'] for nid, old in before['nodes'].items()) and
                all(stable_host(hs[hid]) == old for hid, old in before['hosts'].items()) and
                not any(self.store.exists('grant-' + sid) for sid in before['rights']), 'Live bindings or grants were already changed')
        intent = self.store.get('clone-intent')
        require(intent['sha256'] == before['sha256'] and intent['name'] != NAME and
                isinstance(intent['name'], str) and len(intent['name']) > 30 and valid_profile_name(NAME),
                'Not the rejected invalid-name request')
        profiles = self.api('GET', '/api/config-profiles/')['configProfiles']
        require(not any(p['name'] in (NAME, intent['name']) for p in profiles), 'Clone exists; empty-stage retarget is unsafe')
        if not self.store.exists('empty-stage-rearm-intent'):
            self.store.put('empty-stage-rearm-intent', dict(timestamp=self.clock(), name=NAME,
                sha256=before['sha256'], script=str(Path(__file__).resolve()), old_and_new_absent=True))
        self.timer.cancel()  # verifies both old timer and service are inactive
        self.timer.arm()     # uses this verified release's own __file__
        require(self.timer.verify_script(), 'New rollback target is not verified')
        self.store.put('empty-stage-rearmed', dict(timestamp=self.clock(), name=NAME, sha256=before['sha256'],
            script=str(Path(__file__).resolve()), rollback_script_verified=True))
        return dict(empty_stage_rearmed=True, rollback_seconds=900, sha256=before['sha256'])

    def apply(self):
        before, _, _, _, clone = self.guard(healthy=True)
        require(self.store.exists('staged') and self.timer.active() and not self.store.exists('finished') and
                not self.store.exists('rolled-back'), 'Staged rollback-protected operation required')
        if not self.store.exists('apply-intent'): self.store.put('apply-intent', dict(timestamp=self.clock()))
        newbind = dict(activeConfigProfileUuid=clone['profile'], activeInbounds=[clone['inbound']])
        newhost = dict(configProfileUuid=clone['profile'], configProfileInboundUuid=clone['inbound'])
        for ip, nid, main, auto in TARGETS.values():
            _, ns, hs, _, _ = self.guard()
            if binding(ns[nid]) != newbind:
                self.api('PATCH', '/api/nodes/', dict(uuid=nid, configProfile=newbind))
            for hid in (main, auto):
                if hs[hid]['inbound'] != newhost:
                    self.api('PATCH', '/api/hosts/', dict(uuid=hid, inbound=newhost))
            self.guard()
        self.guard(complete=True)
        if not self.store.exists('applied'): self.store.put('applied', dict(timestamp=self.clock()))
        return dict(applied=True, nodes=6, hosts=12, sha256=before['sha256'])

    def rollback(self):
        if self.store.exists('finished'): return dict(rollback_skipped_finished=True)
        before, ns, hs, ss, clone = self.guard()
        require(self.store.exists('stage-intent'), 'No owned stage attempt')
        for hid, old in before['hosts'].items():
            if hs[hid]['inbound'] != old['inbound']:
                self.api('PATCH', '/api/hosts/', dict(uuid=hid, inbound=old['inbound']))
        for nid, old in before['nodes'].items():
            if binding(ns[nid]) != old['binding']:
                self.api('PATCH', '/api/nodes/', dict(uuid=nid, configProfile=old['binding']))
        if clone:
            for sid in before['rights']:
                _, _, _, live, _ = self.guard()
                actual = {i['uuid'] for i in live[sid]['inbounds']}
                if clone['inbound'] in actual:
                    require(self.store.exists('grant-' + sid), 'Clone grant has no ownership intent')
                    self.api('PATCH', '/api/internal-squads/', dict(uuid=sid, inbounds=sorted(actual - {clone['inbound']})))
        _, ns, hs, _, _ = self.guard()
        require(all(binding(ns[nid]) == old['binding'] for nid, old in before['nodes'].items()) and
                all(stable_host(hs[hid]) == old for hid, old in before['hosts'].items()), 'Rollback readback differs')
        if not self.store.exists('rolled-back'): self.store.put('rolled-back', dict(timestamp=self.clock()))
        return dict(rolled_back=True, inactive_clone_retained=bool(clone))

    def accept_subscription(self, proof):
        self.guard(complete=True, healthy=True); self.fresh(proof)
        require(self.store.exists('applied') and proof['timestamp'] >= self.store.get('applied')['timestamp'],
                'Fresh post-deployment subscription required')
        rows = proof.get('subscription_readback', [])
        require(proof.get('passed') is True and len(rows) == 6 and {row.get('id') for row in rows} == set(TARGETS) and
                all(row.get('mihomo_main_unchanged') is True and row.get('happ_main_unchanged') is True and
                    row.get('happ_auto_unchanged') is True for row in rows), 'Fresh main/auto wire readback failed')
        self.store.put('subscription-proof', proof)
        return dict(fresh_subscription_verified=True)

    def finish(self, proof):
        before, *_ = self.guard(complete=True, healthy=True)
        if self.store.exists('finished'):
            require(self.store.get('traffic-proof') == proof, 'Cannot replace accepted proof')
            if self.timer.active(): self.timer.cancel()
            return dict(finished=True, rollback_disarmed=True)
        require(self.store.exists('applied') and self.timer.active() and not self.store.exists('rolled-back'), 'No pending deployment')
        self.fresh(proof)
        self.fresh(self.store.get('subscription-proof'))
        require(proof['timestamp'] >= self.store.get('applied')['timestamp'], 'Proof predates deployment')
        wanted = {key + '-' + core + '-' + fp: value[0] for key, value in TARGETS.items()
                  for core in ('mihomo', 'xray') for fp in ('firefox', 'chrome')}
        tests = proof.get('tests', [])
        require(len(tests) == 24 and {t.get('id') for t in tests} == set(wanted), '24 protocol tests required')
        require(all(t.get('http') == '204' and t.get('exit_ip') == wanted[t['id']] and
                    t.get('curl_codes') == [0, 0] and t.get('listener_removed') is True for t in tests), 'End-to-end test failed')
        delays = proof.get('live_mihomo_delays', {})
        require(set(delays) == set(TARGETS) and all(isinstance(v, (int, float)) and v > 0 for v in delays.values()),
                'Running client delay proof required for all six')
        self.store.put('traffic-proof', proof)
        self.store.put('finished', dict(timestamp=self.clock(), sha256=before['sha256']))
        self.timer.cancel()
        return dict(finished=True, rollback_disarmed=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'export-candidate', 'accept-installed', 'rearm-empty-stage', 'stage', 'apply', 'rollback', 'accept-subscription', 'finish', 'status'])
    parser.add_argument('--secret-stdout', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'selfsteal-us3'))
    from panel_api import create_client
    api, _ = create_client(); store = Store(); op = Operation(api, store, Timer())
    with store.locked():
        if args.action == 'export-candidate':
            require(args.secret_stdout, 'Private RAM/stdin pipe required'); result = op.load()['candidate']
        elif args.action in ('accept-installed', 'accept-subscription', 'finish'):
            result = getattr(op, args.action.replace('-', '_'))(json.load(sys.stdin))
        elif args.action == 'status':
            before, _, _, _, clone = op.guard()
            result = dict(sha256=before['sha256'], clone_staged=bool(clone), applied=store.exists('applied'),
                          finished=store.exists('finished'), rollback_active=op.timer.active())
        else: result = getattr(op, args.action.replace('-', '_'))()
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__, message='Cohort operation stopped; inspect private state')), file=sys.stderr)
        sys.exit(1)
