"""Guarded two-profile migration, preserving public and autoselect Hosts."""
import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid
from common import *
import model as m

ENTRY_NODE = '560e38b3-6ee8-4f10-861e-e2f1eddd4caa'
EXIT_NODE = '3770a3f9-5a88-4d5d-aef5-7b43d12767d1'
EP = '8deddcaa-fd80-46ed-ac48-e4c5e93b0271'
XP = 'd354e2ac-4b86-40a7-a0b3-ef9499d329b1'
HOST = '4495a293-bf41-401e-a723-445d5b5a9c5e'
HIDDEN = 'e60e3d17-e29c-4981-9f25-799019e0415c'
NEIGHBORS = ['d2a759f8-e9b6-4b7c-9e91-c1663a2fb39d', 'fb8c9f85-07d9-4248-99c2-c1163c853bee', '6f4f2a94-d4b2-40ff-800e-de93d725567c']
TIMER = 'ham-rs633-nl5-rollback'
CLONE_NAME = 'HAM-NL5-REVERSE-AEZA633'


def client():
    path = Path(__file__).resolve().parents[1] / 'selfsteal-us3/panel_api.py'
    spec = importlib.util.spec_from_file_location('private_api', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.create_client()


def binding(n):
    c = n['configProfile']
    values = [i['uuid'] if isinstance(i, dict) else i for i in c['activeInbounds']]
    require(len(values) == len(set(values)), 'Duplicate binding')
    return {'activeConfigProfileUuid': c['activeConfigProfileUuid'], 'activeInbounds': sorted(values)}


def prepare():
    api, _ = client(); require(not (STATE / 'panel-before.json').exists(), 'Existing operation')
    profiles = {p: api('GET', '/api/config-profiles/' + p) for p in [EP, XP]}
    require([n['uuid'] for n in profiles[EP]['nodes']] == [ENTRY_NODE], 'Entry profile shared/drift')
    require(EXIT_NODE in [n['uuid'] for n in profiles[XP]['nodes']], 'Exit profile drift')
    nodes = {n: api('GET', '/api/nodes/' + n) for n in [ENTRY_NODE, EXIT_NODE]}
    require(nodes[ENTRY_NODE]['address'] == m.ENTRY and nodes[EXIT_NODE]['address'] == m.EXIT, 'Node identity mismatch')
    hosts = {h: api('GET', '/api/hosts/' + h) for h in [HOST, HIDDEN] + NEIGHBORS}
    require(all(hosts[h]['address'] == m.ENTRY and hosts[h]['port'] == 18445 for h in [HOST, HIDDEN]), 'Target host drift')
    all_nodes = api('GET', '/api/nodes/')
    before = {'profiles': profiles, 'nodes': nodes, 'hosts': hosts,
              'initial_profiles': [p['uuid'] for p in api('GET', '/api/config-profiles/')['configProfiles']],
              'all_hosts': api('GET', '/api/hosts/'),
              'other_bindings': {n['uuid']: binding(n) for n in all_nodes if n['uuid'] != EXIT_NODE},
              'squads': api('GET', '/api/internal-squads/')['internalSquads'], 'time': time.time()}
    require(not any(EXIT_NODE in h.get('nodes', []) for h in before['all_hosts']),
            'Direct node Hosts require explicit reference mapping')
    save('panel-before', before); require(read('panel-before') == before, 'Snapshot readback')
    private = run('openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER')
    public = run('openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER', data=private)
    require(len(private) == 48 and len(public) == 44, 'Key format')
    enc = lambda b: base64.urlsafe_b64encode(b[-32:]).decode().rstrip('=')
    short = secrets.token_hex(8)
    save('plan', {'exit': m.backend(profiles[XP]['config'], enc(private), short),
                  'public': enc(public), 'short': short, 'service_id': str(uuid.uuid4())})
    save('old-wire', next(o for o in profiles[EP]['config']['outbounds'] if o.get('tag') == 'exit-nl82'))
    return {'panel_snapshot': True, 'sha256': sha(before)}


def accept_backup():
    proof = json.load(sys.stdin)
    require(proof.get('external_copy_verified') and proof['sha256'] == sha(read('panel-before')), 'Panel external backup required')
    save('external-proof-panel', proof); return {'panel_backup_gate_passed': True}


def status():
    out = {}
    for suffix in ['timer', 'service']:
        p = subprocess.run(['systemctl', 'show', TIMER + '.' + suffix, '-p', 'LoadState,ActiveState,Job'], capture_output=True, text=True)
        out[suffix] = dict(x.split('=', 1) for x in p.stdout.splitlines() if '=' in x)
    return out


def arm():
    require(read('external-proof-panel')['sha256'] == sha(read('panel-before')), 'Backup required')
    require(all(v.get('ActiveState') == 'inactive' for v in status().values()), 'Rollback not idle')
    run('systemd-run', '--quiet', '--unit=' + TIMER, '--on-active=25m', '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback')
    require(status()['timer']['ActiveState'] == 'active', 'Rollback missing')
    return {'rollback_armed': True}


def create_probe():
    api, _ = client(); before = read('panel-before')
    require(not (STATE / 'probe-intent.json').exists(), 'Probe intent exists')
    target = before['hosts'][HOST]['inbound']['configProfileInboundUuid']
    excluded = set(before['hosts'][HOST].get('excludedInternalSquads') or [])
    squads = [s['uuid'] for s in before['squads'] if target in [i['uuid'] for i in s['inbounds']] and s['uuid'] not in excluded]
    require(squads, 'No target customer rights')
    ident = str(uuid.uuid4()); body = {'uuid': ident, 'username': 'rs633_nl5_probe_' + ident[:8],
        'expireAt': (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(),
        'trafficLimitBytes': 1073741824, 'trafficLimitStrategy': 'NO_RESET', 'tag': 'RS633_NL5_PROBE',
        'description': 'Temporary reverse NL5 validation', 'activeInternalSquads': [squads[0]]}
    save('probe-intent', body); save('probe', api('POST', '/api/users/', body))
    return exports()


def exports():
    api, _ = client(); user = read('probe'); sub = api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/5.7.0',
        'X-Hwid': 'ham-rs633-nl5-owned-probe', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=25) as r: configs = json.load(r)
    save('actual-subscription', configs)
    wires = {}
    for ident, host in read('panel-before')['hosts'].items():
        if ident == HIDDEN: continue
        candidates = [c for c in configs if c.get('remarks') == host['remark']]
        if not candidates: continue
        matching = [o for o in candidates[0]['outbounds'] if any(
            v.get('address') == host['address'] and v.get('port') == host['port'] for v in o.get('settings', {}).get('vnext', []))]
        require(len(matching) == 1, 'Export ambiguous')
        wires['main' if ident == HOST else 'neighbor-' + str(host['port'])] = matching[0]
    require('main' in wires and len(wires) == 4, 'Main/neighbor exports missing')
    auto = []
    for c in configs:
        if 'автовыбор' not in c.get('remarks', '').lower(): continue
        for o in c.get('outbounds', []):
            if any(v.get('address') == m.ENTRY and v.get('port') == 18445 for v in o.get('settings', {}).get('vnext', [])): auto.append(o)
    if auto: wires['auto-member'] = auto[0]
    save('export-wires', wires)
    if not (STATE / 'exports-before.json').exists(): save('exports-before', wires)
    else: require(wires == read('exports-before'), 'Client exports changed')
    return {'visible_export': True, 'neighbor_exports': 3, 'auto_member_export': bool(auto)}


def stage():
    api, _ = client(); before = read('panel-before'); plan = read('plan'); proof = json.load(sys.stdin)
    require(proof.get('tested') and proof['sha256'] == sha(plan['exit']), 'Installed exit test required')
    require(status()['timer']['ActiveState'] == 'active', 'Rollback required')
    require(api('GET', '/api/config-profiles/' + XP)['config'] == before['profiles'][XP]['config'], 'Exit drift')
    require(binding(api('GET', '/api/nodes/' + EXIT_NODE)) == binding(before['nodes'][EXIT_NODE]), 'Exit binding drift')
    save('stage-intent', {'time': time.time()})
    require(not (STATE / 'clone-intent.json').exists(), 'Clone intent exists; reconcile instead of repeating')
    save('clone-intent', {'name': CLONE_NAME, 'config_sha256': sha(plan['exit'])})
    p = api('POST', '/api/config-profiles/', {'name': CLONE_NAME, 'config': plan['exit']})
    require(p['uuid'] not in before['initial_profiles'] and p['config'] == plan['exit'], 'Clone readback/ownership')
    old_tags = {i['tag']: i['uuid'] for i in before['profiles'][XP]['inbounds']}
    new_tags = {i['tag']: i['uuid'] for i in p['inbounds']}
    require(len(new_tags) == len(p['inbounds']) and set(new_tags) == set(old_tags) | {m.TAG}, 'Clone tag mapping')
    inbound = new_tags[m.TAG]
    mapping = {old_id: new_tags[tag] for tag, old_id in old_tags.items()}
    objects = {'profile': p['uuid'], 'inbound': inbound, 'mapping': mapping}; save('objects', objects)
    # Preserve legacy users on the cloned public 443. Never change the shared profile.
    for squad in before['squads']:
        old_ids = [i['uuid'] for i in squad['inbounds']]
        additions = {mapping[i] for i in old_ids if i in mapping}
        if not additions: continue
        live = api('GET', '/api/internal-squads/' + squad['uuid'])
        require({i['uuid'] for i in live['inbounds']} == set(old_ids), 'Squad drift before clone rights')
        wanted_ids = sorted(set(old_ids) | additions)
        api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': wanted_ids})
        require({i['uuid'] for i in api('GET', '/api/internal-squads/' + squad['uuid'])['inbounds']} == set(wanted_ids), 'Clone rights readback')
    s = api('POST', '/api/internal-squads/', {'name': 'HAM-RS633-NL5-SVC', 'inbounds': [inbound]})
    objects['squad'] = s['uuid']; save('objects', objects)
    body = {'uuid': plan['service_id'], 'username': 'ham_rs633_nl5_service', 'status': 'ACTIVE',
        'expireAt': '2036-09-18T00:00:00Z', 'trafficLimitBytes': 0, 'trafficLimitStrategy': 'NO_RESET',
        'tag': 'RS633_NL5_SVC', 'description': 'Dedicated loopback reverse Reality service', 'activeInternalSquads': [s['uuid']]}
    save('service-intent', body); user = api('POST', '/api/users/', body); save('service', user)
    old_binding = binding(before['nodes'][EXIT_NODE])
    wanted = {'activeConfigProfileUuid': p['uuid'],
              'activeInbounds': sorted([mapping[i] for i in old_binding['activeInbounds']] + [inbound])}
    save('wanted-binding', wanted); api('PATCH', '/api/nodes/', {'uuid': EXIT_NODE, 'configProfile': wanted})
    wire = m.wire(user['vlessUuid'], plan['public'], plan['short']); save('wire', wire)
    save('entry-candidate', m.entry(before['profiles'][EP]['config'], wire))
    return {'dedicated_loopback_backend_staged': True, 'legacy_443_preserved': True}


def accept_probe():
    proof = json.load(sys.stdin)
    require(proof.get('passed') and proof['location'] == 'entry' and proof['wire_sha256'] == sha(read('wire'))
        and 0 <= time.time() - proof['time'] < 900, 'Fresh backend proof required')
    name = 'backend-proof-2' if (STATE / 'backend-proof-1.json').exists() else 'backend-proof-1'
    save(name, proof); return {'accepted': name}


def apply():
    api, _ = client(); before = read('panel-before'); proof = json.load(sys.stdin); candidate = read('entry-candidate')
    require(proof.get('tested') and proof['sha256'] == sha(candidate), 'Installed entry test required')
    for label in ['backend-proof-1', 'backend-proof-2']:
        p = read(label); require(p['passed'] and p['wire_sha256'] == sha(read('wire')) and 0 <= time.time() - p['time'] < 900, 'Backend proof missing/stale')
    require(status()['timer']['ActiveState'] == 'active', 'Rollback required')
    require(api('GET', '/api/config-profiles/' + EP)['config'] == before['profiles'][EP]['config'], 'Entry drift')
    save('apply-intent', {'time': time.time()})
    api('PATCH', '/api/config-profiles/', {'uuid': EP, 'config': candidate})
    require(api('GET', '/api/config-profiles/' + EP)['config'] == candidate, 'Entry readback')
    return {'only_nl5_outbound_migrated': True}


def verify():
    api, _ = client(); before = read('panel-before'); candidate = read('entry-candidate')
    require(api('GET', '/api/config-profiles/' + EP)['config'] == candidate, 'Entry config drift')
    obj = read('objects')
    require(api('GET', '/api/config-profiles/' + XP)['config'] == before['profiles'][XP]['config'], 'Shared profile changed')
    require(api('GET', '/api/config-profiles/' + obj['profile'])['config'] == read('plan')['exit'], 'Clone config drift')
    for ident, host in before['hosts'].items(): require(api('GET', '/api/hosts/' + ident) == host, 'Host drift')
    require(binding(api('GET', '/api/nodes/' + ENTRY_NODE)) == binding(before['nodes'][ENTRY_NODE]), 'Entry binding drift')
    require(binding(api('GET', '/api/nodes/' + EXIT_NODE)) == read('wanted-binding'), 'Exit binding drift')
    require({n['uuid']: binding(n) for n in api('GET', '/api/nodes/') if n['uuid'] != EXIT_NODE} == before['other_bindings'], 'Other node binding changed')
    require(api('GET', '/api/hosts/') == before['all_hosts'], 'Host inventory changed')
    require([n['uuid'] for n in api('GET', '/api/config-profiles/' + obj['profile'])['nodes']] == [EXIT_NODE], 'Clone has unexpected consumers')
    for old in before['squads']:
        old_ids = {i['uuid'] for i in old['inbounds']}
        wanted_ids = old_ids | {obj['mapping'][i] for i in old_ids if i in obj['mapping']}
        live = api('GET', '/api/internal-squads/' + old['uuid'])
        require({i['uuid'] for i in live['inbounds']} == wanted_ids, 'Legacy rights mapping changed')
    rights = [s['uuid'] for s in api('GET', '/api/internal-squads/')['internalSquads'] if obj['inbound'] in [i['uuid'] for i in s['inbounds']]]
    require(rights == [obj['squad']], 'Backend rights not isolated')
    require(all(api('GET', '/api/nodes/' + n)['isConnected'] for n in [ENTRY_NODE, EXIT_NODE]), 'Node disconnected')
    return {'entry_candidate_active': True, 'hosts_and_neighbors_preserved': True, 'backend_rights_isolated': True}


def finish():
    result = verify(); proofs = json.load(sys.stdin); exports = read('export-wires')
    require(set(proofs) == set(exports), 'All real exported paths must be checked')
    for label, proof in proofs.items():
        require(proof.get('checks') and proof['wire_sha256'] == sha(exports[label])
                and 0 <= time.time() - proof['time'] < 900, 'Missing/stale exported client proof: ' + label)
        # Do not expand a one-exit migration into repairs of already-failing neighbors.
        # Their unchanged config/exports are guarded by verify()/exports().
        if not label.startswith('neighbor-') or read('baseline-proofs')[label]['passed']:
            require(proof.get('passed'), 'Client regression: ' + label)
    pc = read('pc-proof')
    require(pc['passed'] and 0 <= time.time() - pc['time'] < 900, 'Fresh real mihomo proof required')
    require(status()['service']['ActiveState'] == 'inactive', 'Rollback already executing')
    run('systemctl', 'stop', TIMER + '.timer')
    require(all(v['ActiveState'] == 'inactive' for v in status().values()), 'Rollback not inactive')
    require(not (STATE / 'rolled-back.json').exists(), 'Rollback marker exists')
    result['clients_passed'] = True; result['time'] = time.time()
    save('finished', {'result': result, 'proofs': proofs})
    return dict(result, rollback_timer_and_service_inactive=True)


def cleanup():
    verify(); read('finished'); api, query = client(); p = read('probe')
    cur = api('GET', '/api/users/' + p['uuid'])
    require(cur['username'] == p['username'] and cur['tag'] == p['tag'], 'Probe ownership conflict')
    api('DELETE', '/api/users/' + p['uuid'])
    require(query("SELECT to_json(count(*)) FROM users WHERE uuid='" + str(uuid.UUID(p['uuid'])) + "'") == 0, 'Probe not removed')
    save('cleaned', {'time': time.time()}); return {'temporary_user_removed': True}


def rollback():
    api, _ = client(); before = read('panel-before')
    current = api('GET', '/api/config-profiles/' + EP)['config']
    if (STATE / 'entry-candidate.json').exists() and current == read('entry-candidate'):
        api('PATCH', '/api/config-profiles/', {'uuid': EP, 'config': before['profiles'][EP]['config']})
    else: require(current == before['profiles'][EP]['config'], 'Entry conflict; preserve external changes')
    if (STATE / 'wanted-binding.json').exists():
        current = binding(api('GET', '/api/nodes/' + EXIT_NODE))
        require(current in [binding(before['nodes'][EXIT_NODE]), read('wanted-binding')], 'Exit binding conflict')
        api('PATCH', '/api/nodes/', {'uuid': EXIT_NODE, 'configProfile': binding(before['nodes'][EXIT_NODE])})
    require(api('GET', '/api/config-profiles/' + XP)['config'] == before['profiles'][XP]['config'], 'Shared profile conflict; never overwrite')
    if (STATE / 'clone-intent.json').exists() and not (STATE / 'objects.json').exists():
        matches = [p for p in api('GET', '/api/config-profiles/')['configProfiles'] if p['name'] == CLONE_NAME]
        require(len(matches) <= 1, 'Ambiguous pending clone')
        if matches:
            p = api('GET', '/api/config-profiles/' + matches[0]['uuid'])
            require(p['uuid'] not in before['initial_profiles'] and p['config'] == read('plan')['exit'] and not p['nodes'], 'Pending clone ownership')
            # Lost creation response: no subsequent write could have occurred.
    if (STATE / 'objects.json').exists():
        obj = read('objects')
        clone = api('GET', '/api/config-profiles/' + obj['profile'])
        require(clone['config'] == read('plan')['exit'] and not clone['nodes'], 'Clone ownership conflict')
        owned = set(obj['mapping'].values())
        for squad in api('GET', '/api/internal-squads/')['internalSquads']:
            ids = {i['uuid'] for i in squad['inbounds']}
            if ids & owned:
                require(squad['uuid'] in {s['uuid'] for s in before['squads']}, 'Unexpected clone-rights consumer')
                api('PATCH', '/api/internal-squads/', {'uuid': squad['uuid'], 'inbounds': sorted(ids - owned)})
    # Stop no SSH service here: the previous tunnel stays active throughout this window.
    # Owned service accounts are retained disabled for explicit post-rollback cleanup.
    if (STATE / 'service.json').exists():
        u = read('service'); cur = api('GET', '/api/users/' + u['uuid'])
        require(cur['username'] == u['username'], 'Service ownership conflict')
        api('PATCH', '/api/users/', {'uuid': u['uuid'], 'status': 'DISABLED'})
    save('rolled-back', {'time': time.time()}); return {'old_route_restored': True}


if __name__ == '__main__':
    cli({k: globals()[k] for k in ['prepare', 'accept_backup', 'arm', 'create_probe', 'exports',
        'stage', 'accept_probe', 'apply', 'verify', 'finish', 'cleanup', 'rollback']})
