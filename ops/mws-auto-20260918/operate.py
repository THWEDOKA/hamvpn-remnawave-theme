"""Explicit, scoped API actions. Runtime state and credentials stay root-only."""
import argparse
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import uuid
import model

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'selfsteal-us3'))
from panel_api import create_client

STATE = Path('/root/ham-mws-auto-20260918')
AUTO = '19fa6ed1-383d-4480-8599-9f8f9348596d'
MWS = '0ff01c25-aca4-438a-addb-2ef1605a6a95'
NODE = '1e84ccc1-eb12-404b-9aa4-3e3619c6fc05'
AUTO_NODE = '69721cba-c85d-4118-88d1-3f7b9ef0ffb0'
AUTO_HOST = '34ac77b5-530a-4a70-a4b6-edec850f0035'
TIMER = 'ham-mws-auto-rollback'


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def sha(obj): return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def save(name, obj):
    STATE.mkdir(mode=0o700, exist_ok=True)
    require(STATE.stat().st_mode & 0o077 == 0 and not STATE.is_symlink(), 'Unsafe state')
    target = STATE / (name + '.json')
    pending = target.with_suffix('.pending')
    with pending.open('x', encoding='utf-8') as f:
        os.chmod(pending, 0o600); json.dump(obj, f, ensure_ascii=False); f.flush(); os.fsync(f.fileno())
    pending.replace(target)


def read(name):
    p = STATE / (name + '.json')
    require(not p.is_symlink() and p.stat().st_mode & 0o077 == 0, 'Unsafe private file')
    return json.loads(p.read_text())


def binding(node):
    c = node['configProfile']
    return {'activeConfigProfileUuid': c['activeConfigProfileUuid'],
            'activeInbounds': sorted(i['uuid'] if isinstance(i, dict) else i for i in c['activeInbounds'])}


def prepare():
    api, _ = create_client()
    require(not (STATE / 'before.json').exists(), 'Existing operation; reconcile instead of replacing backup')
    profiles = {p: api('GET', '/api/config-profiles/' + p) for p in [AUTO, MWS]}
    require([n['uuid'] for n in profiles[AUTO]['nodes']] == [AUTO_NODE], 'Auto profile shared/drift')
    require([n['uuid'] for n in profiles[MWS]['nodes']] == [NODE], 'MWS profile shared/drift')
    before = {'profiles': profiles, 'node': api('GET', '/api/nodes/' + NODE),
              'hosts': api('GET', '/api/hosts/'), 'time': time.time()}
    save('before', before); require(read('before') == before, 'Backup readback')
    private = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'X25519', '-outform', 'DER'])
    public = subprocess.check_output(['openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'], input=private)
    require(len(private) == 48 and len(public) == 44, 'Key format')
    enc = lambda b: base64.urlsafe_b64encode(b[-32:]).decode().rstrip('=')
    short = secrets.token_hex(8)
    save('plan', {'mws': model.backend(profiles[MWS]['config'], enc(private), short),
                  'public': enc(public), 'short': short, 'identity': str(uuid.uuid4())})
    return {'prepared': True, 'backup_sha256': sha(before)}


def status():
    result = {}
    for suffix in ['timer', 'service']:
        p = subprocess.run(['systemctl', 'show', TIMER + '.' + suffix, '-p', 'ActiveState,LoadState,Job'], capture_output=True, text=True)
        result[suffix] = dict(x.split('=', 1) for x in p.stdout.splitlines() if '=' in x)
    return result


def arm():
    read('before')
    require(all(x.get('ActiveState') == 'inactive' for x in status().values()), 'Rollback not idle')
    subprocess.run(['systemd-run', '--quiet', '--unit=' + TIMER, '--on-active=25m',
                    '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback'], check=True)
    require(status()['timer']['ActiveState'] == 'active', 'Rollback missing')
    return {'rollback_armed': True}


def stage():
    api, _ = create_client(); before = read('before'); plan = read('plan')
    proof = json.load(sys.stdin)
    require(proof.get('tested') and proof.get('sha256') == sha(plan['mws']), 'Installed MWS config test required')
    require(status()['timer']['ActiveState'] == 'active', 'Rollback required')
    require(api('GET', '/api/config-profiles/' + MWS)['config'] == before['profiles'][MWS]['config'], 'MWS drift')
    require(binding(api('GET', '/api/nodes/' + NODE)) == binding(before['node']), 'Node binding drift')
    save('stage-intent', {'time': time.time()})
    p = api('PATCH', '/api/config-profiles/', {'uuid': MWS, 'config': plan['mws']})
    p = api('GET', '/api/config-profiles/' + MWS)
    inbound = next(i['uuid'] for i in p['inbounds'] if i['tag'] == model.BACKEND)
    save('objects', {'inbound': inbound})
    squad = api('POST', '/api/internal-squads/', {'name': 'HAM-AUTO-MWS2-SVC', 'inbounds': [inbound]})
    objects = read('objects'); objects['squad'] = squad['uuid']; save('objects', objects)
    body = {'uuid': plan['identity'], 'username': 'ham_auto_mws2_service', 'status': 'ACTIVE',
            'expireAt': '2036-09-18T00:00:00Z', 'trafficLimitBytes': 0, 'trafficLimitStrategy': 'NO_RESET',
            'tag': 'AUTO_MWS2_SVC', 'description': 'Private Selectal to MWS backend; not a customer',
            'activeInternalSquads': [squad['uuid']]}
    save('service-intent', body)
    user = api('POST', '/api/users/', body); save('service', user)
    wanted = binding(before['node']); wanted['activeInbounds'].append(inbound); wanted['activeInbounds'].sort()
    save('wanted-binding', wanted)
    api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': wanted})
    wire = model.wire(user['vlessUuid'], plan['public'], plan['short']); save('wire', wire)
    save('auto-candidate', model.candidate(before['profiles'][AUTO]['config'], wire))
    return {'backend_staged': True, 'port': model.PORT, 'customer_hosts_untouched': True}


def apply():
    api, _ = create_client(); before = read('before'); candidate = read('auto-candidate')
    proof = json.load(sys.stdin)
    require(proof.get('tested') and proof['sha256'] == sha(candidate), 'Installed auto config proof required')
    backend = read('backend-proof')
    require(backend.get('passed') and backend['wire_sha256'] == sha(read('wire')) and
            0 <= time.time() - backend['time'] < 1800, 'Fresh real Selectal backend proof required')
    require(status()['timer']['ActiveState'] == 'active', 'Rollback required')
    require(api('GET', '/api/config-profiles/' + AUTO)['config'] == before['profiles'][AUTO]['config'], 'Auto drift')
    save('apply-intent', {'time': time.time()})
    api('PATCH', '/api/config-profiles/', {'uuid': AUTO, 'config': candidate})
    require(api('GET', '/api/config-profiles/' + AUTO)['config'] == candidate, 'Auto readback failed')
    return {'auto_candidate_applied': True}


def create_probe():
    api, _ = create_client()
    require(not (STATE / 'probe-intent.json').exists(), 'Probe exists; reconcile')
    host = api('GET', '/api/hosts/' + AUTO_HOST)
    inbound = host['inbound']['configProfileInboundUuid']
    excluded = set(host.get('excludedInternalSquads') or [])
    squads = api('GET', '/api/internal-squads/')['internalSquads']
    eligible = [s['uuid'] for s in squads if s['uuid'] not in excluded and inbound in [i['uuid'] for i in s['inbounds']]]
    require(eligible, 'No eligible automatic subscription squad')
    ident = str(uuid.uuid4())
    body = {'uuid': ident, 'username': 'auto_mws_probe_' + ident[:8],
            'expireAt': (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
            'trafficLimitBytes': 536870912, 'trafficLimitStrategy': 'NO_RESET', 'tag': 'AUTO_MWS_PROBE',
            'description': 'Temporary auto subscription validation', 'activeInternalSquads': [eligible[0]]}
    save('probe-intent', body); save('probe', api('POST', '/api/users/', body))
    return subscriptions()


def subscriptions():
    api, _ = create_client(); user = read('probe')
    host = api('GET', '/api/hosts/' + AUTO_HOST)
    sub = api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'Happ/5.7.0',
          'X-Hwid': 'ham-auto-mws-owned-probe', 'X-Device-Os': 'iOS', 'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '18'})
    with urllib.request.urlopen(req, timeout=30) as r: configs = json.load(r)
    selected = [c for c in configs if c.get('remarks') == host['remark']]
    require(len(selected) == 1, 'Actual auto subscription missing')
    out = [o for o in selected[0]['outbounds'] if o.get('protocol') == 'hysteria']
    require(len(out) == 1, 'Actual automatic outbound ambiguous')
    save('subscription-wire', out[0])
    return {'actual_Happ_auto_subscription_read': True}


def store_proof():
    proof = json.load(sys.stdin)
    require(proof.get('passed') and proof['wire_sha256'] == sha(read('wire')) and
            proof.get('location') == 'selectal', 'Wrong backend proof')
    save('backend-proof', proof); return {'backend_proof_saved': True}


def mihomo_subscription():
    api, _ = create_client(); user = read('probe')
    sub = api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])
    req = urllib.request.Request(sub['subscriptionUrl'], headers={'User-Agent': 'mihomo/1.19.29',
          'X-Hwid': 'ham-auto-mws-owned-probe', 'X-Device-Os': 'Windows',
          'X-Device-Model': 'Deployment probe', 'X-Ver-Os': '11'})
    with urllib.request.urlopen(req, timeout=30) as r: raw = r.read()
    save('mihomo-subscription', {'raw': raw.decode('utf-8'),
         'sha256': hashlib.sha256(raw).hexdigest(), 'time': time.time()})
    return {'actual_mihomo_subscription_saved_privately': True}


def finish():
    api, query = create_client(); proof = json.load(sys.stdin)
    if proof.get('client') == 'mihomo':
        require(proof.get('passed') and proof['subscription_sha256'] == read('mihomo-subscription')['sha256']
                and 0 <= time.time() - read('mihomo-subscription')['time'] < 900,
                'Fresh actual mihomo subscription proof required')
    else:
        require(proof.get('passed') and proof['wire_sha256'] == sha(read('subscription-wire')), 'Actual auto client proof required')
    require(api('GET', '/api/config-profiles/' + AUTO)['config'] == read('auto-candidate'), 'Auto drift')
    require(api('GET', '/api/config-profiles/' + MWS)['config'] == read('plan')['mws'], 'MWS drift')
    # Other agents/users may legitimately edit unrelated hosts during a rollout.
    # We never PATCH hosts; guard only the two hosts this operation depends on.
    before_hosts = {h['uuid']: h for h in read('before')['hosts']}
    current_hosts = {h['uuid']: h for h in api('GET', '/api/hosts/')}
    for ident in [AUTO_HOST, '3381a72d-522a-4fbf-878b-532f00ff1ba5']:
        require(current_hosts.get(ident) == before_hosts[ident], 'Target client host changed')
    require(api('GET', '/api/nodes/' + AUTO_NODE)['isConnected'], 'Auto node disconnected')
    require(api('GET', '/api/nodes/' + NODE)['isConnected'], 'MWS node disconnected')
    squad = api('GET', '/api/internal-squads/' + read('objects')['squad'])
    require([i['uuid'] for i in squad['inbounds']] == [read('objects')['inbound']], 'Service permissions drift')
    p = read('probe'); current = api('GET', '/api/users/' + p['uuid'])
    require(current['username'] == p['username'] and current['tag'] == p['tag'], 'Probe ownership drift')
    api('DELETE', '/api/users/' + p['uuid'])
    require(query("SELECT to_json(count(*)) FROM users WHERE uuid='" + str(uuid.UUID(p['uuid'])) + "'") == 0, 'Probe cleanup not confirmed')
    require(status()['service']['ActiveState'] == 'inactive', 'Rollback already executing')
    subprocess.run(['systemctl', 'stop', TIMER + '.timer'], check=True)
    require(all(x['ActiveState'] == 'inactive' for x in status().values()), 'Rollback not inactive')
    require(not (STATE / 'rolled-back.json').exists(), 'Rollback marker found')
    save('finished', {'time': time.time(), 'proof': proof})
    return {'finished': True, 'temporary_user_deleted': True, 'rollback_timer_and_service_inactive': True}


def rollback():
    api, _ = create_client(); before = read('before'); plan = read('plan')
    if (STATE / 'auto-candidate.json').exists():
        current = api('GET', '/api/config-profiles/' + AUTO)['config']
        if current == read('auto-candidate'):
            api('PATCH', '/api/config-profiles/', {'uuid': AUTO, 'config': before['profiles'][AUTO]['config']})
        else: require(current == before['profiles'][AUTO]['config'], 'Auto conflict; rollback refused')
    if (STATE / 'wanted-binding.json').exists():
        current = binding(api('GET', '/api/nodes/' + NODE))
        require(current in [read('wanted-binding'), binding(before['node'])], 'Binding conflict')
        api('PATCH', '/api/nodes/', {'uuid': NODE, 'configProfile': binding(before['node'])})
    current = api('GET', '/api/config-profiles/' + MWS)['config']
    require(current in [plan['mws'], before['profiles'][MWS]['config']], 'MWS conflict')
    if current == plan['mws']:
        api('PATCH', '/api/config-profiles/', {'uuid': MWS, 'config': before['profiles'][MWS]['config']})
    for name in ['probe', 'service']:
        if (STATE / (name + '.json')).exists():
            u = read(name)
            try: cur = api('GET', '/api/users/' + u['uuid'])
            except RuntimeError as e:
                if 'HTTP 404' in str(e): continue
                raise
            require(cur['username'] == u['username'] and cur['tag'] == u['tag'], 'User ownership conflict')
            api('DELETE', '/api/users/' + u['uuid'])
    if (STATE / 'objects.json').exists() and read('objects').get('squad'):
        api('DELETE', '/api/internal-squads/' + read('objects')['squad'])
    save('rolled-back', {'time': time.time()})
    return {'owned_changes_rolled_back': True}


if __name__ == '__main__':
    os.umask(0o077)
    try:
        require(os.geteuid() == 0, 'Root required')
        p = argparse.ArgumentParser(); p.add_argument('action', choices=['prepare', 'arm', 'stage', 'apply',
            'create_probe', 'subscriptions', 'mihomo_subscription', 'store_proof', 'finish', 'rollback']); a = p.parse_args()
        print(json.dumps(globals()[a.action]()))
    except Exception as e:
        print(json.dumps({'failed': True, 'type': type(e).__name__,
                          'detail': str(e) if isinstance(e, RuntimeError) else 'Private details suppressed'})); sys.exit(1)
