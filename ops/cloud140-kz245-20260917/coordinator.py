"""Panel exit-core only; entry preparation is non-applying.

Lifecycle per --id kz2|de245:
  prepare -> export -> accept-test (JSON stdin) -> stage -> arm -> activate-exit
  verify / rollback are readback / guarded restoration, not VPN success proofs.
The caller captures explicit export/export-entry stdout privately. Other actions
emit only safe summaries. No imports from previous deployments are executed.

Installed proof: {id, node, ip, sha256, timestamp, tests: [
  {kind: 'installed-xray', passed: true, returncode: 0, version: '<actual>'}]}
sha256 = checksum(candidate); timestamps must be <=1800s old and not future.
The external runner must execute the installed Xray against exactly the export;
accept-test validates the attestation, it does not execute or invent that test.

NOT IMPLEMENTED: entry activation, host publication, subscription fetch/probes,
finalization/disarming. Those need the full backend/external/subscription gates.
No unsafe substitute actions or flags are provided. Rollback refuses if entry
or hosts have subsequently been switched; extend its guarded scope first.
Inactive owned clones/private infrastructure users are retained after rollback.
"""

import argparse
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid

import preflight as p
import route_model as model


class SafetyError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SafetyError(message)  # Only fixed, non-secret messages.


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def ids(items):
    require(isinstance(items, list), 'Invalid ID list')
    result = [item if isinstance(item, str) else item['uuid'] for item in items]
    require(all(isinstance(item, str) and item for item in result)
            and len(result) == len(set(result)), 'Invalid or duplicate IDs')
    return result


def binding(node):
    config = node['configProfile']
    return dict(profile=config['activeConfigProfileUuid'], inbounds=sorted(ids(config['activeInbounds'])))


def metadata(profile):
    values = profile['inbounds']
    require(len({i['tag'] for i in values}) == len(values), 'Duplicate inbound metadata tags')
    ids(values)
    return {item['tag']: item['uuid'] for item in values}


def stable_host(host):
    return {key: value for key, value in host.items() if key not in ('createdAt', 'updatedAt')}


def target(route_id):
    require(route_id in ('kz2', 'de245'), 'Unknown exit ID')
    matches = [node for node in p.NODES if node['id'] == route_id]
    require(len(matches) == 1, 'Canonical inventory is ambiguous')
    return matches[0]


def proof_valid(proof, record, now):
    node = target(record['id'])
    require(isinstance(proof, dict), 'Invalid installed proof')
    require(all(proof.get(key) == value for key, value in dict(
        id=node['id'], node=node['node'], ip=node['ip'], sha256=record['sha256']).items()),
        'Installed proof scope or digest mismatch')
    stamp = proof.get('timestamp')
    require(type(stamp) in (int, float) and math.isfinite(stamp) and 0 <= now - stamp <= 1800,
            'Installed proof is stale or future dated')
    tests = proof.get('tests')
    require(isinstance(tests, list) and bool(tests), 'Installed proof has no actual tests')
    require(all(isinstance(test, dict) and test.get('kind') == 'installed-xray'
                and test.get('passed') is True and type(test.get('returncode')) is int
                and test['returncode'] == 0 and isinstance(test.get('version'), str)
                and bool(re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}', test['version']))
                for test in tests), 'Installed Xray test did not pass')


class RootStore:
    """Linux root-only state, immutable preflight snapshot and serialized writes."""
    def __init__(self, root=p.STATE):
        self.root = Path(root)
        self.directory = self.root / 'coordinator'

    @staticmethod
    def secure(path, directory=False):
        info = path.lstat()
        require(info.st_uid == 0 and not stat.S_ISLNK(info.st_mode)
                and info.st_mode & 0o077 == 0, 'Unsafe state ownership or permissions')
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1, 'Unsafe state file type')

    def _check(self):
        require(os.geteuid() == 0, 'Panel root required')
        require(self.root.is_absolute() and self.root.resolve() == self.root,
                'State path must not traverse symlinks')
        self.secure(self.root, True)

    def before(self):
        self._check()
        path = self.root / 'before.json'
        digest_path = self.root / 'before-sha256.json'
        self.secure(path)
        self.secure(digest_path)
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        require(json.loads(digest_path.read_bytes())['sha256'] == digest, 'Preflight snapshot digest mismatch')
        return json.loads(raw), digest

    def _path(self, name):
        require(re.fullmatch(r'[a-z0-9-]+', name) is not None, 'Invalid state name')
        self._check()
        self.secure(self.directory, True)
        return self.directory / (name + '.json')

    def exists(self, name):
        path = self._path(name)
        if path.exists() or path.is_symlink():
            self.secure(path)
            return True
        return False

    def read(self, name):
        path = self._path(name)
        self.secure(path)
        return json.loads(path.read_bytes())

    def save(self, name, value):
        path = self._path(name)
        if path.exists() or path.is_symlink():
            self.secure(path)
        pending = path.with_suffix('.pending')
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(path)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextmanager
    def locked(self):
        import fcntl
        self.before()
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.secure(self.directory, True)
        path = self.directory / 'operation.lock'
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self.secure(path)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)


class SystemdTimer:
    def __init__(self, runner=subprocess.run):
        self.run = runner

    @staticmethod
    def name(route_id):
        target(route_id)
        return 'ham-cloud140-kz245-' + route_id + '-rollback'

    def state(self, unit, allow_missing=False):
        result = self.run(['systemctl', 'show', unit, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result'],
                          capture_output=True, text=True, timeout=15)
        value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        missing = (allow_missing and result.returncode == 1 and value.get('LoadState') == 'not-found'
                   and value.get('ActiveState') == 'inactive' and value.get('SubState') == 'dead')
        require(result.returncode == 0 or missing, 'Cannot inspect rollback unit')
        return value

    def start(self, route_id):
        name = self.name(route_id)
        for suffix in ('.timer', '.service'):
            state = self.state(name + suffix, allow_missing=True)
            require(state.get('LoadState') == 'not-found' and state.get('ActiveState') == 'inactive',
                    'Rollback unit already exists; reconcile instead of replacing')
        script = Path(__file__).resolve()
        result = self.run(['systemd-run', '--unit=' + name, '--on-active=25m',
                          '--timer-property=AccuracySec=1s', '--property=UMask=0077',
                          'python3', str(script), 'rollback', '--id', route_id],
                         capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Rollback timer creation uncertain; inspect before resuming')
        self.armed(route_id)

    def armed(self, route_id):
        name = self.name(route_id)
        timer, service = self.state(name + '.timer'), self.state(name + '.service')
        require(timer.get('LoadState') == 'loaded' and timer.get('ActiveState') == 'active'
                and timer.get('SubState') == 'waiting', 'Rollback timer is not waiting')
        require(service.get('LoadState') == 'loaded' and service.get('ActiveState') == 'inactive'
                and service.get('SubState') == 'dead' and service.get('Result') == 'success',
                'Rollback service already ran, is running, or failed')


class Coordinator:
    def __init__(self, api, store, timer, clock=time.time):
        self.api, self.store, self.timer, self.clock = api, store, timer, clock

    def _save(self, record):
        self.store.save('exit-' + record['id'], record)

    def _load(self, route_id):
        target(route_id)
        record = self.store.read('exit-' + route_id)
        before, digest = self.store.before()
        require(record['id'] == route_id and record['snapshot_sha256'] == digest,
                'Coordinator snapshot identity mismatch')
        require(checksum(record['candidate']) == record['sha256'], 'Candidate digest mismatch')
        expected = model.build_exit_config(before['profiles'][target(route_id)['profile']]['config'], route_id, clone=True)
        require(record['candidate'] == expected, 'Candidate differs from scoped model')
        return record

    def _entry_guard(self, before, nodes):
        old = next(node for node in before['nodes'] if node['uuid'] == p.ENTRY_ID)
        current = next(node for node in nodes if node['uuid'] == p.ENTRY_ID)
        require(current['address'] == old['address'] == p.ENTRY and binding(current) == binding(old),
                'Entry identity or binding changed')
        profile_id = binding(old)['profile']
        require([node['uuid'] for node in nodes if binding(node)['profile'] == profile_id] == [p.ENTRY_ID],
                'Entry profile has another consumer')
        require(self.api('GET', '/api/config-profiles/' + profile_id)['config'] == before['profiles'][profile_id]['config'],
                'Entry profile changed; core rollback cannot undo an entry cutover')
        return old

    def _scope(self, record, allow_clone=False):
        before, digest = self.store.before()
        require(record['snapshot_sha256'] == digest, 'Snapshot changed')
        nodes = self.api('GET', '/api/nodes/')
        self._entry_guard(before, nodes)
        for node in p.NODES:
            old_profile = before['profiles'][node['profile']]
            actual = self.api('GET', '/api/config-profiles/' + node['profile'])
            require(actual['config'] == old_profile['config'] and metadata(actual) == metadata(old_profile),
                    'An original exit profile changed')
        node = target(record['id'])
        original = next(item for item in before['nodes'] if item['uuid'] == node['node'])
        current = next(item for item in nodes if item['uuid'] == node['node'])
        require(original['address'] == current['address'] == node['ip']
                and binding(original)['profile'] == node['profile'], 'Exit identity mismatch')
        require(all(current.get(key) == original.get(key) for key in ('name', 'port', 'isDisabled'))
                and not current['isDisabled'], 'Exit management fields changed')
        allowed = [binding(original)]
        if allow_clone and 'activation_intent' in record and 'rolled_back' not in record:
            allowed.append(record['desired_binding'])
        require(binding(current) in allowed, 'Unexpected active exit binding')
        hosts = self.api('GET', '/api/hosts/')
        old_hosts = {item['uuid']: item for item in before['hosts']}
        actual_hosts = {item['uuid']: item for item in hosts}
        for host_id in node['hosts']:
            old = old_hosts[host_id]
            require(old['nodes'] == [node['node']] and old['inbound'] == dict(
                configProfileUuid=node['profile'], configProfileInboundUuid=node['inbound']), 'Snapshot host scope mismatch')
            require(stable_host(actual_hosts[host_id]) == stable_host(old), 'Exit host changed; core rollback refuses')
        if 'profile' in record['objects']:
            clone_id = record['objects']['profile']
            profile = self.api('GET', '/api/config-profiles/' + clone_id)
            self._validate_profile(record, profile)
            consumers = {item['uuid'] for item in nodes if binding(item)['profile'] == clone_id}
            require(consumers <= ({node['node']} if allow_clone else set()), 'Clone has an unexpected consumer')
            require(not any(item.get('inbound', {}).get('configProfileUuid') == clone_id for item in hosts),
                    'Clone is referenced by a host; core rollback refuses')
        return before, current

    def prepare(self, route_id):
        node = target(route_id)
        if self.store.exists('exit-' + route_id):
            record = self._load(route_id)
            require('rolled_back' not in record, 'Rolled-back operation cannot be reused')
            self._scope(record, allow_clone=True)
            return self.summary(record)
        before, digest = self.store.before()
        candidate = model.build_exit_config(before['profiles'][node['profile']]['config'], route_id, clone=True)
        record = dict(id=route_id, snapshot_sha256=digest, candidate=candidate, sha256=checksum(candidate),
                      name='HAM-CLOUD140-' + route_id.upper() + '-EXIT',
                      squad_name='HAM-CLOUD140-' + route_id.upper() + '-BACKEND', objects={}, intents={}, rights={})
        self._scope(record)
        self._save(record)
        return self.summary(record)

    @staticmethod
    def summary(record):
        return dict(id=record['id'], candidate_sha256=record['sha256'],
                    staged='staged' in record, binding_applied='activated' in record and 'rolled_back' not in record,
                    rolled_back='rolled_back' in record)

    def export(self, route_id):
        return deepcopy(self._load(route_id)['candidate'])

    def accept_test(self, route_id, proof):
        record = self._load(route_id)
        require('rolled_back' not in record, 'Rolled-back operation cannot accept proofs')
        # A newly failed test must not leave an older successful attestation usable.
        record.pop('installed_test', None)
        self._save(record)
        proof_valid(proof, record, self.clock())
        record['installed_test'] = deepcopy(proof)
        self._save(record)
        return dict(id=route_id, installed_proof_accepted=True)

    def _validate_profile(self, record, profile):
        require(profile['name'] == record['name'] and profile['config'] == record['candidate'], 'Clone profile drift')
        require(set(metadata(profile)) == {item['tag'] for item in record['candidate']['inbounds']},
                'Clone inbound metadata mismatch')
        if 'profile' in record['objects']:
            require(profile['uuid'] == record['objects']['profile'], 'Clone profile identity mismatch')
        if 'metadata' in record:
            require(metadata(profile) == record['metadata'], 'Clone metadata identity drift')

    def _named(self, record, kind, path, collection, body):
        matches = [item for item in self.api('GET', path)[collection] if item['name'] == body['name']]
        require(len(matches) <= 1, 'Duplicate operation names; reconcile manually')
        if kind in record['objects']:
            require(len(matches) == 1 and matches[0]['uuid'] == record['objects'][kind], 'Owned object disappeared')
            return self.api('GET', path + matches[0]['uuid'])
        if kind in record['intents']:
            require(record['intents'][kind] == body and len(matches) == 1,
                    'Ambiguous creation intent; inspect readback without retrying POST')
            result = self.api('GET', path + matches[0]['uuid'])
        else:
            require(not matches, 'Operation name already exists without ownership intent')
            record['intents'][kind] = deepcopy(body)
            self._save(record)
            result = self.api('POST', path, body)
        # Persist the assigned ID even if subsequent validation fails.
        record['objects'][kind] = result['uuid']
        self._save(record)
        return self.api('GET', path + result['uuid'])

    def _squad_check(self, record, squad):
        require(squad['uuid'] == record['objects']['squad'] and squad['name'] == record['squad_name']
                and ids(squad['inbounds']) == [record['backend']], 'Backend squad is not strictly isolated')

    def _user_check(self, record, user):
        body = record['intents']['user']
        require(all(user.get(key) == body[key] for key in ('uuid', 'username', 'tag', 'description',
                                                         'trafficLimitBytes', 'trafficLimitStrategy')),
                'Private service user identity drift')
        require(ids(user['activeInternalSquads']) == body['activeInternalSquads']
                and user['status'] == 'ACTIVE', 'Private service user scope or status changed')
        expiry = lambda value: datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(abs((expiry(user['expireAt']) - expiry(body['expireAt'])).total_seconds()) < 1,
                'Private service user expiry changed')
        model._service_uuid(user['vlessUuid'])
        if 'service_uuid' in record:
            require(record['service_uuid'] == user['vlessUuid'], 'Backend service credential changed')

    def _private_user(self, record):
        if 'user' in record['intents']:
            user = self.api('GET', '/api/users/' + record['intents']['user']['uuid'])
        else:
            route_id = record['id']
            body = dict(uuid=str(uuid.uuid4()), username='ham_cloud140_' + route_id + '_backend',
                        expireAt=(datetime.fromtimestamp(self.clock(), timezone.utc) + timedelta(days=3650)).isoformat(),
                        trafficLimitBytes=0, trafficLimitStrategy='NO_RESET', tag='CL140_' + route_id.upper() + '_SVC',
                        description='Private CLOUD140 exit infrastructure; not a customer',
                        activeInternalSquads=[record['objects']['squad']])
            record['intents']['user'] = body
            self._save(record)
            self.api('POST', '/api/users/', body)
            user = self.api('GET', '/api/users/' + body['uuid'])
        self._user_check(record, user)
        record['objects']['user'] = user['uuid']
        record['service_uuid'] = user['vlessUuid']
        self._save(record)

    def _rights_plan(self, record, before):
        node = target(record['id'])
        old_meta = metadata(before['profiles'][node['profile']])
        tag_map = model.legacy_tag_map(before['profiles'][node['profile']]['config'], record['id'])
        mapping = {old_id: record['metadata'][tag_map[tag]] for tag, old_id in old_meta.items()}
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        planned = deepcopy(record['rights'])
        for squad in squads:
            current = ids(squad['inbounds'])
            if squad['uuid'] == record['objects']['squad']:
                self._squad_check(record, squad)
                continue
            require(record['backend'] not in current, 'Backend was granted outside its private squad')
            if squad['uuid'] in planned:
                plan = planned[squad['uuid']]
                require(self._required_before(record, squad['uuid'], plan) <= set(current),
                        'Existing squad rights were revoked')
                additions = [new for old, new in mapping.items() if old in current and new not in plan['added']]
                require(not set(additions).intersection(current), 'New clone grant lacks ownership intent')
                plan['added'] += additions
                continue
            additions = [new for old, new in mapping.items() if old in current]
            require(not set(mapping.values()).intersection(current), 'Clone rights exist without operation ownership')
            if additions:
                planned[squad['uuid']] = dict(before=current, added=additions)
        old_squads = {squad['uuid']: squad for squad in before['squads']}
        current_squads = {squad['uuid']: squad for squad in squads}
        for squad_id, old in old_squads.items():
            if set(mapping).intersection(ids(old['inbounds'])):
                require(squad_id in current_squads and set(ids(old['inbounds'])) <= set(ids(current_squads[squad_id]['inbounds'])),
                        'Original frontend squad rights changed')
        record['rights'] = planned
        self._save(record)  # All rights ownership intents precede any PATCH.
        for squad_id, plan in planned.items():
            current = self.api('GET', '/api/internal-squads/' + squad_id)
            current_ids = ids(current['inbounds'])
            require(self._required_before(record, squad_id, plan) <= set(current_ids), 'Squad changed before rights patch')
            wanted = list(dict.fromkeys(current_ids + plan['added']))
            if set(wanted) != set(current_ids):
                self.api('PATCH', '/api/internal-squads/', dict(uuid=squad_id, inbounds=wanted))
            actual = ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])
            require(set(actual) == set(wanted), 'Squad rights readback mismatch')

    def stage(self, route_id):
        record = self._load(route_id)
        require('rolled_back' not in record and 'activation_intent' not in record, 'Stage is closed after activation or rollback')
        proof_valid(record.get('installed_test'), record, self.clock())
        before, _ = self._scope(record)
        candidate_tags = {item['tag'] for item in record['candidate']['inbounds']}
        profiles = self.api('GET', '/api/config-profiles/')['configProfiles']
        for profile in profiles:
            if profile['name'] == record['name']:
                continue  # _named requires our intent/ID before adoption.
            detail = self.api('GET', '/api/config-profiles/' + profile['uuid'])
            require(not candidate_tags.intersection(metadata(detail)), 'Clone tags collide with another profile')
        profile = self._named(record, 'profile', '/api/config-profiles/', 'configProfiles',
                              dict(name=record['name'], config=record['candidate']))
        self._validate_profile(record, profile)
        record['metadata'] = metadata(profile)
        record['backend'] = record['metadata'][model.route_tags(route_id)['backend']]
        node = target(route_id)
        original = next(item for item in before['nodes'] if item['uuid'] == node['node'])
        old_meta = metadata(before['profiles'][node['profile']])
        renamed = model.legacy_tag_map(before['profiles'][node['profile']]['config'], route_id)
        old_to_new = {old_id: record['metadata'][renamed[tag]] for tag, old_id in old_meta.items()}
        require(set(binding(original)['inbounds']) <= set(old_to_new), 'Active legacy inbound metadata missing')
        record['desired_binding'] = dict(profile=profile['uuid'], inbounds=sorted(
            [old_to_new[item] for item in binding(original)['inbounds']] + [record['backend']]))
        self._save(record)
        squad = self._named(record, 'squad', '/api/internal-squads/', 'internalSquads',
                            dict(name=record['squad_name'], inbounds=[record['backend']]))
        self._squad_check(record, squad)
        self._private_user(record)
        self._rights_plan(record, before)
        self._scope(record)
        record['staged'] = self.clock()
        self._save(record)
        return self.summary(record)

    def _required_before(self, record, squad_id, plan):
        # The other exit's owned delta is independent and may already have been
        # rolled back. It is never restored or removed by this exit's action.
        independent = set()
        for route_id in model.REVERSE_PORTS:
            if route_id != record['id'] and self.store.exists('exit-' + route_id):
                other = self._load(route_id)
                independent.update(other['rights'].get(squad_id, {}).get('added', []))
        return set(plan['before']) - independent

    def _resources(self, record):
        self._squad_check(record, self.api('GET', '/api/internal-squads/' + record['objects']['squad']))
        self._user_check(record, self.api('GET', '/api/users/' + record['objects']['user']))
        for squad_id, plan in record['rights'].items():
            current = ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])
            require(self._required_before(record, squad_id, plan) | set(plan['added']) <= set(current),
                    'Cloned legacy rights missing')
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        before, _ = self.store.before()
        profile = before['profiles'][target(record['id'])['profile']]
        renames = model.legacy_tag_map(profile['config'], record['id'])
        mapping = {old_id: record['metadata'][renames[tag]] for tag, old_id in metadata(profile).items()}
        for squad in squads:
            if squad['uuid'] != record['objects']['squad']:
                granted = set(ids(squad['inbounds']))
                require(record['backend'] not in granted, 'Backend access escaped private squad')
                require({new for old, new in mapping.items() if old in granted} <= granted,
                        'New original rights require restaging clone grants')

    def arm(self, route_id):
        record = self._load(route_id)
        require('staged' in record and 'rolled_back' not in record and 'activation_intent' not in record,
                'Only a staged original binding can be armed')
        proof_valid(record.get('installed_test'), record, self.clock())
        self._scope(record)
        self._resources(record)
        if 'arm_intent' in record:
            require(0 <= self.clock() - record['arm_intent'] < 1500, 'Rollback timer deadline passed')
            self.timer.armed(route_id)
        else:
            record['arm_intent'] = self.clock()
            self._save(record)
            self.timer.start(route_id)
        record['armed'] = record['arm_intent']
        self._save(record)
        return dict(id=route_id, rollback_timer_armed=True)

    def activate_exit(self, route_id):
        record = self._load(route_id)
        require('armed' in record and 'staged' in record and 'rolled_back' not in record,
                'Exit is not staged and armed')
        require(0 <= self.clock() - record['armed'] < 1500, 'Rollback deadline passed')
        proof_valid(record.get('installed_test'), record, self.clock())
        _, node = self._scope(record, allow_clone=True)
        self._resources(record)
        self.timer.armed(route_id)
        wanted = record['desired_binding']
        if binding(node) != wanted:
            require(node['isConnected'], 'Exit is disconnected before activation')
            require('activation_intent' not in record, 'Prior activation is uncertain; do not repeat PATCH blindly')
            record['activation_intent'] = self.clock()
            self._save(record)
            self.api('PATCH', '/api/nodes/', dict(uuid=target(route_id)['node'], configProfile=dict(
                activeConfigProfileUuid=wanted['profile'], activeInbounds=wanted['inbounds'])))
        actual = self.api('GET', '/api/nodes/' + target(route_id)['node'])
        require(binding(actual) == wanted, 'Exit binding readback failed')
        self._scope(record, allow_clone=True)
        self.timer.armed(route_id)
        record['activated'] = self.clock()
        self._save(record)
        return self.summary(record)  # Not a claim of authenticated VPN health.

    def verify(self, route_id):
        record = self._load(route_id)
        _, current = self._scope(record, allow_clone=True)
        if 'rolled_back' not in record and 'staged' in record:
            self._resources(record)
        return dict(**self.summary(record), node_connected=current['isConnected'], original_profiles_unchanged=True)

    def rollback(self, route_id):
        record = self._load(route_id)
        before, current = self._scope(record, allow_clone=True)
        require('staged' in record, 'Incomplete staging must be reconciled before rollback')
        # Preflight EVERY affected object before the first rollback mutation.
        self._squad_check(record, self.api('GET', '/api/internal-squads/' + record['objects']['squad']))
        self._user_check(record, self.api('GET', '/api/users/' + record['objects']['user']))
        owned = set(record['metadata'].values()) - {record['backend']}
        squads = self.api('GET', '/api/internal-squads/')['internalSquads']
        indexed = {squad['uuid']: squad for squad in squads}
        for squad in squads:
            granted = set(ids(squad['inbounds']))
            require(squad['uuid'] == record['objects']['squad'] or record['backend'] not in granted,
                    'Foreign backend grant prevents rollback')
            if owned.intersection(granted):
                require(squad['uuid'] in record['rights']
                        and owned.intersection(granted) <= set(record['rights'][squad['uuid']]['added']),
                        'Unowned clone grant prevents rollback')
        for squad_id, plan in record['rights'].items():
            require(squad_id in indexed and self._required_before(record, squad_id, plan) <= set(ids(indexed[squad_id]['inbounds'])),
                    'Squad rollback preflight failed')
        original = next(node for node in before['nodes'] if node['uuid'] == target(route_id)['node'])
        wanted = binding(original)
        record['rollback_intent'] = self.clock()
        self._save(record)
        if binding(current) != wanted:
            self.api('PATCH', '/api/nodes/', dict(uuid=original['uuid'], configProfile=dict(
                activeConfigProfileUuid=wanted['profile'], activeInbounds=wanted['inbounds'])))
        require(binding(self.api('GET', '/api/nodes/' + original['uuid'])) == wanted,
                'Original binding was not restored; refusing to remove rights')
        for squad_id, plan in record['rights'].items():
            current_ids = ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])
            require(self._required_before(record, squad_id, plan) <= set(current_ids), 'Squad changed during rollback')
            desired = [item for item in current_ids if item not in plan['added']]
            if current_ids != desired:
                self.api('PATCH', '/api/internal-squads/', dict(uuid=squad_id, inbounds=desired))
            require(set(ids(self.api('GET', '/api/internal-squads/' + squad_id)['inbounds'])) == set(desired),
                    'Rollback rights readback failed')
        self._scope(record, allow_clone=True)
        record['rolled_back'] = self.clock()
        self._save(record)
        return dict(id=route_id, original_binding_restored=True, own_legacy_grants_removed=True,
                    inactive_owned_objects_retained=True)

    def prepare_entry(self):
        before, digest = self.store.before()
        records = {node['id']: self._load(node['id']) for node in p.NODES}
        for record in records.values():
            require('staged' in record and 'rolled_back' not in record, 'Both exits must be staged')
            self._scope(record, allow_clone=True)
            self._resources(record)
        old = self._entry_guard(before, self.api('GET', '/api/nodes/'))
        profile_id = binding(old)['profile']
        source = before['profiles'][profile_id]['config']
        require(len(source['inbounds']) == 4 and len(binding(old)['inbounds']) == 4,
                'Expected four unchanged entry legacy inbounds')
        if self.store.exists('entry-identities'):
            keys = self.store.read('entry-identities')
        else:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
            keys = {route_id: dict(privateKey=base64.urlsafe_b64encode(
                X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode().rstrip('='),
                shortIds=[secrets.token_hex(8)]) for route_id in records}
            self.store.save('entry-identities', keys)
        config = model.build_entry_config(source, keys, {key: record['service_uuid'] for key, record in records.items()})
        result = dict(snapshot_sha256=digest, profile=profile_id, config=config, sha256=checksum(config))
        if self.store.exists('entry-candidate'):
            require(self.store.read('entry-candidate') == result, 'Entry candidate changed; explicit reconcile required')
        else:
            self.store.save('entry-candidate', result)
        return dict(entry_candidate_ready=True, candidate_sha256=result['sha256'], entry_not_applied=True)

    def export_entry(self):
        before, digest = self.store.before()
        record = self.store.read('entry-candidate')
        require(record['snapshot_sha256'] == digest and checksum(record['config']) == record['sha256'],
                'Entry candidate integrity failure')
        return deepcopy(record['config'])


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'export', 'accept-test', 'stage', 'arm',
                                         'activate-exit', 'verify', 'rollback', 'prepare-entry', 'export-entry'])
    parser.add_argument('--id', choices=['kz2', 'de245'])
    args = parser.parse_args(argv)
    require((args.id is None) == (args.action in ('prepare-entry', 'export-entry')), 'Exit action requires --id')
    store = RootStore()
    with store.locked():
        if args.action in ('export', 'export-entry', 'accept-test'):
            api = None
        else:
            api, _ = p.create_client()
        worker = Coordinator(api, store, SystemdTimer())
        if args.action == 'accept-test':
            result = worker.accept_test(args.id, json.load(sys.stdin))
        elif args.action in ('prepare-entry', 'export-entry'):
            result = getattr(worker, args.action.replace('-', '_'))()
        else:
            result = getattr(worker, args.action.replace('-', '_'))(args.id)
        print(json.dumps(result))  # Sensitive only for the two explicit exports.


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never log API bodies, tracebacks, config, credentials or subscription URLs.
        message = str(error) if isinstance(error, SafetyError) else 'Coordinator failed; inspect protected state'
        print(json.dumps(dict(error=message)), file=sys.stderr)
        sys.exit(1)
