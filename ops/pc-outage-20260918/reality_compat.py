"""One-inbound REALITY/Mihomo compatibility canary; never changes identities.

Run only from the verified published release on the panel. Root-only immutable
snapshot, optimistic drift checks, independently armed rollback, explicit proof
gates. No hosts, users, squads, node assignments, DNS or client settings change.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path('/root/hamvpn-mihomo-compat-20260918')
SCOPES = {
    'aeza-de3': dict(profile='8deddcaa-fd80-46ed-ac48-e4c5e93b0271',
                    node='560e38b3-6ee8-4f10-861e-e2f1eddd4caa',
                    address='193.233.222.244', tag='vless-entry244-de182',
                    port=18443, exit_ip='217.60.68.182'),
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def candidate(config, target):
    result = deepcopy(config)
    selected = [i for i in result['inbounds'] if i['tag'] == target['tag']]
    require(len(selected) == 1, 'Expected exactly one selected inbound')
    inbound = selected[0]
    require(inbound['protocol'] == 'vless' and inbound['port'] == target['port'], 'Inbound identity changed')
    stream = inbound['streamSettings']
    require(stream['security'] == 'reality', 'Inbound is not REALITY')
    reality = stream['realitySettings']
    require('minClientVer' not in reality, 'Refuse to overwrite explicit client-version policy')
    reality['minClientVer'] = '1.8.2'
    return result


class Store:
    def __init__(self, scope):
        require(scope in SCOPES, 'Unknown scope')
        self.path = ROOT / scope

    def secure(self):
        require(os.name == 'posix' and os.geteuid() == 0, 'Linux root required')
        for directory in reversed((self.path, *self.path.parents)):
            if not directory.exists() and not directory.is_symlink():
                directory.mkdir(mode=0o700)
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Unsafe state ancestor')
        require(self.path.stat().st_mode & 0o077 == 0, 'Private state required')

    def file(self, name):
        require(re.fullmatch('[a-z][a-z0-9-]+', name) is not None, 'Invalid record name')
        self.secure()
        return self.path / (name + '.json')

    def exists(self, name):
        p = self.file(name)
        return p.exists() or p.is_symlink()

    def put(self, name, value):
        path = self.file(name)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(encoded(dict(value=value, sha256=digest(value))))
            f.flush()
            os.fsync(f.fileno())
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        require(self.get(name) == value, 'Record readback differs')

    def get(self, name):
        fd = os.open(self.file(name), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            info = os.fstat(f.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'Unsafe record')
            record = json.load(f)
        require(set(record) == {'value', 'sha256'} and record['sha256'] == digest(record['value']),
                'Record integrity failure')
        return record['value']

    @contextmanager
    def locked(self):
        import fcntl
        self.secure()
        fd = os.open(self.path / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)


def consumer_bindings(nodes):
    # activeInbounds may contain derived rawInbound configuration. That payload
    # legitimately changes with this PATCH; compare assignments/identities only.
    return sorted([dict(uuid=n['uuid'], address=n['address'], configProfile=dict(
        activeConfigProfileUuid=n['configProfile']['activeConfigProfileUuid'],
        activeInbounds=sorted([dict(uuid=i['uuid'], tag=i['tag'])
                              for i in n['configProfile']['activeInbounds']], key=lambda i: i['uuid'])))
        for n in nodes], key=lambda n: n['uuid'])


def consumers(nodes, profile):
    return consumer_bindings([n for n in nodes
                              if n.get('configProfile', {}).get('activeConfigProfileUuid') == profile])


class Timer:
    def __init__(self, scope):
        self.scope = scope
        self.unit = 'ham-pc-reality-' + scope + '-rollback'

    def run(self, command):
        p = subprocess.run(command, capture_output=True, text=True, timeout=30)
        require(p.returncode == 0, 'Rollback timer operation failed')
        return p.stdout

    def active(self):
        return self.state('timer')['ActiveState'] == 'active'

    def state(self, suffix):
        require(suffix in ('timer', 'service'), 'Invalid rollback unit type')
        result = subprocess.run(['systemctl', 'show', self.unit + '.' + suffix,
                                 '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState'],
                                capture_output=True, text=True, timeout=15)
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        missing = {'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead'}
        require((result.returncode == 0 and fields.get('LoadState') == 'loaded'
                 and set(fields) == set(missing)) or
                (result.returncode in (0, 1, 4) and fields == missing), 'Cannot inspect rollback unit')
        return fields

    def arm(self):
        require(not self.active(), 'Rollback timer already active')
        require(self.state('service')['ActiveState'] == 'inactive', 'Rollback service is not inactive')
        self.run(['systemd-run', '--unit=' + self.unit, '--on-active=600',
                  '--timer-property=AccuracySec=1s', '--property=UMask=0077',
                  '/usr/bin/python3', str(Path(__file__).resolve()), 'rollback', '--scope', self.scope])
        require(self.active(), 'Rollback timer not armed')

    def cancel(self):
        self.run(['systemctl', 'stop', self.unit + '.timer', self.unit + '.service'])
        require(all(self.state(s)['ActiveState'] == 'inactive' for s in ('timer', 'service')),
                'Rollback timer/service still active')


class Operation:
    def __init__(self, scope, api, store, timer, clock=time.time):
        self.scope, self.api, self.store, self.timer, self.clock = scope, api, store, timer, clock
        self.target = SCOPES[scope]

    def collect(self, healthy=True):
        profile = self.api('GET', '/api/config-profiles/' + self.target['profile'])
        require(profile['uuid'] == self.target['profile'], 'Profile identity changed')
        nodes = self.api('GET', '/api/nodes/')
        attached = consumers(nodes, self.target['profile'])
        require(len(attached) == 1 and attached[0]['uuid'] == self.target['node'] and
                attached[0]['address'] == self.target['address'], 'Profile consumer scope changed')
        node = next(n for n in nodes if n['uuid'] == self.target['node'])
        if healthy:
            require(node['isConnected'] and not node['isDisabled'], 'Canary node is not healthy')
        require(self.target['tag'] in [i['tag'] for i in node['configProfile']['activeInbounds']],
                'Canary inbound is not active')
        return profile, attached

    def plan(self):
        require(not self.store.exists('before'), 'Snapshot already exists')
        profile, attached = self.collect()
        new = candidate(profile['config'], self.target)
        record = dict(profile=profile, consumers=attached, candidate=new,
                      candidate_sha256=digest(new), timestamp=self.clock())
        self.store.put('before', record)
        return dict(planned=True, scope=self.scope, sha256=digest(new), changed_fields=1)

    def load(self):
        record = self.store.get('before')
        require(candidate(record['profile']['config'], self.target) == record['candidate'] and
                digest(record['candidate']) == record['candidate_sha256'], 'Candidate no longer matches approved patch')
        return record

    def check(self, expected, healthy=True):
        record = self.load()
        profile, attached = self.collect(healthy=healthy)
        require(profile['config'] == expected and attached == consumer_bindings(record['consumers']), 'Live configuration drift')
        return record

    def fresh(self, proof, record):
        require(proof.get('sha256') == record['candidate_sha256'] and
                isinstance(proof.get('timestamp'), (int, float)) and
                0 <= self.clock() - proof['timestamp'] < 600, 'Stale or unrelated proof')

    def accept_installed(self, proof):
        record = self.check(self.load()['profile']['config'])
        self.fresh(proof, record)
        require(proof.get('passed') is True and proof.get('returncode') == 0 and
                proof.get('version') == '26.7.28', 'Installed Xray validation required')
        self.store.put('installed-proof', proof)
        return dict(installed_validation_accepted=True)

    def apply(self):
        record = self.check(self.load()['profile']['config'])
        require(not self.store.exists('apply-intent') and not self.store.exists('rolled-back'), 'Operation already started')
        self.fresh(self.store.get('installed-proof'), record)
        self.store.put('apply-intent', dict(timestamp=self.clock()))
        self.timer.arm()
        self.api('PATCH', '/api/config-profiles/', dict(uuid=self.target['profile'], config=record['candidate']))
        # A profile push may briefly reconnect the node. Verify the write now;
        # finish still requires the node connected and actual traffic proofs.
        self.check(record['candidate'], healthy=False)
        require(self.timer.active(), 'Rollback timer was lost')
        self.store.put('applied', dict(timestamp=self.clock()))
        return dict(applied=True, rollback_seconds=600, sha256=record['candidate_sha256'])

    def reconcile_applied(self):
        """Readback only after an uncertain PATCH; never repeat the API mutation."""
        require(self.store.exists('apply-intent') and not self.store.exists('applied') and
                not self.store.exists('rolled-back') and not self.store.exists('finished'),
                'Not an uncertain owned apply')
        record = self.check(self.load()['candidate'], healthy=False)
        require(self.timer.active(), 'Rollback protection missing')
        self.store.put('applied', self.store.get('apply-intent'))
        return dict(owned_patch_readback_verified=True, sha256=record['candidate_sha256'])

    def rollback(self):
        record = self.load()
        require(self.store.exists('apply-intent'), 'No owned apply attempt')
        if self.store.exists('finished'):
            return dict(rollback_skipped_finished=True)
        profile, attached = self.collect(healthy=False)
        require(attached == consumer_bindings(record['consumers']) and
                profile['config'] in (record['candidate'], record['profile']['config']), 'Refuse rollback over unrelated changes')
        if profile['config'] == record['candidate']:
            self.api('PATCH', '/api/config-profiles/', dict(uuid=self.target['profile'], config=record['profile']['config']))
        self.check(record['profile']['config'], healthy=False)
        if not self.store.exists('rolled-back'):
            self.store.put('rolled-back', dict(timestamp=self.clock()))
        return dict(rolled_back=True)

    def finish(self, proof):
        record = self.check(self.load()['candidate'])
        if self.store.exists('finished'):
            require(self.store.get('traffic-proof') == proof, 'Cannot replace accepted proof')
            if self.timer.active():
                self.timer.cancel()
            return dict(finished=True, rollback_disarmed=True)
        require(self.store.exists('applied') and not self.store.exists('rolled-back') and
                not self.store.exists('finished') and self.timer.active(), 'Canary is not pending')
        self.fresh(proof, record)
        require(proof['timestamp'] >= self.store.get('applied')['timestamp'], 'Proof predates deployment')
        tests = proof.get('tests', [])
        required = {'mihomo-firefox', 'mihomo-chrome', 'xray-firefox', 'xray-chrome'}
        require(len(tests) == 4 and {t.get('id') for t in tests} == required, 'Four protocol proofs required')
        require(all(t.get('http') == '204' and t.get('exit_ip') == self.target['exit_ip'] and
                    t.get('curl_codes') == [0, 0] and t.get('listener_removed') is True for t in tests),
                'End-to-end proof failed')
        require(proof.get('live_mihomo_delay', 0) > 0, 'Running application canary proof required')
        self.store.put('traffic-proof', proof)
        # Mark first under the same flock: a timer racing disarm must see finished.
        self.store.put('finished', dict(timestamp=self.clock(), sha256=record['candidate_sha256']))
        self.timer.cancel()
        self.check(record['candidate'])
        return dict(finished=True, rollback_disarmed=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'export-candidate', 'accept-installed', 'apply', 'reconcile-applied', 'rollback', 'finish', 'status'])
    parser.add_argument('--scope', choices=SCOPES, required=True)
    parser.add_argument('--secret-stdout', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'selfsteal-us3'))
    from panel_api import create_client
    api, _ = create_client()
    store = Store(args.scope)
    op = Operation(args.scope, api, store, Timer(args.scope))
    with store.locked():
        if args.action == 'export-candidate':
            require(args.secret_stdout, 'Private stdout-to-stdin pipe is required')
            result = op.load()['candidate']
        elif args.action in ('accept-installed', 'finish'):
            result = getattr(op, args.action.replace('-', '_'))(json.load(sys.stdin))
        elif args.action == 'status':
            record = op.load()
            live, _ = op.collect()
            result = dict(sha256=record['candidate_sha256'], live_candidate=live['config'] == record['candidate'],
                          rollback_active=op.timer.active(), finished=store.exists('finished'))
        else:
            result = getattr(op, args.action.replace('-', '_'))()
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__, message='Scoped operation stopped; inspect private state')), file=sys.stderr)
        sys.exit(1)
