"""Root-only Cloudflare broker: one fixed ACME TXT name, no caller-selected paths."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NAME = '_acme-challenge.ru214.torcalc.ru'
COMMENT = 'HAMVPN ru214 DNS-01 '
CONFIG = Path('/etc/hamvpn-dns-ru214/credentials.json')
STATE = Path('/var/lib/hamvpn-dns-ru214-state')


class RemoteError(Exception):
    pass


class NotFound(RemoteError):
    pass


def parse_request(raw):
    if len(raw) > 2048:
        raise ValueError('Request too large')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'action', 'validation'}:
        raise ValueError('Only action and validation are accepted')
    if value['action'] not in ('present', 'cleanup'):
        raise ValueError('Unsupported action')
    if not isinstance(value['validation'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value['validation']):
        raise ValueError('Invalid SHA256 DNS validation value')
    return value


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


class Cloudflare:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def __call__(self, method, path, body=None):
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
            method=method, data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise NotFound('DNS record not found') from None
            raise RemoteError('Cloudflare HTTP operation failed') from None
        except (OSError, ValueError):
            raise RemoteError('Cloudflare transport or response failed') from None
        if payload.get('success') is not True:
            raise RemoteError('Cloudflare rejected operation')
        if payload.get('result_info', {}).get('total_pages', 1) > 1:
            raise RemoteError('Unexpected paginated DNS result; manual inspection required')
        return payload['result']


def authoritative_propagation(value, nameservers):
    """Check both zone-authoritative servers; node separately checks public caches."""
    if not isinstance(nameservers, list) or len(nameservers) != 2 or len(set(nameservers)) != 2:
        raise RemoteError('Unexpected authoritative server list')
    addresses = {}
    for name in nameservers:
        if not re.fullmatch(r'[a-z0-9-]+\.ns\.cloudflare\.com', name):
            raise RemoteError('Unexpected authoritative server name')
        result = subprocess.run(['/usr/bin/dig', '@8.8.8.8', name, 'A', '+short', '+time=2', '+tries=1'],
                                capture_output=True, text=True, timeout=4, check=True)
        candidates = []
        for line in result.stdout.splitlines():
            try: address = ipaddress.IPv4Address(line.strip())
            except ValueError: continue
            if address.is_global: candidates.append(str(address))
        if not candidates or len(candidates) > 8:
            raise RemoteError('Authoritative server address lookup failed')
        addresses[name] = candidates
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        confirmed = set()
        for name, candidates in addresses.items():
            for address in candidates:
                if time.monotonic() >= deadline: break
                try:
                    result = subprocess.run(['/usr/bin/dig', '@' + address, NAME, 'TXT',
                        '+time=2', '+tries=1', '+norecurse', '+noall', '+comments', '+answer'],
                        capture_output=True, text=True, timeout=4, check=True)
                    if not re.search(r';; flags: [^;\n]*\baa\b', result.stdout): continue
                    for line in result.stdout.splitlines():
                        fields = line.split(None, 4)
                        if (len(fields) == 5 and fields[0].rstrip('.') == NAME
                                and fields[2:4] == ['IN', 'TXT']
                                and ''.join(shlex.split(fields[4])) == value):
                            confirmed.add(name)
                    if name in confirmed: break
                except (OSError, subprocess.SubprocessError, ValueError):
                    continue
        if len(confirmed) == 2: return
        time.sleep(5)
    raise RemoteError('Authoritative TXT propagation not confirmed')


class Broker:
    def __init__(self, api, zone, state, save, propagate=None):
        if not re.fullmatch(r'[0-9a-f]{32}', zone):
            raise ValueError('Invalid fixed zone')
        self.api, self.state, self.save = api, state, save
        self.propagate = propagate
        self.path = '/zones/' + zone + '/dns_records'

    def records(self):
        query = urllib.parse.urlencode({'type': 'TXT', 'name': NAME, 'per_page': 100})
        rows = self.api('GET', self.path + '?' + query)
        if not isinstance(rows, list) or len(rows) >= 100:
            raise RemoteError('Unexpected DNS result size')
        if any(row.get('type') != 'TXT' or row.get('name') != NAME for row in rows):
            raise RemoteError('DNS query returned an unrelated record')
        return rows

    def validate_record(self, row, value, comment):
        if not (row.get('type') == 'TXT' and row.get('name') == NAME
                and row.get('content') == value and row.get('comment') == comment
                and re.fullmatch(r'[0-9a-f]{32}', row.get('id', ''))):
            raise RemoteError('Record ownership or value changed; refusing mutation')

    def execute(self, action, value):
        key = hashlib.sha256(value.encode()).hexdigest()
        comment = COMMENT + key
        intent = self.state.get(key)
        if action == 'present':
            rows = self.records()
            matches = [row for row in rows if row.get('content') == value]
            if matches:
                if len(matches) != 1:
                    raise RemoteError('Conflicting validation records')
                row = matches[0]
                self.validate_record(row, value, comment)
                if not intent:
                    raise RemoteError('Untracked existing record; refusing to adopt')
            else:
                if intent and intent.get('record_id'):
                    raise RemoteError('Tracked record disappeared; manual inspection required')
                # Durable intent precedes creation; a lost response is reconciled by readback.
                self.state[key] = {'status': 'creating', 'comment': comment}
                self.save(self.state)
                try:
                    row = self.api('POST', self.path, {'type': 'TXT', 'name': NAME,
                        'content': value, 'ttl': 60, 'comment': comment})
                except RemoteError:
                    matches = [row for row in self.records()
                               if row.get('content') == value and row.get('comment') == comment]
                    if len(matches) != 1:
                        raise RemoteError('DNS create outcome uncertain; no blind retry') from None
                    row = matches[0]
                self.validate_record(row, value, comment)
            record_id = row['id']
            self.state[key] = {'status': 'created', 'comment': comment, 'record_id': record_id}
            self.save(self.state)
            self.validate_record(self.api('GET', self.path + '/' + record_id), value, comment)
            if self.propagate:
                self.propagate(value)
            return {'ok': True, 'record_id': record_id, 'propagated': self.propagate is not None}
        if not intent:
            return {'ok': True, 'removed': False}
        record_id = intent.get('record_id')
        if not record_id:
            matches = [row for row in self.records()
                       if row.get('content') == value and row.get('comment') == comment]
            if len(matches) > 1:
                raise RemoteError('Conflicting owned records; refusing cleanup')
            record_id = matches[0]['id'] if matches else None
        removed = False
        if record_id:
            if not re.fullmatch(r'[0-9a-f]{32}', record_id):
                raise RemoteError('Invalid stored record identifier')
            try:
                row = self.api('GET', self.path + '/' + record_id)
            except NotFound:
                row = None
            if row:
                self.validate_record(row, value, comment)
                try:
                    self.api('DELETE', self.path + '/' + record_id)
                except RemoteError:
                    pass  # Read state before deciding whether a lost delete response succeeded.
                try:
                    self.api('GET', self.path + '/' + record_id)
                except NotFound:
                    removed = True
                else:
                    raise RemoteError('DNS cleanup not confirmed')
        self.state.pop(key, None)
        self.save(self.state)
        return {'ok': True, 'removed': removed}


def main():
    import fcntl  # Runtime is Linux; pure broker logic remains locally testable.
    if os.geteuid() != 0:
        raise ValueError('Broker must run through the fixed privileged command')
    os.umask(0o077)
    request = parse_request(sys.stdin.buffer.read(2049))
    if CONFIG.stat().st_uid != 0 or CONFIG.stat().st_mode & 0o077:
        raise ValueError('Unsafe credential permissions')
    config = json.loads(CONFIG.read_text())
    STATE.mkdir(mode=0o700, exist_ok=True)
    with (STATE / 'lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_file = STATE / 'records.json'
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        broker = Broker(Cloudflare(config['token']), config['zone_id'], state,
                        lambda value: atomic_json(state_file, value),
                        lambda value: authoritative_propagation(value, config['name_servers']))
        print(json.dumps(broker.execute(request['action'], request['validation'])))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never expose credentials, headers, input, provider payloads or a traceback.
        print(json.dumps({'ok': False, 'error': 'DNS operation refused or unconfirmed',
                          'error_type': type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
