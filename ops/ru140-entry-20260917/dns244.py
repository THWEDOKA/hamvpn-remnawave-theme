"""Confirmed migration of four operation-owned A records, with guarded rollback."""
import argparse
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request
from entry244_common import ENTRY, NODES, save, read, exists

OLD_ENTRY = '162.141.185.208'


def client():
    credentials = json.loads(Path('/etc/hamvpn-dns-ru214/credentials.json').read_text())
    base = 'https://api.cloudflare.com/client/v4/zones/' + credentials['zone_id'] + '/dns_records'
    def request(method, suffix='', body=None):
        req = urllib.request.Request(base + suffix, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + credentials['token'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=25) as response:
            value = json.load(response)
        assert value['success']
        return value['result']
    return request


def verify():
    request = client(); result = []
    for n in NODES:
        rows = request('GET', '?' + urllib.parse.urlencode({'name': n['domain']}))
        assert len(rows) == 1
        row = rows[0]; snapshot = read('dns-' + n['id'])['before']
        assert row['id'] == snapshot['id'] and row['name'] == n['domain']
        assert row['type'] == 'A' and row['content'] == ENTRY and not row['proxied']
        result.append({'domain': n['domain'], 'address': ENTRY, 'dns_only': True})
    save('dns-verified', {'timestamp': time.time(), 'records': result})
    return {'dns_verified': True, 'records': result}


def move():
    proof = read('new-probes')
    assert exists('published') and proof['all_passed'] and 0 <= time.time() - proof['timestamp'] < 1800
    request = client()
    pending = []
    for n in NODES:
        rows = request('GET', '?' + urllib.parse.urlencode({'name': n['domain']}))
        assert len(rows) == 1
        row = rows[0]
        original = json.loads((Path('/root/hamvpn-ru140-entry-20260917') / ('dns-' + n['id'] + '.json')).read_text())
        assert row['id'] == original['created_id'] and row['type'] == 'A' and not row['proxied']
        assert row['content'] in (OLD_ENTRY, ENTRY) and row['ttl'] == 300
        if not exists('dns-' + n['id']):
            assert row['content'] == OLD_ENTRY
        else:
            assert read('dns-' + n['id'])['before']['id'] == row['id']
        pending.append((n, row))
    for n, row in pending:
        if not exists('dns-' + n['id']):
            save('dns-' + n['id'], {'before': row, 'wanted': ENTRY})
        if row['content'] != ENTRY:
            request('PATCH', '/' + row['id'], {'content': ENTRY, 'ttl': 300, 'proxied': False})
    return verify()


def rollback():
    request = client(); restored = 0
    pending = []
    for n in NODES:
        if not exists('dns-' + n['id']): continue
        old = read('dns-' + n['id'])['before']
        current = request('GET', '/' + old['id'])
        assert all(current[k] == old[k] for k in ('name', 'type', 'proxied', 'ttl'))
        assert current['content'] in (OLD_ENTRY, ENTRY), 'Later DNS change; rollback refused'
        pending.append((old, current))
    for old, current in pending:
        if current['content'] == ENTRY:
            request('PATCH', '/' + old['id'], {'content': OLD_ENTRY})
        assert request('GET', '/' + old['id'])['content'] == OLD_ENTRY
        restored += 1
    save('dns-rollback', {'timestamp': time.time(), 'restored': restored})
    return {'dns_records_restored': restored}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['move', 'verify', 'rollback'])
    args = parser.parse_args(); print(json.dumps(globals()[args.action]()))


if __name__ == '__main__': main()
