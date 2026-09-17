"""Move precisely the four operation-owned records after explicit confirmation."""
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request
from entry208_common import ENTRY, NODES, save, read, exists


def main():
    os.umask(0o077)
    credentials = json.loads(Path('/etc/hamvpn-dns-ru214/credentials.json').read_text())
    base = 'https://api.cloudflare.com/client/v4/zones/' + credentials['zone_id'] + '/dns_records'
    def request(method, suffix='', body=None):
        req = urllib.request.Request(base + suffix, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + credentials['token'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=25) as response:
            result = json.load(response)
        assert result['success']
        return result['result']
    for n in NODES:
        rows = request('GET', '?' + urllib.parse.urlencode({'name': n['domain']}))
        assert len(rows) == 1
        row = rows[0]
        old_intent = json.loads((Path('/root/hamvpn-ru140-entry-20260917') / ('dns-' + n['id'] + '.json')).read_text())
        assert row['id'] == old_intent['created_id'] and row['type'] == 'A' and not row['proxied']
        assert row['content'] in ('176.108.245.140', ENTRY)
        if not exists('dns-' + n['id']):
            assert row['content'] == '176.108.245.140'
            save('dns-' + n['id'], {'before': row, 'wanted': ENTRY})
        assert read('dns-' + n['id'])['before']['id'] == row['id']
        if row['content'] != ENTRY:
            request('PATCH', '/' + row['id'], {'content': ENTRY, 'ttl': 300, 'proxied': False})
        current = request('GET', '/' + row['id'])
        assert current['content'] == ENTRY and not current['proxied'] and current['name'] == n['domain']
        print(json.dumps({'domain': n['domain'], 'address': ENTRY, 'dns_only': True, 'verified': True}), flush=True)


if __name__ == '__main__':
    main()
