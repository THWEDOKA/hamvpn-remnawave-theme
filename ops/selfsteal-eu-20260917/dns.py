"""Only four approved DNS-only A records; Cloudflare secret stays on panel."""
import json
import os
from pathlib import Path
import urllib.request
import urllib.parse

ROOT = Path(__file__).resolve().parent
STATE = Path('/root/hamvpn-selfsteal-eu-20260917/dns')


def main():
    os.umask(0o077); STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    credentials = json.loads(Path('/etc/hamvpn-dns-ru214/credentials.json').read_text())
    base = 'https://api.cloudflare.com/client/v4/zones/' + credentials['zone_id'] + '/dns_records'
    def request(method, suffix='', body=None):
        r = urllib.request.Request(base + suffix, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + credentials['token'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(r, timeout=25) as response: data = json.load(response)
        assert data['success']; return data['result']
    for n in json.loads((ROOT / 'nodes.json').read_text()):
        expected = json.loads((ROOT / n['id'] / 'dns-record.json').read_text())
        records = request('GET', '?' + urllib.parse.urlencode({'name': n['domain']}))
        state = STATE / (n['id'] + '.json')
        if not records:
            assert not state.exists(), 'Existing intent without record: investigate before retry'
            state.write_text(json.dumps({'intent': expected})); state.chmod(0o600)
            record = request('POST', body=expected)
            state.write_text(json.dumps({'created_id': record['id'], 'record': expected}))
        records = request('GET', '?' + urllib.parse.urlencode({'name': n['domain']}))
        assert len(records) == 1, 'Conflicting DNS records'
        record = records[0]
        assert all(record[k] == expected[k] for k in ('type', 'name', 'content', 'proxied')), 'DNS conflict'
        print(json.dumps({'domain': n['domain'], 'ip': n['ip'], 'dns_only': True, 'readback_verified': True}))


if __name__ == '__main__': main()
