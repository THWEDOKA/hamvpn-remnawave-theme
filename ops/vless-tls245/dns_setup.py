"""Explicitly approved single DNS record. Token accepted only at a hidden prompt."""
import getpass
import json
import urllib.request

DOMAIN = 'tls245.torcalc.ru'
IP = '196.251.107.245'


def main():
    token = getpass.getpass('Cloudflare token (hidden): ')
    def request(method, path, body=None):
        req = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
            method=method, data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.load(response)
        assert result.get('success'), 'Cloudflare operation failed'
        return result['result']
    zones = request('GET', '/zones?name=torcalc.ru')
    assert len(zones) == 1 and zones[0]['name'] == 'torcalc.ru'
    path = '/zones/' + zones[0]['id'] + '/dns_records'
    records = request('GET', path + '?name=' + DOMAIN)
    if records:
        assert len(records) == 1, 'Existing DNS conflicts; stop'
        rec = records[0]
        assert rec['type'] == 'A' and rec['content'] == IP and not rec['proxied'], 'Existing DNS conflicts; stop'
        created = False
    else:
        rec = request('POST', path, {'type': 'A', 'name': DOMAIN, 'content': IP,
            'ttl': 300, 'proxied': False, 'comment': 'HAMVPN ordinary VLESS TLS node 245'})
        created = True
    verified = request('GET', path + '/' + rec['id'])
    assert verified['name'] == DOMAIN and verified['content'] == IP and not verified['proxied']
    print(json.dumps({'created': created, 'domain': DOMAIN, 'ip': IP,
        'dns_only': True, 'record_id': rec['id']}))


if __name__ == '__main__':
    main()
