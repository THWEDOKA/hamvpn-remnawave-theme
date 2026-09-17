"""Only approved four DNS-only records; credential never leaves panel."""
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request
from common import ENTRY,NODES,save,exists


def main():
    os.umask(0o077)
    credentials=json.loads(Path('/etc/hamvpn-dns-ru214/credentials.json').read_text())
    base='https://api.cloudflare.com/client/v4/zones/'+credentials['zone_id']+'/dns_records'
    def request(method,suffix='',body=None):
        req=urllib.request.Request(base+suffix,method=method,data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization':'Bearer '+credentials['token'],'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=25) as r:d=json.load(r)
        assert d['success'];return d['result']
    for n in NODES:
        query='?'+urllib.parse.urlencode({'name':n['domain']})
        rows=request('GET',query)
        wanted={'type':'A','name':n['domain'],'content':ENTRY,'ttl':300,'proxied':False}
        if not rows:
            assert not exists('dns-'+n['id']), 'Reconcile previous DNS intent first'
            save('dns-'+n['id'],{'intent':wanted})
            created=request('POST',body=wanted)
            save('dns-'+n['id'],{'created_id':created['id'],'record':wanted})
        rows=request('GET',query)
        assert len(rows)==1 and all(rows[0][k]==v for k,v in wanted.items()),'DNS conflict'
        print(json.dumps({'domain':n['domain'],'ip':ENTRY,'dns_only':True,'verified':True}))


if __name__=='__main__':main()
