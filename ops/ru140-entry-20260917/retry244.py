"""Archive the completed failed attempt before one explicitly checked retry."""
import argparse
import json
import os
import time
from entry244_common import *


def prepare(role):
    import panel244 as p
    import node244 as n
    unit = p.TIMER if role == 'panel' else n.TIMER
    assert all(unit_inactive(unit + suffix) for suffix in ('.timer', '.service'))
    archive = STATE / 'attempt1-rolled-back'
    assert not archive.exists(), 'Retry already prepared; inspect current state'
    if role == 'panel':
        assert exists('rollback') and not exists('published') and not exists('publish-intent')
        assert not any(exists('dns-' + node['id']) for node in NODES)
        api,_ = p.prior.create_client()
        current = api('GET','/api/nodes/' + NODE)
        assert current['isConnected'] and current['address'] == ENTRY
        assert p.binding(current) == {'profile':OLD_PROFILE,'inbounds':[OLD_INBOUND]}
        now = {h['uuid']:h for h in api('GET','/api/hosts/')}
        for host in read('before')['hosts']:
            if host['uuid'] in OLD_HOSTS | TARGET_HOSTS:
                assert p.prior.stable_host(host) == p.prior.stable_host(now[host['uuid']])
        assert api('GET','/api/config-profiles/'+read('created')['profile'])['config'] == read('candidate')
        names = ['activate-intent.json','activated.json','rollback.json','new-probes.json']
    else:
        assert ENTRY + '/' in run('ip','-4','addr','show')
        assert exists('nginx-rolled-back') and not n.STREAM.exists()
        assert read('xray-config-test')['passed'] and read('backend-probes')['all_passed']
        n.local_tls()
        names = ['nginx-rolled-back.json','rolled-back-stream.conf','stream-intent.json']
    paths = [STATE/name for name in names]
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    archive.mkdir(mode=0o700)
    for path in paths:
        path.rename(archive/path.name)
    save('retry2-prepared', {'timestamp':time.time(),'role':role,'previous_attempt_archived':True})
    print(json.dumps({'retry2_prepared':role,'previous_failure_evidence_preserved':True}))


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('role',choices=['entry','panel'])
    prepare(parser.parse_args().role)
