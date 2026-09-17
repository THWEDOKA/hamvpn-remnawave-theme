"""Promote verified direct listeners; leave TEST on 443 and nginx HTTP/TLS alone."""
import argparse
import copy
import hashlib
import json
import os
import socket
import ssl
import time

import panel244 as p
import node244 as n
from entry244_common import *

PORTS = dict(zip((node['id'] for node in NODES), (18443, 18444, 18445, 18446)))


def convert(config, before):
    result = copy.deepcopy(config)
    legacy = copy.deepcopy(before['profiles'][OLD_PROFILE]['config']['inbounds'][0])
    legacy['tag'] = LEGACY_TAG
    assert legacy['port'] == 443
    result['inbounds'][0] = legacy
    for node in NODES:
        inbound = next(i for i in result['inbounds'] if i['tag'] == 'vless-entry244-' + node['id'])
        inbound.update(listen=ENTRY, port=PORTS[node['id']])
        inbound['streamSettings']['sockopt'] = {'tcpMaxSeg': 1200}
    return result


def checksum(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def prepare():
    assert not exists('direct-prepared') and not exists('direct-prepare-intent')
    assert exists('retry3-prepared') and exists('rollback')
    assert not exists('published') and not exists('publish-intent')
    assert not any(exists('dns-' + node['id']) for node in NODES)
    assert all(unit_inactive(p.TIMER + suffix) for suffix in ('.timer', '.service'))
    proof = read('isolated-diagnostic-proof')
    assert 0 <= time.time() - proof['timestamp'] < 1800
    assert len(proof['tests']) == 8 and all(t['passed'] for t in proof['tests'])
    assert {t['id'] for t in proof['tests']} == {node['id']+'-'+fp for node in NODES for fp in ('chrome','firefox')}
    api, _ = p.prior.create_client()
    current = api('GET','/api/nodes/' + NODE)
    assert current['isConnected'] and current['address'] == ENTRY
    assert p.binding(current) == {'profile':OLD_PROFILE,'inbounds':[OLD_INBOUND]}
    hosts = {h['uuid']:h for h in api('GET','/api/hosts/')}
    for host in read('before')['hosts']:
        if host['uuid'] in OLD_HOSTS | TARGET_HOSTS:
            assert p.prior.stable_host(host) == p.prior.stable_host(hosts[host['uuid']])
    profile = api('GET','/api/config-profiles/' + read('created')['profile'])
    assert profile['config'] == read('candidate')
    assert not any(p.binding(node)['profile'] == profile['uuid'] for node in api('GET','/api/nodes/'))
    archive = STATE / 'attempt3-rolled-back'
    assert not archive.exists()
    names = ['activate-intent.json','activated.json','rollback.json','new-probes.json']
    assert all((STATE/name).is_file() and not (STATE/name).is_symlink() for name in names)
    save('direct-before-profile', profile)
    save('direct-prepare-intent', {'timestamp':time.time()})
    archive.mkdir(mode=0o700)
    for name in names: (STATE/name).rename(archive/name)
    candidate = convert(read('candidate'), read('before'))
    save('candidate', candidate)
    save('direct-prepared', {'timestamp':time.time(),'sha256':checksum(candidate),'ports':PORTS})
    return {'direct_candidate_ready':True,'test_443_preserved':True,'ports':PORTS}


def stage():
    assert exists('direct-prepared') and not exists('direct-stage-intent')
    config = read('candidate')
    assert read('installed-test')['installed_xray_test_passed']
    assert read('installed-test')['sha256'] == checksum(config) == read('direct-prepared')['sha256']
    api,_ = p.prior.create_client()
    created = read('created'); previous = read('direct-before-profile')
    assert api('GET','/api/config-profiles/'+created['profile']) == previous
    assert not any(p.binding(node)['profile'] == created['profile'] for node in api('GET','/api/nodes/'))
    save('direct-stage-intent', {'timestamp':time.time()})
    api('PATCH','/api/config-profiles/',{'uuid':created['profile'],'config':config})
    current = api('GET','/api/config-profiles/'+created['profile'])
    assert current['config'] == config
    assert {i['tag']:i['uuid'] for i in current['inbounds']} == {i['tag']:i['uuid'] for i in previous['inbounds']}
    save('direct-staged', {'timestamp':time.time(),'sha256':checksum(config)})
    return {'isolated_direct_profile_staged':True,'production_binding_unchanged':True}


def entry_check(finish=False):
    assert ENTRY + '/' in run('ip','-4','addr','show')
    assert not n.STREAM.exists()
    assert all(unit_inactive(n.TIMER + suffix) for suffix in ('.timer','.service'))
    assert all(unit_inactive('ham-entry244-isolated-diagnostic'+suffix+'.service') for suffix in ('','-nginx'))
    config = read('candidate')
    assert config['inbounds'][0]['port'] == 443
    for node in NODES:
        inbound = next(i for i in config['inbounds'] if i['tag'] == 'vless-entry244-'+node['id'])
        assert (inbound['listen'],inbound['port']) == (ENTRY,PORTS[node['id']])
        assert inbound['streamSettings']['sockopt']['tcpMaxSeg'] == 1200
    tested = read('xray-config-test')
    assert tested['passed'] and tested['sha256'] == checksum(config)
    proof = read('backend-probes')
    assert proof['all_passed'] and proof['candidate_sha256'] == checksum(config)
    assert 0 <= time.time()-proof['timestamp'] < 1800
    assert n.digest(n.SITE) == read('certificate')['site_sha256']
    n.local_tls(); run(str(n.FIREWALL),'check'); run('nginx','-t')
    for port in PORTS.values():
        with socket.socket() as sock:
            if finish:
                sock.settimeout(3); sock.connect((ENTRY,port))
            else: sock.bind((ENTRY,port))
    if finish:
        assert read('renewal')['passed']
        run('systemctl','is-enabled','certbot.timer'); run('systemctl','is-active','certbot.timer')
    save('direct-entry-finished' if finish else 'direct-entry-ready',{'timestamp':time.time(),'sha256':checksum(config)})
    return {'direct_entry_verified':True,'renewal_verified':finish,'nginx_public_router_absent':True,'test_443_listener':bool(n.public_443())}


def sites():
    results=[]
    for node in NODES:
        ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(['http/1.1'])
        with socket.create_connection((ENTRY,PORTS[node['id']]),timeout=12) as raw:
            with ctx.wrap_socket(raw,server_hostname=node['domain']) as secure:
                assert secure.version()=='TLSv1.3'
                secure.sendall(('GET / HTTP/1.1\r\nHost: '+node['domain']+'\r\nConnection: close\r\n\r\n').encode())
                body=b''
                while chunk:=secure.recv(65536): body+=chunk
                assert body.startswith(b'HTTP/1.1 200') and 'Ремонт'.encode() in body
                results.append({'domain':node['domain'],'port':PORTS[node['id']],'tls13':True,'website_http':200,'certificate_expires':secure.getpeercert()['notAfter']})
    save('direct-public-sites',{'timestamp':time.time(),'tests':results})
    return {'public_sites_verified':results}


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','stage','entry-check','entry-finish','sites'])
    action=parser.parse_args().action
    result=entry_check(action=='entry-finish') if action.startswith('entry-') else globals()[action]()
    print(json.dumps(result))
