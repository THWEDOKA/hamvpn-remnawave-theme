"""Bounded isolated diagnostic listeners; never changes panel or public 443."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import panel244 as p
from entry244_common import ENTRY, STATE, read, save, run

UNIT = 'ham-entry244-isolated-diagnostic'
PORTS = (18443, 18444, 18445, 18446)


def payload(api):
    user = p.user(api)
    candidate = read('candidate')
    own = next(i for i in candidate['inbounds'] if i['tag'] == 'vless-entry244-de182')
    legacy = candidate['inbounds'][0]
    upstream = next(o for o in candidate['outbounds'] if o['tag'] == 'exit-de182')
    config = {'log': {'loglevel': 'debug'}, 'inbounds': [], 'outbounds': [copy.deepcopy(upstream),
              {'protocol': 'freedom', 'tag': 'DIAGNOSTIC-DIRECT'}], 'routing': {'rules': []}}
    tests = []
    for name, port, source in [('self',18443,own),('legacy',18444,legacy),('tls',18445,own),('self-direct',18446,own)]:
        inbound = copy.deepcopy(source)
        inbound.update(tag='diag-' + name, listen=ENTRY, port=port)
        inbound['settings']['clients'] = [{'id': user['vlessUuid'], 'flow': 'xtls-rprx-vision'}]
        client = p.reality_client(source, user, ENTRY,
                                 'google.com' if name == 'legacy' else 'in-de3.torcalc.ru', 'chrome')
        client['settings']['vnext'][0]['port'] = port
        if name == 'tls':
            inbound['streamSettings'] = {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                'alpn': ['h2','http/1.1'], 'certificates': [{
                    'certificateFile': '/etc/letsencrypt/live/in-de3.torcalc.ru/fullchain.pem',
                    'keyFile': '/etc/letsencrypt/live/in-de3.torcalc.ru/privkey.pem'}]}}
            client['streamSettings'] = {'network': 'raw', 'security': 'tls', 'tlsSettings': {
                'serverName': 'in-de3.torcalc.ru', 'fingerprint': 'chrome', 'allowInsecure': False}}
        config['inbounds'].append(inbound)
        config['routing']['rules'].append({'type':'field','inboundTag':[inbound['tag']],
             'outboundTag':'DIAGNOSTIC-DIRECT' if name == 'self-direct' else 'exit-de182'})
        tests.append({'id': name, 'ip': ENTRY if name == 'self-direct' else '217.60.68.182', 'outbound':client})
    return {'config': config, 'tests': tests}


def start(mss=0):
    assert ENTRY + '/' in run('ip','-4','addr','show')
    value = json.load(sys.stdin)
    config = value['config']
    if mss:
        for inbound in config['inbounds']:
            inbound['streamSettings']['sockopt'] = {'tcpMaxSeg': mss}
    assert len(config['inbounds']) == 4
    assert {i['port'] for i in config['inbounds']} == set(PORTS)
    assert all(i['listen'] == ENTRY and len(i['settings']['clients']) == 1 for i in config['inbounds'])
    for port in PORTS:
        with socket.socket() as s: s.bind((ENTRY,port))
    binary = STATE / 'probe-xray'
    assert binary.is_file()
    save('isolated-diagnostic-config', config)
    save('isolated-diagnostic-tests', value['tests'])
    path = STATE / 'isolated-diagnostic-config.json'
    run(str(binary),'run','-test','-c',str(path))
    run('systemd-run','--unit='+UNIT,'--property=RuntimeMaxSec=900','--property=UMask=0077',
        '--property=StandardOutput=append:'+str(STATE/'isolated-diagnostic.log'),
        '--property=StandardError=append:'+str(STATE/'isolated-diagnostic.log'),
        str(binary),'run','-c',str(path))
    print(json.dumps({'isolated_test_started':True,'ports':PORTS,'auto_stop_seconds':900,'server_mss':mss}))


def probe():
    value = payload(p.prior.create_client()[0])
    tests = []
    for item in value['tests']:
        for attempt in range(2):
            result = {'id':item['id'],'attempt':attempt+1,**p.test_one(item['outbound'],item['ip'])}
            tests.append(result); print(json.dumps(result),flush=True)
    save('isolated-diagnostic-proof',{'timestamp':time.time(),'tests':tests})


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['export','start','probe','stop'])
    parser.add_argument('--mss',type=int,choices=[0,1200],default=0)
    args=parser.parse_args();action=args.action
    if action=='export': print(json.dumps(payload(p.prior.create_client()[0])))
    elif action=='start': start(args.mss)
    elif action=='probe': probe()
    else:
        run('systemctl','stop',UNIT+'.service')
        for port in PORTS:
            with socket.socket() as s: s.bind((ENTRY,port))
        print('{"isolated_test_stopped":true}')


if __name__=='__main__': main()
