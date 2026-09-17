"""Fresh scoped technical user and current DE245 subscription, no VPN changes."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import preflight as p
import coordinator as c
import frontend as f

STATE = Path('/root/hamvpn-cloud140-repair-20260918')
ORIGINAL = p.STATE


def current(api):
    old = f.Store().read('state')
    entry = api('GET', '/api/nodes/' + p.ENTRY_ID)
    exit_node = api('GET', '/api/nodes/' + c.target('de245')['node'])
    core = c.RootStore().read('exit-de245')
    assert entry['address'] == p.ENTRY and exit_node['address'] == c.target('de245')['ip']
    assert c.binding(exit_node) == core['desired_binding']
    assert c.binding(entry)['profile'] == old['profile']
    profile = api('GET', '/api/config-profiles/' + old['profile'])
    assert profile['config'] == old['candidate']
    hosts = [api('GET', '/api/hosts/' + hid) for hid in c.target('de245')['hosts']]
    for host in hosts:
        assert host['address'] == p.ENTRY and host['port'] == 18444 and host['sni'] == 'in-de245.torcalc.ru'
        assert host['nodes'] == [p.ENTRY_ID] and host['inbound']['configProfileInboundUuid'] == old['front']
    return old, core, hosts


def prepare(api):
    current(api)
    before, _ = c.RootStore().before()
    p.STATE = STATE
    if not p.exists('before'):
        p.save('before', before)
    user = p.account(api)
    return dict(disposable_probe_ready=True)


def export(api, kind):
    old, core, hosts = current(api)
    p.STATE = STATE
    user = p.account(api)
    expected = c.target('de245')['ip']
    if kind == 'backend':
        request = deepcopy(old['requests']['backend']['request'])
    elif kind == 'public':
        request = deepcopy(old['requests']['public']['request'])
        for item in request['items']:
            item['outbound']['settings']['vnext'][0]['users'][0]['id'] = user['vlessUuid']
    else:
        configs = f.fetch_happ(api('GET', '/api/subscriptions/by-uuid/' + user['uuid'])['subscriptionUrl'])
        items = []
        for host in hosts:
            remark = f.AUTO_REMARK if host['isHidden'] else host['remark']
            matched = [cfg for cfg in configs if cfg.get('remarks') == remark]
            assert len(matched) == 1
            outputs = [out for out in matched[0].get('outbounds', []) if out.get('protocol') == 'vless'
                       and any(v.get('address') == p.ENTRY and v.get('port') == 18444
                               for v in out.get('settings', {}).get('vnext', []))]
            assert len(outputs) == 1
            f.Frontend._wire(None, outputs[0], old, user['vlessUuid'], host)
            items.append(dict(id='de245-sub-' + ('auto' if host['isHidden'] else 'main'), ip=expected, outbound=outputs[0]))
        request = dict(sha256=old['sha256'], items=items)
    p.save('request-' + kind, request)
    return request


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'export', 'cleanup'])
    parser.add_argument('--kind', choices=['backend', 'public', 'subscription'])
    args = parser.parse_args()
    try:
        api, query = p.create_client()
        if args.action == 'prepare': result = prepare(api)
        elif args.action == 'export':
            assert args.kind
            result = export(api, args.kind)
        else:
            p.STATE = STATE
            result = p.cleanup(api, query)
        print(json.dumps(result))
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__, message='Probe failed; no VPN configuration was written')), file=sys.stderr)
        sys.exit(1)
