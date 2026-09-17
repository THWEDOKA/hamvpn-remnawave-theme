"""Explicit retirement of two user-selected nodes and five dependent hosts.

Includes the GB bypass only because the user separately approved its removal.
Retains source profiles, permissions, protected snapshots and all other nodes.
This removes panel objects, not hosting-provider VMs or their billing.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import preflight as p

TARGETS = {
    'gb': dict(node='a456b92a-8372-45fa-b007-117ef785abc5', ip='51.194.240.216', hosts=[
        '75133919-61a5-47ba-929e-3a27c9a361cf', 'ff845a81-3183-4439-990a-07089a776418',
        '92f1e0c1-90d3-4ed1-b532-88f3c5f0fdfc']),
    'us1': dict(node='f6e49f98-3d96-46aa-b79e-0b636f625a61', ip='162.141.185.231', hosts=[
        '762610b7-944a-4ed1-ae25-55f0d906cb15', '2935d939-15da-4c96-9f20-2060497fb4fa']),
}
NODE_IDS = {t['node'] for t in TARGETS.values()}
HOST_IDS = {h for t in TARGETS.values() for h in t['hosts']}


def stable_host(host):
    return {k:v for k,v in host.items() if k not in ('createdAt','updatedAt','viewPosition')}


def stable_node(node):
    profile = node.get('configProfile') or {}
    return dict(uuid=node['uuid'], address=node.get('address'), isDisabled=node.get('isDisabled'),
                profile=profile.get('activeConfigProfileUuid'),
                inbounds=sorted(i['uuid'] for i in profile.get('activeInbounds',[])))


class Operation:
    def __init__(self, api, store): self.api,self.store=api,store
    def collect(self):
        return p.indexed(self.api('GET','/api/nodes/')),p.indexed(self.api('GET','/api/hosts/'))

    def plan(self):
        p.require(not self.store.exists('before'),'Snapshot already exists')
        nodes,hosts=self.collect()
        for t in TARGETS.values():
            p.require(nodes[t['node']]['address']==t['ip'],'Node identity changed')
            actual={h['uuid'] for h in hosts.values() if t['node'] in h.get('nodes',[]) or h.get('address')==t['ip']}
            p.require(actual==set(t['hosts']),'Unexpected dependent host; review scope')
            p.require(all(hosts[h]['nodes']==[t['node']] for h in t['hosts']),'Shared host cannot be retired')
        profiles={p.active(nodes[n])[0] for n in NODE_IDS}
        configs={pid:self.api('GET','/api/config-profiles/'+pid) for pid in profiles}
        self.store.put('before',dict(nodes=nodes,hosts=hosts,profiles=configs,timestamp=time.time()))
        return dict(planned_nodes=2,planned_hosts=5,profiles_retained=len(configs))

    def guard(self):
        old=self.store.get('before');nodes,hosts=self.collect()
        for nid,node in old['nodes'].items():
            if nid in NODE_IDS:
                if nid not in nodes:
                    p.require(self.store.exists('node-intent-'+nid),'Node disappeared without owned intent')
                else:p.require(stable_node(nodes[nid])==stable_node(node),'Selected node drift')
            else:p.require(nid in nodes and stable_node(nodes[nid])==stable_node(node),'Unrelated node changed')
        for hid,host in old['hosts'].items():
            if hid in HOST_IDS:
                if hid not in hosts:p.require(self.store.exists('host-intent-'+hid),'Host disappeared without owned intent')
                else:p.require(stable_host(hosts[hid])==stable_host(host),'Selected host drift')
            else:p.require(hid in hosts and stable_host(hosts[hid])==stable_host(host),'Unrelated host changed')
        p.require(not any(hid not in HOST_IDS and set(h.get('nodes',[])) & NODE_IDS for hid,h in hosts.items()),'New dependent host appeared')
        for pid,profile in old['profiles'].items():
            current=self.api('GET','/api/config-profiles/'+pid)
            p.require(current['config']==profile['config'],'Retained profile changed')
        return old,nodes,hosts

    def apply(self):
        self.guard()
        for kind,ids in (('host',sorted(HOST_IDS)),('node',sorted(NODE_IDS))):
            for uid in ids:
                _,nodes,hosts=self.guard();current=hosts if kind=='host' else nodes
                if uid not in current:continue
                if kind=='node':p.require(not any(uid in h.get('nodes',[]) for h in hosts.values()),'Node still has hosts')
                marker=kind+'-intent-'+uid
                p.require(not self.store.exists(marker),'Uncertain deletion remains present; inspect before retry')
                self.store.put(marker,dict(uuid=uid,timestamp=time.time()))
                try:self.api('DELETE','/api/'+kind+'s/'+uid)
                except Exception:pass
                _,nodes,hosts=self.guard();remaining=hosts if kind=='host' else nodes
                p.require(uid not in remaining,'Deletion not confirmed')
        _,nodes,hosts=self.guard()
        p.require(not NODE_IDS & set(nodes) and not HOST_IDS & set(hosts),'Retirement incomplete')
        if not self.store.exists('finished'):self.store.put('finished',dict(timestamp=time.time(),nodes=2,hosts=5))
        return dict(deleted_nodes=2,deleted_hosts=5,other_bindings_unchanged=True,profiles_retained=True)


def main():
    import fcntl
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['plan','apply','status']);args=parser.parse_args()
    store=p.Store(Path('/root/hamvpn-cloud140-six-20260918/retirement'));store.secure()
    fd=os.open(store.path/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'selfsteal-us3'))
    from panel_api import create_client
    api,_=create_client();op=Operation(api,store)
    with os.fdopen(fd,'rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='status':
            _,nodes,hosts=op.guard();result=dict(nodes_remaining=len(NODE_IDS & set(nodes)),hosts_remaining=len(HOST_IDS & set(hosts)),finished=store.exists('finished'))
        else:result=getattr(op,args.action)()
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print(json.dumps(dict(error=type(error).__name__,message='Retirement stopped; inspect protected snapshot')),file=sys.stderr);sys.exit(1)
