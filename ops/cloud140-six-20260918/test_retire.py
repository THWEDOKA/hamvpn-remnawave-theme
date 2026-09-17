from copy import deepcopy
import unittest
import retire as r

class Memory:
    def __init__(self):self.records={}
    def exists(self,k):return k in self.records
    def get(self,k):return deepcopy(self.records[k])
    def put(self,k,v):
        if k in self.records:raise RuntimeError('immutable')
        self.records[k]=deepcopy(v)

class API:
    def __init__(self):
        self.nodes={};self.hosts={};self.calls=[];self.fail=False
        for t in r.TARGETS.values():
            self.nodes[t['node']]=dict(uuid=t['node'],address=t['ip'],isDisabled=False,configProfile=dict(activeConfigProfileUuid='profile',activeInbounds=[dict(uuid='inbound')]))
            for hid in t['hosts']:self.hosts[hid]=dict(uuid=hid,address=t['ip'],nodes=[t['node']])
        self.nodes['other']=dict(uuid='other',address='192.0.2.1',isDisabled=False,configProfile=None)
        self.hosts['other']=dict(uuid='other',address='192.0.2.1',nodes=['other'])
    def __call__(self,method,path,body=None):
        if method=='GET':
            if path=='/api/nodes/':return deepcopy(list(self.nodes.values()))
            if path=='/api/hosts/':return deepcopy(list(self.hosts.values()))
            return dict(config={'fixture':'kept'})
        self.calls.append((method,path));kind,uid=path.split('/')[-2:]
        if self.fail:raise TimeoutError('fixture')
        del (self.nodes if kind=='nodes' else self.hosts)[uid]

class Tests(unittest.TestCase):
    def setUp(self):self.api=API();self.s=Memory();self.op=r.Operation(self.api,self.s)
    def test_only_two_nodes_and_five_hosts_deleted(self):
        self.op.plan();self.op.apply();self.op.apply()
        self.assertEqual(set(self.api.nodes),{'other'});self.assertEqual(set(self.api.hosts),{'other'})
        self.assertEqual(len(self.api.calls),7)
        self.assertTrue(all(m=='DELETE' for m,_ in self.api.calls))
    def test_unexpected_dependency_refused(self):
        self.api.hosts['new']=dict(uuid='new',address='192.0.2.2',nodes=[next(iter(r.NODE_IDS))])
        with self.assertRaises(RuntimeError):self.op.plan()
        self.assertEqual(self.api.calls,[])
    def test_shared_host_refused(self):
        self.api.hosts[next(iter(r.HOST_IDS))]['nodes'].append('other')
        with self.assertRaises(RuntimeError):self.op.plan()
    def test_uncertain_delete_not_retried(self):
        self.op.plan();self.api.fail=True
        for _ in range(2):
            with self.assertRaises(RuntimeError):self.op.apply()
        self.assertEqual(len(self.api.calls),1)
    def test_unrelated_drift_blocks_deletion(self):
        self.op.plan();self.api.nodes['other']['address']='192.0.2.8'
        with self.assertRaises(RuntimeError):self.op.apply()
        self.assertEqual(self.api.calls,[])

if __name__=='__main__':unittest.main()
