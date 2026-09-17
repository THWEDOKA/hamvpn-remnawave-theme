import copy
import unittest
from unittest.mock import patch
import direct244 as d
import panel244 as p
from test_entry244 import fixture, SERVICE, CREATED


class DirectTests(unittest.TestCase):
    def setUp(self):
        self.before=fixture()
        with patch.object(p.prior,'public_key',return_value='NOT_A_PUBLIC_KEY'):
            self.old=p.candidate(self.before,SERVICE)
        self.new=d.convert(self.old,self.before)

    def test_only_front_listeners_and_sockopt_change(self):
        original=copy.deepcopy(self.old)
        self.assertEqual(self.old,original)
        self.assertEqual(self.new['routing'],self.old['routing'])
        self.assertEqual(self.new['outbounds'],self.old['outbounds'])
        legacy=copy.deepcopy(self.before['profiles'][p.OLD_PROFILE]['config']['inbounds'][0])
        legacy['tag']=p.LEGACY_TAG
        self.assertEqual(self.new['inbounds'][0],legacy)
        for node in p.NODES:
            old=next(i for i in self.old['inbounds'] if i['tag']=='vless-entry244-'+node['id'])
            expected=copy.deepcopy(old)
            expected.update(listen=p.ENTRY,port=d.PORTS[node['id']])
            expected['streamSettings']['sockopt']={'tcpMaxSeg':1200}
            actual=next(i for i in self.new['inbounds'] if i['tag']==expected['tag'])
            self.assertEqual(actual,expected)

    def test_main_and_hidden_hosts_get_correct_direct_port(self):
        with patch.object(p,'read',side_effect=lambda name: self.new if name=='candidate' else CREATED):
            for node in p.NODES:
                for host in self.before['hosts']:
                    if host['uuid'] in node['hosts']:
                        fields=p.target_host(host)
                        self.assertEqual(fields['port'],d.PORTS[node['id']])
                        self.assertEqual(fields['address'],node['domain'])
                        self.assertNotIn('isHidden',fields)
                        self.assertNotIn('remark',fields)

    def test_historical_loopback_candidate_keeps_443(self):
        with patch.object(p,'read',return_value=self.old):
            self.assertTrue(all(p.frontend_port(node)==443 for node in p.NODES))


if __name__=='__main__': unittest.main()
