import copy
import unittest
from unittest.mock import patch
import usa244panel as u


class CandidateTests(unittest.TestCase):
    def fixture(self):
        original={'tag':'old-us','port':15443,'listen':'127.0.0.1','protocol':'vless',
            'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'raw','security':'reality',
            'realitySettings':{'privateKey':'FAKE_PRIVATE_KEY','shortIds':['FAKE_SHORT_ID'],
                'serverNames':['us3.torcalc.ru','google.com'],'target':'127.0.0.1:8443'}}}
        old={'inbounds':[{'tag':'old-'+str(i),'port':443+i} for i in range(5)],
            'outbounds':[{'tag':'DIRECT','protocol':'freedom'},{'tag':'BLOCK','protocol':'blackhole'}],
            'routing':{'rules':[{'ip':['geoip:private'],'outboundTag':'BLOCK'},
                {'inboundTag':['old-1'],'outboundTag':'exit-de'},
                {'domain':['geosite:ru'],'outboundTag':'DIRECT'}]}}
        return {'profile':{'config':old},'source_profile':{'inbounds':[{'uuid':u.SOURCE_INBOUND,'tag':'old-us'}],
            'config':{'inbounds':[original]}}}

    def candidate(self):
        before=self.fixture()
        with patch.object(u.p.prior,'public_key',return_value='FAKE_PUBLIC_KEY'):
            result=u.build(before,{'vlessUuid':'00000000-0000-4000-8000-000000000001'})
        return before,result

    def test_only_usa_is_added_and_source_not_mutated(self):
        before,result=self.candidate()
        self.assertEqual(before,self.fixture())
        u.assert_preserved(result,before['profile']['config'])
        self.assertEqual(result['inbounds'][:-1],before['profile']['config']['inbounds'])

    def test_frontend_own_sni_preserves_keys_and_legacy_snis(self):
        before,result=self.candidate();front=result['inbounds'][-1]
        self.assertEqual((front['listen'],front['port']),(u.ENTRY,18447))
        reality=front['streamSettings']['realitySettings'];old=u.source_inbound(before['source_profile'])['streamSettings']['realitySettings']
        self.assertEqual(reality['privateKey'],old['privateKey']);self.assertEqual(reality['shortIds'],old['shortIds'])
        self.assertEqual(reality['serverNames'],[u.DOMAIN,*old['serverNames']])
        self.assertEqual(reality['target'],'127.0.0.1:19443')
        self.assertEqual(front['streamSettings']['sockopt']['tcpMaxSeg'],1200)

    def test_usa_route_precedes_direct_and_backend_is_loopback(self):
        _,result=self.candidate();rules=result['routing']['rules']
        self.assertLess(next(i for i,r in enumerate(rules) if r.get('outboundTag')==u.OUT),next(i for i,r in enumerate(rules) if r.get('outboundTag')=='DIRECT'))
        upstream=result['outbounds'][-1]
        self.assertEqual(upstream['settings']['vnext'][0]['address'],'127.0.0.1')
        self.assertEqual(upstream['settings']['vnext'][0]['port'],25443)
        self.assertEqual(upstream['streamSettings']['security'],'reality')

    def test_existing_route_modification_is_rejected(self):
        before,result=self.candidate();result['inbounds'][0]['port']=8443
        with self.assertRaises(AssertionError):u.assert_preserved(result,before['profile']['config'])


if __name__=='__main__':unittest.main()
