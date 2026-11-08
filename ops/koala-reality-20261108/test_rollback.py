import copy
import unittest
import core_rollback as core
import profile_compat as profile


def fixture():
    return {'inbounds':[{'tag':'plreg-raw','port':443,'protocol':'vless','settings':{'flow':'xtls-rprx-vision','clients':[{'id':'fixture-user'}]},'streamSettings':{'network':'raw','security':'reality','realitySettings':{'privateKey':'fixture-key','shortIds':['aa'],'serverNames':['pl.yaneznayvas.lol'],'minClientVer':'0.0.0'}}},{'tag':'untouched','port':12345}],'routing':{'rules':[{'outboundTag':'DIRECT'}]},'outbounds':[{'tag':'DIRECT','protocol':'freedom'}]}


class RollbackTests(unittest.TestCase):
    def test_only_one_version_field_changes_without_mutating_source(self):
        before=fixture();expected=copy.deepcopy(before);expected['inbounds'][0]['streamSettings']['realitySettings']['minClientVer']='1.8.2'
        self.assertEqual(core.candidate(before),expected);self.assertEqual(profile.candidate(before),expected)
        self.assertEqual(before,fixture())
    def test_target_identity_guards(self):
        for field,value in [('port',8443),('protocol','trojan'),('tag','other')]:
            cfg=fixture();cfg['inbounds'][0][field]=value
            with self.assertRaises(ValueError):core.candidate(cfg)
            with self.assertRaises(ValueError):profile.candidate(cfg)
    def test_rejects_non_reality(self):
        cfg=fixture();cfg['inbounds'][0]['streamSettings']['security']='tls'
        with self.assertRaises(ValueError):core.candidate(cfg)
        with self.assertRaises(ValueError):profile.candidate(cfg)
    def test_preserves_stricter_explicit_policy(self):
        cfg=fixture();cfg['inbounds'][0]['streamSettings']['realitySettings']['minClientVer']='26.10.31'
        with self.assertRaises(ValueError):profile.candidate(cfg)
    def test_godebug_preserves_unrelated_settings_and_disables_mptcp(self):
        self.assertEqual(core.godebug('gctrace=1,multipathtcp=2,netdns=go'),'gctrace=1,netdns=go,multipathtcp=0')
        self.assertEqual(core.godebug(''),'multipathtcp=0')
        self.assertEqual(core.godebug(core.godebug('netdns=go')),core.godebug('netdns=go'))
    def test_wrong_domain_refused(self):
        cfg=fixture();cfg['inbounds'][0]['streamSettings']['realitySettings']['serverNames']=['elsewhere.invalid']
        with self.assertRaises(ValueError):core.candidate(cfg)
    def test_duplicate_inbound_refused(self):
        cfg=fixture();cfg['inbounds'].append(copy.deepcopy(cfg['inbounds'][0]))
        with self.assertRaises(ValueError):core.candidate(cfg)
        with self.assertRaises(ValueError):profile.candidate(cfg)
    def test_version_change_is_idempotent(self):
        cfg=profile.candidate(fixture());self.assertEqual(profile.candidate(cfg),cfg)


if __name__=='__main__':unittest.main()
