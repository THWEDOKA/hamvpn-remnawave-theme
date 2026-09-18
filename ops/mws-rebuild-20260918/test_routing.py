import importlib.util
from pathlib import Path
import unittest
from copy import deepcopy

spec=importlib.util.spec_from_file_location('mws_routing',Path(__file__).with_name('routing.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


class SplitRoutingTests(unittest.TestCase):
    def setUp(self):
        self.out=r.outbound('72.56.101.218','mws-exit.torcalc.ru',443,
            'f13f4068-c4de-4f88-b6aa-ddf20a4bf720','test-public-key','abcd1234')
        self.c=r.entry_config(self.out,'test-private-key','abcd1234')

    def test_default_goes_abroad_without_direct_fallback(self):
        self.assertEqual(self.c['outbounds'][0]['tag'],'FOREIGN')
        self.assertEqual(self.c['routing']['domainStrategy'],'IPIfNonMatch')
        self.assertNotIn('balancers',self.c['routing'])
        for rule in self.c['routing']['rules']:
            self.assertTrue(any(k in rule for k in ('ip','domain','protocol','inboundTag')))
            if 'inboundTag' in rule:self.assertEqual(rule['inboundTag'],['MWS2-DNS'])

    def test_russian_domains_and_ips(self):
        rules=self.c['routing']['rules']
        self.assertTrue(any(x.get('ip')==['geoip:ru'] and x['outboundTag']=='RU-DIRECT' for x in rules))
        self.assertTrue(any('geosite:category-ru' in x.get('domain',[]) and x['outboundTag']=='RU-DIRECT' for x in rules))
        self.assertIn('domain:xn--p1ai',r.RUSSIAN_DOMAINS)

    def test_ssrf_block_precedes_direct_domains(self):
        self.assertEqual(self.c['routing']['rules'][0]['ip'],['geoip:private'])
        self.assertEqual(self.c['routing']['rules'][0]['outboundTag'],'BLOCK')

    def test_no_plain_backend_or_insecure_tls(self):
        self.assertEqual(self.out['streamSettings']['security'],'reality')
        self.assertEqual(self.out['settings']['vnext'][0]['address'],'72.56.101.218')
        self.assertNotIn('allowInsecure',str(self.c))

    def test_mihomo_compatibility_and_local_target(self):
        reality=self.c['inbounds'][0]['streamSettings']['realitySettings']
        self.assertEqual(reality['minClientVer'],'1.8.2')
        self.assertEqual(reality['target'],'127.0.0.1:9444')
        self.assertEqual(self.c['inbounds'][0]['port'],18443)

    def test_legacy_copy_does_not_modify_source(self):
        old={'tag':'old','port':2083,'protocol':'vless','settings':{'clients':[{'id':'sentinel'}]},
             'streamSettings':{'network':'xhttp','security':'tls','tlsSettings':{'serverName':'keep.example'}}}
        before=deepcopy(old)
        c=r.entry_config(self.out,'test-private-key','abcd1234',old)
        self.assertEqual(old,before)
        self.assertEqual(c['inbounds'][1]['streamSettings'],old['streamSettings'])
        self.assertEqual(c['inbounds'][1]['tag'],r.LEGACY_TAG)

    def test_exit_blocks_private_addresses(self):
        c=r.exit_config('test-private-key','abcd1234')
        self.assertEqual(c['routing']['rules'][0]['outboundTag'],'BLOCK')
        self.assertEqual(c['outbounds'][0]['tag'],'DIRECT')


if __name__=='__main__':unittest.main()
