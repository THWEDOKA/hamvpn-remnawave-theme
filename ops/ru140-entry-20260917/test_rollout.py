import ast
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent


class Rollout(unittest.TestCase):
    def test_python(self):
        for path in ROOT.glob('*.py'):ast.parse(path.read_text(encoding='utf-8'),filename=str(path))

    def test_scope(self):
        nodes=json.loads((ROOT/'nodes.json').read_text())
        self.assertEqual({n['ip'] for n in nodes},{'217.60.68.182','31.56.188.150','94.183.255.82','62.60.226.94'})
        self.assertEqual(len({n['domain'] for n in nodes}),4)
        self.assertEqual(len({n['link'] for n in nodes}),4)
        self.assertEqual(len({n['port'] for n in nodes}),4)
        stream=(ROOT/'nginx-stream.conf').read_text()
        for n in nodes:self.assertIn(n['domain']+' 127.0.0.1:'+str(n['port']),stream)
        self.assertIn('listen 443;',stream)
        self.assertIn('ssl_preread on;',stream)

    def test_cert_and_site(self):
        tls=(ROOT/'nginx-tls.conf').read_text()
        self.assertIn('listen 127.0.0.1:8443 ssl http2;',tls)
        self.assertNotIn('listen 443',tls)
        for n in json.loads((ROOT/'nodes.json').read_text()):self.assertIn(n['domain'],tls)
        html=(ROOT/'site/index.html').read_text(encoding='utf-8')
        self.assertIn('viewport',html);self.assertIn('Ремонт чайников',html)

    def test_isolation(self):
        source=(ROOT/'exit_link.py').read_text()
        for value in ['127.0.0.1:443','/bin/false',"'MaxSessions':'0'",'root_policy_unchanged','authorized_keys.pending']:
            self.assertIn(value,source)
        firewall=(ROOT/'firewall.sh').read_text()
        self.assertNotIn('iptables -F',firewall)
        self.assertNotIn('--dport 22 ',firewall)
        node=(ROOT/'node.py').read_text()
        self.assertIn('StrictHostKeyChecking=yes',node)
        self.assertIn('ServerAliveCountMax=3',node)
        self.assertIn('--run-deploy-hooks',node)

    def test_entry_is_fail_closed(self):
        import sys
        sys.path.insert(0,str(ROOT))
        import panel
        profiles={};nodes=json.loads((ROOT/'nodes.json').read_text())
        for n in nodes:
            profiles[n['profile']]={'inbounds':[{'uuid':n['inbound'],'tag':'test'}],
                'config':{'inbounds':[{'tag':'test','streamSettings':{'network':'raw','security':'tls'}}]}}
        c=panel.candidate(profiles,{'vlessUuid':'00000000-0000-4000-8000-000000000001'})
        self.assertEqual(c['outbounds'][0],{'tag':'BLOCK','protocol':'blackhole'})
        self.assertNotIn('freedom',[o['protocol'] for o in c['outbounds']])
        self.assertEqual(len(c['inbounds']),4)
        for n,inbound,outbound in zip(nodes,c['inbounds'],c['outbounds'][1:]):
            self.assertEqual(inbound['listen'],'127.0.0.1')
            self.assertEqual(inbound['streamSettings']['realitySettings']['target'],'127.0.0.1:8443')
            self.assertEqual(outbound['settings']['vnext'][0]['address'],'127.0.0.1')
            self.assertEqual(outbound['settings']['vnext'][0]['port'],n['link'])


if __name__=='__main__':unittest.main()
