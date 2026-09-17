from copy import deepcopy
import unittest
import node_ops as n


class Tests(unittest.TestCase):
    def request(self):
        return dict(sha256='a'*64, items=[dict(id='at-baseline', expected_egress='147.45.71.38',
                    outbound=dict(protocol='vless', settings=dict(vnext=[dict(address='147.45.71.38', port=443)]),
                    streamSettings=dict(network='raw', security='reality')))])

    def test_valid_scoped_request_is_not_mutated(self):
        value=self.request(); prior=deepcopy(value)
        self.assertEqual(len(n.validate_request(value)), 1)
        self.assertEqual(value,prior)

    def test_empty_duplicates_or_foreign_target_rejected(self):
        for mode in ('empty','duplicate','foreign'):
            value=self.request()
            if mode=='empty': value['items']=[]
            elif mode=='duplicate':value['items']*=2
            else:value['items'][0]['outbound']['settings']['vnext'][0]['address']='192.0.2.1'
            with self.assertRaises(RuntimeError):n.validate_request(value)

    def test_plain_backend_is_loopback_only(self):
        value=self.request();value['items'][0]['outbound']['streamSettings']['security']='none'
        with self.assertRaises(RuntimeError):n.validate_request(value)
        value['items'][0]['outbound']['settings']['vnext'][0]['address']='127.0.0.1'
        n.validate_request(value)

    def test_tls_bypass_prohibited(self):
        value=self.request();value['items'][0]['outbound']['streamSettings'].update(security='tls',tlsSettings={'allowInsecure':True})
        with self.assertRaises(RuntimeError):n.validate_request(value)


if __name__=='__main__':unittest.main()
