import unittest
import measure as m

class Tests(unittest.TestCase):
    def values(self):
        item=dict(id='pl-legacy',legacy_tag='legacy',expected_egress='31.77.59.141',outbound=dict(protocol='vless',tag='LOCAL'))
        result=dict(id=item['id'],listener_removed=True,wire_sha256=m.p.digest({'protocol':'vless'}),curl_codes=[0,0],http='204',exit_ip=item['expected_egress'],passed=True)
        return item,result
    def test_measured_success(self):
        i,r=self.values(); proof=m.legacy_result(i,r,'26.3.27')
        self.assertTrue(proof['authenticated']);self.assertEqual(proof['client'],'xray-26.3.27')
    def test_measured_failure_not_promoted(self):
        i,r=self.values();r.update(curl_codes=[28,28],http='000',exit_ip=None,passed=False)
        proof=m.legacy_result(i,r,'26.3.27');self.assertFalse(proof['authenticated']);self.assertFalse(proof['passed'])
    def test_wrong_wire_or_leaked_listener_rejected(self):
        for change in ({'wire_sha256':'a'*64},{'listener_removed':False},{'id':'other'}):
            i,r=self.values();r.update(change)
            with self.assertRaises(RuntimeError):m.legacy_result(i,r,'26.3.27')

if __name__=='__main__':unittest.main()
