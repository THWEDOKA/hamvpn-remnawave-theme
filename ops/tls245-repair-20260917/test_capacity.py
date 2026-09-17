import unittest
import capacity


class CapacityTest(unittest.TestCase):
    def test_expected_baseline(self):
        capacity.validate({'net.netfilter.nf_conntrack_max': 65536,
                           'net.ipv4.tcp_max_orphans': 16384,
                           'net.ipv4.tcp_orphan_retries': 0}, 4*1024*1024, 1024*1024)

    def test_wrong_runtime_refused(self):
        with self.assertRaises(AssertionError): capacity.validate({}, 4*1024*1024, 1024*1024)

    def test_small_machine_refused(self):
        with self.assertRaises(AssertionError): capacity.validate({}, 1024*1024, 1024*1024)

    def test_low_memory_refused(self):
        with self.assertRaises(AssertionError): capacity.validate({}, 4*1024*1024, 100*1024)

    def test_only_measured_limits_changed(self):
        self.assertEqual(set(capacity.TARGET), {'net.netfilter.nf_conntrack_max',
                         'net.ipv4.tcp_max_orphans', 'net.ipv4.tcp_orphan_retries'})
        self.assertNotIn('tcp_retries2', capacity.config_text())
        self.assertNotIn('tcp_fin_timeout', capacity.config_text())

    def test_firewall_counters_not_policy_changes(self):
        a = '# Generated at A\n*filter\n:INPUT ACCEPT [12:1200]\n-A INPUT -p tcp --dport 2222 -j HAM_TLS245\nCOMMIT'
        b = a.replace('at A', 'at B').replace('[12:1200]', '[55:10000]')
        self.assertEqual(capacity.firewall_policy(a), capacity.firewall_policy(b))

    def test_real_firewall_changes_detected(self):
        a = ':INPUT ACCEPT [12:1200]\n-A INPUT -p tcp --dport 2222 -j HAM_TLS245'
        self.assertNotEqual(capacity.firewall_policy(a), capacity.firewall_policy(a.replace('2222', '22')))


if __name__ == '__main__': unittest.main()
