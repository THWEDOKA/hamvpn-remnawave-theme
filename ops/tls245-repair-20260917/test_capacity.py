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


if __name__ == '__main__': unittest.main()
