import unittest
import conntrack_capacity as c


class CapacityTests(unittest.TestCase):
    def value(self, maximum=8192, available=415136):
        return dict(count=maximum, maximum=maximum, memory_available_kib=available, memory_total_kib=984568)

    def test_low_limit_and_four_gib_case(self):
        self.assertEqual(c.choose(self.value()), 65536)
        self.assertEqual(c.choose(self.value(65536, 2941520)), 262144)

    def test_no_exhaustion_or_insufficient_memory_no_change(self):
        for values in [dict(count=100), dict(memory_available_kib=50000), dict(memory_total_kib=200000), dict(maximum=262144)]:
            status=self.value();status.update(values)
            with self.assertRaises(RuntimeError):c.choose(status)

    def test_exact_single_sysctl_no_timeout_or_firewall_changes(self):
        for value in (65536,262144):
            lines=[v for v in c.content(value).splitlines() if not v.startswith('#')]
            self.assertEqual(lines,[c.KEY+' = '+str(value)])
        with self.assertRaises(RuntimeError):c.content(1048576)

    def test_retired_nodes_outside_scope(self):
        self.assertNotIn('51.194.240.216',c.ALLOWED)
        self.assertNotIn('162.141.185.231',c.ALLOWED)


if __name__=='__main__':unittest.main()
