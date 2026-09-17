import unittest
import backend_firewall as f

class Tests(unittest.TestCase):
    def test_jump_scoped_destination_tcp_port(self):
        self.assertEqual(f.jump('147.45.71.38'),['-d','147.45.71.38/32','-p','tcp','--dport','15444','-j',f.CHAIN])
    def test_chain_never_opens_other_sources(self):
        self.assertEqual(f.rules()[0],['-i','lo','-j','ACCEPT'])
        self.assertEqual(f.rules()[1],['-s','176.108.245.140/32','-j','ACCEPT'])
        self.assertEqual(f.rules()[-1],['-j','REJECT','--reject-with','tcp-reset'])
    def test_withdrawn_routes_rejected(self):
        for route in ('gb','us1','unknown'):
            with self.assertRaises(RuntimeError):f.store(route)
    def test_persistent_unit_does_not_restart_any_service(self):
        text=f.unit_text('at')
        self.assertIn(' ensure --id at',text)
        self.assertIn('After=network.target ufw.service',text)
        self.assertNotIn('restart',text);self.assertNotIn('flush',text)

if __name__=='__main__':unittest.main()
