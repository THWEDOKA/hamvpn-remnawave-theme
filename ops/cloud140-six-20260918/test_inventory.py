"""Read-only inventory boundaries; no credentials or network required."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('six_inventory', Path(__file__).with_name('inventory.py'))
i = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i)


class InventoryTests(unittest.TestCase):
    def test_six_unique_exact_targets(self):
        self.assertEqual([t['id'] for t in i.TARGETS], ['at', 'pl', 'cz', 'gb', 'us1', 'gbpower'])
        for field in ('id', 'ip', 'node', 'host'):
            self.assertEqual(len({t[field] for t in i.TARGETS}), 6)

    def test_nested_keys_and_clients_never_returned(self):
        raw = {'tag': 'fixture', 'port': 443, 'protocol': 'vless',
               'settings': {'clients': [{'id': 'SECRET_CLIENT'}]},
               'streamSettings': {'network': 'raw', 'security': 'reality',
                                  'realitySettings': {'privateKey': 'SECRET_KEY', 'shortIds': ['SECRET_ID'],
                                                      'serverNames': ['example.com'], 'target': 'example.com:443'}}}
        safe = i.safe_inbound({'uuid': 'public-id', 'tag': 'fixture', 'rawInbound': raw},
                              {'config': {'inbounds': [raw]}})
        self.assertNotIn('SECRET', json.dumps(safe))
        self.assertEqual(safe['server_names'], ['example.com'])

    def test_foreign_target_rejected_before_connection(self):
        with patch.object(i.socket, 'create_connection') as connect:
            with self.assertRaises(AssertionError):
                i.connection_probe({'id': 'at', 'ip': '127.0.0.1', 'port': 22})
            connect.assert_not_called()

    def test_invalid_port_rejected_before_connection(self):
        for port in (0, 65536, '443'):
            with self.subTest(port=port), patch.object(i.socket, 'create_connection') as connect:
                with self.assertRaises(AssertionError):
                    i.connection_probe(dict(i.TARGETS[0], port=port))
                connect.assert_not_called()

    def test_socket_failure_is_not_authenticated_vpn_result(self):
        with patch.object(i.socket, 'create_connection', side_effect=TimeoutError):
            result = i.connection_probe(dict(i.TARGETS[0], port=443, sni='example.com'))
        self.assertFalse(result['tcp_connect'])
        self.assertFalse(result['trusted_tls'])
        self.assertEqual(result['error_type'], 'TimeoutError')
        self.assertNotIn('vpn_passed', result)


if __name__ == '__main__':
    unittest.main()
