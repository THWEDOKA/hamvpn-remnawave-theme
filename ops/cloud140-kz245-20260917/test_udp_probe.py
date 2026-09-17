"""Offline protocol and bounded-runtime tests: no production network calls."""
import io
import json
import socket
import unittest
from unittest.mock import Mock

import udp_probe as p


CREDENTIALS = p.Credentials(b"k" * 32, b"n" * 16)


def packet(size=64, sequence=0, kind=p.REQUEST, direction=0, port=54433, credentials=CREDENTIALS):
    return p.encode(credentials, port, kind, direction, sequence,
                    b"x" * (size - p.HEADER.size - p.MAC_SIZE))


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now
    def sleep(self, seconds): self.now += seconds


class FakeSocket:
    def __init__(self, clock, config, responsive=True):
        self.clock, self.config, self.responsive = clock, config, responsive
        self.closed = False
        self.sent = []
    def __enter__(self): return self
    def __exit__(self, *unused): self.close()
    def close(self): self.closed = True
    def bind(self, address): self.bound = address
    def settimeout(self, timeout): self.timeout = timeout
    def sendto(self, data, target): self.sent.append((data, target))
    def recvfrom(self, size):
        if not self.responsive:
            self.clock.sleep(self.timeout)
            raise socket.timeout
        data, target = self.sent[-1]
        parsed, error = p.decode(CREDENTIALS, self.config.port, data, p.REQUEST,
                                 self.config.outgoing_direction)
        assert error is None
        sequence, payload = parsed
        self.clock.sleep(0.01)
        return p.encode(CREDENTIALS, self.config.port, p.RESPONSE,
                        self.config.outgoing_direction, sequence, payload), target


class ProtocolTests(unittest.TestCase):
    def test_exact_scope(self):
        self.assertEqual(p.IPS, {"entry": "176.108.245.140", "kz2": "206.223.240.179"})
        for config in (("other", 54433), ("entry", 22), ("entry", 443), ("entry", 54435)):
            with self.assertRaises(p.ProbeError): p.Config(*config)

    def test_duration_count_bounds(self):
        for duration in (0, -1, 121, float("inf"), float("nan")):
            with self.assertRaises(p.ProbeError): p.Config("entry", 54433, duration)
        for count in (0, -1, 9, True, 1.5):
            with self.assertRaises(p.ProbeError): p.Config("entry", 54433, count=count)

    def test_secret_input_and_redacted_repr(self):
        value = {"key_hex": "6b" * 32, "nonce_hex": "6e" * 16}
        self.assertEqual(p.read_credentials(io.StringIO(json.dumps(value))), CREDENTIALS)
        self.assertEqual(repr(CREDENTIALS), "Credentials(<redacted>)")
        for raw in ("", "x" * 4097, "null", "[]", "{}", '{"key_hex":3}',
                    json.dumps({**value, "extra": "x"}),
                    json.dumps({**value, "key_hex": " " * 64}),
                    json.dumps({**value, "nonce_hex": "zz" * 16})):
            with self.subTest(raw=raw[:20]), self.assertRaises(p.ProbeError):
                p.read_credentials(io.StringIO(raw))

    def test_sizes_ports_directions_roundtrip(self):
        for size in p.SIZES:
            for port in p.PORTS:
                for direction in (0, 1):
                    data = packet(size=size, port=port, direction=direction)
                    parsed, error = p.decode(CREDENTIALS, port, data, p.REQUEST, direction)
                    self.assertEqual(len(data), size)
                    self.assertIsNone(error)
                    self.assertEqual(parsed[0], 0)

    def test_wrong_key_nonce_port_direction_kind_tamper(self):
        data = packet()
        cases = [
            (p.Credentials(b"z" * 32, b"n" * 16), 54433, data, p.REQUEST, 0),
            (p.Credentials(b"k" * 32, b"z" * 16), 54433, data, p.REQUEST, 0),
            (CREDENTIALS, 54434, data, p.REQUEST, 0),
            (CREDENTIALS, 54433, data, p.REQUEST, 1),
            (CREDENTIALS, 54433, data, p.RESPONSE, 0),
            (CREDENTIALS, 54433, data[:-1] + bytes([data[-1] ^ 1]), p.REQUEST, 0),
            (CREDENTIALS, 54433, data[:-1], p.REQUEST, 0),
            (CREDENTIALS, 54433, b"x" * 65535, p.REQUEST, 0),
        ]
        for case in cases:
            parsed, error = p.decode(*case)
            self.assertIsNone(parsed)
            self.assertIsNotNone(error)

    def test_bad_packet_construction(self):
        for change in ({"sequence": 64}, {"sequence": -1}, {"port": 22},
                       {"kind": 2}, {"direction": 2}, {"size": 65}):
            with self.assertRaises(p.ProbeError): packet(**change)


class EchoTests(unittest.TestCase):
    def setUp(self):
        self.echo = p.Echo(p.Config("kz2", 54433), CREDENTIALS, 0)
        self.peer = (p.IPS["entry"], 39999)

    def test_equal_size_no_amplification(self):
        for seq, size in enumerate(p.SIZES):
            request = packet(size=size, sequence=seq)
            reply = self.echo.accept(request, self.peer, seq)
            self.assertEqual(len(reply), len(request))
            parsed, error = p.decode(CREDENTIALS, 54433, reply, p.RESPONSE, 0)
            self.assertIsNone(error)
            self.assertEqual(parsed, (seq, b"x" * (size - 56)))

    def test_wrong_peer_not_replied(self):
        self.assertIsNone(self.echo.accept(packet(), ("196.251.107.245", 4444), 0))
        self.assertEqual(self.echo.replies, 0)

    def test_replay_and_reflection_not_replied(self):
        response = self.echo.accept(packet(), self.peer, 0)
        self.assertIsNotNone(response)
        self.assertIsNone(self.echo.accept(packet(), self.peer, 1))
        self.assertIsNone(self.echo.accept(response, self.peer, 2))
        self.assertEqual(self.echo.replies, 1)

    def test_rate_limit_and_no_later_replay(self):
        for seq in range(4): self.assertIsNotNone(self.echo.accept(packet(sequence=seq), self.peer, 0))
        self.assertIsNone(self.echo.accept(packet(sequence=4), self.peer, 0))
        self.assertIsNone(self.echo.accept(packet(sequence=4), self.peer, 1))
        self.assertIsNotNone(self.echo.accept(packet(sequence=5), self.peer, 1))

    def test_received_count_cap(self):
        for _ in range(p.MAX_RECEIVED + 20): self.echo.accept(b"bad", self.peer, 0)
        self.assertEqual(self.echo.received, p.MAX_RECEIVED)
        self.assertTrue(self.echo.exhausted)

    def test_byte_cap_no_reply(self):
        for _ in range(20): self.echo.accept(b"x" * 65535, self.peer, 0)
        self.assertTrue(self.echo.exhausted)
        self.assertEqual(self.echo.tx_bytes, 0)
        self.assertLessEqual(self.echo.rx_bytes + self.echo.tx_bytes, p.MAX_BYTES)

    def test_sixty_four_unique_reply_cap(self):
        for seq in range(64): self.assertIsNotNone(self.echo.accept(packet(sequence=seq), self.peer, seq))
        self.assertTrue(self.echo.exhausted)
        self.assertEqual(self.echo.replies, 64)


class RuntimeTests(unittest.TestCase):
    def test_exclusive_bind_no_reuse(self):
        sock = Mock()
        factory = Mock(return_value=sock)
        config = p.Config("entry", 54434)
        self.assertIs(p.exclusive_socket(config, True, factory), sock)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind.assert_called_once_with((p.IPS["entry"], 54434))
        sock.setsockopt.assert_not_called()

    def test_bind_failure_closes_and_redacts_error(self):
        sock = Mock()
        sock.bind.side_effect = OSError("sensitive-value")
        with self.assertRaisesRegex(p.ProbeError, "^exclusive_bind_failed$"):
            p.exclusive_socket(p.Config("kz2", 54433), True, lambda *args: sock)
        sock.close.assert_called_once()

    def test_client_success_both_directions_and_ports(self):
        for side in p.IPS:
            for port in p.PORTS:
                clock, config = Clock(), p.Config(side, port)
                sock = FakeSocket(clock, config)
                proof = p.client(config, CREDENTIALS, lambda *args: sock, clock, lambda: 123, clock.sleep)
                self.assertTrue(proof["all_passed"])
                self.assertTrue(sock.closed)
                self.assertEqual(sock.bound, (p.IPS[side], 0))
                self.assertEqual(len(proof["tests"]), 12)
                self.assertTrue(all(x["lost"] == 0 for x in proof["summary"]))
                self.assertFalse(proof["wireguard_proven"])
                self.assertNotIn(CREDENTIALS.key.hex(), json.dumps(proof))
                self.assertNotIn(CREDENTIALS.nonce.hex(), json.dumps(proof))

    def test_client_loss_bounded_and_closed(self):
        clock, config = Clock(), p.Config("entry", 54433, duration=3)
        sock = FakeSocket(clock, config, responsive=False)
        proof = p.client(config, CREDENTIALS, lambda *args: sock, clock, lambda: 123, clock.sleep)
        self.assertFalse(proof["all_passed"])
        self.assertTrue(sock.closed)
        self.assertLessEqual(proof["seconds"], 3.001)
        self.assertTrue(all(not x["received"] for x in proof["tests"]))

    def test_client_rejects_wrong_peer_port_and_replayed_response(self):
        for corruption in ("peer", "port", "replay"):
            clock, config = Clock(), p.Config("entry", 54433, duration=1, count=1)
            sock = FakeSocket(clock, config)
            original = sock.recvfrom
            def invalid(size):
                data, peer = original(size)
                if corruption == "peer": peer = ("196.251.107.245", peer[1])
                if corruption == "port": peer = (peer[0], 54434)
                if corruption == "replay": data = packet(kind=p.RESPONSE, sequence=3)
                return data, peer
            sock.recvfrom = invalid
            proof = p.client(config, CREDENTIALS, lambda *args: sock, clock, lambda: 123, clock.sleep)
            self.assertFalse(proof["all_passed"])
            self.assertTrue(all(not x["received"] for x in proof["tests"]))
            self.assertTrue(sock.closed)

    def test_server_deadline_closes_and_emits_ready_and_final(self):
        clock, config, output = Clock(), p.Config("kz2", 54434, duration=1), []
        sock = FakeSocket(clock, config, responsive=False)
        result = p.serve(config, CREDENTIALS, output.append, lambda *args: sock, clock, lambda: 123)
        self.assertEqual([x["event"] for x in output], ["ready", "finished"])
        self.assertEqual(result["stop_reason"], "deadline")
        self.assertTrue(result["listener_closed"])
        self.assertTrue(sock.closed)
        self.assertEqual(result["seconds"], 1)


if __name__ == "__main__":
    unittest.main()
