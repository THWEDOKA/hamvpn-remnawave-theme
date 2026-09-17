"""Bounded, authenticated UDP reachability diagnostic; never a tunnel or proxy.

Run a listener on one side, then a client on the other, and repeat with roles
reversed, for each allowed port. Both processes take one JSON line on stdin:
{"key_hex": <64 fresh random hex characters>, "nonce_hex": <32 fresh random hex>}
Generate those values in the trusted controller's memory, transfer over pinned
SSH stdin. Use a fresh pair for each listener invocation and its single client.
Never put them in argv.
No files, firewall, services, routes, or production configurations are changed.
An echo result is UDP evidence, not proof that WireGuard will work.
"""

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
import socket
import struct
import sys
import time


IPS = {"entry": "176.108.245.140", "kz2": "206.223.240.179"}
PORTS = (54433, 54434)
SIZES = (64, 512, 1200)  # Complete UDP payload lengths, not IP packet lengths.
MAX_SECONDS = 120
MAX_PACKETS = 64
MAX_RECEIVED = 512  # Also bounds unauthenticated traffic / CPU work.
MAX_BYTES = 1024 * 1024  # Combined received + transmitted bytes per process.
HEADER = struct.Struct("!4sBBH16s")
MAC_SIZE = 32
MAGIC = b"HCUP"
REQUEST, RESPONSE = 0, 1


class ProbeError(Exception):
    """Fixed public error codes only; never include input or exception text."""


@dataclass(frozen=True, repr=False)
class Credentials:
    key: bytes
    nonce: bytes

    def __post_init__(self):
        if len(self.key) != 32 or len(self.nonce) != 16:
            raise ProbeError("invalid_credentials")

    def __repr__(self):
        return "Credentials(<redacted>)"


@dataclass(frozen=True)
class Config:
    side: str
    port: int
    duration: float = MAX_SECONDS
    count: int = 4

    def __post_init__(self):
        if self.side not in IPS or type(self.port) is not int or self.port not in PORTS:
            raise ProbeError("target_outside_scope")
        if (not isinstance(self.duration, (int, float)) or
                not math.isfinite(self.duration) or not 1 <= self.duration <= MAX_SECONDS):
            raise ProbeError("invalid_duration")
        if type(self.count) is not int or not 1 <= self.count <= 8:
            raise ProbeError("invalid_count")

    @property
    def local(self):
        return IPS[self.side]

    @property
    def peer(self):
        return IPS["kz2" if self.side == "entry" else "entry"]

    @property
    def outgoing_direction(self):
        return 0 if self.side == "entry" else 1


def read_credentials(stream):
    raw = stream.readline(4097)
    if not raw or len(raw) > 4096:
        raise ProbeError("invalid_credentials")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"key_hex", "nonce_hex"}:
            raise ValueError
        if not isinstance(value["key_hex"], str) or not isinstance(value["nonce_hex"], str):
            raise ValueError
        if len(value["key_hex"]) != 64 or len(value["nonce_hex"]) != 32:
            raise ValueError
        return Credentials(bytes.fromhex(value["key_hex"]), bytes.fromhex(value["nonce_hex"]))
    except (ValueError, TypeError):
        raise ProbeError("invalid_credentials") from None


def encode(credentials, port, kind, direction, sequence, payload):
    if (port not in PORTS or kind not in (REQUEST, RESPONSE) or direction not in (0, 1)
            or not 0 <= sequence < MAX_PACKETS
            or HEADER.size + MAC_SIZE + len(payload) not in SIZES):
        raise ProbeError("invalid_packet_parameters")
    body = HEADER.pack(MAGIC, kind, direction, sequence, credentials.nonce) + payload
    # Bind authentication to port as well as direction, run nonce, and kind.
    context = b"HAM-cloud140-kz2-UDP-v1\x00" + struct.pack("!H", port)
    return body + hmac.new(credentials.key, context + body, hashlib.sha256).digest()


def decode(credentials, port, data, kind, direction):
    if len(data) not in SIZES:
        return None, "invalid_size"
    magic, got_kind, got_direction, sequence, nonce = HEADER.unpack(data[:HEADER.size])
    if (magic != MAGIC or got_kind != kind or got_direction != direction or
            sequence >= MAX_PACKETS or not hmac.compare_digest(nonce, credentials.nonce)):
        return None, "invalid_header"
    payload = data[HEADER.size:-MAC_SIZE]
    expected = encode(credentials, port, kind, direction, sequence, payload)
    if not hmac.compare_digest(data, expected):
        return None, "invalid_mac"
    return (sequence, payload), None


class Echo:
    """At most 64 unique authenticated, equal-size replies; no amplification."""

    def __init__(self, config, credentials, now):
        self.config, self.credentials = config, credentials
        self.seen = set()
        self.received = self.rx_bytes = self.tx_bytes = self.replies = 0
        self.byte_limit = False
        self.rejected = Counter()
        self.tokens, self.last = 4.0, now

    @property
    def exhausted(self):
        return (self.byte_limit or self.received >= MAX_RECEIVED or self.replies >= MAX_PACKETS or
                self.rx_bytes + self.tx_bytes >= MAX_BYTES)

    def accept(self, data, peer, now):
        if self.exhausted:
            return None
        self.received += 1
        if self.rx_bytes + self.tx_bytes + len(data) > MAX_BYTES:
            self.byte_limit = True
            self.rejected["byte_limit"] += 1
            return None
        self.rx_bytes += len(data)
        if peer[0] != self.config.peer:
            self.rejected["wrong_peer"] += 1
            return None
        direction = 1 - self.config.outgoing_direction
        parsed, error = decode(self.credentials, self.config.port, data, REQUEST, direction)
        if error:
            self.rejected[error] += 1
            return None
        sequence, payload = parsed
        if sequence in self.seen:
            self.rejected["replay"] += 1
            return None
        self.seen.add(sequence)  # A rate-limited packet cannot be replayed later.
        self.tokens = min(4.0, self.tokens + max(0, now - self.last) * 20)
        self.last = now
        if self.tokens < 1 or self.rx_bytes + self.tx_bytes + len(data) > MAX_BYTES:
            self.rejected["send_limit"] += 1
            return None
        self.tokens -= 1
        response = encode(self.credentials, self.config.port, RESPONSE, direction, sequence, payload)
        self.replies += 1
        self.tx_bytes += len(response)
        return response


def exclusive_socket(config, server, factory=socket.socket):
    sock = factory(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No wildcard, SO_REUSEADDR, or SO_REUSEPORT. Successful exclusive bind
        # is the atomic free-port check, avoiding a check-then-bind race.
        sock.bind((config.local, config.port if server else 0))
    except OSError:
        sock.close()
        raise ProbeError("exclusive_bind_failed") from None
    return sock


def base_proof(config, mode, timestamp):
    return {"schema": 1, "mode": mode, "timestamp": timestamp, "local_ip": config.local,
            "peer_ip": config.peer, "port": config.port, "max_seconds": config.duration,
            "exclusive_bind": True, "firewall_changed": False}


def serve(config, credentials, emit, factory=socket.socket, clock=time.monotonic, wall=time.time):
    with exclusive_socket(config, True, factory) as sock:
        started = clock()
        deadline = started + config.duration
        state = Echo(config, credentials, started)
        proof = base_proof(config, "server", wall())
        emit({**proof, "event": "ready", "port_was_free": True})
        while clock() < deadline and not state.exhausted:
            sock.settimeout(min(0.5, max(0.001, deadline - clock())))
            try:
                data, peer = sock.recvfrom(min(65535, MAX_BYTES - state.rx_bytes - state.tx_bytes))
            except (socket.timeout, TimeoutError):
                continue
            response = state.accept(data, peer, clock())
            if response is not None:
                try:
                    sock.sendto(response, peer)
                except OSError:
                    state.rejected["send_error"] += 1
        proof.update(event="finished", seconds=round(clock() - started, 3),
                     received=state.received, replies_attempted=state.replies,
                     rx_bytes=state.rx_bytes, tx_bytes_attempted=state.tx_bytes,
                     rejected=dict(state.rejected),
                     stop_reason="budget" if state.exhausted else "deadline")
    proof["listener_closed"] = True
    emit(proof)
    return proof


def client(config, credentials, factory=socket.socket, clock=time.monotonic,
           wall=time.time, sleep=time.sleep):
    proof = base_proof(config, "client", wall())
    started = clock()
    deadline = started + config.duration
    results, received, rx_bytes, tx_bytes = [], 0, 0, 0
    with exclusive_socket(config, False, factory) as sock:
        sequence = 0
        for size in SIZES:
            for _ in range(config.count):
                if (clock() >= deadline or received >= MAX_RECEIVED or
                        rx_bytes + tx_bytes + size > MAX_BYTES):
                    break
                payload = os.urandom(size - HEADER.size - MAC_SIZE)
                request = encode(credentials, config.port, REQUEST, config.outgoing_direction,
                                 sequence, payload)
                expected = encode(credentials, config.port, RESPONSE, config.outgoing_direction,
                                  sequence, payload)
                test = {"sequence": sequence, "size": size, "received": False}
                sent = clock()
                try:
                    sock.sendto(request, (config.peer, config.port))
                    tx_bytes += len(request)
                    packet_deadline = min(deadline, sent + 2)
                    while (clock() < packet_deadline and received < MAX_RECEIVED
                           and rx_bytes + tx_bytes < MAX_BYTES):
                        sock.settimeout(max(0.001, packet_deadline - clock()))
                        try:
                            data, peer = sock.recvfrom(min(65535, MAX_BYTES - rx_bytes - tx_bytes))
                        except (socket.timeout, TimeoutError):
                            break
                        received += 1
                        rx_bytes += len(data)
                        if peer == (config.peer, config.port) and hmac.compare_digest(data, expected):
                            test.update(received=True, rtt_ms=round((clock() - sent) * 1000, 3))
                            break
                except OSError:
                    test["error"] = "socket_error"
                results.append(test)
                sequence += 1
                # At most ten requests/second; fast replies do not create a burst.
                sleep(max(0, min(0.1, deadline - clock())))
    summary = []
    for size in SIZES:
        items = [x for x in results if x["size"] == size]
        good = [x["rtt_ms"] for x in items if x["received"]]
        summary.append({"size": size, "sent": len(items), "received": len(good),
                        "lost": len(items) - len(good),
                        "min_rtt_ms": min(good) if good else None,
                        "max_rtt_ms": max(good) if good else None})
    proof.update(direction=config.side + "->" + ("kz2" if config.side == "entry" else "entry"),
                 tests=results, summary=summary, seconds=round(clock() - started, 3),
                 rx_bytes=rx_bytes, tx_bytes=tx_bytes,
                 all_passed=len(results) == config.count * len(SIZES) and all(x["received"] for x in results),
                 socket_closed=True, wireguard_proven=False)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "client"))
    parser.add_argument("--side", choices=tuple(IPS), required=True)
    parser.add_argument("--port", type=int, choices=PORTS, required=True)
    parser.add_argument("--duration", type=float, default=MAX_SECONDS)
    parser.add_argument("--count", type=int, default=4)
    args = parser.parse_args()
    emit = lambda value: print(json.dumps(value, sort_keys=True), flush=True)
    try:
        config = Config(args.side, args.port, args.duration, args.count)
        credentials = read_credentials(sys.stdin)
        if args.action == "serve":
            serve(config, credentials, emit)
            return 0
        proof = client(config, credentials)
        emit(proof)
        return 0 if proof["all_passed"] else 2
    except ProbeError as error:
        emit({"error": str(error), "all_passed": False})
        return 2
    except (OSError, KeyboardInterrupt):
        emit({"error": "io_error_or_interrupted", "all_passed": False})
        return 2


if __name__ == "__main__":
    sys.exit(main())
