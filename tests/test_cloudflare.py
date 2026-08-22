import asyncio
import json
import os
from pathlib import Path

import pytest

from orchestrator.app.cloudflare import (
    CloudflareClient,
    CloudflareConfigStore,
    CloudflareError,
    normalize_hostname,
)


class FakeCloudflare(CloudflareClient):
    def __init__(self):
        super().__init__("x" * 32, {"example.test": "zone-1"}, 60)
        self.record = {
            "id": "record-1",
            "type": "A",
            "name": "nl.example.test",
            "content": "192.0.2.10",
            "proxied": True,
            "ttl": 300,
        }

    async def _request(self, method, path, *, params=None, body=None):
        if path == "/zones/zone-1/dns_records":
            return [dict(self.record)]
        if path == "/zones/zone-1/dns_records/record-1" and method == "GET":
            return dict(self.record)
        if path == "/zones/zone-1/dns_records/record-1" and method == "PATCH":
            self.record.update(body)
            return dict(self.record)
        raise AssertionError((method, path, params, body))


def test_normalize_hostname_rejects_ip_and_invalid_names():
    assert normalize_hostname("NL.Example.Test.") == "nl.example.test"
    assert normalize_hostname("192.0.2.1") is None
    assert normalize_hostname("not a host") is None


def test_cloudflare_plan_and_update_enforces_dns_only():
    client = FakeCloudflare()
    records = asyncio.run(
        client.plan_records(["nl.example.test"], "192.0.2.10", "192.0.2.20")
    )
    assert records[0]["proxyWasEnabled"] is True
    asyncio.run(
        client.update_record(
            records[0],
            records[0]["newAddress"],
            records[0]["newTtl"],
            expected_address=records[0]["oldAddress"],
        )
    )
    assert client.record["content"] == "192.0.2.20"
    assert client.record["proxied"] is False
    assert client.record["ttl"] == 60


def test_cloudflare_rejects_record_pointing_elsewhere():
    client = FakeCloudflare()
    client.record["content"] = "198.51.100.50"
    with pytest.raises(CloudflareError, match="указывает не на текущий IP"):
        asyncio.run(
            client.plan_records(["nl.example.test"], "192.0.2.10", "192.0.2.20")
        )


def test_cloudflare_rejects_ipv6_for_a_record_workflow():
    client = FakeCloudflare()
    with pytest.raises(CloudflareError, match="только IPv4"):
        asyncio.run(
            client.plan_records(["nl.example.test"], "192.0.2.10", "2001:db8::20")
        )


def test_cloudflare_config_store_is_private_and_roundtrips(tmp_path: Path):
    store = CloudflareConfigStore(tmp_path)
    store.save("secret-token", {"example.test": "zone-1"}, 60)

    assert store.load() == {
        "token": "secret-token",
        "zoneIds": {"example.test": "zone-1"},
        "ttl": 60,
    }
    assert json.loads(store.path.read_text(encoding="utf-8"))["token"] == "secret-token"
    if os.name != "nt":
        assert store.path.stat().st_mode & 0o777 == 0o600
