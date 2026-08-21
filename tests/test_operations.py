import asyncio
from copy import deepcopy
from pathlib import Path

import pytest

from orchestrator.app.audit import AuditStore
from orchestrator.app.operations import (
    OperationError,
    apply_ip_change,
    create_ip_plan,
    create_node_plan,
)
from orchestrator.app.settings import Settings


def raw_inventory():
    return {
        "nodes": [
            {
                "uuid": "node-1",
                "name": "Germany-4",
                "address": "192.0.2.10",
                "port": 2222,
                "countryCode": "DE",
                "isConnected": True,
                "configProfile": {
                    "activeConfigProfileUuid": "profile-1",
                    "activeInbounds": ["inbound-1"],
                },
            }
        ],
        "hosts": [
            {
                "uuid": "host-1",
                "remark": "Germany",
                "address": "192.0.2.10",
                "port": 443,
                "nodes": ["node-1"],
            }
        ],
        "profiles": {
            "configProfiles": [
                {
                    "uuid": "profile-1",
                    "name": "BASE",
                    "config": {"route": {"address": "192.0.2.10"}},
                    "inbounds": [{"uuid": "inbound-1", "tag": "VLESS", "type": "vless"}],
                }
            ]
        },
        "squads": {"internalSquads": [{"uuid": "squad-base", "name": "BASE"}]},
    }


class FakeClient:
    def __init__(self, fail_profile_once: bool = False):
        self.data = raw_inventory()
        self.fail_profile_once = fail_profile_once
        self.restarted = False

    async def inventory(self):
        return deepcopy(self.data)

    async def update_node(self, body):
        node = self.data["nodes"][0]
        node.update({key: value for key, value in body.items() if key != "uuid"})
        return deepcopy(node)

    async def update_host(self, body):
        host = self.data["hosts"][0]
        host.update({key: value for key, value in body.items() if key != "uuid"})
        return deepcopy(host)

    async def update_profile(self, body):
        if self.fail_profile_once:
            self.fail_profile_once = False
            raise RuntimeError("profile write failed")
        profile = self.data["profiles"]["configProfiles"][0]
        profile["config"] = deepcopy(body["config"])
        return deepcopy(profile)

    async def restart_node(self, _uuid):
        self.restarted = True


def test_ip_change_applies_and_verifies(tmp_path: Path, monkeypatch):
    async def no_tcp_check(*_args, **_kwargs):
        return None

    monkeypatch.setattr("orchestrator.app.operations.tcp_check", no_tcp_check)
    client = FakeClient()
    store = AuditStore(tmp_path)
    actor = "actor"
    plan = asyncio.run(create_ip_plan(client, store, actor, "node-1", "192.0.2.20"))
    settings = Settings("", "", tmp_path, "198.51.100.1", "image", 900, 1)
    result = asyncio.run(
        apply_ip_change(client, store, settings, actor, plan["operationId"], "Germany-4")
    )
    assert result["verified"] is True
    assert client.data["nodes"][0]["address"] == "192.0.2.20"
    assert client.data["hosts"][0]["address"] == "192.0.2.20"
    assert client.data["profiles"]["configProfiles"][0]["config"]["route"]["address"] == "192.0.2.20"
    assert client.restarted is True
    assert store.get(plan["operationId"])["state"] == "completed"


def test_ip_change_rolls_back_on_profile_failure(tmp_path: Path, monkeypatch):
    async def no_tcp_check(*_args, **_kwargs):
        return None

    monkeypatch.setattr("orchestrator.app.operations.tcp_check", no_tcp_check)
    client = FakeClient(fail_profile_once=True)
    store = AuditStore(tmp_path)
    plan = asyncio.run(create_ip_plan(client, store, "actor", "node-1", "192.0.2.20"))
    settings = Settings("", "", tmp_path, "198.51.100.1", "image", 900, 1)
    with pytest.raises(OperationError, match="автоматически отменено"):
        asyncio.run(
            apply_ip_change(
                client, store, settings, "actor", plan["operationId"], "Germany-4"
            )
        )
    assert client.data["nodes"][0]["address"] == "192.0.2.10"
    assert client.data["hosts"][0]["address"] == "192.0.2.10"
    assert store.get(plan["operationId"])["state"] == "rolled_back"


def test_node_plan_rejects_unknown_squad(tmp_path: Path):
    client = FakeClient()
    store = AuditStore(tmp_path)
    body = {
        "node": {
            "name": "Germany-5",
            "address": "192.0.2.30",
            "port": 2222,
            "countryCode": "DE",
            "profileUuid": "profile-1",
            "inboundUuids": ["inbound-1"],
        },
        "host": {
            "enabled": True,
            "inboundUuid": "inbound-1",
            "squadUuids": ["unknown"],
        },
    }
    with pytest.raises(OperationError, match="существующий сквад"):
        asyncio.run(create_node_plan(client, store, "actor", body))

