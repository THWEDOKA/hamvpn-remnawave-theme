import asyncio
import base64
import json
import time
import uuid
from copy import deepcopy

import pytest

from orchestrator.app import gconfig
from orchestrator.app.gconfig_model import fresh_config, relay_candidate
from orchestrator.app.managed_store import ManagedStore
from orchestrator.app.operations import OperationError
from orchestrator.app.probes import exported_wire
from orchestrator.app.rollback import Rollbacks
from orchestrator.app.settings import Settings


def config():
    return {
        "inbounds": [
            {
                "tag": "reality",
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": []},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "privateKey": "source-secret",
                        "shortIds": ["1234"],
                        "serverNames": ["google.com"],
                        "target": "google.com:443",
                    },
                },
            }
        ],
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom"},
            {"tag": "BLOCK", "protocol": "blackhole"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "BLOCK"}
            ]
        },
    }


class Client:
    def __init__(self):
        claims = (
            base64.urlsafe_b64encode(json.dumps({"exp": time.time() + 3600}).encode())
            .decode()
            .rstrip("=")
        )
        self.token = "header." + claims + ".signature"
        self.data = {
            "nodes": [],
            "hosts": [],
            "config-profiles": [
                {
                    "uuid": "template",
                    "name": "G-CONFIG",
                    "config": config(),
                    "inbounds": [{"uuid": "original", "tag": "reality"}],
                }
            ],
            "internal-squads": [
                {"uuid": "customers", "name": "BASE", "inbounds": ["original"]}
            ],
            "users": [],
        }
        self.fail_patch = False
        self.lost_post = False

    async def request(self, method, path, body=None):
        parts = path.strip("/").split("/")
        collection = parts[1]
        if method == "GET":
            if len(parts) > 2:
                return deepcopy(
                    next(v for v in self.data[collection] if v["uuid"] == parts[2])
                )
            return deepcopy(self.data[collection])
        if method == "POST":
            row = {"uuid": str(uuid.uuid4()), **deepcopy(body)}
            if collection == "config-profiles":
                row["inbounds"] = [
                    {"uuid": str(uuid.uuid4()), "tag": i["tag"]}
                    for i in body["config"]["inbounds"]
                ]
            if collection == "nodes":
                row.update(isConnected=True, isDisabled=False)
            self.data[collection].append(row)
            if self.lost_post:
                self.lost_post = False
                raise TimeoutError()
            return deepcopy(row)
        if method == "PATCH":
            if self.fail_patch:
                self.fail_patch = False
                raise RuntimeError("write failed")
            row = next(v for v in self.data[collection] if v["uuid"] == body["uuid"])
            row.update(deepcopy(body))
            return deepcopy(row)
        if method == "DELETE":
            self.data[collection] = [
                v for v in self.data[collection] if v["uuid"] != parts[2]
            ]
            return None
        raise AssertionError(method)

    async def inventory(self):
        return deepcopy(
            {
                "nodes": self.data["nodes"],
                "hosts": self.data["hosts"],
                "profiles": self.data["config-profiles"],
                "squads": self.data["internal-squads"],
            }
        )

    async def secret_key(self):
        return "node-secret"

    async def update_squad(self, body):
        return await self.request("PATCH", "/api/internal-squads/", body)

    async def update_profile(self, body):
        return await self.request("PATCH", "/api/config-profiles/", body)

    async def update_host(self, body):
        return await self.request("PATCH", "/api/hosts/", body)

    async def restart_node(self, _):
        pass


@pytest.fixture
def setup(tmp_path, monkeypatch):
    client = Client()
    store = ManagedStore(tmp_path)
    rollback = Rollbacks(tmp_path, "http://panel")
    settings = Settings("http://panel", "", tmp_path, "1.1.1.1", "node-pinned", 900, 1)
    monkeypatch.setattr(
        gconfig, "install_node", lambda *a, **kw: {"composeHash": "owned"}
    )
    monkeypatch.setattr(gconfig, "rollback_install", lambda *a, **kw: None)
    monkeypatch.setattr(gconfig, "check_xray", lambda *a, **kw: None)

    async def wires(*a, **kw):
        return {"xray": {}, "mihomo": {}}

    async def verify(*a, **kw):
        return [
            {
                "engine": "xray",
                "httpsRequests": 3,
                "egress": "8.8.4.4",
                "delayMs": None,
            },
            {
                "engine": "mihomo",
                "httpsRequests": 3,
                "egress": "8.8.4.4",
                "delayMs": 20,
            },
        ]

    monkeypatch.setattr(gconfig, "subscription_wires", wires)
    monkeypatch.setattr(gconfig, "verify_wires", verify)
    monkeypatch.setattr("orchestrator.app.rollback.RemnawaveClient", lambda *a: client)
    return client, store, rollback, settings


def request_body():
    return {
        "name": "Test Netherlands",
        "address": "8.8.4.4",
        "countryCode": "NL",
        "squadUuids": ["customers"],
        "selfSteal": "no",
    }


async def install(setup):
    client, store, rollback, settings = setup
    plan = await gconfig.create_plan(client, store, "actor", request_body())
    body = {
        "operationId": plan["operationId"],
        "confirmation": plan["name"],
        "expectedFingerprint": "SHA256:pinned",
        "ssh": {"host": plan["address"], "username": "root", "password": "private"},
    }
    result = await gconfig.install(client, store, settings, rollback, "actor", body)
    return result, body


def test_new_profile_has_unique_identity_and_preserves_source():
    source = {"config": config()}
    before = deepcopy(source)
    first = fresh_config(source, "one")
    second = fresh_config(source, "two")
    assert source == before
    reality = first["inbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["minClientVer"] == "1.8.2"
    assert (
        reality["privateKey"]
        != second["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
    )
    assert first["routing"] == source["config"]["routing"]


def test_relay_is_fixed_destination_and_keeps_neighbors():
    source = config()
    out = relay_candidate(source, tag="new", port=19443, exit_ip="8.8.4.4")
    assert out["inbounds"][:-1] == source["inbounds"]
    assert out["routing"]["rules"][1:] == source["routing"]["rules"]
    assert out["inbounds"][-1]["settings"] == {
        "address": "8.8.4.4",
        "port": 443,
        "network": "tcp",
        "followRedirect": False,
    }
    with pytest.raises(OperationError):
        relay_candidate(source, tag="new", port=443, exit_ip="8.8.4.4")
    with pytest.raises(OperationError):
        relay_candidate(source, tag="new", port=19443, exit_ip="127.0.0.1")


def test_installs_separate_node_without_modifying_template(setup):
    client, store, rollback, _ = setup
    baseline = deepcopy(client.data["config-profiles"][0])
    record, body = asyncio.run(install(setup))
    assert record["mode"] == "direct"
    assert client.data["config-profiles"][0] == baseline
    assert len(client.data["nodes"]) == len(client.data["hosts"]) == 1
    assert client.data["users"] == []
    assert len(client.data["internal-squads"]) == 1
    assert "original" in client.data["internal-squads"][0]["inbounds"]
    assert record["inboundUuid"] in client.data["internal-squads"][0]["inbounds"]
    assert not list(rollback.directory.glob("*.lease"))
    assert "private" not in json.dumps(store.get(body["operationId"]))
    with pytest.raises(OperationError):
        asyncio.run(gconfig.install(client, store, setup[3], rollback, "actor", body))


def test_requires_self_steal_answer_and_valid_squads(setup):
    for patch in (
        {"selfSteal": None},
        {"selfSteal": "yes"},
        {"squadUuids": ["missing"]},
        {"address": "127.0.0.1"},
    ):
        with pytest.raises(OperationError):
            asyncio.run(
                gconfig.create_plan(
                    setup[0], setup[1], "actor", {**request_body(), **patch}
                )
            )
    assert setup[1].recent() == []


def test_failed_client_test_removes_only_created_objects(setup, monkeypatch):
    before = deepcopy(setup[0].data)

    async def fail(*a, **kw):
        raise OperationError("client test failed")

    monkeypatch.setattr(gconfig, "verify_wires", fail)
    with pytest.raises(OperationError):
        asyncio.run(install(setup))
    assert setup[0].data == before
    assert setup[1].recent()[0]["state"] == "rolled_back"


def add_entry(client, shared=False):
    client.data["config-profiles"].append(
        {"uuid": "entry-profile", "name": "ENTRY", "config": config(), "inbounds": []}
    )
    client.data["nodes"].append(
        {
            "uuid": "entry",
            "name": "RU entry",
            "address": "1.1.1.1",
            "countryCode": "RU",
            "isConnected": True,
            "isDisabled": False,
            "configProfile": {
                "activeConfigProfileUuid": "entry-profile",
                "activeInbounds": ["old-entry"],
            },
        }
    )
    if shared:
        client.data["nodes"].append(
            {**deepcopy(client.data["nodes"][-1]), "uuid": "neighbor"}
        )


def prepare_body(record):
    return {
        "id": record["id"],
        "entryUuid": "entry",
        "port": 19443,
        "expectedFingerprint": "SHA256:pinned",
        "ssh": {"host": "1.1.1.1", "username": "root", "password": "private"},
    }


def test_prepare_then_switch_both_directions_preserves_host_identity(setup):
    async def scenario():
        client, store, rollback, settings = setup
        record, _ = await install(setup)
        add_entry(client)
        original_host = deepcopy(client.data["hosts"][0])
        original_binding = deepcopy(client.data["nodes"][-1]["configProfile"])
        await gconfig.prepare_route(
            client, store, settings, rollback, "actor", prepare_body(record)
        )
        assert client.data["hosts"][0] == original_host
        assert client.data["nodes"][-1]["configProfile"] == original_binding
        result = await gconfig.switch_route(
            client, store, rollback, "actor", {"id": record["id"], "mode": "ru"}
        )
        assert result["mode"] == "ru"
        assert client.data["hosts"][0] == {
            **original_host,
            "address": "1.1.1.1",
            "port": 19443,
        }
        await gconfig.switch_route(
            client, store, rollback, "actor", {"id": record["id"], "mode": "direct"}
        )
        assert client.data["hosts"][0] == original_host
        assert not list(rollback.directory.glob("*.lease"))
        assert client.data["users"] == []

    asyncio.run(scenario())


def test_shared_entry_profile_is_rejected_before_mutation(setup):
    async def scenario():
        client, store, rollback, settings = setup
        record, _ = await install(setup)
        add_entry(client, shared=True)
        before = deepcopy(client.data)
        with pytest.raises(OperationError, match="общий профиль"):
            await gconfig.prepare_route(
                client, store, settings, rollback, "actor", prepare_body(record)
            )
        assert client.data == before

    asyncio.run(scenario())


async def existing_setup(setup):
    record, _ = await install(setup)
    client, store, _, _ = setup
    with store.connection() as db:
        db.execute("DELETE FROM managed_nodes")
    profile = next(
        p for p in client.data["config-profiles"] if p["uuid"] == record["profileUuid"]
    )
    profile["config"]["inbounds"][0]["port"] = 32443
    profile["config"]["inbounds"].append(
        {"tag": "other", "protocol": "hysteria", "port": 4500}
    )
    client.data["hosts"][0]["port"] = 32443
    client.data["nodes"].append(
        {**deepcopy(client.data["nodes"][0]), "uuid": "neighbor", "address": "9.9.9.9"}
    )
    return {"nodeUuid": record["nodeUuid"], "hostUuid": record["hostUuid"]}


def test_adopts_existing_shared_profile_without_writes_and_switches_original_port(
    setup,
):
    async def scenario():
        client, store, rollback, settings = setup
        body = await existing_setup(setup)
        before = deepcopy(client.data)
        record = await gconfig.adopt_existing(client, store, "actor", body)
        assert client.data == before
        assert record["verifiedAt"] is None and record["lastProof"] == []
        with pytest.raises(OperationError, match="уже подключён"):
            await gconfig.adopt_existing(client, store, "actor", body)
        add_entry(client)
        original_profiles = deepcopy(client.data["config-profiles"][:-1])
        original_host = deepcopy(client.data["hosts"][0])
        await gconfig.prepare_route(
            client, store, settings, rollback, "actor", prepare_body(record)
        )
        assert (
            client.data["config-profiles"][-1]["config"]["inbounds"][-1]["settings"][
                "port"
            ]
            == 32443
        )
        for mode in ("ru", "direct"):
            await gconfig.switch_route(
                client, store, rollback, "actor", {"id": record["id"], "mode": mode}
            )
        assert client.data["hosts"][0] == original_host
        assert client.data["config-profiles"][:-1] == original_profiles
        assert client.data["users"] == []
        assert not list(rollback.directory.glob("*.lease"))

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "change", ["bridge", "fingerprint", "compatibility", "binding", "udp", "disabled"]
)
def test_adoption_rejects_unsafe_existing_host_without_writes(setup, change):
    async def scenario():
        client, store, _, _ = setup
        body = await existing_setup(setup)
        host = client.data["hosts"][0]
        incoming = client.data["config-profiles"][-1]["config"]["inbounds"][0]
        if change == "bridge":
            host["address"] = "1.1.1.1"
        elif change == "fingerprint":
            host["fingerprint"] = "chrome"
        elif change == "compatibility":
            incoming["streamSettings"]["realitySettings"].pop("minClientVer")
        elif change == "binding":
            host["nodes"].append("neighbor")
        elif change == "udp":
            incoming["protocol"] = "hysteria"
        else:
            host["isDisabled"] = True
        before = deepcopy(client.data)
        with pytest.raises(OperationError):
            await gconfig.adopt_existing(client, store, "actor", body)
        assert client.data == before and store.nodes() == []
        rows = gconfig.existing_candidates(
            gconfig.normalize_inventory(await client.inventory()), []
        )
        assert rows and all(not r["ready"] and r["reason"] for r in rows)

    asyncio.run(scenario())


def test_adopted_profile_drift_blocks_switch_before_writes(setup):
    async def scenario():
        client, store, rollback, _ = setup
        body = await existing_setup(setup)
        record = await gconfig.adopt_existing(client, store, "actor", body)
        client.data["config-profiles"][-1]["config"]["routing"]["rules"] = []
        before = deepcopy(client.data)
        with pytest.raises(OperationError, match="изменился"):
            await gconfig.switch_route(
                client, store, rollback, "actor", {"id": record["id"], "mode": "ru"}
            )
        assert client.data == before

    asyncio.run(scenario())


def test_post_switch_probe_failure_rolls_host_back(setup, monkeypatch):
    async def scenario():
        client, store, rollback, settings = setup
        record, _ = await install(setup)
        add_entry(client)
        await gconfig.prepare_route(
            client, store, settings, rollback, "actor", prepare_body(record)
        )
        before = deepcopy(client.data["hosts"][0])
        count = 0

        async def probe(*a, **kw):
            nonlocal count
            count += 1
            if count == 2:
                raise OperationError("exported client failed")
            return []

        monkeypatch.setattr(gconfig, "verify_wires", probe)
        with pytest.raises(OperationError):
            await gconfig.switch_route(
                client, store, rollback, "actor", {"id": record["id"], "mode": "ru"}
            )
        assert client.data["hosts"][0] == before
        assert not list(rollback.directory.glob("*.lease"))

    asyncio.run(scenario())


def test_lease_is_encrypted_and_does_not_overwrite_concurrent_change(setup):
    client, _store, rollback, _settings = setup
    client.data["hosts"] = [{"uuid": "host", "address": "old", "port": 443}]
    identifier = str(uuid.uuid4())
    rollback.arm(
        identifier,
        client.token,
        [gconfig.action("hosts", "host", {"address": "old"}, {"address": "new"})],
    )
    assert client.token.encode() not in rollback._path(identifier).read_bytes()
    client.data["hosts"][0]["address"] = "other-operator"
    assert asyncio.run(rollback.restore(identifier)) == ["drift:hosts"]
    assert client.data["hosts"][0]["address"] == "other-operator"
    client.data["hosts"][0]["address"] = "new"
    assert asyncio.run(rollback.restore(identifier)) == []
    assert client.data["hosts"][0]["address"] == "old"


def test_uncertain_post_is_read_back_without_duplicate(setup):
    client = setup[0]
    client.lost_post = True
    result = asyncio.run(
        gconfig.create_owned(
            client, "internal-squads", {"name": "one", "inbounds": []}, "name"
        )
    )
    assert result["name"] == "one"
    assert sum(s["name"] == "one" for s in client.data["internal-squads"]) == 1


def test_export_validation_rejects_wrong_route_fingerprint_and_insecure():
    wire = {
        "name": "test",
        "type": "vless",
        "server": "8.8.4.4",
        "port": 443,
        "client-fingerprint": "firefox",
        "tls": True,
        "flow": "xtls-rprx-vision",
        "reality-opts": {"public-key": "public", "short-id": "1234"},
    }
    assert (
        exported_wire(json.dumps({"proxies": [wire]}), "test", "mihomo", "8.8.4.4", 443)
        == wire
    )
    for changed in (
        {"server": "1.1.1.1"},
        {"client-fingerprint": "chrome"},
        {"skip-cert-verify": True},
    ):
        with pytest.raises(OperationError):
            exported_wire(
                json.dumps({"proxies": [{**wire, **changed}]}),
                "test",
                "mihomo",
                "8.8.4.4",
                443,
            )


def test_prepare_failure_restores_entry_profile(setup, monkeypatch):
    async def scenario():
        client, store, rollback, settings = setup
        record, _ = await install(setup)
        add_entry(client)
        before = deepcopy(client.data["config-profiles"][-1])

        async def fail(*args, **kwargs):
            raise OperationError("entry-to-exit blocked")

        monkeypatch.setattr(gconfig, "verify_wires", fail)
        with pytest.raises(OperationError):
            await gconfig.prepare_route(
                client, store, settings, rollback, "actor", prepare_body(record)
            )
        assert client.data["config-profiles"][-1] == before
        assert store.node(record["id"])["route"] is None
        assert not list(rollback.directory.glob("*.lease"))

    asyncio.run(scenario())


def test_restart_watcher_restores_expired_lease(setup):
    async def scenario():
        client, store, rollback, settings = setup
        client.data["hosts"] = [{"uuid": "host", "address": "new"}]
        identifier = store.create("gconfig-route-switch", "actor", "node", {})
        rollback.arm(
            identifier,
            client.token,
            [gconfig.action("hosts", "host", {"address": "old"}, {"address": "new"})],
        )
        lease = rollback.read(identifier)
        lease["deadline"] = time.time() - 1
        rollback.write(identifier, lease)
        restarted = Rollbacks(settings.data_dir, settings.remnawave_url)
        task = asyncio.create_task(restarted.watch(store))
        for _ in range(20):
            if store.get(identifier)["state"] == "rolled_back":
                break
            await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert client.data["hosts"][0]["address"] == "old"
        assert store.get(identifier)["state"] == "rolled_back"
        assert not list(rollback.directory.glob("*.lease"))

    asyncio.run(scenario())


def test_ssh_host_key_mismatch_prevents_authentication(monkeypatch):
    from orchestrator.app.ssh import SshCredentials, SshError, SshSession

    authenticated = []

    class Key:
        def asbytes(self):
            return b"unexpected-host-key"

    class Transport:
        def close(self):
            pass

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

        def connect(self, **kwargs):
            self.policy.missing_host_key(self, kwargs["hostname"], Key())
            authenticated.append(True)

    monkeypatch.setattr("orchestrator.app.ssh.paramiko.SSHClient", Transport)
    with pytest.raises(SshError):
        SshSession(SshCredentials("8.8.4.4", 22, "root", "secret"), "SHA256:expected")
    assert authenticated == []


def test_exhausted_rollback_discards_session_token(setup):
    client, _store, rollback, _settings = setup
    client.data["hosts"] = [{"uuid": "host", "address": "other-operator"}]
    identifier = str(uuid.uuid4())
    rollback.arm(
        identifier,
        client.token,
        [gconfig.action("hosts", "host", {"address": "old"}, {"address": "new"})],
    )
    for _ in range(3):
        assert asyncio.run(rollback.restore(identifier)) == ["drift:hosts"]
    assert "token" not in rollback.read(identifier)
    assert client.data["hosts"][0]["address"] == "other-operator"
