import asyncio
from typing import Any

import httpx

from orchestrator.app.remnawave import RemnawaveClient


class FakeResponse:
    status_code = 200

    def __init__(self, payload: Any = None):
        self.payload = [] if payload is None else payload

    def json(self) -> dict[str, Any]:
        return {"response": self.payload}


class FakeAsyncClient:
    def __init__(self, captured: dict[str, Any], **_: Any):
        self.captured = captured

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object):
        return None

    async def request(self, method: str, path: str, **kwargs: Any):
        request = {"method": method, "path": path, **kwargs}
        self.captured.setdefault("requests", []).append(request)
        self.captured.update(request)
        if path == "/api/config-profiles/":
            return FakeResponse(
                {
                    "total": 1,
                    "configProfiles": [
                        {"uuid": "profile-1", "name": "BASE", "config": {}}
                    ],
                }
            )
        if path == "/api/config-profiles/profile-1":
            return FakeResponse(
                {
                    "uuid": "profile-1",
                    "name": "BASE",
                    "config": {"outbounds": [{"address": "192.0.2.1"}]},
                    "inbounds": [],
                }
            )
        return FakeResponse()


def test_browser_session_headers_and_canonical_node_path(monkeypatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeAsyncClient(captured, **kwargs),
    )

    result = asyncio.run(RemnawaveClient("http://remnawave:3000", "a" * 32).validate())

    assert result == []
    assert captured["path"] == "/api/nodes/"
    assert captured["headers"] == {
        "Authorization": f"Bearer {'a' * 32}",
        "Accept": "application/json",
        "X-Remnawave-Client-Type": "browser",
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Proto": "https",
    }


def test_collection_paths_match_remnawave_281_contract(monkeypatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeAsyncClient(captured, **kwargs),
    )

    asyncio.run(RemnawaveClient("http://remnawave:3000", "b" * 32).inventory())

    assert [item["path"] for item in captured["requests"]] == [
        "/api/nodes/",
        "/api/hosts/",
        "/api/config-profiles/",
        "/api/config-profiles/profile-1",
        "/api/internal-squads/",
    ]


def test_inventory_hydrates_profile_details(monkeypatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeAsyncClient(captured, **kwargs),
    )

    inventory = asyncio.run(RemnawaveClient("http://remnawave:3000", "c" * 32).inventory())

    assert inventory["profiles"][0]["config"]["outbounds"][0]["address"] == "192.0.2.1"


def test_restart_body_matches_remnawave_281_contract(monkeypatch):
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: FakeAsyncClient(captured, **kwargs),
    )

    asyncio.run(
        RemnawaveClient("http://remnawave:3000", "d" * 32).restart_node(
            "node-1", force_restart=False
        )
    )

    assert captured["path"] == "/api/nodes/node-1/actions/restart"
    assert captured["json"] == {"forceRestart": False}
