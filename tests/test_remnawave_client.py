import asyncio
from typing import Any

import httpx

from orchestrator.app.remnawave import RemnawaveClient


class FakeResponse:
    status_code = 200

    @staticmethod
    def json() -> dict[str, Any]:
        return {"response": []}


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
        "/api/internal-squads/",
    ]
