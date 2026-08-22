from __future__ import annotations

from typing import Any

import httpx


class RemnawaveError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class RemnawaveClient:
    def __init__(self, base_url: str, token: str, timeout: float = 15):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    async def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "X-Remnawave-Client-Type": "browser",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, headers=headers, json=body)
        except httpx.HTTPError as error:
            raise RemnawaveError("Панель не ответила на внутренний запрос") from error
        if response.status_code in {401, 403}:
            raise RemnawaveError("Сессия администратора истекла", 401)
        if response.status_code >= 400:
            detail = ""
            try:
                payload = response.json()
                detail = str(payload.get("message") or payload.get("error") or "")
            except ValueError:
                detail = ""
            raise RemnawaveError(
                detail or f"Remnawave вернула HTTP {response.status_code}", response.status_code
            )
        if response.status_code == 204:
            return None
        try:
            payload = response.json()
        except ValueError as error:
            raise RemnawaveError("Remnawave вернула некорректный JSON") from error
        return payload.get("response", payload)

    async def validate(self) -> list[dict[str, Any]]:
        result = await self.request("GET", "/api/nodes/")
        if not isinstance(result, list):
            raise RemnawaveError("Неожиданный формат списка нод")
        return result

    async def inventory(self) -> dict[str, Any]:
        nodes = await self.validate()
        hosts = await self.request("GET", "/api/hosts/")
        profiles = await self.request("GET", "/api/config-profiles/")
        squads = await self.request("GET", "/api/internal-squads/")
        return {
            "nodes": nodes if isinstance(nodes, list) else [],
            "hosts": hosts if isinstance(hosts, list) else [],
            "profiles": profiles if isinstance(profiles, list) else [],
            "squads": squads if isinstance(squads, list) else [],
        }

    async def update_node(self, body: dict[str, Any]) -> Any:
        return await self.request("PATCH", "/api/nodes/", body)

    async def create_node(self, body: dict[str, Any]) -> Any:
        return await self.request("POST", "/api/nodes/", body)

    async def delete_node(self, uuid: str) -> Any:
        return await self.request("DELETE", f"/api/nodes/{uuid}")

    async def restart_node(self, uuid: str) -> Any:
        return await self.request("POST", f"/api/nodes/{uuid}/actions/restart", {})

    async def update_host(self, body: dict[str, Any]) -> Any:
        return await self.request("PATCH", "/api/hosts/", body)

    async def create_host(self, body: dict[str, Any]) -> Any:
        return await self.request("POST", "/api/hosts/", body)

    async def delete_host(self, uuid: str) -> Any:
        return await self.request("DELETE", f"/api/hosts/{uuid}")

    async def update_profile(self, body: dict[str, Any]) -> Any:
        return await self.request("PATCH", "/api/config-profiles/", body)

    async def secret_key(self) -> str:
        result = await self.request("GET", "/api/keygen/")
        if not isinstance(result, dict) or not result.get("pubKey"):
            raise RemnawaveError("Панель не выдала ключ ноды")
        return str(result["pubKey"])
