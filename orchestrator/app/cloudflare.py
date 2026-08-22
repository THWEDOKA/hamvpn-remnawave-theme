from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import uuid
from pathlib import Path
from typing import Any

import httpx


class CloudflareError(RuntimeError):
    pass


def normalize_hostname(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_name.split(".")
    if len(labels) < 2 or len(ascii_name) > 253:
        return None
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        return None
    return ascii_name


class CloudflareClient:
    def __init__(
        self,
        token: str,
        zone_ids: dict[str, str] | None = None,
        ttl: int = 60,
        timeout: float = 12,
    ):
        self.token = token.strip()
        self.zone_ids = {
            str(name).strip().rstrip(".").lower(): str(zone_id).strip()
            for name, zone_id in (zone_ids or {}).items()
            if str(name).strip() and str(zone_id).strip()
        }
        self.ttl = max(60, min(int(ttl), 86400))
        self.timeout = timeout

    def configure(self, token: str, zone_ids: dict[str, str], ttl: int) -> None:
        self.token = token.strip()
        self.zone_ids = {
            str(name).strip().rstrip(".").lower(): str(zone_id).strip()
            for name, zone_id in zone_ids.items()
            if str(name).strip() and str(zone_id).strip()
        }
        self.ttl = max(60, min(int(ttl), 86400))

    @property
    def configured(self) -> bool:
        return len(self.token) >= 20

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not self.configured:
            raise CloudflareError("Cloudflare API не настроен")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(
                    base_url="https://api.cloudflare.com/client/v4",
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = await client.request(
                        method,
                        path,
                        headers=headers,
                        params=params,
                        json=body,
                    )
            except httpx.HTTPError as error:
                if attempt == 2:
                    raise CloudflareError("Cloudflare API не ответил") from error
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            if response.status_code in {429, 500, 502, 503, 504} and attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            if response.status_code in {401, 403}:
                raise CloudflareError("Cloudflare отклонил API-токен или его права")
            if response.status_code >= 400:
                raise CloudflareError(f"Cloudflare вернул HTTP {response.status_code}")
            try:
                payload = response.json()
            except ValueError as error:
                raise CloudflareError("Cloudflare вернул некорректный JSON") from error
            if not payload.get("success"):
                raise CloudflareError("Cloudflare не подтвердил операцию")
            return payload.get("result")
        raise CloudflareError("Cloudflare API не ответил")

    async def _zone_id(self, hostname: str) -> str:
        for zone_name, zone_id in sorted(
            self.zone_ids.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if hostname == zone_name or hostname.endswith(f".{zone_name}"):
                return zone_id
        labels = hostname.split(".")
        for index in range(max(0, len(labels) - 3), len(labels) - 1):
            zone_name = ".".join(labels[index:])
            result = await self._request(
                "GET",
                "/zones",
                params={"name": zone_name, "status": "active", "per_page": 5},
            )
            if isinstance(result, list) and len(result) == 1 and result[0].get("id"):
                return str(result[0]["id"])
        raise CloudflareError(f"DNS-зона для {hostname} не найдена")

    async def verify_zone(self, zone_name: str) -> str:
        normalized = normalize_hostname(zone_name)
        if not normalized:
            raise CloudflareError("Укажите корректную DNS-зону")
        await self._request("GET", "/user/tokens/verify")
        zone_id = await self._zone_id(normalized)
        await self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": "A", "per_page": 1},
        )
        return zone_id

    async def plan_records(
        self, hostnames: list[str], old_address: str, new_address: str
    ) -> list[dict[str, Any]]:
        try:
            old_ip = ipaddress.ip_address(old_address)
            new_ip = ipaddress.ip_address(new_address)
        except ValueError as error:
            raise CloudflareError("Cloudflare получил некорректный IP-адрес") from error
        if old_ip.version != 4 or new_ip.version != 4:
            raise CloudflareError("Автосмена Hysteria DNS сейчас поддерживает только IPv4 A-записи")
        records: list[dict[str, Any]] = []
        normalized_hostnames = {normalize_hostname(hostname) for hostname in hostnames}
        if None in normalized_hostnames:
            raise CloudflareError("У Hysteria-хоста указано некорректное доменное имя")
        for hostname in sorted(normalized_hostnames):
            zone_id = await self._zone_id(hostname)
            result = await self._request(
                "GET",
                f"/zones/{zone_id}/dns_records",
                params={"type": "A", "name": hostname, "per_page": 100},
            )
            matches = [
                item
                for item in result or []
                if item.get("type") == "A" and item.get("name", "").rstrip(".").lower() == hostname
            ]
            if len(matches) != 1:
                raise CloudflareError(
                    f"Для {hostname} требуется ровно одна A-запись, найдено: {len(matches)}"
                )
            record = matches[0]
            if record.get("content") != old_address:
                raise CloudflareError(
                    f"A-запись {hostname} указывает не на текущий IP ноды"
                )
            records.append(
                {
                    "zoneId": zone_id,
                    "recordId": str(record["id"]),
                    "hostname": hostname,
                    "oldAddress": old_address,
                    "newAddress": new_address,
                    "oldTtl": int(record.get("ttl") or 1),
                    "newTtl": self.ttl,
                    "proxyWasEnabled": bool(record.get("proxied")),
                }
            )
        return records

    async def _record(self, record: dict[str, Any]) -> dict[str, Any]:
        result = await self._request(
            "GET",
            f"/zones/{record['zoneId']}/dns_records/{record['recordId']}",
        )
        if not isinstance(result, dict):
            raise CloudflareError(f"A-запись {record['hostname']} не найдена")
        return result

    async def update_record(
        self,
        record: dict[str, Any],
        address: str,
        ttl: int,
        *,
        expected_address: str | None = None,
    ) -> None:
        current = await self._record(record)
        if current.get("type") != "A" or current.get("name", "").rstrip(".").lower() != record[
            "hostname"
        ]:
            raise CloudflareError("Cloudflare DNS-запись изменилась после построения плана")
        if expected_address is not None and current.get("content") != expected_address:
            raise CloudflareError("Cloudflare DNS-запись изменилась после построения плана")
        await self._request(
            "PATCH",
            f"/zones/{record['zoneId']}/dns_records/{record['recordId']}",
            body={"content": address, "proxied": False, "ttl": ttl},
        )
        verified = await self._record(record)
        if verified.get("content") != address or bool(verified.get("proxied")):
            raise CloudflareError(f"Cloudflare не подтвердил DNS only для {record['hostname']}")

    async def public_dns(self, hostname: str, expected_address: str) -> dict[str, Any]:
        async def lookup(url: str) -> list[str]:
            try:
                async with httpx.AsyncClient(
                    timeout=5,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = await client.get(
                        url,
                        params={"name": hostname, "type": "A"},
                        headers={"Accept": "application/dns-json"},
                    )
                response.raise_for_status()
                payload = response.json()
                return sorted(
                    {
                        item.get("data")
                        for item in payload.get("Answer", [])
                        if item.get("type") == 1 and item.get("data")
                    }
                )
            except (httpx.HTTPError, ValueError, TypeError):
                return []

        cloudflare, google = await asyncio.gather(
            lookup("https://cloudflare-dns.com/dns-query"),
            lookup("https://dns.google/resolve"),
        )
        return {
            "hostname": hostname,
            "cloudflare": cloudflare,
            "google": google,
            "propagated": expected_address in cloudflare or expected_address in google,
        }


class CloudflareConfigStore:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "cloudflare.json"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def save(self, token: str, zone_ids: dict[str, str], ttl: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        payload = {"token": token, "zoneIds": zone_ids, "ttl": int(ttl)}
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            temporary.chmod(0o600)
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
        finally:
            temporary.unlink(missing_ok=True)
