from __future__ import annotations

import asyncio
import json
import os
import socket
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from .operations import OperationError

CHECK_URL = "https://www.gstatic.com/generate_204"
IP_URL = "https://api.ipify.org"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exported_wire(
    content: str, remark: str, engine: str, address: str, port: int
) -> dict:
    try:
        data = json.loads(content) if engine == "xray" else yaml.safe_load(content)
        if engine == "xray":
            configs = data if isinstance(data, list) else [data]
            wires = [
                o
                for c in configs
                if c.get("remarks") == remark
                for o in c.get("outbounds", [])
                if o.get("protocol") == "vless"
            ]
            if len(wires) != 1:
                raise ValueError()
            wire = wires[0]
            stream = wire["streamSettings"]
            endpoint = wire["settings"]["vnext"][0]
            if (
                endpoint["address"] != address
                or endpoint["port"] != port
                or stream.get("security") != "reality"
                or stream.get("network", "raw") not in ("tcp", "raw")
                or stream["realitySettings"].get("fingerprint") != "firefox"
                or endpoint["users"][0].get("flow") != "xtls-rprx-vision"
            ):
                raise ValueError()
        else:
            wires = [p for p in data.get("proxies", []) if p.get("name") == remark]
            if len(wires) != 1:
                raise ValueError()
            wire = wires[0]
            if (
                wire.get("server") != address
                or wire.get("port") != port
                or wire.get("type") != "vless"
                or wire.get("client-fingerprint") != "firefox"
                or not wire.get("tls")
                or not wire.get("reality-opts")
                or wire.get("skip-cert-verify")
                or wire.get("flow") != "xtls-rprx-vision"
            ):
                raise ValueError()
        return deepcopy(wire)
    except (ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as error:
        raise OperationError(
            "Фактическая подписка не соответствует REALITY/Vision/Firefox выбранного хоста"
        ) from error


async def subscription_wires(
    client, user_uuid: str, remark: str, address: str, port: int
) -> dict:
    subscription = await client.request(
        "GET", f"/api/subscriptions/by-uuid/{user_uuid}"
    )
    url = subscription.get("subscriptionUrl", "")
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise OperationError("Панель не выдала HTTPS-ссылку тестовой подписки")
    result = {}
    async with httpx.AsyncClient(
        timeout=25, follow_redirects=False, trust_env=False
    ) as http:
        for engine, agent in (("xray", "Happ/5.7.0"), ("mihomo", "mihomo/1.19.24")):
            response = await http.get(
                url,
                headers={
                    "User-Agent": agent,
                    "X-Hwid": "ham-infra-owned-probe",
                    "X-Device-Os": "Linux",
                    "X-Device-Model": "Infrastructure probe",
                },
            )
            if response.status_code != 200 or len(response.content) > 4_000_000:
                raise OperationError(
                    "Не удалось получить фактическую тестовую подписку"
                )
            result[engine] = exported_wire(response.text, remark, engine, address, port)
    return result


async def run_core(engine: str, wire: dict, expected_ip: str) -> dict:
    socks_port, controller_port = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="ham-probe-") as directory:
        path = Path(directory) / "config.json"
        if engine == "xray":
            config = {
                "log": {"loglevel": "none"},
                "inbounds": [
                    {
                        "listen": "127.0.0.1",
                        "port": socks_port,
                        "protocol": "socks",
                        "settings": {"udp": False},
                    }
                ],
                "outbounds": [wire],
            }
            command = ["/usr/local/bin/xray", "run", "-config", str(path)]
        else:
            wire = {**wire, "name": "probe"}
            config = {
                "mixed-port": socks_port,
                "bind-address": "127.0.0.1",
                "allow-lan": False,
                "mode": "rule",
                "log-level": "silent",
                "ipv6": False,
                "external-controller": f"127.0.0.1:{controller_port}",
                "proxies": [wire],
                "rules": ["MATCH,probe"],
            }
            command = ["/usr/local/bin/mihomo", "-d", directory, "-f", str(path)]
        path.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(path, 0o600)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            for _ in range(40):
                if process.returncode is not None:
                    raise OperationError("Тестовое ядро не запустилось")
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", socks_port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.1)
            started = time.monotonic()
            delay = None
            if engine == "mihomo":
                async with httpx.AsyncClient(timeout=20, trust_env=False) as http:
                    response = await http.get(
                        f"http://127.0.0.1:{controller_port}/proxies/probe/delay",
                        params={"url": CHECK_URL, "timeout": "10000"},
                    )
                    if response.status_code != 200 or not isinstance(
                        response.json().get("delay"), int
                    ):
                        raise OperationError("URL-test mihomo не пройден")
                    delay = response.json()["delay"]
            async with httpx.AsyncClient(
                proxy=f"socks5h://127.0.0.1:{socks_port}", timeout=20, trust_env=False
            ) as http:
                for _ in range(3):
                    response = await http.get(CHECK_URL)
                    if response.status_code != 204:
                        raise OperationError("HTTPS-проверка VPN не пройдена")
                response = await http.get(IP_URL)
                if response.status_code != 200 or response.text.strip() != expected_ip:
                    raise OperationError(
                        "Выходной IP не совпадает с выбранной зарубежной нодой"
                    )
            return {
                "engine": engine,
                "httpsRequests": 3,
                "egress": expected_ip,
                "delayMs": delay,
                "durationMs": round((time.monotonic() - started) * 1000),
            }
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()


async def verify_wires(
    wires: dict, expected_ip: str, override: tuple[str, int] | None = None
) -> list:
    try:
        async with asyncio.timeout(180):
            return await _verify_wires(wires, expected_ip, override)
    except TimeoutError:
        raise OperationError("Истекло трёхминутное окно клиентской проверки") from None


async def _verify_wires(
    wires: dict, expected_ip: str, override: tuple[str, int] | None
) -> list:
    results = []
    for engine in ("xray", "mihomo"):
        wire = deepcopy(wires[engine])
        if override:
            if engine == "xray":
                wire["settings"]["vnext"][0].update(
                    address=override[0], port=override[1]
                )
            else:
                wire.update(server=override[0], port=override[1])
        for attempt in range(3):
            try:
                proof = await run_core(engine, wire, expected_ip)
                results.append({**proof, "attempts": attempt + 1})
                break
            except (OperationError, httpx.HTTPError, OSError):
                if attempt == 2:
                    raise OperationError(
                        f"Клиентская проверка {engine} не пройдена за три попытки"
                    ) from None
                await asyncio.sleep(2)
    return results
