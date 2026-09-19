"""Run the complete auto configurations in isolated, disposable client processes."""

import asyncio
import ipaddress
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

import httpx


def port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


async def measure(engine, source, members):
    socks, controller = port(), port()
    secret = secrets.token_hex(24)
    config = deepcopy(source)
    if engine == "xray":
        config["log"] = {"loglevel": "none"}
        config["inbounds"] = [
            {
                "listen": "127.0.0.1",
                "port": socks,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ]
        config.pop("api", None)
        command = ["xray", "run", "-config"]
        check = ["xray", "run", "-test", "-config"]
    else:
        config.update(
            {
                "mixed-port": socks,
                "port": 0,
                "socks-port": 0,
                "redir-port": 0,
                "tproxy-port": 0,
                "bind-address": "127.0.0.1",
                "allow-lan": False,
                "mode": "rule",
                "log-level": "silent",
                "external-controller": f"127.0.0.1:{controller}",
                "secret": secret,
                "tun": {"enable": False},
                "dns": {"enable": False},
                "profile": {"store-selected": False},
            }
        )
        assert not config.get("listeners")
    with tempfile.TemporaryDirectory(prefix="ham-auto-visible-") as directory:
        if engine == "mihomo":
            command = ["mihomo", "-d", directory, "-f"]
            check = ["mihomo", "-t", "-d", directory, "-f"]
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        os.chmod(path, 0o600)
        process = await asyncio.create_subprocess_exec(
            *check,
            str(path),
            cwd=directory,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert await asyncio.wait_for(process.wait(), 20) == 0, (
            engine + " configuration rejected"
        )
        process = await asyncio.create_subprocess_exec(
            *command,
            str(path),
            cwd=directory,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            for _ in range(60):
                assert process.returncode is None, engine + " stopped"
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", socks)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.1)
            result = {"engine": engine, "configValid": True}
            if engine == "mihomo":
                groups = [g for g in config["proxy-groups"] if g["type"] == "url-test"]
                assert len(groups) == 1
                group = groups[0]
                expected = {
                    p["name"]
                    for p in config["proxies"]
                    if re.search(group["filter"], p["name"])
                }
                assert expected == set(members)
                async with httpx.AsyncClient(
                    trust_env=False,
                    timeout=25,
                    headers={"Authorization": "Bearer " + secret},
                ) as control:
                    response = await control.get(
                        f"http://127.0.0.1:{controller}/proxies"
                    )
                    actual = response.json()["proxies"][group["name"]]
                    assert (
                        actual["type"] == "URLTest" and set(actual["all"]) == expected
                    )
                    delay = await control.get(
                        f"http://127.0.0.1:{controller}/group/{quote(group['name'], safe='')}/delay",
                        params={
                            "url": "https://www.gstatic.com/generate_204",
                            "timeout": "10000",
                        },
                    )
                    assert delay.status_code == 200 and delay.json(), (
                        "Mihomo URL-test failed"
                    )
                    result["urlTest"] = True
                    result["members"] = len(expected)
            started = time.monotonic()
            async with httpx.AsyncClient(
                proxy=f"socks5h://127.0.0.1:{socks}", timeout=12, trust_env=False
            ) as http:
                # A fresh leastLoad config needs observatory results before it can route.
                for attempt in range(8):
                    try:
                        response = await http.get(
                            "https://www.gstatic.com/generate_204"
                        )
                        if response.status_code == 204:
                            break
                    except httpx.HTTPError:
                        pass
                    await asyncio.sleep(2)
                else:
                    raise RuntimeError(engine + " auto did not pass HTTPS")
                for _ in range(3):
                    assert (
                        await http.get("https://www.gstatic.com/generate_204")
                    ).status_code == 204
                response = await http.get("https://api.ipify.org")
                assert (
                    response.status_code == 200
                    and ipaddress.ip_address(response.text.strip()).is_global
                )
                result.update(
                    httpsRequests=3,
                    egress=response.text.strip(),
                    durationMs=round((time.monotonic() - started) * 1000),
                )
            return result
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()


async def main():
    payload = json.load(sys.stdin)
    return await asyncio.gather(
        *(
            measure(engine, payload[engine], payload["members"])
            for engine in ("xray", "mihomo")
        )
    )


try:
    print(json.dumps(asyncio.run(main())))
except Exception as error:  # noqa: BLE001 - Client output may contain private subscription data.
    print(
        json.dumps(
            {
                "failed": True,
                "type": type(error).__name__,
                "message": str(error)
                if isinstance(error, (AssertionError, RuntimeError))
                else "Client probe failed",
            }
        )
    )
    sys.exit(1)
