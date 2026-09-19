from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
from copy import deepcopy
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from .operations import OperationError


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def ids(values: list) -> list[str]:
    return [v["uuid"] if isinstance(v, dict) else v for v in values]


def public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise OperationError("Нужен публичный IP сервера") from error
    if address.version != 4 or not address.is_global:
        raise OperationError("Нужен публичный IPv4 сервера")
    return str(address)


def template(inventory: dict) -> dict:
    matches = [p for p in inventory["profiles"] if p["name"] == "G-CONFIG"]
    if len(matches) != 1:
        raise OperationError("Нужен один существующий профиль с точным именем G-CONFIG")
    profile = matches[0]
    config = profile["config"]
    incoming = config.get("inbounds", [])
    if len(incoming) != 1:
        raise OperationError("G-CONFIG должен содержать один клиентский вход")
    inbound = incoming[0]
    stream = inbound.get("streamSettings", {})
    if (
        inbound.get("protocol") != "vless"
        or stream.get("security") != "reality"
        or stream.get("network", "raw") not in ("tcp", "raw")
        or inbound.get("port") != 443
    ):
        raise OperationError("Поддерживается G-CONFIG с VLESS / REALITY / TCP на 443")
    if any(
        o.get("protocol") not in ("freedom", "blackhole")
        for o in config.get("outbounds", [])
    ):
        raise OperationError(
            "Шаблон содержит дополнительные выходы: требуется отдельная проверка"
        )
    reality = stream.get("realitySettings", {})
    if not reality.get("serverNames") or not (
        reality.get("target") or reality.get("dest")
    ):
        raise OperationError("В шаблоне отсутствует REALITY target или SNI")
    return profile


def fresh_config(profile: dict, suffix: str) -> dict:
    config = deepcopy(profile["config"])
    inbound = config["inbounds"][0]
    old_tag = inbound["tag"]
    inbound["tag"] = "ham-g-" + suffix
    inbound["listen"] = "0.0.0.0"
    inbound["settings"]["clients"] = []
    raw_key = X25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    reality = inbound["streamSettings"]["realitySettings"]
    reality["privateKey"] = base64.urlsafe_b64encode(raw_key).decode().rstrip("=")
    reality["shortIds"] = [secrets.token_hex(8)]
    reality["minClientVer"] = "1.8.2"
    for rule in config.get("routing", {}).get("rules", []):
        if "inboundTag" in rule:
            rule["inboundTag"] = [
                inbound["tag"] if tag == old_tag else tag for tag in rule["inboundTag"]
            ]
    return config


def relay_candidate(
    config: dict, *, tag: str, port: int, exit_ip: str, exit_port: int = 443
) -> dict:
    public_ip(exit_ip)
    if type(exit_port) is not int or not 1 <= exit_port <= 65535:
        raise OperationError("Некорректный TCP-порт зарубежной ноды")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise OperationError("Порт российского входа должен быть от 1024 до 65535")
    result = deepcopy(config)
    for inbound in result.get("inbounds", []):
        if inbound.get("tag") == tag:
            raise OperationError("Маршрут уже существует; сначала обновите состояние")
        for part in str(inbound.get("port", "")).split(","):
            try:
                bounds = [int(n) for n in part.split("-")]
            except ValueError as error:
                raise OperationError(
                    "Не удалось проверить занятость портов профиля"
                ) from error
            if bounds and bounds[0] <= port <= bounds[-1]:
                raise OperationError("Порт уже используется профилем российского входа")
    direct = [
        o["tag"] for o in result.get("outbounds", []) if o.get("protocol") == "freedom"
    ]
    if len(direct) != 1:
        raise OperationError("В профиле российского входа нужен один прямой outbound")
    result.setdefault("inbounds", []).append(
        {
            "tag": tag,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "dokodemo-door",
            "settings": {
                "address": exit_ip,
                "port": exit_port,
                "network": "tcp",
                "followRedirect": False,
            },
            "sniffing": {"enabled": False},
        }
    )
    result.setdefault("routing", {}).setdefault("rules", []).insert(
        0,
        {
            "type": "field",
            "inboundTag": [tag],
            "outboundTag": direct[0],
        },
    )
    return result
