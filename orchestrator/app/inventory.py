from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from typing import Any


def _profile_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("configProfiles", "internalSquads", "profiles", "squads", "items"):
            items = value.get(key)
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
    return []


def normalize_inventory(raw: dict[str, Any]) -> dict[str, Any]:
    profiles = _profile_items(raw.get("profiles"))
    squads = _profile_items(raw.get("squads"))
    nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    hosts = raw.get("hosts") if isinstance(raw.get("hosts"), list) else []
    profile_by_uuid = {item.get("uuid"): item for item in profiles if item.get("uuid")}
    node_rows = []
    for node in nodes:
        config_profile = node.get("configProfile") or {}
        profile_uuid = config_profile.get("activeConfigProfileUuid")
        node_rows.append(
            {
                "uuid": node.get("uuid"),
                "name": node.get("name"),
                "address": node.get("address"),
                "port": node.get("port"),
                "countryCode": node.get("countryCode"),
                "isConnected": bool(node.get("isConnected")),
                "isDisabled": bool(node.get("isDisabled")),
                "lastStatusMessage": node.get("lastStatusMessage"),
                "profileUuid": profile_uuid,
                "profileName": (profile_by_uuid.get(profile_uuid) or {}).get("name"),
                "activeInbounds": config_profile.get("activeInbounds") or [],
                "tags": node.get("tags") or [],
            }
        )
    host_rows = []
    for host in hosts:
        inbound = host.get("inbound") or {}
        host_rows.append(
            {
                "uuid": host.get("uuid"),
                "remark": host.get("remark"),
                "address": host.get("address"),
                "port": host.get("port"),
                "isDisabled": bool(host.get("isDisabled")),
                "nodes": host.get("nodes") or [],
                "inbound": inbound,
                "excludedInternalSquads": host.get("excludedInternalSquads") or [],
                "tags": host.get("tags") or [],
            }
        )
    return {
        "nodes": node_rows,
        "hosts": host_rows,
        "profiles": [
            {
                "uuid": item.get("uuid"),
                "name": item.get("name"),
                "config": item.get("config") or {},
                "inbounds": item.get("inbounds") or [],
            }
            for item in profiles
        ],
        "squads": [
            {
                "uuid": item.get("uuid"),
                "name": item.get("name"),
                "inbounds": item.get("inbounds") or [],
            }
            for item in squads
        ],
        "summary": {
            "nodes": len(node_rows),
            "connectedNodes": sum(1 for item in node_rows if item["isConnected"]),
            "hosts": len(host_rows),
            "profiles": len(profiles),
            "squads": len(squads),
        },
    }


def find_exact_paths(value: Any, target: str, path: tuple[Any, ...] = ()) -> list[list[Any]]:
    matches: list[list[Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            matches.extend(find_exact_paths(child, target, path + (key,)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(find_exact_paths(child, target, path + (index,)))
    elif isinstance(value, str) and value == target:
        matches.append(list(path))
    return matches


def replace_paths(value: Any, paths: list[list[Any]], replacement: str) -> Any:
    result = deepcopy(value)
    for path in paths:
        cursor = result
        for part in path[:-1]:
            cursor = cursor[part]
        cursor[path[-1]] = replacement
    return result


def _node_uuids(host: dict[str, Any]) -> set[str]:
    result = set()
    for value in host.get("nodes") or []:
        uuid = value.get("uuid") if isinstance(value, dict) else value
        if uuid:
            result.add(str(uuid))
    return result


def hysteria_hostnames(inventory: dict[str, Any], node_uuid: str) -> list[str]:
    result = set()
    for host in inventory["hosts"]:
        if node_uuid not in _node_uuids(host):
            continue
        inbound = host.get("inbound") or {}
        protocol = f"{inbound.get('type', '')} {inbound.get('network', '')}".lower()
        if "hysteria" not in protocol:
            continue
        address = str(host.get("address") or "").strip().rstrip(".").lower()
        try:
            ipaddress.ip_address(address)
            continue
        except ValueError:
            pass
        if address and "." in address:
            result.add(address)
    return sorted(result)


def build_ip_plan(inventory: dict[str, Any], node_uuid: str, new_address: str) -> dict[str, Any]:
    nodes = inventory["nodes"]
    node = next((item for item in nodes if item.get("uuid") == node_uuid), None)
    if not node:
        raise ValueError("Нода не найдена")
    old_address = str(node.get("address") or "")
    if not old_address:
        raise ValueError("У ноды отсутствует текущий адрес")
    if old_address == new_address:
        raise ValueError("Новый IP совпадает с текущим")
    related_hosts = []
    for host in inventory["hosts"]:
        reasons = []
        if node_uuid in _node_uuids(host):
            reasons.append("host-node-link")
        if host.get("address") == old_address:
            reasons.append("address-match")
        if reasons:
            related_hosts.append(
                {
                    "uuid": host.get("uuid"),
                    "remark": host.get("remark"),
                    "oldAddress": host.get("address"),
                    "newAddress": new_address if host.get("address") == old_address else None,
                    "willChange": host.get("address") == old_address,
                    "reasons": reasons,
                }
            )
    profile_changes = []
    for profile in inventory["profiles"]:
        config = profile.get("config") or {}
        paths = find_exact_paths(config, old_address)
        if paths:
            profile_changes.append(
                {
                    "uuid": profile.get("uuid"),
                    "name": profile.get("name"),
                    "paths": paths,
                    "matches": len(paths),
                }
            )
    serialized = json.dumps(
        [item.get("config") or {} for item in inventory["profiles"]], ensure_ascii=False
    )
    exact_count = sum(item["matches"] for item in profile_changes)
    warnings = []
    if old_address in serialized and exact_count == 0:
        warnings.append("Старый IP найден внутри составной строки профиля; автоматическая замена отключена")
    if any(not item["willChange"] for item in related_hosts):
        warnings.append("Часть хостов связана с нодой, но использует домен или другой адрес")
    return {
        "node": {
            "uuid": node.get("uuid"),
            "name": node.get("name"),
            "oldAddress": old_address,
            "newAddress": new_address,
            "port": node.get("port"),
        },
        "hosts": related_hosts,
        "profiles": profile_changes,
        "warnings": warnings,
        "impact": {
            "nodes": 1,
            "hosts": sum(1 for item in related_hosts if item["willChange"]),
            "profileValues": exact_count,
        },
    }
