from __future__ import annotations

import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import Any

from .audit import AuditStore
from .inventory import build_ip_plan, normalize_inventory, replace_paths
from .remnawave import RemnawaveClient
from .settings import Settings
from .ssh import (
    credentials_from_payload,
    install_node,
    preflight,
    rollback_install,
)


class OperationError(RuntimeError):
    pass


async def tcp_check(host: str, port: int, timeout: float) -> None:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError) as error:
        raise OperationError(f"Новый адрес не отвечает на порту ноды {port}") from error


def _not_expired(operation: dict[str, Any], ttl_seconds: int) -> None:
    created = datetime.fromisoformat(operation["created_at"])
    age = (datetime.now(timezone.utc) - created).total_seconds()
    if age > ttl_seconds:
        raise OperationError("План устарел. Выполните проверку заново")


async def create_ip_plan(
    client: RemnawaveClient,
    store: AuditStore,
    actor: str,
    node_uuid: str,
    new_address: str,
) -> dict[str, Any]:
    try:
        new_address = str(ipaddress.ip_address(new_address.strip()))
    except ValueError as error:
        raise OperationError("Укажите корректный новый IP-адрес") from error
    inventory = normalize_inventory(await client.inventory())
    try:
        plan = build_ip_plan(inventory, node_uuid, new_address)
    except ValueError as error:
        raise OperationError(str(error)) from error
    operation_id = store.create("ip-change", actor, plan["node"]["name"], plan)
    return {"operationId": operation_id, **plan}


async def apply_ip_change(
    client: RemnawaveClient,
    store: AuditStore,
    settings: Settings,
    actor: str,
    operation_id: str,
    confirmation: str,
) -> dict[str, Any]:
    operation = store.get(operation_id)
    if not operation or operation["operation_type"] != "ip-change":
        raise OperationError("План смены IP не найден")
    if operation["state"] != "planned" or operation["actor_fingerprint"] != actor:
        raise OperationError("Этот план уже выполнен или создан другой сессией")
    _not_expired(operation, settings.plan_ttl_seconds)
    plan = operation["plan"]
    node_plan = plan["node"]
    if confirmation.strip() != node_plan["name"]:
        raise OperationError("Для подтверждения введите точное имя ноды")
    raw = await client.inventory()
    inventory = normalize_inventory(raw)
    node = next((item for item in inventory["nodes"] if item["uuid"] == node_plan["uuid"]), None)
    if not node or node["address"] != node_plan["oldAddress"]:
        raise OperationError("Адрес ноды уже изменился. Сформируйте новый план")
    await tcp_check(node_plan["newAddress"], int(node_plan["port"]), settings.connect_timeout_seconds)
    host_by_uuid = {item["uuid"]: item for item in inventory["hosts"]}
    profile_by_uuid = {item["uuid"]: item for item in inventory["profiles"]}
    snapshot = {
        "node": {"uuid": node_plan["uuid"], "address": node_plan["oldAddress"]},
        "hosts": [],
        "profiles": [],
    }
    for item in plan["hosts"]:
        if item["willChange"] and item["uuid"] in host_by_uuid:
            snapshot["hosts"].append(
                {"uuid": item["uuid"], "address": host_by_uuid[item["uuid"]]["address"]}
            )
    for item in plan["profiles"]:
        if item["uuid"] in profile_by_uuid:
            snapshot["profiles"].append(
                {"uuid": item["uuid"], "config": profile_by_uuid[item["uuid"]]["config"]}
            )
    store.update(operation_id, state="applying", snapshot=snapshot)
    completed: list[str] = []
    try:
        await client.update_node({"uuid": node_plan["uuid"], "address": node_plan["newAddress"]})
        completed.append("node")
        for item in plan["hosts"]:
            if item["willChange"]:
                await client.update_host({"uuid": item["uuid"], "address": node_plan["newAddress"]})
                completed.append(f"host:{item['uuid']}")
        for item in plan["profiles"]:
            profile = profile_by_uuid[item["uuid"]]
            changed = replace_paths(profile["config"], item["paths"], node_plan["newAddress"])
            await client.update_profile({"uuid": item["uuid"], "config": changed})
            completed.append(f"profile:{item['uuid']}")
        verify = normalize_inventory(await client.inventory())
        verified_node = next(item for item in verify["nodes"] if item["uuid"] == node_plan["uuid"])
        if verified_node["address"] != node_plan["newAddress"]:
            raise OperationError("Проверка после применения не подтвердила новый IP")
        for item in plan["hosts"]:
            if not item["willChange"]:
                continue
            verified_host = next(
                (host for host in verify["hosts"] if host["uuid"] == item["uuid"]),
                None,
            )
            if not verified_host or verified_host["address"] != node_plan["newAddress"]:
                raise OperationError("Проверка после применения не подтвердила адрес хоста")
        for item in plan["profiles"]:
            verified_profile = next(
                (profile for profile in verify["profiles"] if profile["uuid"] == item["uuid"]),
                None,
            )
            if not verified_profile:
                raise OperationError("Проверка после применения не нашла изменённый профиль")
            for path in item["paths"]:
                cursor: Any = verified_profile["config"]
                try:
                    for part in path:
                        cursor = cursor[part]
                except (KeyError, IndexError, TypeError) as error:
                    raise OperationError(
                        "Проверка после применения не нашла изменённое поле профиля"
                    ) from error
                if cursor != node_plan["newAddress"]:
                    raise OperationError("Проверка после применения не подтвердила профиль")

        changed_profile_uuids = {item["uuid"] for item in plan["profiles"]}
        restart_node_uuids: list[str] = []
        for item in verify["nodes"]:
            should_restart = item["uuid"] == node_plan["uuid"] or (
                item.get("profileUuid") in changed_profile_uuids
            )
            if should_restart and not item.get("isDisabled") and item["uuid"] not in restart_node_uuids:
                restart_node_uuids.append(item["uuid"])
        restart_errors: list[str] = []
        restarted_nodes: list[str] = []
        for node_uuid in restart_node_uuids:
            try:
                await client.restart_node(node_uuid, force_restart=False)
                restarted_nodes.append(node_uuid)
            except Exception:  # noqa: BLE001
                restart_errors.append(node_uuid)
        restart_warning = None
        if restart_errors:
            restart_warning = (
                "Изменения применены, но перезапуск части затронутых нод не подтвердился"
            )
        result = {
            "verified": True,
            "completed": completed,
            "warning": restart_warning,
            "restartedNodes": restarted_nodes,
            "restartErrors": restart_errors,
            "newAddress": node_plan["newAddress"],
        }
        store.update(operation_id, state="completed", result=result)
        return result
    except Exception as error:
        rollback_errors: list[str] = []
        for profile in reversed(snapshot["profiles"]):
            try:
                await client.update_profile({"uuid": profile["uuid"], "config": profile["config"]})
            except Exception:  # noqa: BLE001
                rollback_errors.append(f"profile:{profile['uuid']}")
        for host in reversed(snapshot["hosts"]):
            try:
                await client.update_host({"uuid": host["uuid"], "address": host["address"]})
            except Exception:  # noqa: BLE001
                rollback_errors.append(f"host:{host['uuid']}")
        try:
            await client.update_node(snapshot["node"])
        except Exception:  # noqa: BLE001
            rollback_errors.append("node")
        state = "rollback_failed" if rollback_errors else "rolled_back"
        store.update(
            operation_id,
            state=state,
            result={"error": str(error), "rollbackErrors": rollback_errors},
        )
        if rollback_errors:
            raise OperationError("Ошибка применения; автоматический откат завершён не полностью") from error
        raise OperationError("Изменение не прошло проверку и было автоматически отменено") from error


def ssh_preflight(payload: dict[str, Any]) -> dict[str, Any]:
    return preflight(credentials_from_payload(payload))


async def create_node_plan(
    client: RemnawaveClient,
    store: AuditStore,
    actor: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    inventory = normalize_inventory(await client.inventory())
    node = body.get("node") if isinstance(body.get("node"), dict) else {}
    host = body.get("host") if isinstance(body.get("host"), dict) else {}
    name = str(node.get("name") or "").strip()
    address = str(node.get("address") or "").strip()
    country = str(node.get("countryCode") or "XX").upper()
    profile_uuid = str(node.get("profileUuid") or "")
    inbound_uuids = node.get("inboundUuids") if isinstance(node.get("inboundUuids"), list) else []
    try:
        node_port = int(node.get("port") or 2222)
        host_port = int(host.get("port") or 443)
    except (TypeError, ValueError) as error:
        raise OperationError("Некорректный порт") from error
    if not 3 <= len(name) <= 30 or not address or len(country) != 2:
        raise OperationError("Заполните имя, адрес и страну ноды")
    if not 1 <= node_port <= 65535 or not 1 <= host_port <= 65535:
        raise OperationError("Порт должен быть от 1 до 65535")
    profile = next((item for item in inventory["profiles"] if item["uuid"] == profile_uuid), None)
    if not profile:
        raise OperationError("Профиль конфигурации не найден")
    if not inbound_uuids:
        raise OperationError("Выберите хотя бы один inbound")
    valid_inbounds = {str(item.get("uuid")) for item in profile.get("inbounds", [])}
    if any(str(item) not in valid_inbounds for item in inbound_uuids):
        raise OperationError("Один из inbound не принадлежит выбранному профилю")
    target_squads = host.get("squadUuids") if isinstance(host.get("squadUuids"), list) else []
    valid_squads = {str(item["uuid"]) for item in inventory["squads"]}
    if bool(host.get("enabled", True)) and (
        not target_squads or any(str(item) not in valid_squads for item in target_squads)
    ):
        raise OperationError("Выберите хотя бы один существующий сквад для хоста")
    excluded_squads = [item["uuid"] for item in inventory["squads"] if item["uuid"] not in target_squads]
    host_enabled = bool(host.get("enabled", True))
    host_inbound_uuid = str(host.get("inboundUuid") or inbound_uuids[0])
    if host_enabled and host_inbound_uuid not in valid_inbounds:
        raise OperationError("Inbound хоста не принадлежит выбранному профилю")
    plan = {
        "node": {
            "name": name,
            "address": address,
            "port": node_port,
            "countryCode": country,
            "profileUuid": profile_uuid,
            "profileName": profile.get("name"),
            "inboundUuids": inbound_uuids,
        },
        "host": {
            "enabled": host_enabled,
            "remark": str(host.get("remark") or name).strip()[:40],
            "address": str(host.get("address") or address).strip(),
            "port": host_port,
            "inboundUuid": host_inbound_uuid,
            "squadUuids": target_squads,
            "excludedSquadUuids": excluded_squads,
            "sni": str(host.get("sni") or "").strip() or None,
            "fingerprint": str(host.get("fingerprint") or "").strip() or None,
        },
        "impact": {"nodes": 1, "hosts": 1 if host_enabled else 0, "profiles": 1},
    }
    operation_id = store.create("node-add", actor, name, plan)
    return {"operationId": operation_id, **plan}


async def apply_node_add(
    client: RemnawaveClient,
    store: AuditStore,
    settings: Settings,
    actor: str,
    operation_id: str,
    confirmation: str,
    ssh_payload: dict[str, Any],
    expected_fingerprint: str,
) -> dict[str, Any]:
    operation = store.get(operation_id)
    if not operation or operation["operation_type"] != "node-add":
        raise OperationError("План добавления ноды не найден")
    if operation["state"] != "planned" or operation["actor_fingerprint"] != actor:
        raise OperationError("Этот план уже выполнен или создан другой сессией")
    _not_expired(operation, settings.plan_ttl_seconds)
    plan = operation["plan"]
    if confirmation.strip() != plan["node"]["name"]:
        raise OperationError("Для подтверждения введите точное имя ноды")
    credentials = credentials_from_payload(ssh_payload)
    secret_key = await client.secret_key()
    store.update(operation_id, state="applying")
    remote_installed = False
    node_uuid = None
    host_uuid = None
    try:
        install_result = await asyncio.to_thread(
            install_node,
            credentials,
            expected_fingerprint=expected_fingerprint,
            node_port=plan["node"]["port"],
            secret_key=secret_key,
            node_image=settings.node_image,
            panel_ip=settings.panel_ip,
        )
        remote_installed = True
        created_node = await client.create_node(
            {
                "name": plan["node"]["name"],
                "address": plan["node"]["address"],
                "port": plan["node"]["port"],
                "countryCode": plan["node"]["countryCode"],
                "isTrafficTrackingActive": True,
                "configProfile": {
                    "activeConfigProfileUuid": plan["node"]["profileUuid"],
                    "activeInbounds": plan["node"]["inboundUuids"],
                },
                "note": "Добавлено через HAMVPN Infrastructure",
            }
        )
        node_uuid = created_node.get("uuid")
        if not node_uuid:
            raise OperationError("Панель не вернула UUID созданной ноды")
        if plan["host"]["enabled"]:
            host_body: dict[str, Any] = {
                "inbound": {
                    "configProfileUuid": plan["node"]["profileUuid"],
                    "configProfileInboundUuid": plan["host"]["inboundUuid"],
                },
                "remark": plan["host"]["remark"],
                "address": plan["host"]["address"],
                "port": plan["host"]["port"],
                "nodes": [node_uuid],
                "excludedInternalSquads": plan["host"]["excludedSquadUuids"],
                "isDisabled": False,
            }
            if plan["host"]["sni"]:
                host_body["sni"] = plan["host"]["sni"]
            if plan["host"]["fingerprint"]:
                host_body["fingerprint"] = plan["host"]["fingerprint"]
            created_host = await client.create_host(host_body)
            host_uuid = created_host.get("uuid")
        await tcp_check(
            plan["node"]["address"], plan["node"]["port"], settings.connect_timeout_seconds
        )
        result = {
            "verified": True,
            "nodeUuid": node_uuid,
            "hostUuid": host_uuid,
            "remote": install_result,
        }
        store.update(operation_id, state="completed", result=result)
        return result
    except Exception as error:
        rollback_errors = []
        if host_uuid:
            try:
                await client.delete_host(host_uuid)
            except Exception:  # noqa: BLE001
                rollback_errors.append("host")
        if node_uuid:
            try:
                await client.delete_node(node_uuid)
            except Exception:  # noqa: BLE001
                rollback_errors.append("node")
        if remote_installed:
            try:
                await asyncio.to_thread(
                    rollback_install,
                    credentials,
                    expected_fingerprint,
                    plan["node"]["port"],
                )
            except Exception:  # noqa: BLE001
                rollback_errors.append("remote")
        state = "rollback_failed" if rollback_errors else "rolled_back"
        store.update(operation_id, state=state, result={"error": str(error), "rollbackErrors": rollback_errors})
        if rollback_errors:
            raise OperationError("Добавление ноды завершилось ошибкой; откат неполный") from error
        raise OperationError("Добавление ноды не прошло проверку и было отменено") from error
