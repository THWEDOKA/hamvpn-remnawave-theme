from __future__ import annotations

import asyncio
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from .gconfig_model import (
    digest,
    fresh_config,
    ids,
    public_ip,
    relay_candidate,
    template,
)
from .inventory import normalize_inventory
from .operations import OperationError, _not_expired
from .probes import subscription_wires, verify_wires
from .remnawave import RemnawaveError
from .rollback import projection
from .ssh import check_xray, credentials_from_payload, install_node, rollback_install


def find(items: list, identifier: str) -> dict:
    matches = [item for item in items if item.get("uuid") == identifier]
    if len(matches) != 1:
        raise OperationError("Объект панели отсутствует или неоднозначен")
    return matches[0]


async def connected(client, node_uuid: str) -> None:
    for _ in range(30):
        node = await client.request("GET", f"/api/nodes/{node_uuid}")
        if node.get("isConnected") and not node.get("isDisabled"):
            return
        await asyncio.sleep(2)
    raise OperationError("Нода не подключилась к панели за 60 секунд")


def action(collection: str, identifier: str, before: dict, after: dict) -> dict:
    return {
        "resource": collection,
        "uuid": identifier,
        "read": f"/api/{collection}/{identifier}",
        "write": f"/api/{collection}/",
        "before": projection(before, before),
        "after": projection(after, after),
    }


async def create_plan(client, store, actor: str, body: dict) -> dict:
    inventory = normalize_inventory(await client.inventory())
    profile = template(inventory)
    if body.get("selfSteal") != "no":
        raise OperationError(
            "Этот пресет использует внешний target G-CONFIG. Выберите «Без self-steal»; свой сайт требует отдельной настройки"
        )
    name = str(body.get("name", "")).strip()
    address = public_ip(str(body.get("address", "")).strip())
    country = str(body.get("countryCode", "")).upper()
    if (
        not 3 <= len(name) <= 24
        or not re.fullmatch(r"[A-Z]{2}", country)
        or country == "RU"
    ):
        raise OperationError("Укажите имя (3–24 символа) и код страны зарубежной ноды")
    if any(
        n["address"] == address or n["name"] == name for n in inventory["nodes"]
    ) or any(h["remark"] == name for h in inventory["hosts"]):
        raise OperationError("Нода с таким адресом или именем уже есть в панели")
    squads = body.get("squadUuids")
    if (
        not isinstance(squads, list)
        or not squads
        or any(s not in ids(inventory["squads"]) for s in squads)
    ):
        raise OperationError("Выберите сквады, которым будет доступна новая нода")
    reality = profile["config"]["inbounds"][0]["streamSettings"]["realitySettings"]
    target = str(reality.get("target") or reality.get("dest"))
    if target.startswith(("127.", "localhost", "[::1]", "/")):
        raise OperationError(
            "G-CONFIG с локальным target нельзя переносить без self-steal"
        )
    sni = (
        "google.com"
        if "google.com" in reality["serverNames"]
        else reality["serverNames"][0]
    )
    plan = {
        "name": name,
        "address": address,
        "countryCode": country,
        "squadUuids": sorted(set(squads)),
        "profileUuid": profile["uuid"],
        "templateHash": digest(profile["config"]),
        "sni": sni,
        "fingerprint": "firefox",
        "minClientVer": "1.8.2",
        "selfSteal": "no",
        "impact": {"nodes": 1, "hosts": 1, "profiles": 1},
    }
    identifier = store.create("gconfig-install", actor, name, plan)
    return {"operationId": identifier, **plan}


class CreationUncertain(OperationError):
    pass


async def create_owned(client, collection: str, body: dict, unique: str) -> dict:
    try:
        return await client.request("POST", f"/api/{collection}/", body)
    except Exception:  # noqa: BLE001
        # Reconcile a lost POST response by the unique operation name; never retry creation.
        if collection == "users":
            try:
                return await client.request(
                    "GET", f"/api/users/by-username/{body['username']}"
                )
            except Exception:  # noqa: BLE001
                raise CreationUncertain(
                    "Не подтверждено создание тестового пользователя"
                ) from None
        try:
            value = await client.request("GET", f"/api/{collection}/")
        except Exception:  # noqa: BLE001
            raise CreationUncertain("Не подтверждено создание объекта") from None
        if isinstance(value, dict):
            value = value.get(
                {
                    "config-profiles": "configProfiles",
                    "internal-squads": "internalSquads",
                    "users": "users",
                }.get(collection, "items"),
                [],
            )
        found = [v for v in value if v.get(unique) == body[unique]]
        if len(found) == 1:
            return found[0]
        raise CreationUncertain(
            "Ответ на создание объекта не подтверждён; повторная установка остановлена"
        ) from None


async def probe_user(client, suffix: str, squad_uuid: str) -> dict:
    return await create_owned(
        client,
        "users",
        {
            "username": "infra_probe_" + suffix,
            "expireAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "trafficLimitBytes": 100_000_000,
            "trafficLimitStrategy": "NO_RESET",
            "status": "ACTIVE",
            "activeInternalSquads": [squad_uuid],
            "description": "Temporary Infrastructure verification",
        },
        "username",
    )


async def delete(client, collection: str, identifier: str | None, errors: list) -> None:
    if identifier:
        try:
            await client.request("DELETE", f"/api/{collection}/{identifier}")
        except RemnawaveError as error:
            if error.status_code != 404:
                errors.append(collection)
        except Exception:  # noqa: BLE001
            errors.append(collection)


async def install(client, store, settings, rollbacks, actor: str, body: dict) -> dict:
    identifier = str(body.get("operationId", ""))
    operation = store.get(identifier)
    if not operation or operation["operation_type"] != "gconfig-install":
        raise OperationError("План установки не найден")
    _not_expired(operation, settings.plan_ttl_seconds)
    plan = operation["plan"]
    credentials = credentials_from_payload(body.get("ssh") or {})
    fingerprint = str(body.get("expectedFingerprint") or "")
    if (
        credentials.host != plan["address"]
        or not fingerprint
        or body.get("confirmation") != plan["name"]
    ):
        raise OperationError(
            "SSH-проверка и подтверждение должны относиться к выбранному серверу"
        )
    inventory = normalize_inventory(await client.inventory())
    profile = template(inventory)
    if (
        profile["uuid"] != plan["profileUuid"]
        or digest(profile["config"]) != plan["templateHash"]
    ):
        raise OperationError("G-CONFIG изменился после планирования; обновите план")
    if any(
        n["address"] == plan["address"] or n["name"] == plan["name"]
        for n in inventory["nodes"]
    ) or any(h["remark"] == plan["name"] for h in inventory["hosts"]):
        raise OperationError("Сервер уже зарегистрирован в панели")
    if not store.claim(identifier, actor):
        raise OperationError("План уже запущен или принадлежит другой сессии")
    suffix = identifier.replace("-", "")[:12]
    config = fresh_config(profile, suffix)
    node_id = profile_id = host_id = squad_id = user_id = inbound_id = None
    remote_installed = False
    remote_hash = None
    changed_squads = []

    def checkpoint(stage: str) -> None:
        store.update(
            identifier,
            state="applying",
            result={
                "stage": stage,
                "created": {
                    "profileUuid": profile_id,
                    "nodeUuid": node_id,
                    "hostUuid": host_id,
                    "probeSquadUuid": squad_id,
                    "probeUserUuid": user_id,
                },
            },
        )

    try:
        checkpoint("Установка Remnawave Node")
        key = await client.secret_key()
        installed = await asyncio.to_thread(
            install_node,
            credentials,
            expected_fingerprint=fingerprint,
            node_port=2222,
            secret_key=key,
            node_image=settings.node_image,
            panel_ip=settings.panel_ip,
        )
        remote_hash = installed["composeHash"]
        remote_installed = True
        await asyncio.to_thread(
            check_xray, credentials, fingerprint, config, identifier, 443
        )
        created = await create_owned(
            client, "config-profiles", {"name": "G-" + suffix, "config": config}, "name"
        )
        profile_id = created["uuid"]
        checkpoint("Создан отдельный профиль")
        created = await client.request("GET", f"/api/config-profiles/{profile_id}")
        if created["config"] != config:
            raise OperationError("Панель изменила созданный профиль")
        inbound_id = find(created["inbounds"], created["inbounds"][0]["uuid"])["uuid"]
        node = await create_owned(
            client,
            "nodes",
            {
                "name": plan["name"],
                "address": plan["address"],
                "port": 2222,
                "countryCode": plan["countryCode"],
                "isTrafficTrackingActive": True,
                "configProfile": {
                    "activeConfigProfileUuid": profile_id,
                    "activeInbounds": [inbound_id],
                },
                "note": "HAM Infrastructure G-CONFIG " + identifier,
            },
            "name",
        )
        node_id = node["uuid"]
        checkpoint("Нода зарегистрирована")
        squad = await create_owned(
            client,
            "internal-squads",
            {"name": "INFRA-" + suffix, "inbounds": [inbound_id]},
            "name",
        )
        squad_id = squad["uuid"]
        checkpoint("Созданы тестовые права")
        fresh = normalize_inventory(await client.inventory())
        host = await create_owned(
            client,
            "hosts",
            {
                "remark": plan["name"],
                "address": plan["address"],
                "port": 443,
                "sni": plan["sni"],
                "fingerprint": "firefox",
                "isDisabled": False,
                "nodes": [node_id],
                "inbound": {
                    "configProfileUuid": profile_id,
                    "configProfileInboundUuid": inbound_id,
                },
                "excludedInternalSquads": [
                    s["uuid"] for s in fresh["squads"] if s["uuid"] != squad_id
                ],
            },
            "remark",
        )
        host_id = host["uuid"]
        checkpoint("Хост доступен только тестовому скваду")
        user = await probe_user(client, suffix, squad_id)
        user_id = user["uuid"]
        checkpoint("Проверка Xray и mihomo")
        await connected(client, node_id)
        wires = await subscription_wires(
            client, user_id, plan["name"], plan["address"], 443
        )
        proof = await verify_wires(wires, plan["address"])
        publish_actions = []
        for squad_uuid in plan["squadUuids"]:
            squad = await client.request("GET", f"/api/internal-squads/{squad_uuid}")
            before = ids(squad.get("inbounds", []))
            if inbound_id not in before:
                publish_actions.append(
                    action(
                        "internal-squads",
                        squad_uuid,
                        {"inbounds": sorted(before)},
                        {"inbounds": sorted([*before, inbound_id])},
                    )
                )
        fresh = normalize_inventory(await client.inventory())
        current_host = await client.request("GET", f"/api/hosts/{host_id}")
        publish_actions.append(
            action(
                "hosts",
                host_id,
                {
                    "excludedInternalSquads": sorted(
                        ids(current_host.get("excludedInternalSquads", []))
                    )
                },
                {
                    "excludedInternalSquads": sorted(
                        s["uuid"]
                        for s in fresh["squads"]
                        if s["uuid"] not in [*plan["squadUuids"], squad_id]
                    )
                },
            )
        )
        rollbacks.arm(identifier, client.token, publish_actions)
        checkpoint("Публикация в выбранных сквадах")
        for change in publish_actions:
            current = await client.request("GET", change["read"])
            if projection(current, change["before"]) != change["before"]:
                raise OperationError("Права сквада изменены во время публикации")
            await client.request(
                "PATCH", change["write"], {"uuid": change["uuid"], **change["after"]}
            )
            readback = await client.request("GET", change["read"])
            if projection(readback, change["after"]) != change["after"]:
                raise OperationError(
                    "Права хоста или сквада не прошли проверку после записи"
                )
            if change["resource"] == "internal-squads":
                changed_squads.append(change["uuid"])
        final = await client.request("GET", f"/api/hosts/{host_id}")
        if (
            final["address"] != plan["address"]
            or final["fingerprint"] != "firefox"
            or final.get("isDisabled")
            or final["inbound"]["configProfileInboundUuid"] != inbound_id
        ):
            raise OperationError("Не подтверждены итоговые параметры хоста")
        wires = await subscription_wires(
            client, user_id, plan["name"], plan["address"], 443
        )
        proof = await verify_wires(wires, plan["address"])
        cleanup_errors = []
        await delete(client, "users", user_id, cleanup_errors)
        await delete(client, "internal-squads", squad_id, cleanup_errors)
        if cleanup_errors:
            raise OperationError("Не удалены временные тестовые объекты")
        user_id = squad_id = None
        record = {
            "id": identifier,
            "name": plan["name"],
            "nodeUuid": node_id,
            "hostUuid": host_id,
            "profileUuid": profile_id,
            "inboundUuid": inbound_id,
            "address": plan["address"],
            "mode": "direct",
            "route": None,
            "lastProof": proof,
            "squadUuids": plan["squadUuids"],
            "verifiedAt": datetime.now(timezone.utc).isoformat(),
        }
        store.save_node(identifier, record)
        rollbacks.disarm(identifier)
        store.update(
            identifier,
            state="completed",
            result={"verified": True, "nodeUuid": node_id, "proof": proof},
        )
        return record
    except Exception as error:  # noqa: BLE001
        errors = ["unconfirmed-create"] if isinstance(error, CreationUncertain) else []
        if rollbacks._path(identifier).exists():
            errors.extend(await rollbacks.restore(identifier))
        if errors:
            store.update(
                identifier,
                state="rollback_failed",
                result={
                    **store.get(identifier)["result"],
                    "rollbackErrors": errors,
                    "warning": "Автоматическое удаление остановлено: состояние изменилось или не подтверждено",
                },
            )
            raise OperationError(
                "Установка остановлена. Созданные объекты требуют сверки; автоматическое удаление не выполнялось"
            ) from None
        await delete(client, "hosts", host_id, errors)
        for squad_uuid in changed_squads:
            try:
                squad = await client.request(
                    "GET", f"/api/internal-squads/{squad_uuid}"
                )
                await client.update_squad(
                    {
                        "uuid": squad_uuid,
                        "inbounds": [
                            i for i in ids(squad.get("inbounds", [])) if i != inbound_id
                        ],
                    }
                )
            except Exception:  # noqa: BLE001
                errors.append("squad-access")
        await delete(client, "users", user_id, errors)
        user_id = None
        await delete(client, "internal-squads", squad_id, errors)
        squad_id = None
        await delete(client, "nodes", node_id, errors)
        await delete(client, "config-profiles", profile_id, errors)
        if remote_installed:
            try:
                await asyncio.to_thread(
                    rollback_install, credentials, fingerprint, 2222, remote_hash
                )
            except Exception:  # noqa: BLE001
                errors.append("remote")
        if not errors:
            rollbacks.disarm(identifier)
        store.update(
            identifier,
            state="rollback_failed" if errors else "rolled_back",
            result={
                "rollbackErrors": errors,
                "warning": "Установка не прошла проверку",
            },
        )
        raise OperationError(
            "Установка не прошла проверку. "
            + (
                "Откат неполный: проверьте журнал"
                if errors
                else "Созданные объекты удалены"
            )
        ) from None
    finally:
        cleanup_errors = []
        await delete(client, "users", user_id, cleanup_errors)
        await delete(client, "internal-squads", squad_id, cleanup_errors)
        if cleanup_errors:
            store.update(
                identifier,
                state="cleanup_failed",
                result={
                    "warning": "Не удалось удалить временные тестовые объекты",
                    "rollbackErrors": cleanup_errors,
                },
            )


async def managed_state(client, store, identifier: str) -> tuple[dict, dict, dict]:
    record = store.node(identifier)
    if not record:
        raise OperationError("Выберите ноду, установленную через G-CONFIG")
    node = await client.request("GET", f"/api/nodes/{record['nodeUuid']}")
    host = await client.request("GET", f"/api/hosts/{record['hostUuid']}")
    profile = await client.request(
        "GET", f"/api/config-profiles/{record['profileUuid']}"
    )
    if (
        node["address"] != record["address"]
        or node["configProfile"]["activeConfigProfileUuid"] != record["profileUuid"]
        or ids(host.get("nodes", [])) != [record["nodeUuid"]]
        or host["inbound"]["configProfileInboundUuid"] != record["inboundUuid"]
        or host.get("fingerprint") != "firefox"
        or host.get("isDisabled")
    ):
        raise OperationError(
            "Параметры управляемой ноды изменены вне мастера; требуется сверка"
        )
    incoming = profile["config"].get("inbounds", [])
    if (
        len(incoming) != 1
        or incoming[0]
        .get("streamSettings", {})
        .get("realitySettings", {})
        .get("minClientVer")
        != "1.8.2"
    ):
        raise OperationError(
            "Не подтверждена настройка совместимости REALITY в профиле"
        )
    if (host["address"], host["port"]) == (record["address"], 443):
        record["mode"] = "direct"
    elif record.get("route") and (host["address"], host["port"]) == (
        record["route"]["address"],
        record["route"]["port"],
    ):
        record["mode"] = "ru"
    else:
        raise OperationError(
            "Адрес хоста изменён вне мастера; автоматическое переключение остановлено"
        )
    return record, host, profile


@asynccontextmanager
async def test_identity(client, record: dict):
    suffix = uuid.uuid4().hex[:12]
    squad_id = user_id = None
    try:
        squad = await create_owned(
            client,
            "internal-squads",
            {"name": "INFRA-" + suffix, "inbounds": [record["inboundUuid"]]},
            "name",
        )
        squad_id = squad["uuid"]
        user = await probe_user(client, suffix, squad_id)
        user_id = user["uuid"]
        yield user_id
    finally:
        errors = []
        await delete(client, "users", user_id, errors)
        await delete(client, "internal-squads", squad_id, errors)
        if errors:
            raise OperationError(
                "Не удалось удалить временные объекты проверки; операция не завершена"
            )


async def prepare_route(
    client, store, settings, rollbacks, actor: str, body: dict
) -> dict:
    record, host, _ = await managed_state(client, store, str(body.get("id", "")))
    if record["mode"] != "direct" or record.get("route"):
        raise OperationError(
            "Для этой ноды уже подготовлен маршрут. Используйте переключение туда/обратно"
        )
    inventory = normalize_inventory(await client.inventory())
    entry = find(inventory["nodes"], str(body.get("entryUuid", "")))
    if entry["countryCode"] != "RU" or entry["isDisabled"] or not entry["isConnected"]:
        raise OperationError("Выберите подключённый российский вход")
    profile = find(inventory["profiles"], entry["profileUuid"])
    if [
        n["uuid"] for n in inventory["nodes"] if n["profileUuid"] == profile["uuid"]
    ] != [entry["uuid"]]:
        raise OperationError(
            "Российский вход использует общий профиль. Подготовьте для него отдельный профиль, чтобы не менять соседние ноды"
        )
    address = public_ip(entry["address"])
    if address == record["address"]:
        raise OperationError("Вход и выход должны быть разными серверами")
    credentials = credentials_from_payload(body.get("ssh") or {})
    fingerprint = str(body.get("expectedFingerprint") or "")
    if credentials.host != address or not fingerprint:
        raise OperationError("Проверьте SSH именно выбранного российского входа")
    port = body.get("port")
    tag = "ham-relay-" + record["id"].replace("-", "")[:12]
    config = relay_candidate(
        profile["config"], tag=tag, port=port, exit_ip=record["address"]
    )
    operation_id = store.create(
        "gconfig-route-prepare",
        actor,
        record["name"],
        {
            "managedId": record["id"],
            "entryUuid": entry["uuid"],
            "entryName": entry["name"],
            "port": port,
            "impact": {"nodes": 1, "profiles": 1},
        },
    )
    store.claim(operation_id, actor)
    try:
        await asyncio.to_thread(
            check_xray, credentials, fingerprint, config, operation_id, port
        )
        async with test_identity(client, record) as user_id:
            wires = await subscription_wires(
                client, user_id, host["remark"], host["address"], host["port"]
            )
            current = await client.request(
                "GET", f"/api/config-profiles/{profile['uuid']}"
            )
            if current["config"] != profile["config"]:
                raise OperationError("Профиль входа изменён во время подготовки")
            rollbacks.arm(
                operation_id,
                client.token,
                [
                    action(
                        "config-profiles",
                        profile["uuid"],
                        {"config": profile["config"]},
                        {"config": config},
                    )
                ],
            )
            await client.update_profile({"uuid": profile["uuid"], "config": config})
            readback = await client.request(
                "GET", f"/api/config-profiles/{profile['uuid']}"
            )
            if readback["config"] != config:
                raise OperationError("Профиль входа не прошёл проверку после записи")
            # Inbounds without users are retained by Remnawave independently of activeInbounds.
            await client.restart_node(entry["uuid"])
            await connected(client, entry["uuid"])
            proof = await verify_wires(wires, record["address"], (address, port))
            current_host = await client.request(
                "GET", f"/api/hosts/{record['hostUuid']}"
            )
            if projection(
                current_host, {"address": None, "port": None, "inbound": None}
            ) != projection(host, {"address": None, "port": None, "inbound": None}):
                raise OperationError("Хост изменён во время подготовки")
        record["route"] = {
            "entryUuid": entry["uuid"],
            "entryName": entry["name"],
            "address": address,
            "port": port,
            "profileUuid": profile["uuid"],
            "tag": tag,
            "inbound": config["inbounds"][-1],
            "rule": config["routing"]["rules"][0],
        }
        record["lastProof"] = proof
        record["verifiedAt"] = datetime.now(timezone.utc).isoformat()
        store.save_node(record["id"], record)
        rollbacks.disarm(operation_id)
        store.update(
            operation_id, state="completed", result={"verified": True, "proof": proof}
        )
        return public_record(record)
    except Exception:  # noqa: BLE001
        errors = (
            await rollbacks.restore(operation_id)
            if rollbacks._path(operation_id).exists()
            else []
        )
        store.update(
            operation_id,
            state="rollback_failed" if errors else "rolled_back",
            result={
                "rollbackErrors": errors,
                "warning": "Пара серверов не прошла подготовку и клиентские проверки",
            },
        )
        raise OperationError(
            "Маршрут через РФ не прошёл проверку; прямой хост не переключался. "
            + (
                "Откат неполный: проверьте журнал"
                if errors
                else "Изменения входа отменены"
            )
        ) from None


async def verify_route(client, record: dict) -> None:
    route = record.get("route")
    if not route:
        raise OperationError("Сначала подготовьте пару серверов")
    node = await client.request("GET", f"/api/nodes/{route['entryUuid']}")
    profile = await client.request(
        "GET", f"/api/config-profiles/{route['profileUuid']}"
    )
    if (
        node["address"] != route["address"]
        or node.get("isDisabled")
        or not node.get("isConnected")
        or node["configProfile"]["activeConfigProfileUuid"] != route["profileUuid"]
        or route["inbound"] not in profile["config"].get("inbounds", [])
        or route["rule"] not in profile["config"].get("routing", {}).get("rules", [])
    ):
        raise OperationError(
            "Подготовленный российский маршрут изменён; требуется сверка"
        )
    rules = profile["config"]["routing"]["rules"]
    preceding = rules[: rules.index(route["rule"])]
    if any(
        not r.get("inboundTag") or route["tag"] in r["inboundTag"] for r in preceding
    ):
        raise OperationError(
            "Правила перед российским маршрутом изменились; требуется сверка"
        )


async def switch_route(client, store, rollbacks, actor: str, body: dict) -> dict:
    record, host, _ = await managed_state(client, store, str(body.get("id", "")))
    mode = body.get("mode")
    if mode not in ("direct", "ru") or mode == record["mode"]:
        raise OperationError("Выберите другой режим подключения")
    if mode == "ru":
        await verify_route(client, record)
    address, port = (
        (record["address"], 443)
        if mode == "direct"
        else (record["route"]["address"], record["route"]["port"])
    )
    operation_id = store.create(
        "gconfig-route-switch",
        actor,
        record["name"],
        {"managedId": record["id"], "mode": mode, "impact": {"hosts": 1}},
    )
    store.claim(operation_id, actor)
    before = {"address": host["address"], "port": host["port"]}
    after = {"address": address, "port": port}
    try:
        async with test_identity(client, record) as user_id:
            wires = await subscription_wires(
                client, user_id, host["remark"], host["address"], host["port"]
            )
            await verify_wires(wires, record["address"], (address, port))
            fresh = await client.request("GET", f"/api/hosts/{record['hostUuid']}")
            if (
                projection(fresh, before) != before
                or fresh["inbound"] != host["inbound"]
            ):
                raise OperationError(
                    "Хост изменён другим действием; переключение отменено"
                )
            rollbacks.arm(
                operation_id,
                client.token,
                [action("hosts", record["hostUuid"], before, after)],
            )
            await client.update_host({"uuid": record["hostUuid"], **after})
            fresh = await client.request("GET", f"/api/hosts/{record['hostUuid']}")
            if projection(fresh, after) != after:
                raise OperationError("Адрес хоста не прошёл проверку после записи")
            wires = await subscription_wires(
                client, user_id, host["remark"], address, port
            )
            proof = await verify_wires(wires, record["address"])
        record["mode"] = mode
        record["lastProof"] = proof
        record["verifiedAt"] = datetime.now(timezone.utc).isoformat()
        store.save_node(record["id"], record)
        rollbacks.disarm(operation_id)
        store.update(
            operation_id, state="completed", result={"verified": True, "proof": proof}
        )
        return public_record(record)
    except Exception:  # noqa: BLE001
        errors = (
            await rollbacks.restore(operation_id)
            if rollbacks._path(operation_id).exists()
            else []
        )
        store.update(
            operation_id,
            state="rollback_failed" if errors else "rolled_back",
            result={
                "rollbackErrors": errors,
                "warning": "Новый маршрут не прошёл клиентские проверки",
            },
        )
        raise OperationError(
            "Переключение не прошло проверку. "
            + (
                "Откат неполный: проверьте журнал"
                if errors
                else "Прежний адрес хоста восстановлен"
            )
        ) from None


def public_record(record: dict) -> dict:
    result = {
        k: record[k]
        for k in (
            "id",
            "name",
            "nodeUuid",
            "address",
            "mode",
            "lastProof",
            "verifiedAt",
        )
    }
    route = record.get("route")
    result["route"] = (
        {k: route[k] for k in ("entryUuid", "entryName", "address", "port")}
        if route
        else None
    )
    return result
