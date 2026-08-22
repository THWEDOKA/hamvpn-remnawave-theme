from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from time import monotonic
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .audit import AuditStore
from .cloudflare import CloudflareClient, CloudflareConfigStore, CloudflareError
from .inventory import normalize_inventory
from .operations import (
    OperationError,
    apply_ip_change,
    apply_node_add,
    create_ip_plan,
    create_node_plan,
    ssh_preflight,
)
from .remnawave import RemnawaveClient, RemnawaveError
from .settings import settings
from .ssh import SshError

BASE = "/ham-infrastructure"
app = FastAPI(title="HAMVPN Infrastructure", docs_url=None, redoc_url=None, openapi_url=None)
store = AuditStore(settings.data_dir)
cloudflare_store = CloudflareConfigStore(settings.data_dir)
stored_cloudflare = cloudflare_store.load()
try:
    stored_cloudflare_ttl = int(stored_cloudflare.get("ttl") or settings.cloudflare_dns_ttl)
except (TypeError, ValueError):
    stored_cloudflare_ttl = settings.cloudflare_dns_ttl
cloudflare = CloudflareClient(
    str(stored_cloudflare.get("token") or settings.cloudflare_token),
    stored_cloudflare.get("zoneIds")
    if isinstance(stored_cloudflare.get("zoneIds"), dict)
    else settings.cloudflare_zone_ids,
    stored_cloudflare_ttl,
)
rate_buckets: dict[str, deque[float]] = defaultdict(deque)


def _token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Откройте раздел из авторизованной панели")
    token = authorization.removeprefix("Bearer ").strip()
    if len(token) < 20:
        raise HTTPException(status_code=401, detail="Некорректная сессия администратора")
    return token


async def context(authorization: str | None = Header(default=None)) -> tuple[str, str, RemnawaveClient]:
    token = _token(authorization)
    actor = store.actor(token)
    return token, actor, RemnawaveClient(settings.remnawave_url, token)


def mutation_guard(request: Request, actor: str, limit: int = 20) -> None:
    origin = request.headers.get("origin", "").rstrip("/")
    if origin != settings.trusted_origin:
        raise HTTPException(status_code=403, detail="Запрос отклонён защитой источника")
    now = monotonic()
    bucket = rate_buckets[actor]
    while bucket and bucket[0] < now - 300:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(status_code=429, detail="Слишком много операций. Подождите несколько минут")
    bucket.append(now)


@app.exception_handler(RemnawaveError)
async def remnawave_error(_: Request, error: RemnawaveError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=error.status_code)


@app.exception_handler(OperationError)
async def operation_error(_: Request, error: OperationError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=409)


@app.exception_handler(SshError)
async def ssh_error(_: Request, error: SshError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=422)


@app.exception_handler(CloudflareError)
async def cloudflare_error(_: Request, error: CloudflareError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=422)


@app.get(f"{BASE}/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get(f"{BASE}/api/inventory")
async def inventory(ctx: tuple[str, str, RemnawaveClient] = Depends(context)) -> dict[str, Any]:
    _, _, client = ctx
    result = normalize_inventory(await client.inventory())
    for profile in result["profiles"]:
        profile.pop("config", None)
    result["cloudflare"] = {
        "configured": cloudflare.configured,
        "zones": sorted(cloudflare.zone_ids),
    }
    return result


@app.post(f"{BASE}/api/cloudflare/config")
async def cloudflare_config(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor, 6)
    await client.validate()
    body = await request.json()
    token = str(body.get("token") or "").strip()
    zone_name = str(body.get("zone") or "").strip().rstrip(".").lower()
    if len(token) < 20:
        raise CloudflareError("Укажите действующий Cloudflare API-токен")
    candidate = CloudflareClient(token, ttl=settings.cloudflare_dns_ttl)
    zone_id = await candidate.verify_zone(zone_name)
    zone_ids = {zone_name: zone_id}
    cloudflare_store.save(token, zone_ids, candidate.ttl)
    cloudflare.configure(token, zone_ids, candidate.ttl)
    return {"configured": True, "zone": zone_name, "ttl": candidate.ttl}


@app.get(f"{BASE}/api/operations")
async def operations(ctx: tuple[str, str, RemnawaveClient] = Depends(context)) -> dict[str, Any]:
    _, _, client = ctx
    await client.validate()
    rows = store.recent(40)
    return {
        "operations": [
            {
                "id": item["id"],
                "type": item["operation_type"],
                "state": item["state"],
                "resource": item["resource_name"],
                "createdAt": item["created_at"],
                "updatedAt": item["updated_at"],
                "impact": item["plan"].get("impact", {}),
                "result": {
                    key: value
                    for key, value in item["result"].items()
                    if key
                    in {
                        "verified",
                        "warning",
                        "newAddress",
                        "rollbackErrors",
                        "dnsRecords",
                    }
                },
            }
            for item in rows
        ]
    }


@app.post(f"{BASE}/api/ip-change/plan")
async def ip_plan(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor)
    body = await request.json()
    return await create_ip_plan(
        client,
        store,
        actor,
        str(body.get("nodeUuid") or ""),
        str(body.get("newAddress") or ""),
        cloudflare,
    )


@app.post(f"{BASE}/api/ip-change/apply")
async def ip_apply(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor)
    body = await request.json()
    return await apply_ip_change(
        client,
        store,
        settings,
        actor,
        str(body.get("operationId") or ""),
        str(body.get("confirmation") or ""),
        cloudflare,
    )


@app.post(f"{BASE}/api/node-add/ssh-preflight")
async def node_ssh_preflight(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor, 10)
    await client.validate()
    body = await request.json()
    return await asyncio.to_thread(ssh_preflight, body.get("ssh") or {})


@app.post(f"{BASE}/api/node-add/plan")
async def node_plan(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor)
    return await create_node_plan(client, store, actor, await request.json())


@app.post(f"{BASE}/api/node-add/apply")
async def node_apply(
    request: Request,
    ctx: tuple[str, str, RemnawaveClient] = Depends(context),
) -> dict[str, Any]:
    _, actor, client = ctx
    mutation_guard(request, actor, 10)
    body = await request.json()
    return await apply_node_add(
        client,
        store,
        settings,
        actor,
        str(body.get("operationId") or ""),
        str(body.get("confirmation") or ""),
        body.get("ssh") if isinstance(body.get("ssh"), dict) else {},
        str(body.get("expectedFingerprint") or ""),
    )
