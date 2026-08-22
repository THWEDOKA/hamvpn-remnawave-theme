import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    remnawave_url: str
    trusted_origin: str
    data_dir: Path
    panel_ip: str
    node_image: str
    plan_ttl_seconds: int
    connect_timeout_seconds: float
    cloudflare_token: str = ""
    cloudflare_zone_ids: dict[str, str] = field(default_factory=dict)
    cloudflare_dns_ttl: int = 60


def _cloudflare_zones() -> dict[str, str]:
    raw = os.getenv("CLOUDFLARE_ZONE_IDS", "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(value, dict):
        return {}
    return {
        str(name).strip().rstrip(".").lower(): str(zone_id).strip()
        for name, zone_id in value.items()
        if str(name).strip() and str(zone_id).strip()
    }


def load_settings() -> Settings:
    return Settings(
        remnawave_url=os.getenv("REMNAWAVE_BASE_URL", "http://remnawave:3000").rstrip("/"),
        trusted_origin=os.getenv("TRUSTED_ORIGIN", "https://goszapravki.com").rstrip("/"),
        data_dir=Path(os.getenv("INFRA_DATA_DIR", "/data")),
        panel_ip=os.getenv("PANEL_PUBLIC_IP", "").strip(),
        node_image=os.getenv("INFRA_NODE_IMAGE", "remnawave/node:latest").strip(),
        plan_ttl_seconds=int(os.getenv("PLAN_TTL_SECONDS", "900")),
        connect_timeout_seconds=float(os.getenv("CONNECT_TIMEOUT_SECONDS", "5")),
        cloudflare_token=os.getenv("CLOUDFLARE_API_TOKEN", "").strip(),
        cloudflare_zone_ids=_cloudflare_zones(),
        cloudflare_dns_ttl=int(os.getenv("CLOUDFLARE_DNS_TTL", "60")),
    )


settings = load_settings()
