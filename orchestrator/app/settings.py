import os
from dataclasses import dataclass
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


def load_settings() -> Settings:
    return Settings(
        remnawave_url=os.getenv("REMNAWAVE_BASE_URL", "http://remnawave:3000").rstrip("/"),
        trusted_origin=os.getenv("TRUSTED_ORIGIN", "https://goszapravki.com").rstrip("/"),
        data_dir=Path(os.getenv("INFRA_DATA_DIR", "/data")),
        panel_ip=os.getenv("PANEL_PUBLIC_IP", "").strip(),
        node_image=os.getenv("INFRA_NODE_IMAGE", "remnawave/node:latest").strip(),
        plan_ttl_seconds=int(os.getenv("PLAN_TTL_SECONDS", "900")),
        connect_timeout_seconds=float(os.getenv("CONNECT_TIMEOUT_SECONDS", "5")),
    )


settings = load_settings()

