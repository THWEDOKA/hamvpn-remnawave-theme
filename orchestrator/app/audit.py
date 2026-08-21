from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class AuditStore:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "infrastructure.sqlite3"
        self._init()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init(self) -> None:
        with self.connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY,
                    operation_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    actor_fingerprint TEXT NOT NULL,
                    resource_name TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL DEFAULT '{}',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS operations_created_at ON operations(created_at DESC)"
            )
        self.path.chmod(0o600)

    @staticmethod
    def actor(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    def create(
        self,
        operation_type: str,
        actor: str,
        resource_name: str,
        plan: dict[str, Any],
        state: str = "planned",
    ) -> str:
        operation_id = str(uuid.uuid4())
        now = _now()
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO operations (
                    id, operation_type, state, actor_fingerprint, resource_name,
                    plan_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (operation_id, operation_type, state, actor, resource_name, _json(plan), now, now),
            )
        return operation_id

    def get(self, operation_id: str) -> dict[str, Any] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM operations WHERE id = ?", (operation_id,)
            ).fetchone()
        return self._decode(row) if row else None

    def update(
        self,
        operation_id: str,
        *,
        state: str,
        snapshot: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        values: list[Any] = [state]
        fields = ["state = ?"]
        if snapshot is not None:
            fields.append("snapshot_json = ?")
            values.append(_json(snapshot))
        if result is not None:
            fields.append("result_json = ?")
            values.append(_json(result))
        fields.append("updated_at = ?")
        values.append(_now())
        values.append(operation_id)
        with self.connection() as connection:
            connection.execute(
                f"UPDATE operations SET {', '.join(fields)} WHERE id = ?", values
            )

    def recent(self, limit: int = 40) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM operations ORDER BY created_at DESC LIMIT ?", (safe_limit,)
            ).fetchall()
        return [self._decode(row) for row in rows]

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["plan"] = json.loads(value.pop("plan_json"))
        value["snapshot"] = json.loads(value.pop("snapshot_json"))
        value["result"] = json.loads(value.pop("result_json"))
        return value
