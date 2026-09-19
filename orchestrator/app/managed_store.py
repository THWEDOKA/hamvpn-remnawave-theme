from __future__ import annotations

import json

from .audit import AuditStore, _json, _now


class ManagedStore(AuditStore):
    def _init(self) -> None:
        super()._init()
        with self.connection() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS managed_nodes (id TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )

    def save_node(self, identifier: str, value: dict) -> None:
        with self.connection() as db:
            db.execute(
                "INSERT INTO managed_nodes VALUES (?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
                (identifier, _json(value)),
            )

    def node(self, identifier: str) -> dict | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT value FROM managed_nodes WHERE id=?", (identifier,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def nodes(self) -> list[dict]:
        with self.connection() as db:
            rows = db.execute("SELECT value FROM managed_nodes ORDER BY id").fetchall()
        return [json.loads(row[0]) for row in rows]

    def claim(self, identifier: str, actor: str) -> bool:
        with self.connection() as db:
            result = db.execute(
                "UPDATE operations SET state='applying', updated_at=? "
                "WHERE id=? AND actor_fingerprint=? AND state='planned'",
                (_now(), identifier, actor),
            )
        return result.rowcount == 1
