from pathlib import Path

from orchestrator.app.audit import AuditStore


def test_audit_round_trip_without_credentials(tmp_path: Path):
    store = AuditStore(tmp_path)
    actor = store.actor("secret-session-token")
    operation_id = store.create(
        "ip-change",
        actor,
        "Germany-4",
        {"impact": {"nodes": 1}, "node": {"oldAddress": "192.0.2.10"}},
    )
    store.update(operation_id, state="completed", result={"verified": True})
    operation = store.get(operation_id)
    assert operation["actor_fingerprint"] == actor
    assert operation["state"] == "completed"
    assert operation["result"] == {"verified": True}
    content = (tmp_path / "infrastructure.sqlite3").read_bytes()
    assert b"secret-session-token" not in content

