"""Short-lived encrypted rollback leases survive API process/container restarts."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from cryptography.fernet import Fernet

from .gconfig_model import ids
from .remnawave import RemnawaveClient


def projection(value: dict, fields: dict) -> dict:
    result = {k: value.get(k) for k in fields}
    if result.get("configProfile"):
        binding = result["configProfile"]
        result["configProfile"] = {
            "activeConfigProfileUuid": binding["activeConfigProfileUuid"],
            "activeInbounds": sorted(ids(binding.get("activeInbounds", []))),
        }
    for key in ("inbounds", "excludedInternalSquads"):
        if key in result:
            result[key] = sorted(ids(result[key] or []))
    return result


class Rollbacks:
    def __init__(self, directory: Path, base_url: str):
        self.directory = directory / "rollback-leases"
        self.directory.mkdir(mode=0o700, exist_ok=True)
        key_path = self.directory / "key"
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as file:
                file.write(Fernet.generate_key())
        self.cipher = Fernet(key_path.read_bytes())
        self.base_url = base_url
        self.lock = asyncio.Lock()

    def _path(self, identifier: str) -> Path:
        from uuid import UUID

        return self.directory / (str(UUID(identifier)) + ".lease")

    def read(self, identifier: str) -> dict:
        return json.loads(self.cipher.decrypt(self._path(identifier).read_bytes()))

    def write(self, identifier: str, value: dict) -> None:
        path = self._path(identifier)
        temporary = path.with_suffix(".tmp")
        with temporary.open("wb") as handle:
            os.chmod(temporary, 0o600)
            handle.write(self.cipher.encrypt(json.dumps(value).encode()))
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    def arm(
        self, identifier: str, token: str, actions: list[dict], seconds: int = 600
    ) -> None:
        import base64

        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        if claims.get("exp", 0) < time.time() + seconds + 180:
            raise RuntimeError("Session expires before rollback window")
        if self._path(identifier).exists():
            raise RuntimeError("Rollback lease already exists")
        self.write(
            identifier,
            {"token": token, "deadline": time.time() + seconds, "actions": actions},
        )

    def disarm(self, identifier: str) -> None:
        self._path(identifier).unlink(missing_ok=True)

    async def restore(self, identifier: str) -> list[str]:
        lease = self.read(identifier)
        client = RemnawaveClient(self.base_url, lease["token"])
        errors = []
        for action in reversed(lease["actions"]):
            try:
                current = await client.request("GET", action["read"])
                if projection(current, action["before"]) == action["before"]:
                    continue
                if projection(current, action["after"]) != action["after"]:
                    errors.append("drift:" + action["resource"])
                    continue
                await client.request(
                    "PATCH",
                    action["write"],
                    {"uuid": action["uuid"], **action["before"]},
                )
                current = await client.request("GET", action["read"])
                if projection(current, action["before"]) != action["before"]:
                    errors.append("readback:" + action["resource"])
            except Exception:  # noqa: BLE001
                errors.append("unavailable:" + action["resource"])
        if errors:
            lease["deadline"] = time.time() + 60
            lease["failures"] = lease.get("failures", 0) + 1
            self.write(identifier, lease)
        else:
            self.disarm(identifier)
        return errors

    async def watch(self, store) -> None:
        while True:
            async with self.lock:
                for path in self.directory.glob("*.lease"):
                    try:
                        lease = self.read(path.stem)
                        if (
                            lease["deadline"] > time.time()
                            or lease.get("failures", 0) >= 3
                        ):
                            continue
                        errors = await self.restore(path.stem)
                        store.update(
                            path.stem,
                            state="rollback_failed" if errors else "rolled_back",
                            result={
                                "rollbackErrors": errors,
                                "warning": "Истекло окно проверки операции",
                            },
                        )
                    except Exception:  # noqa: BLE001
                        store.update(
                            path.stem,
                            state="rollback_failed",
                            result={
                                "warning": "Не удалось прочитать или исполнить автоматический откат"
                            },
                        )
            await asyncio.sleep(5)
