from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import time
from dataclasses import dataclass
from io import StringIO
from typing import Any, Self

import paramiko


class SshError(RuntimeError):
    pass


@dataclass
class SshCredentials:
    host: str
    port: int
    username: str
    password: str | None = None
    private_key: str | None = None


def _load_private_key(value: str) -> paramiko.PKey:
    errors: list[Exception] = []
    for key_type in (
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
    ):
        try:
            return key_type.from_private_key(StringIO(value))
        except Exception as error:  # noqa: BLE001
            errors.append(error)
    raise SshError("Приватный SSH-ключ не распознан") from errors[-1]


class SshSession:
    def __init__(self, credentials: SshCredentials, expected_fingerprint: str | None = None):
        self.credentials = credentials
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect: dict[str, Any] = {
            "hostname": credentials.host,
            "port": credentials.port,
            "username": credentials.username,
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 12,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if credentials.private_key:
            connect["pkey"] = _load_private_key(credentials.private_key)
        elif credentials.password:
            connect["password"] = credentials.password
        else:
            raise SshError("Укажите пароль или приватный SSH-ключ")
        try:
            self.client.connect(**connect)
        except (paramiko.SSHException, OSError) as error:
            raise SshError("Не удалось подключиться к серверу по SSH") from error
        self.fingerprint = self._fingerprint()
        if expected_fingerprint and self.fingerprint != expected_fingerprint:
            self.close()
            raise SshError("SSH-ключ сервера изменился после предварительной проверки")

    def _fingerprint(self) -> str:
        transport = self.client.get_transport()
        if not transport:
            raise SshError("SSH-транспорт не установлен")
        digest = hashlib.sha256(transport.get_remote_server_key().asbytes()).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def run(self, command: str, timeout: int = 120, check: bool = True) -> str:
        try:
            _, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            code = stdout.channel.recv_exit_status()
            output = stdout.read(131072).decode("utf-8", "replace")
            error = stderr.read(131072).decode("utf-8", "replace")
        except (TimeoutError, paramiko.SSHException) as exception:
            raise SshError("SSH-команда не завершилась") from exception
        if check and code != 0:
            safe_error = " ".join(error.strip().split())[:500]
            raise SshError(safe_error or f"SSH-команда завершилась с кодом {code}")
        return output.strip()

    def upload(self, remote_path: str, content: str, mode: int = 0o600) -> None:
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, "w") as handle:
                handle.write(content)
            sftp.chmod(remote_path, mode)
            sftp.close()
        except (OSError, paramiko.SSHException) as error:
            raise SshError("Не удалось записать конфигурацию на сервер") from error


def credentials_from_payload(payload: dict[str, Any]) -> SshCredentials:
    host = str(payload.get("host") or "").strip()
    username = str(payload.get("username") or "root").strip()
    try:
        port = int(payload.get("port") or 22)
    except (TypeError, ValueError) as error:
        raise SshError("Некорректный SSH-порт") from error
    if not host or not username or not 1 <= port <= 65535:
        raise SshError("Некорректные параметры SSH")
    return SshCredentials(
        host=host,
        port=port,
        username=username,
        password=str(payload.get("password") or "") or None,
        private_key=str(payload.get("privateKey") or "") or None,
    )


def preflight(credentials: SshCredentials) -> dict[str, Any]:
    with SshSession(credentials) as session:
        identity = session.run("id -u && uname -s && uname -m && . /etc/os-release && printf '%s' \"$ID:$VERSION_ID\"")
        parts = identity.splitlines()
        if len(parts) < 4 or parts[0] != "0" or parts[1] != "Linux":
            raise SshError("Нужен Linux-сервер с root-доступом")
        distribution = parts[3]
        if not distribution.startswith(("ubuntu:", "debian:")):
            raise SshError("Автоустановка поддерживает Ubuntu и Debian")
        disk = session.run("df -Pk / | awk 'NR==2 {print $4}'")
        if int(disk or 0) < 2_000_000:
            raise SshError("На сервере меньше 2 ГБ свободного места")
        occupied = session.run("test -e /opt/remnanode/docker-compose.yml && echo yes || echo no")
        docker = session.run("command -v docker >/dev/null 2>&1 && docker --version || true", check=False)
        return {
            "fingerprint": session.fingerprint,
            "distribution": distribution,
            "architecture": parts[2],
            "docker": docker or "будет установлен",
            "existingNode": occupied == "yes",
            "freeDiskKb": int(disk or 0),
        }


def _compose(node_port: int, secret_key: str, node_image: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._/@:-]+", node_image):
        raise SshError("Некорректно настроен образ Remnawave Node")
    return f"""services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: {node_image}
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      NODE_PORT: {json.dumps(str(node_port))}
      SECRET_KEY: {json.dumps(secret_key)}
"""


def install_node(
    credentials: SshCredentials,
    *,
    expected_fingerprint: str,
    node_port: int,
    secret_key: str,
    node_image: str,
    panel_ip: str,
) -> dict[str, Any]:
    if not panel_ip:
        raise SshError("Не настроен публичный IP панели для файрвола")
    with SshSession(credentials, expected_fingerprint) as session:
        exists = session.run("test -e /opt/remnanode/docker-compose.yml && echo yes || echo no")
        if exists == "yes":
            raise SshError("На сервере уже есть /opt/remnanode; автоматическая перезапись запрещена")
        panel = shlex.quote(panel_ip)
        port = shlex.quote(str(node_port))
        try:
            session.run(
                "command -v docker >/dev/null 2>&1 || "
                "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io iptables ca-certificates)"
            )
            session.run("systemctl enable --now docker")
            session.run(
                "docker compose version >/dev/null 2>&1 || "
                "(apt-get update && (DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 || "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin))"
            )
            session.run("install -d -m 700 /opt/remnanode")
            session.upload("/opt/remnanode/docker-compose.yml", _compose(node_port, secret_key, node_image))
            firewall = (
                "iptables -N HAMVPN_NODE 2>/dev/null || true; "
                "iptables -F HAMVPN_NODE; "
                f"iptables -A HAMVPN_NODE -s {panel} -j ACCEPT; "
                "iptables -A HAMVPN_NODE -j DROP; "
                f"iptables -C INPUT -p tcp --dport {port} -j HAMVPN_NODE 2>/dev/null || "
                f"iptables -I INPUT 1 -p tcp --dport {port} -j HAMVPN_NODE; "
                "if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save; "
                "elif test -d /etc/iptables; then iptables-save > /etc/iptables/rules.v4; fi"
            )
            session.run(firewall)
            session.run("cd /opt/remnanode && docker compose pull && docker compose up -d", timeout=300)
            deadline = time.monotonic() + 45
            running = ""
            while time.monotonic() < deadline:
                running = session.run("docker inspect -f '{{.State.Running}}' remnanode 2>/dev/null || true", check=False)
                if running == "true":
                    break
                time.sleep(2)
            if running != "true":
                raise SshError("Контейнер Remnawave Node не запустился")
            image_id = session.run("docker inspect -f '{{.Image}}' remnanode")
            session.run("chmod 600 /opt/remnanode/docker-compose.yml")
            return {"fingerprint": session.fingerprint, "imageId": image_id, "container": "running"}
        except Exception:
            session.run("cd /opt/remnanode && docker compose down 2>/dev/null || true", check=False)
            session.run(f"iptables -D INPUT -p tcp --dport {port} -j HAMVPN_NODE 2>/dev/null || true", check=False)
            session.run("iptables -F HAMVPN_NODE 2>/dev/null || true; iptables -X HAMVPN_NODE 2>/dev/null || true", check=False)
            session.run("rm -f /opt/remnanode/docker-compose.yml; rmdir /opt/remnanode 2>/dev/null || true", check=False)
            raise


def rollback_install(credentials: SshCredentials, expected_fingerprint: str, node_port: int) -> None:
    with SshSession(credentials, expected_fingerprint) as session:
        port = shlex.quote(str(node_port))
        session.run("cd /opt/remnanode && docker compose down || true", check=False)
        session.run(f"iptables -D INPUT -p tcp --dport {port} -j HAMVPN_NODE 2>/dev/null || true", check=False)
        session.run("iptables -F HAMVPN_NODE 2>/dev/null || true; iptables -X HAMVPN_NODE 2>/dev/null || true", check=False)
        session.run("rm -f /opt/remnanode/docker-compose.yml; rmdir /opt/remnanode 2>/dev/null || true", check=False)
