"""Build and deploy a verified archive without replacing production configuration."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
REVISION = (ROOT / ".revision").read_text().strip()
assert len(REVISION) == 40 and all(c in "0123456789abcdef" for c in REVISION)
STATE = Path("/root/ham-infra-release-" + REVISION[:12])
STATE.mkdir(mode=0o700, exist_ok=True)
os.umask(0o077)
COMPOSE = ["docker", "compose", "--project-directory", "/opt/remnawave", "-f", "/opt/remnawave/docker-compose.yml",
           "-f", "/opt/hamvpn-remnawave-theme/deploy/docker-compose.theme.yml"]
IMAGES = {"remnawave": "hamvpn/remnawave", "remnawave-hamvpn-infrastructure-1": "hamvpn/remnawave-infrastructure"}
ALIASES = {"remnawave": "hamvpn/remnawave:2-default-infra", "remnawave-hamvpn-infrastructure-1": "hamvpn/remnawave-infrastructure:1"}
TIMER = "ham-infra-rollback-" + REVISION[:12]


def run(*args, timeout=120):
    return subprocess.check_output(args, timeout=timeout, stderr=subprocess.DEVNULL).decode().strip()


def inspect(name):
    return json.loads(run("docker", "inspect", name))[0]


def save(name, value):
    path = STATE / (name + ".json")
    with path.open("x") as file:
        json.dump(value, file)
        file.flush()
        os.fsync(file.fileno())


def load(name):
    return json.loads((STATE / (name + ".json")).read_text())


def api():
    path = ROOT / "ops/selfsteal-us3/panel_api.py"
    spec = importlib.util.spec_from_file_location("release_api", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_client()[0]


def inventory_hash():
    call = api()
    nodes = call("GET", "/api/nodes/")
    hosts = call("GET", "/api/hosts/")
    profiles = call("GET", "/api/config-profiles/")["configProfiles"]
    state = {
        "nodes": [{k: n.get(k) for k in ("uuid", "name", "address", "port", "configProfile", "isDisabled")} for n in nodes],
        "hosts": [{k: v for k, v in h.items() if k not in ("updatedAt", "createdAt")} for h in hosts],
        "profiles": [{"uuid": p["uuid"], "config": call("GET", "/api/config-profiles/" + p["uuid"])["config"]} for p in profiles],
    }
    for rows in state.values():
        rows.sort(key=lambda row: row["uuid"])
    return {"sha256": hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest(),
            "nodes": len(nodes), "hosts": len(hosts), "profiles": len(profiles)}


def build():
    with (STATE / "build.log").open("w") as log:
        for context, image in ((str(ROOT), IMAGES["remnawave"]), (str(ROOT / "orchestrator"), IMAGES["remnawave-hamvpn-infrastructure-1"])):
            subprocess.run(["docker", "build", "--pull=false", "--build-arg", "VCS_REF=" + REVISION,
                            "-t", image + ":gconfig-" + REVISION[:12], context], check=True, stdout=log, stderr=log, timeout=1800)
    results = {}
    for name, image in IMAGES.items():
        tag = image + ":gconfig-" + REVISION[:12]
        data = json.loads(run("docker", "image", "inspect", tag))[0]
        assert data["Config"]["Labels"]["org.opencontainers.image.revision"] == REVISION
        results[name] = data["Id"]
    image = IMAGES["remnawave-hamvpn-infrastructure-1"] + ":gconfig-" + REVISION[:12]
    for core in ("xray", "mihomo"):
        run("docker", "run", "--rm", "--network", "none", "--entrypoint", core, image, "version" if core == "xray" else "-v")
    save("built", results)
    return {"built": True, "revision": REVISION}


def deploy():
    built = load("built")
    assert not (STATE / "before.json").exists(), "Deployment already started; inspect status"
    database = Path("/opt/hamvpn-infrastructure/infrastructure.sqlite3")
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT count(*) FROM operations WHERE state='applying'").fetchone()[0] == 0
        with sqlite3.connect(STATE / "infrastructure-before.sqlite3") as backup:
            db.backup(backup)
    leases = Path("/opt/hamvpn-infrastructure/rollback-leases")
    assert not leases.exists() or not list(leases.glob("*.lease")), "Outstanding rollback lease"
    before = {"images": {name: inspect(name)["Image"] for name in IMAGES}, "inventory": inventory_hash(),
              "configHashes": {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in (COMPOSE[5], COMPOSE[7])}}
    save("before", before)
    for name, image in before["images"].items():
        run("docker", "tag", image, IMAGES[name] + ":before-gconfig-" + REVISION[:12])
    run("systemd-run", "--unit=" + TIMER, "--on-active=10m", "/usr/bin/python3", str(Path(__file__).resolve()), "rollback")
    for name, image in built.items():
        run("docker", "tag", image, ALIASES[name])
    run(*COMPOSE, "up", "-d", "--no-deps", "remnawave", "hamvpn-infrastructure", timeout=180)
    for _ in range(60):
        if all(inspect(name)["State"].get("Health", {}).get("Status") == "healthy" for name in IMAGES):
            break
        time.sleep(2)
    else:
        raise RuntimeError("New containers are not healthy")
    return verify()


def verify():
    before, built = load("before"), load("built")
    assert all(inspect(name)["Image"] == image and inspect(name)["State"]["Health"]["Status"] == "healthy" for name, image in built.items())
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in before["configHashes"].items())
    current = inventory_hash()
    assert current == before["inventory"], "Production VPN objects changed"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:8090/ham-infrastructure/healthz", timeout=5) as response:
        assert json.load(response) == {"status": "ok"}
    try:
        opener.open("http://127.0.0.1:8090/ham-infrastructure/api/gconfig", timeout=5)
    except urllib.error.HTTPError as error:
        assert error.code == 401
    else:
        raise RuntimeError("G-CONFIG endpoint must require authentication")
    if not (STATE / "verified.json").exists():
        save("verified", {"revision": REVISION, "inventory": current})
    return {"healthy": True, "authenticatedApi": True, "vpnInventoryUnchanged": current, "revision": REVISION}


def finalize():
    result = verify()
    run("systemctl", "stop", TIMER + ".timer")
    # An already-running rollback must not be masked by stopping its service.
    state = run("systemctl", "show", TIMER + ".service", "-p", "ActiveState", "--value")
    assert state == "inactive" and not (STATE / "rollback.json").exists()
    assert run("systemctl", "show", TIMER + ".timer", "-p", "ActiveState", "--value") == "inactive"
    verify()
    return {**result, "rollbackTimer": "inactive"}


def rollback():
    before, built = load("before"), load("built")
    for name, image in before["images"].items():
        assert inspect(name)["Image"] in (image, built[name]), "Another release owns the container"
        run("docker", "tag", image, ALIASES[name])
    run(*COMPOSE, "up", "-d", "--no-deps", "remnawave", "hamvpn-infrastructure", timeout=180)
    save("rollback", {"restoredImages": before["images"]})
    return {"rolledBack": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("build", "deploy", "verify", "finalize", "rollback"))
    args = parser.parse_args()
    try:
        print(json.dumps(globals()[args.phase]()))
    except Exception as error:
        print(json.dumps({"failed": args.phase, "errorType": type(error).__name__}))
        raise SystemExit(1) from None
