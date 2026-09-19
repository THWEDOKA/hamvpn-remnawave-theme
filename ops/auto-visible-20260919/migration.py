import argparse
import base64
import fcntl
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from model import digest, plan, rebind_managed, require

ROOT = Path(__file__).resolve().parent
STATE = Path("/root/ham-auto-visible-20260919")
TIMER = "ham-auto-visible-rollback"
IMAGE = "hamvpn/remnawave-infrastructure:gconfig-18d59413f4aa"
HEADERS = {
    "X-Hwid": "ham-autovisible-owned-probe",
    "X-Device-Os": "Linux",
    "X-Device-Model": "Auto pool verification",
}


def save(name, value):
    temp = STATE / (name + ".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(STATE / (name + ".json"))


def read(name):
    return json.loads((STATE / (name + ".json")).read_text())


def exists(name):
    return (STATE / (name + ".json")).exists()


def run(*args, payload=None, timeout=60):
    result = subprocess.run(
        args, input=payload, capture_output=True, timeout=timeout, check=False
    )
    require(result.returncode == 0, "Command failed: " + args[0])
    return result.stdout


def api_client():
    spec = importlib.util.spec_from_file_location(
        "panel_api", ROOT.parent / "selfsteal-us3/panel_api.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_client()[0]


def yaml_json(encoded):
    return native({"action": "yaml", "yaml": base64.b64decode(encoded).decode()})


def native(payload):
    return json.loads(
        run(
            "docker",
            "exec",
            "-i",
            "remnawave",
            "node",
            "-e",
            (ROOT / "render.cjs").read_text(),
            payload=json.dumps(payload).encode(),
        )
    )


def inventory(api):
    templates = [
        api("GET", "/api/subscription-templates/" + t["uuid"])
        for t in api("GET", "/api/subscription-templates")["templates"]
    ]
    nodes = api("GET", "/api/nodes/")
    profiles = api("GET", "/api/config-profiles/")["configProfiles"]
    protected = {
        "nodes": [
            {
                k: n.get(k)
                for k in ("uuid", "address", "port", "configProfile", "isDisabled")
            }
            for n in nodes
        ],
        "profiles": [
            {
                "uuid": p["uuid"],
                "config": api("GET", "/api/config-profiles/" + p["uuid"])["config"],
            }
            for p in profiles
        ],
        "squads": [
            {k: s.get(k) for k in ("uuid", "name", "inbounds")}
            for s in api("GET", "/api/internal-squads/")["internalSquads"]
        ],
    }
    for rows in protected.values():
        rows.sort(key=lambda row: row["uuid"])
    return {
        "hosts": api("GET", "/api/hosts/"),
        "templates": templates,
        "protected": protected,
    }


def stable(host):
    return {
        k: v
        for k, v in host.items()
        if k not in ("viewPosition", "createdAt", "updatedAt")
    }


def prepare(api):
    require(not exists("before"), "Existing operation: inspect saved state")
    before = inventory(api)
    mt = next(
        t
        for t in before["templates"]
        if t["name"] == "Default" and t["templateType"] == "MIHOMO"
    )
    candidate = plan(
        before["hosts"], before["templates"], yaml_json(mt["encodedTemplateYaml"])
    )
    with sqlite3.connect(
        "file:/opt/hamvpn-infrastructure/infrastructure.sqlite3?mode=ro", uri=True
    ) as db:
        records = [
            json.loads(row[0]) for row in db.execute("SELECT value FROM managed_nodes")
        ]
    before["managed"] = records
    candidate["managedAfter"] = rebind_managed(
        records, candidate["pairs"], candidate["hiddenIds"]
    )
    candidate["sha256"] = digest({k: v for k, v in candidate.items() if k != "sha256"})
    save("before", before)
    save("plan", candidate)
    db = json.loads(run("docker", "inspect", "remnawave-db"))[0]
    env = dict(v.split("=", 1) for v in db["Config"]["Env"] if "=" in v)
    with (STATE / "database-before.dump").open("xb") as backup:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "remnawave-db",
                "pg_dump",
                "-U",
                env.get("POSTGRES_USER", "postgres"),
                "-d",
                env.get("POSTGRES_DB", "postgres"),
                "-Fc",
            ],
            stdout=backup,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
    require(
        result.returncode == 0 and (STATE / "database-before.dump").stat().st_size > 0,
        "Database backup failed",
    )
    return {
        "hidden": len(candidate["hiddenIds"]),
        "pairs": len(candidate["pairs"]),
        "unpaired": len(candidate["unmatched"]),
        "visibleBaseCandidates": len(candidate["poolNames"]),
        "backup": True,
    }


def assert_state(api, phase):
    now, before, candidate = inventory(api), read("before"), read("plan")
    with sqlite3.connect(
        "file:/opt/hamvpn-infrastructure/infrastructure.sqlite3?mode=ro", uri=True
    ) as db:
        managed = [
            json.loads(row[0]) for row in db.execute("SELECT value FROM managed_nodes")
        ]
    expected_managed = (
        candidate["managedAfter"] if phase == "deleted" else before["managed"]
    )
    require(
        {r["id"]: r for r in managed} == {r["id"]: r for r in expected_managed},
        "Route switcher registry changed",
    )
    require(
        digest(now["protected"]) == digest(before["protected"]),
        "Node/profile/squad drift",
    )
    expected = before["hosts"] if phase == "before" else candidate["hostsAfter"]
    if phase == "deleted":
        expected = [h for h in expected if not h["isHidden"]]
    require(
        {h["uuid"]: stable(h) for h in now["hosts"]}
        == {h["uuid"]: stable(h) for h in expected},
        "Host state differs from planned delta",
    )
    before_order = [h["uuid"] for h in before["hosts"] if not h["isHidden"]]
    require(
        [h["uuid"] for h in now["hosts"] if not h["isHidden"]] == before_order,
        "Visible host order changed",
    )
    patches = (
        {t["uuid"]: t for t in candidate["templates"]} if phase != "before" else {}
    )

    def meaningful(t):
        return {k: v for k, v in t.items() if k not in ("createdAt", "updatedAt")}

    require(
        {t["uuid"]: meaningful(t) for t in now["templates"]}
        == {
            t["uuid"]: meaningful({**t, **patches.get(t["uuid"], {})})
            for t in before["templates"]
        },
        "Template drift",
    )
    return now


def probe_user(api):
    if not exists("probe-intent"):
        identifier = str(uuid.uuid4())
        save(
            "probe-intent",
            {
                "uuid": identifier,
                "username": "avprobe_" + identifier.replace("-", "")[:16],
            },
        )
        intent = read("probe-intent")
        api(
            "POST",
            "/api/users/",
            {
                **intent,
                "expireAt": (
                    datetime.now(timezone.utc) + timedelta(hours=2)
                ).isoformat(),
                "trafficLimitBytes": 300_000_000,
                "trafficLimitStrategy": "NO_RESET",
                "status": "ACTIVE",
                "hwidDeviceLimit": 1,
                "activeInternalSquads": [],
                "description": "Temporary visible auto pool verification",
            },
        )
    intent = read("probe-intent")
    user = api("GET", "/api/users/" + intent["uuid"])
    require(user["username"] == intent["username"], "Probe ownership changed")
    return user


def exports(api, user):
    url = api("GET", "/api/subscriptions/by-uuid/" + user["uuid"])["subscriptionUrl"]
    result = {}
    for name, agent in (("xray", "Happ/5.7.0"), ("mihomo", "mihomo/1.19.24")):
        request = urllib.request.Request(url, headers={**HEADERS, "User-Agent": agent})
        with urllib.request.urlopen(request, timeout=30) as response:
            require(response.status == 200, "Subscription HTTP failure")
            data = response.read(4_000_001)
            require(len(data) <= 4_000_000, "Subscription too large")
        result[name] = (
            json.loads(data)
            if name == "xray"
            else yaml_json(base64.b64encode(data).decode())
        )
    original = urllib.request.Request

    def with_headers(*args, **kwargs):
        request = original(*args, **kwargs)
        if "/raw?" in request.full_url:
            for key, value in {**HEADERS, "User-Agent": "Happ/5.7.0"}.items():
                request.add_header(key, value)
        return request

    urllib.request.Request = with_headers
    try:
        raw = api(
            "GET",
            "/api/subscriptions/by-short-uuid/"
            + user["shortUuid"]
            + "/raw?withDisabledHosts=false",
        )
    finally:
        urllib.request.Request = original
    result["raw"] = raw["resolvedProxyConfigs"]
    require(
        isinstance(result["xray"], list)
        and isinstance(result["mihomo"].get("proxies"), list),
        "Client export is a placeholder",
    )
    return result


def expected_export(raw):
    before, candidate = read("before"), read("plan")
    patches = {t["uuid"]: t for t in candidate["templates"]}
    templates = [{**t, **patches.get(t["uuid"], {})} for t in before["templates"]]
    default = next(
        t["templateJson"]
        for t in templates
        if t["name"] == "Default" and t["templateType"] == "XRAY_JSON"
    )
    return native(
        {
            "hosts": deepcopy(raw),
            "catalog": candidate["hostsAfter"],
            "templates": templates,
            "defaultXray": default,
            "mihomo": candidate["mihomoAfter"],
        }
    )


def wire(outbound):
    return {k: v for k, v in outbound.items() if k != "tag"}


def validate_exports(actual, expected, baseline):
    receivers = {
        h["remark"]
        for h in read("before")["hosts"]
        if h.get("xrayJsonTemplateUuid") and not h["isHidden"]
    }
    ordinary = lambda configs: {
        c["remarks"]: c.get("outbounds", [])
        for c in configs
        if c.get("remarks") not in receivers
    }
    require(
        ordinary(actual["xray"]) == ordinary(baseline["xray"]),
        "Ordinary Xray connections changed",
    )
    require(
        ordinary(actual["xray"]) == ordinary(expected["xray"]),
        "Xray rights differ from resolved visible hosts",
    )
    for want in expected["xray"]:
        if want.get("remarks") not in receivers:
            continue
        got = [c for c in actual["xray"] if c.get("remarks") == want["remarks"]]
        require(
            len(got) == 1
            and got[0]["routing"] == want["routing"]
            and got[0]["outbounds"] == want["outbounds"],
            "Actual Xray auto pool differs",
        )
        require(
            any(
                o.get("tag", "").startswith(("basepool", "whitepool"))
                for o in got[0]["outbounds"]
            ),
            "Visible auto tile has no candidates",
        )
    require(
        actual["mihomo"] == expected["mihomo"],
        "Actual Mihomo export differs from native generator",
    )
    old = {p["name"]: p for p in baseline["mihomo"]["proxies"]}
    require(
        all(old.get(p["name"]) == p for p in actual["mihomo"]["proxies"]),
        "Ordinary Mihomo connections changed",
    )


def measure(expected):
    receivers = {
        h["remark"]
        for h in read("before")["hosts"]
        if h.get("xrayJsonTemplateUuid") and not h["isHidden"]
    }
    autos = [
        c
        for c in expected["xray"]
        if c.get("remarks") in receivers
        and any(o.get("tag", "").startswith("basepool") for o in c.get("outbounds", []))
    ]
    require(
        len(autos) == 1 and expected["memberNames"],
        "BASE must have one nonempty auto config",
    )
    payload = {
        "xray": autos[0],
        "mihomo": expected["mihomo"],
        "members": expected["memberNames"],
    }
    result = run(
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "host",
        "--mount",
        f"type=bind,src={ROOT / 'measure.py'},dst=/tmp/measure.py,readonly",
        "--entrypoint",
        "python",
        IMAGE,
        "/tmp/measure.py",
        payload=json.dumps(payload).encode(),
        timeout=240,
    )
    return json.loads(result)


def probe(api, published=False):
    assert_state(api, "staged" if published else "before")
    user = probe_user(api)
    squads = {s["name"]: s["uuid"] for s in read("before")["protected"]["squads"]}
    results = []
    for names in (["BASE"], ["WHITE"], ["OLD"], ["TEST"], ["BASE", "WHITE"]):
        key = "-".join(names).lower()
        api(
            "PATCH",
            "/api/users/",
            {"uuid": user["uuid"], "activeInternalSquads": [squads[n] for n in names]},
        )
        actual = exports(api, user)
        expected = expected_export(actual["raw"])
        if not published:
            save("baseline-" + key, actual)
            # Candidate rendering must preserve every ordinary client connection.
            validate_exports(expected, expected, actual)
        else:
            validate_exports(actual, expected, read("baseline-" + key))
        result = {
            "cohort": key,
            "visibleCandidates": len(expected["memberNames"]),
            "structural": True,
        }
        if names == ["BASE"]:
            result["network"] = measure(
                expected
                if not published
                else {**expected, "xray": actual["xray"], "mihomo": actual["mihomo"]}
            )
        results.append(result)
        save(("public" if published else "candidate") + "-progress", results)
    save(
        "public-proof" if published else "candidate-proof",
        {"time": time.time(), "plan": read("plan")["sha256"], "results": results},
    )
    return {"published": published, "cohorts": results}


def apply(api):
    require(not exists("applied") and not exists("rollback"), "Existing mutation state")
    proof = read("candidate-proof")
    require(
        time.time() - proof["time"] < 900 and proof["plan"] == read("plan")["sha256"],
        "Candidate proof expired",
    )
    assert_state(api, "before")
    run(
        "systemd-run",
        "--unit=" + TIMER,
        "--on-active=20m",
        "/usr/bin/python3",
        str(Path(__file__).resolve()),
        "rollback",
    )
    save("apply-intent", {"time": time.time()})
    candidate = read("plan")
    for identifier, tags in candidate["hostTags"].items():
        api("PATCH", "/api/hosts/", {"uuid": identifier, "tags": tags})
    for patch in candidate["templates"]:
        api("PATCH", "/api/subscription-templates/", patch)
    for identifier in candidate["hiddenIds"]:
        api("PATCH", "/api/hosts/", {"uuid": identifier, "isDisabled": True})
    assert_state(api, "staged")
    save("applied", {"time": time.time()})
    return {"staged": True, "rollbackArmed": True}


def rollback(api):
    require(
        not exists("delete-intent"),
        "Deletion already finalized; use protected backup for manual recovery",
    )
    before, candidate = read("before"), read("plan")
    current = {h["uuid"]: h for h in api("GET", "/api/hosts/")}
    after = {h["uuid"]: h for h in candidate["hostsAfter"]}
    for old in before["hosts"]:
        now = current[old["uuid"]]
        require(
            stable(now) in (stable(old), stable(after[old["uuid"]])),
            "Host edited by another operation",
        )
    patches = {t["uuid"]: t for t in candidate["templates"]}
    for old in before["templates"]:
        if old["uuid"] not in patches:
            continue
        keys = set(patches[old["uuid"]]) - {"uuid"}
        now = api("GET", "/api/subscription-templates/" + old["uuid"])
        require(
            all(now[k] in (old[k], patches[old["uuid"]][k]) for k in keys),
            "Template edited by another operation",
        )
        api(
            "PATCH",
            "/api/subscription-templates/",
            {"uuid": old["uuid"], **{k: old[k] for k in keys}},
        )
    for old in before["hosts"]:
        if (
            old["uuid"] in candidate["hostTags"]
            or old["uuid"] in candidate["hiddenIds"]
        ):
            api(
                "PATCH",
                "/api/hosts/",
                {
                    "uuid": old["uuid"],
                    "tags": old["tags"],
                    "isDisabled": old["isDisabled"],
                },
            )
    assert_state(api, "before")
    save("rollback", {"restored": True})
    return {"restored": True}


def finalize(api):
    proof = read("public-proof")
    require(
        time.time() - proof["time"] < 900 and proof["plan"] == read("plan")["sha256"],
        "Public proof expired",
    )
    require(
        time.time() - read("apply-intent")["time"] < 1100 and not exists("rollback"),
        "Rollback deadline elapsed",
    )
    assert_state(api, "staged")
    run("systemctl", "stop", TIMER + ".timer")
    require(
        run(
            "systemctl", "show", TIMER + ".service", "-p", "ActiveState", "--value"
        ).strip()
        == b"inactive",
        "Rollback already running",
    )
    save("delete-intent", {"time": time.time(), "ids": read("plan")["hiddenIds"]})
    with sqlite3.connect("/opt/hamvpn-infrastructure/infrastructure.sqlite3") as db:
        db.execute("BEGIN IMMEDIATE")
        require(
            db.execute(
                "SELECT count(*) FROM operations WHERE state='applying'"
            ).fetchone()[0]
            == 0,
            "An infrastructure operation is running",
        )
        rows = {
            identifier: value
            for identifier, value in db.execute("SELECT id,value FROM managed_nodes")
        }
        require(
            {i: json.loads(v) for i, v in rows.items()}
            == {r["id"]: r for r in read("before")["managed"]},
            "Managed registry changed before finalization",
        )
        for record in read("plan")["managedAfter"]:
            db.execute(
                "UPDATE managed_nodes SET value=? WHERE id=?",
                (json.dumps(record, ensure_ascii=False), record["id"]),
            )
    for identifier in read("plan")["hiddenIds"]:
        api("DELETE", "/api/hosts/" + identifier)
    assert_state(api, "deleted")
    # A fresh public export must also be valid after permanent record cleanup.
    user = probe_user(api)
    base = next(
        s["uuid"] for s in read("before")["protected"]["squads"] if s["name"] == "BASE"
    )
    api("PATCH", "/api/users/", {"uuid": user["uuid"], "activeInternalSquads": [base]})
    actual = exports(api, user)
    validate_exports(actual, expected_export(actual["raw"]), read("baseline-base"))
    api("DELETE", "/api/users/" + user["uuid"])
    try:
        api("GET", "/api/users/" + user["uuid"])
    except RuntimeError as error:
        require("HTTP 404" in str(error), "Probe deletion not verified")
    else:
        raise RuntimeError("Probe still exists")
    save(
        "finished",
        {
            "time": time.time(),
            "deletedHiddenHosts": len(read("plan")["hiddenIds"]),
            "visibleHosts": len(actual["mihomo"]["proxies"]),
            "probeDeleted": True,
            "rollbackTimer": "inactive",
        },
    )
    return read("finished")


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=[
            "prepare",
            "candidate",
            "apply",
            "public",
            "finalize",
            "rollback",
            "verify",
        ],
    )
    args = parser.parse_args()
    with (STATE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        api = api_client()
        if args.action == "candidate":
            result = probe(api)
        elif args.action == "public":
            result = probe(api, True)
        elif args.action == "verify":
            assert_state(api, "deleted" if exists("finished") else "staged")
            result = {"stateVerified": True, "finished": exists("finished")}
        else:
            result = globals()[args.action](api)
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - Do not expose subscription or credential payloads.
        print(
            json.dumps(
                {
                    "failed": True,
                    "type": type(error).__name__,
                    "message": str(error)
                    if type(error) is RuntimeError
                    else "Private details suppressed",
                }
            )
        )
        sys.exit(1)
