import base64
import hashlib
import json
import re
from copy import deepcopy

TAGS = {"AUTO_BASE_POOL", "AUTO_WHITE_POOL"}
IGNORED = {
    "uuid",
    "remark",
    "isHidden",
    "tags",
    "viewPosition",
    "createdAt",
    "updatedAt",
    "serverDescription",
    "excludedInternalSquads",
}


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def exact_regex(names):
    require(names and len(set(names)) == len(names), "Empty or duplicate group names")
    return (
        "^("
        + "|".join(re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", n) for n in names)
        + ")$"
    )


def plan(hosts, templates, mihomo):
    visible = [h for h in hosts if not h["isHidden"]]
    hidden = [h for h in hosts if h["isHidden"]]
    require(hidden, "No hidden hosts to migrate")
    require(
        all(
            h["remark"].startswith(("ABP-", "AWP-"))
            or h["isDisabled"]
            and h.get("xrayJsonTemplateUuid")
            for h in hidden
        ),
        "Unrecognized hidden host",
    )
    changes, pairs, unmatched = {}, [], []
    for h in hidden:
        if h["isDisabled"]:
            continue
        pool = set(h["tags"]) & TAGS
        require(pool, "Hidden host has no reviewed pool tag")
        matches = [
            v
            for v in visible
            if not v["isDisabled"]
            and not v.get("xrayJsonTemplateUuid")
            and (v["address"], v["port"]) == (h["address"], h["port"])
        ]
        if not matches:
            unmatched.append(h["uuid"])
            continue
        require(len(matches) == 1, "Ambiguous visible counterpart")
        v = matches[0]
        require(
            all(v.get(k) == h.get(k) for k in (set(v) | set(h)) - IGNORED),
            "Counterpart changes connection settings",
        )
        tags = sorted(set(changes.get(v["uuid"], v["tags"])) | pool)
        require(len(tags) <= 10, "Tag limit exceeded")
        changes[v["uuid"]] = tags
        pairs.append({"hidden": h["uuid"], "visible": v["uuid"], "name": v["remark"]})
    after_hosts = deepcopy(hosts)
    for h in after_hosts:
        if h["uuid"] in changes:
            h["tags"] = changes[h["uuid"]]
        if h["isHidden"]:
            h["isDisabled"] = True
    template_changes = []
    for t in templates:
        injector = (t.get("templateJson") or {}).get("remnawave", {}).get("injectHosts")
        if not injector:
            continue
        require(
            t["name"] in ("Auto Base Pool", "Auto White Pool") and len(injector) == 1,
            "Unknown injection template",
        )
        require(
            injector[0]["selector"]
            == {
                "type": "tagRegex",
                "pattern": "^"
                + (
                    "AUTO_BASE_POOL"
                    if t["name"] == "Auto Base Pool"
                    else "AUTO_WHITE_POOL"
                )
                + "$",
            },
            "Unknown pool selector",
        )
        updated = deepcopy(t["templateJson"])
        updated["remnawave"]["injectHosts"][0]["selectFrom"] = "NOT_HIDDEN"
        template_changes.append({"uuid": t["uuid"], "templateJson": updated})
    require(len(template_changes) == 2, "Expected two automatic templates")
    mt = [
        t for t in templates if t["templateType"] == "MIHOMO" and t["name"] == "Default"
    ]
    require(len(mt) == 1, "Mihomo template ambiguous")
    require(len(mihomo["proxy-groups"]) == 2, "Mihomo layout changed")
    after_m = deepcopy(mihomo)
    main, auto = after_m["proxy-groups"]
    require(
        main["type"] == "select" and auto["type"] == "url-test", "Unexpected groups"
    )
    pool_names = [
        h["remark"]
        for h in after_hosts
        if not h["isHidden"]
        and not h["isDisabled"]
        and "AUTO_BASE_POOL" in h["tags"]
        and not h.get("xrayJsonTemplateUuid")
    ]
    receivers = [h["remark"] for h in visible if h.get("xrayJsonTemplateUuid")]
    after_m["remnawave"] = {"includeHiddenHosts": False}
    main["exclude-filter"] = exact_regex(receivers)
    auto["filter"] = exact_regex(pool_names)
    template_changes.append(
        {
            "uuid": mt[0]["uuid"],
            "encodedTemplateYaml": base64.b64encode(
                json.dumps(after_m, ensure_ascii=False).encode()
            ).decode(),
        }
    )
    result = {
        "hostTags": changes,
        "hiddenIds": [h["uuid"] for h in hidden],
        "unmatched": unmatched,
        "pairs": pairs,
        "templates": template_changes,
        "hostsAfter": after_hosts,
        "mihomoAfter": after_m,
        "poolNames": pool_names,
    }
    result["sha256"] = digest(result)
    return result
