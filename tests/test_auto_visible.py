import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "auto_visible", Path(__file__).parents[1] / "ops/auto-visible-20260919/model.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def source():
    host = {
        "uuid": "main",
        "remark": "Node (1)+",
        "isHidden": False,
        "isDisabled": False,
        "tags": ["OTHER"],
        "address": "8.8.8.8",
        "port": 443,
        "excludedInternalSquads": ["premium"],
        "fingerprint": "firefox",
    }
    hidden = {
        **host,
        "uuid": "hidden",
        "remark": "ABP-1",
        "isHidden": True,
        "tags": ["AUTO_BASE_POOL"],
        "excludedInternalSquads": [],
    }
    receiver = {
        **host,
        "uuid": "auto",
        "remark": "AUTO",
        "xrayJsonTemplateUuid": "base",
    }
    templates = [
        {
            "uuid": name,
            "name": "Auto " + label + " Pool",
            "templateType": "XRAY_JSON",
            "templateJson": {
                "remnawave": {
                    "injectHosts": [
                        {
                            "selector": {
                                "type": "tagRegex",
                                "pattern": "^AUTO_" + label.upper() + "_POOL$",
                            },
                            "selectFrom": "ALL",
                            "tagPrefix": label.lower(),
                        }
                    ]
                },
                "routing": {"untouched": True},
            },
        }
        for name, label in (("base", "Base"), ("white", "White"))
    ]
    templates.append({"uuid": "mihomo", "name": "Default", "templateType": "MIHOMO"})
    yaml = {
        "proxy-groups": [
            {"name": "Main", "type": "select", "exclude-filter": "old"},
            {"name": "Auto", "type": "url-test", "filter": "old", "interval": 300},
        ]
    }
    return [host, hidden, receiver], templates, yaml


def test_visible_pool_preserves_wires_and_tariff_restrictions():
    hosts, templates, yaml = source()
    original = deepcopy((hosts, templates, yaml))
    p = m.plan(hosts, templates, yaml)
    assert (hosts, templates, yaml) == original
    assert p["hostsAfter"][0] == {**hosts[0], "tags": ["AUTO_BASE_POOL", "OTHER"]}
    assert p["hostsAfter"][0]["excludedInternalSquads"] == ["premium"]
    assert p["templates"][0]["templateJson"]["routing"] == {"untouched": True}
    assert (
        p["templates"][0]["templateJson"]["remnawave"]["injectHosts"][0]["selectFrom"]
        == "NOT_HIDDEN"
    )
    assert p["mihomoAfter"]["remnawave"] == {"includeHiddenHosts": False}
    assert p["mihomoAfter"]["proxy-groups"][1]["filter"] == r"^(Node \(1\)\+)$"


def test_unpaired_hidden_candidate_is_removed_without_exposing_new_host():
    hosts, templates, yaml = source()
    hosts.append(
        {**hosts[1], "uuid": "orphan", "remark": "ABP-2", "address": "1.1.1.1"}
    )
    p = m.plan(hosts, templates, yaml)
    assert p["unmatched"] == ["orphan"]
    assert p["poolNames"] == ["Node (1)+"]
    assert all(h["isDisabled"] for h in p["hostsAfter"] if h["isHidden"])


@pytest.mark.parametrize(
    "difference", ["fingerprint", "inbound", "nodes", "excludeFromSubscriptionTypes"]
)
def test_different_connections_are_not_silently_merged(difference):
    hosts, templates, yaml = source()
    hosts[1][difference] = "different"
    with pytest.raises(RuntimeError, match="connection settings"):
        m.plan(hosts, templates, yaml)


def test_ambiguous_counterpart_is_rejected():
    hosts, templates, yaml = source()
    hosts.append({**hosts[0], "uuid": "second"})
    with pytest.raises(RuntimeError, match="Ambiguous"):
        m.plan(hosts, templates, yaml)


def test_legacy_auto_chrome_uses_existing_visible_firefox_without_editing_host():
    hosts, templates, yaml = source()
    hosts[1]["fingerprint"] = "chrome"
    p = m.plan(hosts, templates, yaml)
    assert p["hostsAfter"][0]["fingerprint"] == "firefox"
    assert p["hostTags"]["main"] == ["AUTO_BASE_POOL", "OTHER"]
