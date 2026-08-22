from orchestrator.app.inventory import (
    build_ip_plan,
    hysteria_hostnames,
    normalize_inventory,
    replace_paths,
)


def sample_inventory():
    return normalize_inventory(
        {
            "nodes": [
                {
                    "uuid": "node-1",
                    "name": "Germany-4",
                    "address": "192.0.2.10",
                    "port": 2222,
                    "countryCode": "DE",
                    "isConnected": True,
                    "configProfile": {
                        "activeConfigProfileUuid": "profile-1",
                        "activeInbounds": ["inbound-1"],
                    },
                }
            ],
            "hosts": [
                {
                    "uuid": "host-1",
                    "remark": "Germany",
                    "address": "192.0.2.10",
                    "port": 443,
                    "nodes": ["node-1"],
                },
                {
                    "uuid": "host-2",
                    "remark": "Germany domain",
                    "address": "de.example.test",
                    "port": 443,
                    "nodes": [{"uuid": "node-1"}],
                    "inbound": {"type": "hysteria", "network": "hysteria"},
                },
            ],
            "profiles": {
                "configProfiles": [
                    {
                        "uuid": "profile-1",
                        "name": "BASE",
                        "config": {
                            "outbounds": [{"settings": {"address": "192.0.2.10"}}],
                            "unchanged": "http://192.0.2.10:8443",
                        },
                        "inbounds": [{"uuid": "inbound-1", "tag": "VLESS", "type": "vless"}],
                    }
                ]
            },
            "squads": {"internalSquads": [{"uuid": "squad-1", "name": "BASE"}]},
        }
    )


def test_normalize_wrapped_collections():
    inventory = sample_inventory()
    assert inventory["summary"] == {
        "nodes": 1,
        "connectedNodes": 1,
        "hosts": 2,
        "profiles": 1,
        "squads": 1,
    }
    assert inventory["nodes"][0]["profileName"] == "BASE"


def test_ip_plan_only_changes_exact_values():
    plan = build_ip_plan(sample_inventory(), "node-1", "192.0.2.20")
    assert plan["impact"] == {"nodes": 1, "hosts": 1, "profileValues": 1}
    assert len(plan["hosts"]) == 2
    assert any(not host["willChange"] for host in plan["hosts"])
    assert plan["profiles"][0]["paths"] == [["outbounds", 0, "settings", "address"]]


def test_replace_paths_preserves_original():
    source = {"a": [{"ip": "192.0.2.10"}], "other": "192.0.2.10:443"}
    result = replace_paths(source, [["a", 0, "ip"]], "192.0.2.20")
    assert source["a"][0]["ip"] == "192.0.2.10"
    assert result == {"a": [{"ip": "192.0.2.20"}], "other": "192.0.2.10:443"}


def test_hysteria_hostnames_only_returns_linked_domains():
    assert hysteria_hostnames(sample_inventory(), "node-1") == ["de.example.test"]
