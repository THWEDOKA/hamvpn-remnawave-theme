import asyncio

from orchestrator.app.remnawave import RemnawaveClient


def test_inventory_preserves_wrapped_squads_and_hosts():
    client = RemnawaveClient("http://panel", "test")
    responses = {
        "/api/nodes/": [{"uuid": "node"}],
        "/api/hosts/": {"hosts": [{"uuid": "host"}]},
        "/api/config-profiles/": {"configProfiles": [{"uuid": "profile"}]},
        "/api/config-profiles/profile": {"uuid": "profile", "config": {"inbounds": []}},
        "/api/internal-squads/": {
            "internalSquads": [{"uuid": "squad", "name": "Customers"}]
        },
    }

    async def request(method, path):
        assert method == "GET"
        return responses[path]

    client.request = request
    result = asyncio.run(client.inventory())
    assert result["squads"] == [{"uuid": "squad", "name": "Customers"}]
    assert result["hosts"] == [{"uuid": "host"}]
    assert result["profiles"][0]["config"] == {"inbounds": []}
