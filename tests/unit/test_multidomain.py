"""F19 multi-domain: domain tree, the domain in previews, inherited objects/policies blocked below their
owner domain."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, DOMAIN, items, make_settings

CHILD_CFG = f"/api/fmc_config/v1/domain/{CHILD}"
GLOBAL_REF = {"id": DOMAIN, "name": "Global", "type": "Domain"}
CHILD_REF = {"id": CHILD, "name": "Branch", "type": "Domain"}
HOST = {
    "id": "00505686-0000-0ed3-0000-000000000001",
    "name": "h1",
    "type": "Host",
    "value": "10.0.0.1",
    "metadata": {"domain": GLOBAL_REF},
}


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def test_domain_tree_with_devices(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": "d1", "name": "ftd1", "metadata": {"domain": CHILD_REF}}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_list_domains", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows["Global"]["leaf"] is False and rows["Global"]["default"] is True
    assert rows["Global"].get("devices") is None
    assert rows["Global/Branch"]["leaf"] is True and rows["Global/Branch"]["devices"] == ["ftd1"]
    assert rows["Global/Branch"]["parent_uuid"] == DOMAIN


async def test_inherited_object_is_blocked_in_child_domain(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CHILD_CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CHILD_CFG}/object/operational/usage").mock(return_value=items([]))
    put = fmc.put(f"{CHILD_CFG}/object/hosts/{HOST['id']}")
    async with Client(server()) as c:
        out = await run(
            c, "fmc_update_object", {"object": "h1", "type": "host", "value": "10.0.0.9", "domain": "Branch"}
        )
    assert out["status"] == "blocked", out
    assert out["preview"]["domain"] == "Global/Branch"
    assert "defined in domain 'Global'" in out["blockers"][0] and "domain='Global'" in out["blockers"][0]
    assert not put.called


async def test_owner_domain_edit_shows_domain(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=items([]))
    fmc.put(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    async with Client(server()) as c:
        out = await run(c, "fmc_update_object", {"object": "h1", "type": "host", "value": "10.0.0.9"})
    assert out["status"] == "preview" and out["preview"]["domain"] == "Global"


async def test_device_paths_go_to_the_owning_leaf_domain(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    dev_id = "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb"
    lookup = fmc.get(f"{CFG}/devices/devicerecords/{dev_id}").mock(
        return_value=httpx.Response(200, json={"id": dev_id, "metadata": {"domain": CHILD_REF}})
    )
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        sub = f"devices/devicerecords/{dev_id}/routing/ipv4staticroutes"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"  # cached
        assert lookup.call_count == 1
        # explicitly in the leaf: unchanged; collections and other paths: unchanged
        assert await app.config_path(sub, "Branch") == f"{CHILD_CFG}/{sub}"
        assert await app.config_path("devices/devicerecords") == f"{CFG}/devices/devicerecords"
        assert await app.config_path("object/hosts") == f"{CFG}/object/hosts"
    finally:
        await app.aclose()


def test_is_below_uses_whole_path_segments() -> None:
    from fmc_mcp.client import FmcApp

    app = FmcApp(make_settings())
    app.domains = [
        {"name": "Global", "uuid": DOMAIN},
        {"name": "Global/A", "uuid": "a" * 8 + "-0000-0000-0000-000000000000"},
        {"name": "Global/AB", "uuid": "b" * 8 + "-0000-0000-0000-000000000000"},
    ]
    a, ab = app.domains[1]["uuid"], app.domains[2]["uuid"]
    assert app._is_below(ab, DOMAIN) and app._is_below(a, DOMAIN)
    assert not app._is_below(ab, a) and not app._is_below(DOMAIN, a)


async def test_listing_teaches_device_domains_without_lookups(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    dev_id = "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb"
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": dev_id, "name": "ftd1", "metadata": {"domain": CHILD_REF}}])
    )
    lookup = fmc.get(f"{CFG}/devices/devicerecords/{dev_id}")
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        await app.all(await app.config_path("devices/devicerecords"))
        sub = f"devices/devicerecords/{dev_id}/physicalinterfaces"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"
        assert not lookup.called
        app.forget_devices()
        assert dev_id not in app.device_domains
    finally:
        await app.aclose()
