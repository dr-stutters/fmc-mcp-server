import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.refs import network_literal, port_literal
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, NAT_ID, empty, fixture, items, make_settings

HOST = {"id": "00000000-0000-0000-0000-0000000000a1", "name": "h1", "type": "Host", "value": "10.0.0.1"}


async def run(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await client.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else r.content[0].text  # type: ignore[union-attr]


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
        return preview, done


def test_literals() -> None:
    assert network_literal("10.1.1.5") == {"type": "Host", "value": "10.1.1.5"}
    assert network_literal("10.1.1.5/32") == {"type": "Host", "value": "10.1.1.5"}
    assert network_literal("10.1.1.9/24") == {"type": "Network", "value": "10.1.1.0/24"}
    assert network_literal("10.1.1.1-10.1.1.9") == {"type": "Range", "value": "10.1.1.1-10.1.1.9"}
    assert network_literal("web-servers") is None
    assert port_literal("tcp/443") == {"type": "PortLiteral", "protocol": "6", "port": "443"}
    assert port_literal("UDP/1000-2000") == {"type": "PortLiteral", "protocol": "17", "port": "1000-2000"}
    assert port_literal("icmp/8") == {"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "8"}
    assert port_literal("icmp") == {"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "Any"}
    assert port_literal("HTTPS") is None and port_literal("443") is None


async def test_create_host(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    post = fmc.post(f"{CFG}/object/hosts").mock(return_value=httpx.Response(201, json={**HOST, "links": {}}))
    preview, done = await preview_apply(
        "fmc_create_object", {"type": "host", "name": "h1", "value": "10.0.0.1"}
    )
    assert preview["preview"]["body"] == {"name": "h1", "type": "Host", "value": "10.0.0.1"}
    assert post.call_count == 1 and json.loads(post.calls.last.request.content)["value"] == "10.0.0.1"
    assert done["result"]["id"] == HOST["id"] and "links" not in done["result"]


async def test_create_rejects_bad_value(fmc: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="Invalid network"):
            await run(c, "fmc_create_object", {"type": "network", "name": "n", "value": "10.0.0.0/33"})
        with pytest.raises(ToolError, match="tcp or udp"):
            await run(c, "fmc_create_object", {"type": "port", "name": "p", "value": "443"})


async def test_create_blocked_when_name_exists(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "fmc_create_object", {"type": "host", "name": "h1", "value": "10.0.0.2"})
    assert out["status"] == "blocked" and "already exists" in out["blockers"][0]


async def test_update_object_and_stale_token(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    put = fmc.put(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    args = {"object": "h1", "type": "host", "value": "10.0.0.9"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = await run(c, "fmc_update_object", args)
        assert preview["preview"]["changes"] == {"value": {"from": "10.0.0.1", "to": "10.0.0.9"}}
        # someone else changes the object before confirm -> token refused
        fmc.get(f"{CFG}/object/hosts").mock(return_value=items([{**HOST, "description": "changed"}]))
        with pytest.raises(ToolError, match="changed since the preview"):
            await run(c, "fmc_update_object", {**args, "confirm": preview["confirm"]})
    assert put.call_count == 0


async def test_delete_blocked_when_in_use(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=items([{"type": "AccessPolicy", "name": "acp1", "id": "p1"}])
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "fmc_delete_object", {"object": "h1", "type": "host"})
    assert out["status"] == "blocked" and "AccessPolicy acp1" in out["blockers"][0]


async def test_update_group(fmc: respx.MockRouter) -> None:
    group = {
        "id": "00000000-0000-0000-0000-0000000000g1",
        "name": "g1",
        "type": "NetworkGroup",
        "objects": [{"id": HOST["id"], "type": "Host", "name": "h1"}],
        "literals": [{"type": "Network", "value": "10.9.0.0/16"}],
    }
    fmc.get(f"{CFG}/object/networkgroups").mock(return_value=items([group]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    put = fmc.put(f"{CFG}/object/networkgroups/{group['id']}").mock(
        return_value=httpx.Response(200, json=group)
    )
    preview, _ = await preview_apply(
        "fmc_update_group", {"group": "g1", "add": ["10.8.0.0/16"], "remove": ["h1"]}
    )
    assert preview["preview"]["removed"] == ["h1"] and preview["preview"]["added"] == ["10.8.0.0/16"]
    sent = json.loads(put.calls.last.request.content)
    assert "objects" not in sent
    assert sent["literals"] == [
        {"type": "Network", "value": "10.9.0.0/16"},
        {"type": "Network", "value": "10.8.0.0/16"},
    ]


async def test_create_access_rule_position_and_refs(lab: respx.MockRouter) -> None:
    zone = {"id": "z1", "name": "inside", "type": "SecurityZone"}
    lab.get(f"{CFG}/object/securityzones").mock(return_value=items([zone]))
    web = next(i for i in fixture("networkaddresses")["items"] if i["name"] == "mcp-test-web")
    lab.get(f"{CFG}/object/hosts").mock(return_value=items([web]))
    https = next(i for i in fixture("protocolportobjects")["items"] if i["name"] == "HTTPS")
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(201, json={"id": "new", "name": "r"})
    )
    preview, _ = await preview_apply(
        "fmc_create_access_rule",
        {
            "policy": "mcp-test-acp",
            "name": "r",
            "action": "ALLOW",
            "source_zones": ["inside"],
            "destination_networks": ["mcp-test-web", "10.5.0.0/16"],
            "destination_ports": ["HTTPS", "tcp/8080"],
            "insert_before": 2,
        },
    )
    assert preview["preview"]["position"] == "before rule 2"
    req = post.calls.last.request
    assert req.url.params["insertBefore"] == "2"
    body = json.loads(req.content)
    assert body["sourceZones"]["objects"][0]["id"] == "z1"
    assert body["destinationNetworks"]["objects"][0]["id"] == web["id"]
    assert body["destinationNetworks"]["literals"] == [{"type": "Network", "value": "10.5.0.0/16"}]
    assert body["destinationPorts"]["objects"][0]["id"] == https["id"]
    assert body["destinationPorts"]["literals"] == [{"type": "PortLiteral", "protocol": "6", "port": "8080"}]
    assert body["logEnd"] is True and body["sendEventsToFMC"] is True


async def test_block_rule_logs_at_connection_start(lab: respx.MockRouter) -> None:
    # FMC 10.0.1 rejects logEnd on block rules ("LogEnd is not supported for BLOCK Action").
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(201, json={"id": "new", "name": "b"})
    )
    await preview_apply(
        "fmc_create_access_rule",
        {"policy": "mcp-test-acp", "name": "b", "action": "BLOCK", "destination_ports": ["tcp/23"]},
    )
    body = json.loads(post.calls.last.request.content)
    assert body["logBegin"] is True and body["logEnd"] is False and body["sendEventsToFMC"] is True


async def test_create_access_rule_blocks_duplicate_name(lab: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(
            c,
            "fmc_create_access_rule",
            {"policy": "mcp-test-acp", "name": "mcp-test-ssh-admin", "action": "BLOCK"},
        )
    assert out["status"] == "blocked"


@pytest.mark.parametrize(("move_to", "param"), [(6, "insertAfter"), (1, "insertBefore")])
async def test_move_access_rule(lab: respx.MockRouter, move_to: int, param: str) -> None:
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json={})
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "mcp-test-ssh-admin", "move_to": move_to}
    )
    assert preview["preview"]["move"] == f"2 -> {move_to}"
    req = put.calls.last.request
    assert req.url.params["bulk"] == "true" and req.url.params[param] == str(move_to)
    body = json.loads(req.content)
    assert body[0]["name"] == "mcp-test-ssh-admin" and "metadata" not in body[0]


async def test_disable_access_rule(lab: respx.MockRouter) -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "2", "enabled": False, "comment": "why"}
    )
    assert preview["preview"]["changes"]["enabled"] == {"from": True, "to": False}
    body = json.loads(put.calls.last.request.content)
    assert body["enabled"] is False and body["newComments"] == ["why"]


async def test_create_auto_nat(lab: respx.MockRouter) -> None:
    addrs = fixture("networkaddresses")["items"]
    web = next(i for i in addrs if i["name"] == "mcp-test-web")
    db = next(i for i in addrs if i["name"] == "mcp-test-db")
    lab.get(f"{CFG}/object/hosts").mock(side_effect=lambda req: items([web, db]))
    post = lab.post(f"{CFG}/policy/ftdnatpolicies/{NAT_ID}/autonatrules").mock(
        return_value=httpx.Response(201, json={"id": "n1"})
    )
    await preview_apply(
        "fmc_create_nat_rule",
        {
            "policy": "mcp-test-nat",
            "kind": "auto",
            "original_source": "mcp-test-web",
            "translated_source": "mcp-test-db",
            "original_port": "tcp/80",
            "translated_port": "tcp/8080",
        },
    )
    body = json.loads(post.calls.last.request.content)
    assert body["originalNetwork"]["id"] == web["id"] and body["translatedNetwork"]["id"] == db["id"]
    assert (body["serviceProtocol"], body["originalPort"], body["translatedPort"]) == ("TCP", 80, 8080)


async def test_nat_rule_rejects_literal(lab: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="need network objects"):
            await run(
                c,
                "fmc_create_nat_rule",
                {
                    "policy": "mcp-test-nat",
                    "kind": "auto",
                    "original_source": "10.0.0.1",
                    "translated_source": "x",
                },
            )


async def test_writes_hidden_when_disabled(fmc: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        names = {t.name for t in await c.list_tools()}
    assert "fmc_create_object" not in names and "fmc_list_objects" in names


async def test_clear_condition_shows_any(lab: respx.MockRouter) -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "mcp-test-ssh-admin", "source_zones": []}
    )
    assert preview["preview"]["changes"]["sourceZones"] == {"from": ["mcp-test-inside"], "to": "any"}
    assert "sourceZones" not in json.loads(put.calls.last.request.content)


async def test_replaced_condition_preview_shows_what_it_removes(lab: respx.MockRouter) -> None:
    """F29: an object replaced by a literal used to show only 'literals: null -> [...]'."""
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-ssh-admin", "destination_networks": ["10.1.1.1"]},
    )
    changes = preview["preview"]["changes"]
    assert changes["destinationNetworks"] == {"from": ["mcp-test-db"], "to": ["10.1.1.1"]}
    assert not any(k.startswith("destinationNetworks.") for k in changes)


async def test_insert_before_and_after_rejected(lab: respx.MockRouter) -> None:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        with pytest.raises(ToolError, match="not both"):
            await run(
                c,
                "fmc_create_access_rule",
                {
                    "policy": "mcp-test-acp",
                    "name": "x",
                    "action": "BLOCK",
                    "insert_before": 1,
                    "insert_after": 2,
                },
            )


async def test_update_object_preview_shows_removed_field(fmc: respx.MockRouter) -> None:
    """Core 0.12.4 replace=True: the PUT drops 'port' (all ports), so the preview must say so."""
    port = {
        "id": "00000000-0000-0000-0000-0000000000p1",
        "name": "p1",
        "type": "ProtocolPortObject",
        "protocol": "TCP",
        "port": "22",
    }
    fmc.get(f"{CFG}/object/protocolportobjects").mock(return_value=items([port]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    put = fmc.put(f"{CFG}/object/protocolportobjects/{port['id']}").mock(
        return_value=httpx.Response(200, json=port)
    )
    args = {"object": "p1", "type": "port", "value": "0-65535"}
    preview, _ = await preview_apply("fmc_update_object", args)
    assert preview["preview"]["changes"]["port"] == {"from": "22", "to": None, "removed": True}
    assert "port" not in json.loads(put.calls.last.request.content)


async def test_rule_action_change_preview_shows_dropped_policies(lab: respx.MockRouter) -> None:
    """ALLOW -> BLOCK drops ipsPolicy/filePolicy from the PUT body; the preview lists both."""
    data = fixture("accessrules")
    rule = next(r for r in data["items"] if r["name"] == "mcp-test-ssh-admin")
    rule["ipsPolicy"] = {"id": "ips1", "type": "IntrusionPolicy", "name": "Balanced"}
    rule["filePolicy"] = {"id": "fp1", "type": "FilePolicy", "name": "Block Malware"}
    lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=data)
    )
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "mcp-test-ssh-admin", "action": "BLOCK"}
    )
    changes = preview["preview"]["changes"]
    assert changes["ipsPolicy"]["removed"] is True and changes["filePolicy"]["removed"] is True
    assert "commentHistoryList" not in changes
    body = json.loads(put.calls.last.request.content)
    assert "ipsPolicy" not in body and "filePolicy" not in body
