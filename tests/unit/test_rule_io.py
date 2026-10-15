"""F23 access rule export / import."""

import json

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.rule_io import export_row, literal_label, to_csv

from .conftest import CFG, items, make_settings

ACP = {"id": "00000000-0000-0ed3-0000-021474837418", "name": "acp", "type": "AccessPolicy"}
RULES = f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules"
RULE = {
    "id": "r1",
    "name": "allow-web",
    "action": "ALLOW",
    "enabled": True,
    "logEnd": True,
    "sourceNetworks": {"objects": [{"name": "web-net", "id": "n1", "type": "Network"}]},
    "destinationPorts": {
        "literals": [
            {"type": "PortLiteral", "protocol": "6", "port": "443"},
            {"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "8"},
        ]
    },
    "metadata": {"ruleIndex": 1, "section": "Default"},
}


def test_labels_round_trip_format() -> None:
    assert literal_label({"type": "PortLiteral", "protocol": "6", "port": "443"}) == "tcp/443"
    assert literal_label({"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "8"}) == "icmp/8"
    assert literal_label({"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "Any"}) == "icmp"
    row = export_row(RULE)
    assert row["dst_ports"] == ["tcp/443", "icmp/8"] and row["src_networks"] == ["web-net"]
    assert row["section"] == "default" and row["log"] == "end"
    assert "tcp/443;icmp/8" in to_csv([row])


async def test_import_validates_then_posts_in_bulk(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(RULES).mock(return_value=items([RULE]))
    post = fmc.post(RULES).mock(return_value=httpx.Response(201, json={"items": []}))
    good = {"name": "r-new", "action": "BLOCK", "dst_networks": ["10.9.9.0/24"], "dst_ports": ["tcp/23"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        bad = (
            await c.call_tool(
                "fmc_import_access_rules",
                {
                    "policy": "acp",
                    "rules": [good, {"name": "allow-web", "action": "ALLOW", "users": ["bob"]}],
                },
            )
        ).structured_content
        assert bad["status"] == "blocked" and any("can't import users" in b for b in bad["blockers"])
        args = {"policy": "acp", "rules": [good]}
        preview = (await c.call_tool("fmc_import_access_rules", args)).structured_content
        assert preview["status"] == "preview" and preview["blast_radius"] == 1, preview
        await c.call_tool("fmc_import_access_rules", {**args, "confirm": preview["confirm"]})
    req = post.calls.last.request
    assert req.url.params["bulk"] == "true" and req.url.params["section"] == "default"
    body = json.loads(req.content)
    assert (
        body[0]["name"] == "r-new" and body[0]["destinationNetworks"]["literals"][0]["value"] == "10.9.9.0/24"
    )
    assert body[0]["logBegin"] is True and body[0]["logEnd"] is False  # block rules log at the start
