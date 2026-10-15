"""End-to-end operator workflows against a real FTD (the FTDv from cml-mcp-server's ftd-fmc recipe).

Runs only when FMC_LIVE_FTD_HOST and FMC_LIVE_FTD_REG_KEY are set (in the environment or .env). The
FTD must already point at this FMC (`configure manager add`). The tests run in order and share state:

1. onboarding: delete the device if FMC already manages it, register it again (waits for the
   initial deployment), configure interfaces, zones, a default route and NAT, deploy, and verify on
   the device with show commands;
2. troubleshooting: packet tracer (allowed and blocked flows), hit counts, device health;
3. change -> preview -> deploy -> verify -> rollback with a subinterface, then clean up.

The device is left registered and configured (interfaces, route, NAT, mcp-test-ftd-acp rules).
Lab addressing (CML ftd-fmc recipe): outside Ethernet0/0 198.18.128.155/18 (gateway .128.1),
inside Ethernet0/1 10.99.1.1/24.
"""

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

pytestmark = pytest.mark.live

DEVICE = "mcp-ftd1"
ACP = "mcp-test-ftd-acp"
NAT = "mcp-test-ftd-nat"
ZONE_IN, ZONE_OUT, ZONE_DMZ = "mcp-test-ftd-in", "mcp-test-ftd-out", "mcp-test-ftd-dmz"
INSIDE_NET = "mcp-test-ftd-inside-net"
FMC_HOST = "198.18.134.76"


def _env(name: str) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    env = Path(__file__).resolve().parents[2] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name and value.strip():
                return value.strip()
    return None


FTD_HOST = _env("FMC_LIVE_FTD_HOST")
REG_KEY = _env("FMC_LIVE_FTD_REG_KEY")
needs_ftd = pytest.mark.skipif(not (FTD_HOST and REG_KEY), reason="FMC_LIVE_FTD_HOST/REG_KEY not set")


_port = [40000 + int(time.time()) % 20000]


def fresh_port() -> int:
    """A new TCP source port per trace: packet tracer reuses a cached flow with the same 5-tuple,
    and Snort keeps blocked flows black-listed for a while."""
    _port[0] = 40000 + (_port[0] - 39999) % 20000
    return _port[0]


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    result = await client.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def apply(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    preview = await call(client, name, args)
    assert preview["status"] == "preview", preview
    done = await call(client, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done["result"]


async def ensure(client: Client[Any], name: str, args: dict[str, Any]) -> None:
    """Apply unless the preview says there is nothing to do / it already exists."""
    preview = await call(client, name, args)
    if preview["status"] == "blocked":
        assert any("already" in b.lower() or "nothing to change" in b.lower() for b in preview["blockers"]), (
            preview
        )
        return
    await call(client, name, {**args, "confirm": preview["confirm"]})


async def show(client: Client[Any], command: str, match: str | None = None) -> str:
    args: dict[str, Any] = {"device": DEVICE, "command": command}
    if match:
        args["match"] = match
    out = await call(client, "fmc_run_show_command", args)
    return str(out["output"])


async def deploy(client: Client[Any], note: str, ignore_warning: bool = False) -> None:
    pending = await call(client, "fmc_list_deployable_devices", {"response_format": "json"})
    if any(r["device"] == DEVICE for r in pending["results"]):
        args = {"devices": [DEVICE], "note": note, "ignore_warning": ignore_warning}
        result = await apply(client, "fmc_deploy", args)
        assert "Deployed" in str(result["task"]["status"]) or "SUCCE" in str(result["task"]), result


@needs_ftd
async def test_onboard_configure_deploy(client: Client[Any]) -> None:
    devices = await call(client, "fmc_list_devices", {"name": DEVICE, "response_format": "json"})
    if devices["results"] and os.environ.get("FMC_LIVE_FTD_REREGISTER") == "1":
        # Deleting the device makes the FTD forget its manager; the operator must run
        # `configure manager add <fmc> <key>` on the FTD before registration can succeed again.
        await apply(client, "fmc_delete_device", {"device": DEVICE})
        pytest.skip("Device deleted; re-add the manager on the FTD CLI, then rerun without REREGISTER.")
    await ensure(client, "fmc_create_access_policy", {"name": ACP, "default_action": "BLOCK"})
    if devices["results"]:
        await register_check(client)
    else:
        await register(client)
    await configure_and_deploy(client)


async def register_check(client: Client[Any]) -> None:
    dev = await call(client, "fmc_get_device", {"device": DEVICE})
    assert dev["isConnected"] is True and dev["hostName"] == FTD_HOST


async def register(client: Client[Any]) -> None:
    reg = await apply(
        client,
        "fmc_register_device",
        {
            "name": DEVICE,
            "host": FTD_HOST,
            "reg_key": REG_KEY,
            "access_policy": ACP,
            "performance_tier": "FTDv5",
        },
    )
    assert reg["task"]["status"] == "SUCCESS", reg
    assert reg["initial_deployment"].get("status") in ("DEPLOYED", "SUCCEEDED"), reg
    await register_check(client)


async def configure_and_deploy(client: Client[Any]) -> None:
    for zone in (ZONE_IN, ZONE_OUT):
        await ensure(client, "fmc_create_security_zone", {"name": zone})
    await ensure(
        client, "fmc_create_object", {"type": "network", "name": INSIDE_NET, "value": "10.99.1.0/24"}
    )
    await ensure(
        client,
        "fmc_update_interface",
        {
            "device": DEVICE,
            "interface": "Ethernet0/0",
            "logical_name": "outside",
            "enabled": True,
            "security_zone": ZONE_OUT,
            "ipv4": "198.18.128.155/18",
        },
    )
    await ensure(
        client,
        "fmc_update_interface",
        {
            "device": DEVICE,
            "interface": "Ethernet0/1",
            "logical_name": "inside",
            "enabled": True,
            "security_zone": ZONE_IN,
            "ipv4": "10.99.1.1/24",
        },
    )
    ifaces = await call(client, "fmc_list_device_interfaces", {"device": DEVICE, "response_format": "json"})
    named = {r["logical_name"]: r for r in ifaces["results"]}
    assert named["inside"]["zone"] == ZONE_IN and named["outside"]["ipv4"] == "198.18.128.155/18"

    routes = await call(client, "fmc_list_routes", {"device": DEVICE, "response_format": "json"})
    for r in routes["results"]:  # start clean: also exercises fmc_delete_static_route
        await apply(client, "fmc_delete_static_route", {"device": DEVICE, "route_id": r["id"]})
    await apply(
        client,
        "fmc_create_static_route",
        {"device": DEVICE, "interface": "outside", "networks": ["0.0.0.0/0"], "gateway": "198.18.128.1"},
    )
    dup = await call(
        client,
        "fmc_create_static_route",
        {"device": DEVICE, "interface": "outside", "networks": ["0.0.0.0/0"], "gateway": "198.18.128.1"},
    )
    assert dup["status"] == "blocked" and any("already has this route" in b for b in dup["blockers"]), dup
    routes = await call(client, "fmc_list_routes", {"device": DEVICE, "response_format": "json"})
    assert [r["networks"] for r in routes["results"]] == [["any-ipv4"]]

    # Access rules (kept across runs) and NAT.
    rules = await call(client, "fmc_list_access_rules", {"policy": ACP, "response_format": "json"})
    have = {r["name"] for r in rules["results"]}
    if "mcp-test-allow-out" not in have:
        await apply(
            client,
            "fmc_create_access_rule",
            {
                "policy": ACP,
                "name": "mcp-test-allow-out",
                "action": "ALLOW",
                "source_zones": [ZONE_IN],
                "destination_zones": [ZONE_OUT],
                "source_networks": [INSIDE_NET],
                "destination_ports": ["icmp", "tcp/80", "tcp/443", "tcp/22", "udp/53"],
            },
        )
    if "mcp-test-block-telnet" not in have:
        await apply(
            client,
            "fmc_create_access_rule",
            {
                "policy": ACP,
                "name": "mcp-test-block-telnet",
                "action": "BLOCK",
                "source_zones": [ZONE_IN],
                "destination_zones": [ZONE_OUT],
                "destination_ports": ["tcp/23"],
            },
        )
    nat = await call(client, "fmc_list_policies", {"kind": "nat", "name": NAT, "response_format": "json"})
    if not nat["results"]:
        await apply(client, "fmc_create_nat_policy", {"name": NAT})
        await apply(
            client,
            "fmc_create_nat_rule",
            {
                "policy": NAT,
                "kind": "auto",
                "original_source": INSIDE_NET,
                "translated_source": "interface",
                "nat_type": "DYNAMIC",
                "source_interface": ZONE_IN,
                "destination_interface": ZONE_OUT,
            },
        )
    await ensure(client, "fmc_assign_policy", {"kind": "nat", "policy": NAT, "devices": [DEVICE]})

    changes = await call(client, "fmc_pending_changes", {"device": DEVICE, "response_format": "json"})
    assert changes["results"], "the route was recreated, so something must be pending"
    await deploy(client, "mcp live test: onboarding")

    assert "198.18.128.155" in await show(client, "show interface ip brief", "Ethernet0/0")
    assert "via 198.18.128.1, outside" in await show(client, "show route", "0.0.0.0")
    assert "dynamic interface" in await show(client, "show running-config nat")
    history = await call(client, "fmc_list_deployments", {"device": DEVICE, "response_format": "json"})
    assert history["results"][0]["status"] == "DEPLOYED"


@needs_ftd
async def test_why_is_this_blocked(client: Client[Any]) -> None:
    blocked = await call(
        client,
        "fmc_packet_tracer",
        {
            "device": DEVICE,
            "input_interface": "inside",
            "protocol": "tcp",
            "source_port": fresh_port(),
            "source_ip": "10.99.1.10",
            "destination_ip": FMC_HOST,
            "destination_port": 23,
        },
    )
    res = blocked["results"][0]
    # acl-drop when the ACL decides; "firewall" (Snort) when a Snort-evaluated rule such as the
    # dynamic-object quarantine rule sits above it.
    assert res["action"] == "drop" and ("acl-drop" in res["drop_reason"] or "firewall" in res["drop_reason"])
    assert res["verdict_rule"] == "mcp-test-block-telnet", res
    blocked_rule_id = res["matched_rules"][-1]["rule_id"]
    allowed = await call(
        client,
        "fmc_packet_tracer",
        {
            "device": DEVICE,
            "input_interface": "inside",
            "protocol": "tcp",
            "source_port": fresh_port(),
            "source_ip": "10.99.1.10",
            "destination_ip": FMC_HOST,
            "destination_port": 443,
        },
    )
    res = allowed["results"][0]
    # The policy allows it; on a freshly deployed device the simulated packet can still drop for a
    # missing ARP entry of the next hop (no-v4-adjacency), which the tool reports as the reason.
    assert res["verdict_rule"] == "mcp-test-allow-out", res
    assert res["action"] == "allow" or "adjacency" in res.get("drop_reason", ""), res
    assert any(p.get("type") == "NAT" and "translate" in p.get("info", "") for p in res["phases"])

    # Packet tracer packets count as hits, so both rules have been hit at least once now.
    hits = await call(
        client, "fmc_get_hit_counts", {"policy": ACP, "device": DEVICE, "response_format": "json"}
    )
    by_rule = {r["rule"]: r for r in hits["results"]}
    assert by_rule["mcp-test-block-telnet"]["hits"] >= 1
    assert by_rule["mcp-test-block-telnet"]["device_rule_id"] == blocked_rule_id
    assert "Default Action" in by_rule

    lookup = await call(
        client,
        "fmc_rule_lookup",
        {"policy": ACP, "source": "10.99.1.10", "destination": FMC_HOST, "protocol": "tcp", "port": 23},
    )
    assert "mcp-test-block-telnet" in json.dumps(lookup)

    health = await call(client, "fmc_device_health", {"device": DEVICE})
    assert health["connected"] is True and "module_counts" in health


@needs_ftd
async def test_change_deploy_rollback(client: Client[Any]) -> None:
    await ensure(client, "fmc_create_security_zone", {"name": ZONE_DMZ})
    subs = await call(
        client,
        "fmc_list_device_interfaces",
        {"device": DEVICE, "kinds": ["subinterface"], "response_format": "json"},
    )
    for sub in subs["results"]:  # left over from an interrupted run
        if sub.get("logical_name") == "mcp-dmz":
            await apply(client, "fmc_delete_interface", {"device": DEVICE, "interface": sub["id"]})
    await apply(
        client,
        "fmc_create_subinterface",
        {
            "device": DEVICE,
            "parent": "Ethernet0/1",
            "vlan_id": 100,
            "logical_name": "mcp-dmz",
            "security_zone": ZONE_DMZ,
            "ipv4": "10.99.100.1/24",
        },
    )
    await deploy(client, "mcp live test: subinterface")
    assert "10.99.100.1" in await show(client, "show interface ip brief", "Ethernet0/1.100")

    preview = await call(client, "fmc_rollback_deployment", {"device": DEVICE})
    assert preview["status"] == "preview", preview
    done = await call(client, "fmc_rollback_deployment", {"device": DEVICE, "confirm": preview["confirm"]})
    assert done["status"] == "applied" and done["result"]["task"]["taskType"] == "DEVICE_ROLLBACK", done
    assert "Ethernet0/1.100" not in await show(client, "show interface ip brief", "Ethernet0/1")

    # FMC still holds the subinterface: delete it and deploy so FMC and the device agree again.
    await apply(client, "fmc_delete_interface", {"device": DEVICE, "interface": "mcp-dmz"})
    subs = await call(
        client,
        "fmc_list_device_interfaces",
        {"device": DEVICE, "kinds": ["subinterface"], "response_format": "json"},
    )
    assert not [r for r in subs["results"] if r.get("logical_name") == "mcp-dmz"], subs
    try:
        await deploy(client, "mcp live test: remove subinterface")
    except ToolError as e:
        # Removing the subinterface touches the virtual router, and FMC's validation warns about it
        # ("may cause traffic disruption"); the tool says to repeat with ignore_warning.
        assert "ignore_warning" in str(e), e
        await deploy(client, "mcp live test: remove subinterface", ignore_warning=True)
    pending = await call(client, "fmc_list_deployable_devices", {"response_format": "json"})
    assert not any(r["device"] == DEVICE for r in pending["results"])


@needs_ftd
async def test_why_blocked_prompt_steps(client: Client[Any]) -> None:
    """Render fmc_why_blocked and run its steps for the three lab cases: TCP 23 blocked by
    mcp-test-block-telnet, TCP 443 allowed, and a no-ARP drop to an unused outside address."""
    prompt = await client.get_prompt(
        "fmc_why_blocked", {"source": "10.99.1.10", "destination": FMC_HOST, "port": "23", "device": DEVICE}
    )
    body = prompt.messages[0].content.text  # type: ignore[union-attr]
    tools = {t.name for t in await client.list_tools()}
    steps = [
        "fmc_rule_lookup",
        "fmc_packet_tracer",
        "fmc_get_hit_counts",
        "fmc_pending_changes",
        "fmc_list_deployments",
        "fmc_list_audit_records",
    ]
    assert all(f"`{s}`" in body and s in tools for s in steps)
    zones = {"source_zone": ZONE_IN, "destination_zone": ZONE_OUT}
    cases = [
        (FMC_HOST, 23, "BLOCK", "drop", None),
        (FMC_HOST, 443, "ALLOW", "allow", None),
        ("198.18.128.199", 443, "ALLOW", "drop", "adjacency"),
    ]
    for dst, port, verdict, action, reason in cases:
        lookup = await call(
            client,
            "fmc_rule_lookup",
            {
                "policy": ACP,
                "source": "10.99.1.10",
                "destination": dst,
                "protocol": "tcp",
                "port": port,
                **zones,
            },
        )
        assert verdict in lookup["verdict"], lookup
        trace = await call(
            client,
            "fmc_packet_tracer",
            {
                "device": DEVICE,
                "input_interface": "inside",
                "protocol": "tcp",
                "source_ip": "10.99.1.10",
                "destination_ip": dst,
                "destination_port": port,
                "source_port": fresh_port(),
            },
        )
        res = trace["results"][0]
        if action == "allow" and "adjacency" in res.get("drop_reason", ""):
            # Allowed by policy; the FTD just has no ARP entry for the next hop right now.
            assert res["verdict_rule"] == "mcp-test-allow-out", res
            continue
        assert res["action"] == action and (reason is None or reason in res.get("drop_reason", "")), res
        if port == 23:
            assert res["verdict_rule"] == "mcp-test-block-telnet", res
    hits = await call(
        client,
        "fmc_get_hit_counts",
        {"policy": ACP, "device": DEVICE, "rule": "block-telnet", "response_format": "json"},
    )
    assert hits["results"][0]["hits"] >= 1
    for name, args in (
        ("fmc_pending_changes", {"device": DEVICE}),
        ("fmc_list_deployments", {"device": DEVICE, "since_hours": 24}),
        ("fmc_list_audit_records", {"since_minutes": 1440, "text": ACP}),
    ):
        out = await call(client, name, {**args, "response_format": "json"})
        assert "results" in out


QUARANTINE = "mcp-test-quarantine"
QUARANTINE_RULE = "mcp-test-quarantine-block"


@needs_ftd
async def test_dynamic_object_blocks_without_deploy(client: Client[Any]) -> None:
    """F4: a BLOCK rule on a dynamic object (deployed once), then mapping/unmapping the inside host
    changes the verdict with no deployment. Object and rule are kept for later runs (empty = no effect)."""
    objs = await call(client, "fmc_list_dynamic_objects", {"name": QUARANTINE, "response_format": "json"})
    if not any(o["name"] == QUARANTINE for o in objs["results"]):
        await apply(client, "fmc_create_dynamic_object", {"name": QUARANTINE, "description": "mcp live test"})
    rules = await call(client, "fmc_list_access_rules", {"policy": ACP, "response_format": "json"})
    if not any(r["name"] == QUARANTINE_RULE for r in rules["results"]):
        await apply(
            client,
            "fmc_create_access_rule",
            {
                "policy": ACP,
                "name": QUARANTINE_RULE,
                "action": "BLOCK",
                "source_dynamic_objects": [QUARANTINE],
                "insert_before": 1,
            },
        )
    await deploy(client, "mcp live test: quarantine rule")
    blocked_delete = await call(client, "fmc_delete_dynamic_object", {"object": QUARANTINE})
    assert blocked_delete["status"] == "blocked" and QUARANTINE_RULE in " ".join(blocked_delete["blockers"])

    trace_args = {
        "device": DEVICE,
        "input_interface": "inside",
        "protocol": "tcp",
        "source_ip": "10.99.1.10",
        "destination_ip": FMC_HOST,
        "destination_port": 443,
    }
    try:
        preview = await call(client, "fmc_map_dynamic_object", {"object": QUARANTINE, "add": ["10.99.1.10"]})
        assert any(r["rule"] == QUARANTINE_RULE for r in preview["preview"]["rules"]), preview
        await call(
            client,
            "fmc_map_dynamic_object",
            {"object": QUARANTINE, "add": ["10.99.1.10"], "confirm": preview["confirm"]},
        )
        res = (await call(client, "fmc_packet_tracer", trace_args))["results"][0]
        assert res["action"] == "drop" and res["verdict_rule"] == QUARANTINE_RULE, res
        pending = await call(client, "fmc_list_deployable_devices", {"response_format": "json"})
        assert not any(r["device"] == DEVICE for r in pending["results"]), "a mapping must not need a deploy"
    finally:
        await apply(client, "fmc_map_dynamic_object", {"object": QUARANTINE, "remove": ["10.99.1.10"]})
    # The blocked 5-tuple stays black-listed in Snort for a while; packet tracer with the same source
    # port reuses that flow ("snort-blacklist"), so trace a fresh flow.
    trace_args["source_port"] = fresh_port()
    res = (await call(client, "fmc_packet_tracer", trace_args))["results"][0]
    assert res["verdict_rule"] == "mcp-test-allow-out", res
    assert res["action"] == "allow" or "adjacency" in res.get("drop_reason", ""), res


@needs_ftd
async def test_recent_activity(client: Client[Any]) -> None:
    """F5: the merged timeline answers from FMC alone (no appliance setup); earlier tests in this
    module deployed to the device, so its deploy rows are in the window."""
    out = await call(
        client, "fmc_recent_activity", {"since_minutes": 120, "device": DEVICE, "response_format": "json"}
    )
    sources = {r["source"] for r in out["results"]}
    assert "deploy" in sources, out
    assert not out.get("errors"), out
    alerts = await call(
        client,
        "fmc_list_health_alerts",
        {"since_minutes": 1440, "status": ["RED", "YELLOW", "RECOVERED"], "response_format": "json"},
    )
    assert "raw_alerts" in alerts


PS_POLICY = "mcp-test-ps"
SYSLOG_HOST = "10.99.1.30"


@needs_ftd
async def test_platform_settings_syslog(client: Client[Any]) -> None:
    """F3: platform settings policy -> syslog server -> assign -> deploy -> verify on the device ->
    remove -> deploy. The syslog host is a lab address nobody listens on (ADR-003: no receiving)."""
    pols = await call(client, "fmc_list_policies", {"kind": "platform_settings", "response_format": "json"})
    if not any(p["name"] == PS_POLICY for p in pols["results"]):
        await apply(client, "fmc_create_platform_settings_policy", {"name": PS_POLICY})
    await ensure(
        client, "fmc_assign_policy", {"kind": "platform_settings", "policy": PS_POLICY, "devices": [DEVICE]}
    )
    current = await call(client, "fmc_get_platform_settings", {"policy": PS_POLICY})
    if any(s["host"] == SYSLOG_HOST for s in current["syslog"]["servers"]):  # left over from a failed run
        await apply(client, "fmc_configure_syslog", {"policy": PS_POLICY, "remove_servers": [SYSLOG_HOST]})
    await apply(
        client,
        "fmc_configure_syslog",
        {
            "policy": PS_POLICY,
            "add_servers": [SYSLOG_HOST],
            "interfaces": [ZONE_IN],
            "logging_enabled": True,
            "server_level": "WARNING",
            "timestamp_format": "RFC_5424",
        },
    )
    summary = await call(client, "fmc_get_platform_settings", {"policy": PS_POLICY})
    assert DEVICE in summary["assigned_to"]
    assert any(s["host"] == SYSLOG_HOST and s["port"] == "514" for s in summary["syslog"]["servers"])
    await deploy(client, "mcp live test: syslog server")
    config = await show(client, "show running-config logging")
    assert f"logging host inside {SYSLOG_HOST}" in config and "logging timestamp rfc5424" in config, config
    assert "logging trap warnings" in config

    await apply(client, "fmc_configure_syslog", {"policy": PS_POLICY, "remove_servers": [SYSLOG_HOST]})
    await deploy(client, "mcp live test: remove syslog server")
    assert SYSLOG_HOST not in await show(client, "show running-config logging")


PEER = (
    "10.99.1.2"  # peer1 (iol-xe) on inside-sw: AS 65001, Lo0 172.31.1.1 in BGP, Lo1 172.31.2.1 in OSPF area 0
)
needs_peer = pytest.mark.skipif(
    os.environ.get("FMC_LIVE_NO_PEER") == "1", reason="peer1 router not in the lab"
)


async def _wait_route(client: Client[Any], prefix: str, present: bool, tries: int = 12) -> str:
    out = ""
    for _ in range(tries):
        out = await show(client, "show route")
        if (prefix in out) == present:
            return out
        await asyncio.sleep(10)
    raise AssertionError(f"{prefix} {'missing from' if present else 'still in'} the routing table:\n{out}")


@needs_ftd
@needs_peer
async def test_routing_bgp_ospf_vrf(client: Client[Any]) -> None:
    """F6: eBGP to peer1 and OSPF area 0 on the inside network, deployed and verified in the FTD's
    routing table (B 172.31.1.1, O 172.31.2.1), a VRF created and deleted, then everything removed."""
    current = await call(client, "fmc_get_routing", {"device": DEVICE})
    if "bgp" in current:
        await apply(client, "fmc_configure_bgp", {"device": DEVICE, "remove_bgp": True})
    if current.get("ospfv2"):
        await apply(client, "fmc_configure_ospf", {"device": DEVICE, "remove_process": True})
    await apply(
        client,
        "fmc_configure_bgp",
        {
            "device": DEVICE,
            "neighbor": PEER,
            "remote_as": "65001",
            "local_as": "65000",
            "advertise": [INSIDE_NET],
        },
    )
    await apply(
        client, "fmc_configure_ospf", {"device": DEVICE, "area": "0", "add_networks": ["10.99.1.0/24"]}
    )
    view = await call(client, "fmc_get_routing", {"device": DEVICE})
    assert view["bgp"]["as"] == "65000" and view["bgp"]["ipv4"]["neighbors"][0]["address"] == PEER
    assert view["ospfv2"][0]["areas"][0]["networks"] == [INSIDE_NET]
    # a read-modify-PUT of the existing BGP object (FMC rejects echoed maximumPaths; the tool drops it)
    await apply(
        client, "fmc_configure_bgp", {"device": DEVICE, "neighbor": PEER, "neighbor_description": "peer1"}
    )
    dup = await call(client, "fmc_configure_bgp", {"device": DEVICE, "neighbor": PEER, "remote_as": "65001"})
    assert dup["status"] == "blocked", dup
    await deploy(client, "mcp live test: bgp + ospf", ignore_warning=True)
    table = await _wait_route(client, "172.31.1.1", True)
    assert f"via {PEER}" in table
    await _wait_route(client, "172.31.2.1", True)

    await apply(client, "fmc_create_vrf", {"device": DEVICE, "name": "mcp-test-vrf"})
    assert any(
        v["name"] == "mcp-test-vrf"
        for v in (await call(client, "fmc_get_routing", {"device": DEVICE}))["vrfs"]
    )
    await apply(client, "fmc_delete_vrf", {"device": DEVICE, "name": "mcp-test-vrf"})

    await apply(client, "fmc_configure_bgp", {"device": DEVICE, "remove_bgp": True})
    await apply(client, "fmc_configure_ospf", {"device": DEVICE, "remove_process": True})
    await deploy(client, "mcp live test: remove bgp + ospf", ignore_warning=True)
    await _wait_route(client, "172.31.1.1", False)
    await _wait_route(client, "172.31.2.1", False)
