"""F56: fmc_prove_policy (expected flows -> packet tracer on the right FTD -> pass/fail/mismatch) and the
fmc_prove_user_policy prompt. Traces recorded from mcp-ftd1 (tests/fixtures/ftd_packettracer_*.json)."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools import prove
from fmc_mcp.tools.prompts import _prove_user_policy_text
from fmc_mcp.tools.prove import policy_verdict, user_seen

from .conftest import CFG, DOMAIN, TOP_CFG, as_leaf, fixture, items, make_settings
from .test_tools_ftd import ACP, DEV, DEVPATH, _catalog, ftd  # noqa: F401  (ftd is a fixture)

ALLOW = fixture("ftd_packettracer_allow")
RECORDED = fixture("ha_cluster_records")  # FMC 10.0.1 device records with containerDetails, a cluster
DROP = fixture("ftd_packettracer_drop")
TRACES = f"/api/fmc_troubleshoot/v1/domain/{DOMAIN}/packettracer/traces"
RULES = [
    {"id": "00000000-0000-0ed3-0000-000268434447", "name": "mcp-test-allow-out", "type": "AccessRule"},
    {"id": "00000000-0000-0ed3-0000-000268434450", "name": "mcp-test-quarantine-block", "type": "AccessRule"},
]


def with_user(trace: dict[str, Any], user: str, realm: str = "LAB") -> dict[str, Any]:
    t = copy.deepcopy(trace)
    for ph in t["deviceResponse"][0]["phases"]:
        if ph.get("subType") == "identity":
            ph["additionalInformation"] = (
                f"user id: 7, realm id: 2, device type: 0, auth type: passive, auth proto: basic, "
                f"username: {user}, AD domain: {realm},\nsrc sgt: 0, src sgt type: unknown"
            )
    return t


def dropped(reason: str, at: str, keep_rules: bool) -> dict[str, Any]:
    """The allow trace with a later (or earlier) non-policy drop."""
    t = copy.deepcopy(ALLOW)
    dr = t["deviceResponse"][0]
    dr["result"].update(action="drop", dropReason=reason)
    for ph in dr["phases"]:
        if ph["type"] == at:
            ph["result"] = "DROP"
    if not keep_rules:
        dr["phases"] = [ph for ph in dr["phases"] if ph["type"] in ("ROUTE-LOOKUP",)]
    return t


@pytest.fixture
def lab(ftd: respx.MockRouter) -> respx.MockRouter:  # noqa: F811
    _catalog(ftd)
    ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(RULES))
    ftd.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
    ftd.get(f"{CFG}/deviceclusters/ftddevicecluster").mock(return_value=items([]))
    ftd.get(f"{DEVPATH}/ftdallinterfaces").mock(return_value=items(RECORDED["ftdallinterfaces"]))
    return ftd


def tracer(lab: respx.MockRouter, answer: Any) -> respx.Route:
    def reply(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        return httpx.Response(200, json=answer(body))

    return lab.post(TRACES).mock(side_effect=reply)


async def call(args: dict[str, Any]) -> Any:
    return await call_tool(
        create_server(make_settings()), "fmc_prove_policy", {"response_format": "json", **args}
    )


# --- pure helpers -------------------------------------------------------------------------------------


def test_policy_verdict_and_user_seen() -> None:
    from fmc_mcp.tools.troubleshoot import summarize_trace

    (allow,) = summarize_trace(ALLOW, verbose=True)
    (drop,) = summarize_trace(DROP, verbose=True)
    assert policy_verdict(allow) == ("allow", None)
    assert policy_verdict(drop) == ("block", None)
    assert user_seen(allow) is None
    (alice,) = summarize_trace(with_user(ALLOW, "alice"), verbose=True)
    assert user_seen(alice) == "LAB\\alice"
    (arp,) = summarize_trace(
        dropped("(no-v4-adjacency) No valid V4 adjacency", "ADJACENCY-LOOKUP", True), True
    )
    assert policy_verdict(arp) == ("allow", "(no-v4-adjacency) No valid V4 adjacency")
    (route,) = summarize_trace(dropped("(no-route) No route to host", "ROUTE-LOOKUP", False), True)
    assert policy_verdict(route) == ("unknown", "(no-route) No route to host")


# --- fmc_prove_policy ------------------------------------------------------------------------------------


async def test_table_pass_fail_mismatch(lab: respx.MockRouter) -> None:
    post = tracer(lab, lambda b: DROP if b.get("destinationPort") == "23" else ALLOW)
    data = await call(
        {
            "device": "mcp-ftd1",
            "flows": [
                {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"},
                {
                    "source": "10.99.1.10",
                    "destination": "192.0.2.80",
                    "port": 23,
                    "expect": "block",
                    "name": "telnet",
                },
                {"source": "10.99.1.10", "destination": "192.0.2.80", "port": 23, "expect": "allow"},
                {
                    "source": "10.99.1.10",
                    "destination": "192.0.2.10",
                    "protocol": "icmp",
                    "expect": "allow",
                    "rule": "mcp-test-allow-web",
                },
            ],
        }
    )
    rows = data["results"]
    assert [r["result"] for r in rows] == ["pass", "pass", "fail", "mismatch"]
    assert rows[0]["rule"] == "mcp-test-allow-out"  # Snort's decision, named from the policy's rule ids
    assert (rows[0]["device"], rows[0]["input_interface"]) == ("mcp-ftd1", "inside")
    assert (
        rows[0]["flow"] == "icmp 10.99.1.10 -> 192.0.2.10"
        and rows[1]["flow"] == "tcp 10.99.1.10 -> 192.0.2.80:23"
    )
    assert rows[1]["name"] == "telnet" and rows[1]["verdict"] == "block (drop)"
    assert "acl-drop" in rows[2]["note"]
    assert rows[3]["note"] == "decided by mcp-test-allow-out, expected mcp-test-allow-web"
    assert (data["passed"], data["failed"], data["mismatch"], data["errors"], data["all_passed"]) == (
        2,
        1,
        1,
        0,
        False,
    )
    body = json.loads(post.calls[1].request.content)
    assert (body["protocol"], body["destinationPort"], body["interface"]["name"]) == ("TCP", "23", "inside")
    # one device: its interfaces and routes are read once for all four flows
    phys = [c for c in lab.calls if c.request.url.path.endswith("/physicalinterfaces")]
    every = [c for c in lab.calls if c.request.url.path.endswith("/ftdallinterfaces")]
    assert (len(every), len(phys)) == (1, 1)  # flow context (one read) + packet tracer's interface pick


async def test_device_found_from_interfaces_and_routes(lab: respx.MockRouter) -> None:
    tracer(lab, lambda b: ALLOW)
    data = await call(
        {
            "flows": [
                {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"},
                # 172.16.5.5 and 192.0.2.80 both leave by 'outside': this FTD doesn't carry it
                {"source": "172.16.5.5", "destination": "192.0.2.80", "port": 80, "expect": "allow"},
            ]
        }
    )
    ok, none = data["results"]
    assert ok["result"] == "pass" and ok["device"] == "mcp-ftd1"
    assert ok["device_found_by"].startswith("connected 10.99.1.0/24 -> ")
    assert none["result"] == "error" and "No device routes 172.16.5.5 -> 192.0.2.80" in none["note"]


async def test_user_flows_check_the_user_the_device_saw(lab: respx.MockRouter) -> None:
    tracer(lab, lambda b: with_user(ALLOW, "alice"))
    flows = [
        {
            "source": "10.99.1.10",
            "destination": "192.0.2.10",
            "protocol": "icmp",
            "user": "alice",
            "expect": "allow",
        },
        {
            "source": "10.99.1.10",
            "destination": "192.0.2.10",
            "protocol": "icmp",
            "user": "LAB\\bob",
            "expect": "allow",
        },
    ]
    alice, bob = (await call({"device": "mcp-ftd1", "flows": flows}))["results"]
    assert (alice["result"], alice["user_seen"]) == ("pass", "LAB\\alice")
    assert bob["result"] == "mismatch" and "sees LAB\\alice on 10.99.1.10, not LAB\\bob" in bob["note"]


async def test_user_without_source(lab: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    post = tracer(lab, lambda b: with_user(ALLOW, "alice"))
    flow = {"user": "alice", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
    monkeypatch.setattr(prove, "USER_IP_RESOLVERS", [])
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert row["result"] == "error" and "no user-to-IP lookup" in row["note"]
    assert not post.calls

    async def sessions(app: Any, user: str, domain: Any) -> list[str]:
        return ["10.99.1.10"] if user == "alice" else []

    monkeypatch.setattr(prove, "USER_IP_RESOLVERS", [sessions])
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert (row["result"], row["flow"]) == ("pass", "icmp 10.99.1.10 -> 192.0.2.10")
    (row,) = (await call({"device": "mcp-ftd1", "flows": [{**flow, "user": "LAB\\carol"}]}))["results"]
    assert row["result"] == "error" and "no active session" in row["note"]
    tracer(lab, lambda b: with_user(ALLOW, "bob"))
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert row["result"] == "mismatch" and "sees LAB\\bob on 10.99.1.10, not alice" in row["note"]


async def test_user_ip_comes_from_fmc_identity_sessions(lab: respx.MockRouter) -> None:
    """The wired-in resolver (identity_sources.user_ips): the user's newest FMC session gives the source."""
    tracer(lab, lambda b: with_user(ALLOW, "alice"))
    sessions = [
        {"currentIP": "10.99.1.10", "username": "alice", "realmName": "LAB", "lastSeen": 1792334300},
        {"currentIP": "10.99.1.99", "username": "alice", "realmName": "LAB", "lastSeen": 1792330000},
        {"currentIP": "10.99.1.20", "username": "malice", "realmName": "LAB", "lastSeen": 1792339999},
    ]
    route = lab.get(f"{CFG}/analysis/activesessions").mock(return_value=items(sessions))
    flow = {"user": "LAB\\alice", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert (row["result"], row["flow"]) == ("pass", "icmp 10.99.1.10 -> 192.0.2.10")
    assert route.calls.last.request.url.params["username"] == "alice"
    # no session for the user, then the API role without Analysis > Users: error rows that say why
    (row,) = (await call({"device": "mcp-ftd1", "flows": [{**flow, "user": "carol"}]}))["results"]
    assert row["result"] == "error" and "no active session" in row["note"]
    lab.get(f"{CFG}/analysis/activesessions").mock(return_value=httpx.Response(403, json={}))
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert row["result"] == "error" and "Analysis > Users" in row["note"]


async def test_user_ip_skips_an_ipv6_link_local_session(lab: respx.MockRouter) -> None:
    """Live on FMC 10.0.1: ISE gave a dual-stack client an IPv4 and an IPv6 link-local session with the same
    lastSeen, link-local listed first; the flow is traced from the IPv4 address."""
    post = tracer(lab, lambda b: with_user(ALLOW, "alice"))
    v4 = {"currentIP": "10.99.1.10", "username": "alice", "realmName": "LAB", "lastSeen": 1792334300}
    lab.get(f"{CFG}/analysis/activesessions").mock(return_value=items([{**v4, "currentIP": "fe80::a"}, v4]))
    flow = {"user": "LAB\\alice", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]
    assert (row["result"], row["flow"]) == ("pass", "icmp 10.99.1.10 -> 192.0.2.10")
    assert json.loads(post.calls.last.request.content)["sourceIPValue"] == "10.99.1.10"


async def test_user_ip_in_a_leaf_comes_from_global_sessions(lab: respx.MockRouter) -> None:
    """Live on FMC 10.0.1: the ISE source (and so its sessions) lives in Global only; a user flow without a
    source in the leaf domain takes the IP from Global's session instead of failing 'no active session'."""
    as_leaf(lab)
    post = tracer(lab, lambda b: with_user(ALLOW, "alice"))
    leaf = lab.get(f"{CFG}/analysis/activesessions").mock(return_value=items([]))
    alice = {"currentIP": "10.99.1.10", "username": "alice", "realmName": "LAB", "lastSeen": 1792334300}
    top = lab.get(f"{TOP_CFG}/analysis/activesessions").mock(return_value=items([alice]))
    flow = {"user": "LAB\\alice", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
    args = {"device": "mcp-ftd1", "flows": [flow], "domain": "Global/mcp-test-leaf"}
    (row,) = (await call(args))["results"]
    assert (row["result"], row["flow"], row["user_seen"]) == (
        "pass",
        "icmp 10.99.1.10 -> 192.0.2.10",
        "LAB\\alice",
    )
    assert leaf.called and top.calls.last.request.url.params["username"] == "alice"
    assert post.calls.last.request.url.path == TRACES  # traced on the leaf's device, as before
    # nobody logged in anywhere: still an error row, now saying the ancestors were read too
    top.mock(return_value=items([]))
    (row,) = (await call(args))["results"]
    assert row["result"] == "error" and "no active session" in row["note"] and "ancestors" in row["note"]


async def test_non_policy_drops_are_mismatches(lab: respx.MockRouter) -> None:
    answers = {
        "192.0.2.10": dropped("(no-v4-adjacency) No valid V4 adjacency", "ADJACENCY-LOOKUP", True),
        "192.0.2.99": dropped("(no-route) No route to host", "ROUTE-LOOKUP", False),
    }
    tracer(lab, lambda b: answers[b["destinationIPValue"]])
    flows = [
        {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"},
        {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "block"},
        {"source": "10.99.1.10", "destination": "192.0.2.99", "protocol": "icmp", "expect": "block"},
    ]
    arp_allow, arp_block, no_route = (await call({"device": "mcp-ftd1", "flows": flows}))["results"]
    assert arp_allow["result"] == "mismatch" and "the device drops it: (no-v4-adjacency)" in arp_allow["note"]
    assert arp_block["result"] == "fail" and arp_allow["verdict"] == "allow (drop)"
    assert no_route["result"] == "mismatch" and no_route["note"].startswith("not decided by the policy")


async def test_flow_limits_and_validation(lab: respx.MockRouter) -> None:
    from fastmcp.exceptions import ToolError

    flow = {"source": "10.99.1.10", "destination": "192.0.2.10", "expect": "allow"}
    with pytest.raises(ToolError):
        await call({"device": "mcp-ftd1", "flows": [flow] * 26})
    with pytest.raises(ToolError):
        await call({"device": "mcp-ftd1", "flows": [{**flow, "expect": "maybe"}]})
    tracer(lab, lambda b: ALLOW)
    (row,) = (await call({"device": "mcp-ftd1", "flows": [flow]}))["results"]  # tcp without a port
    assert row["result"] == "error" and "destination_port is required" in row["note"]


async def test_markdown_table(lab: respx.MockRouter) -> None:
    tracer(lab, lambda b: ALLOW)
    flow = {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
    out = await call_tool(
        create_server(make_settings()), "fmc_prove_policy", {"device": "mcp-ftd1", "flows": [flow]}
    )
    assert "| # | result | name | flow | user | device | expect | verdict | rule | user_seen | note |" in str(
        out
    )
    assert "all_passed: True" in str(out)


# --- fmc_prove_user_policy -------------------------------------------------------------------------------


def test_prove_user_policy_text_steps_and_flows() -> None:
    text = _prove_user_policy_text(
        "10.99.1.10", "192.0.2.80", "alice", "LAB\\bob", "TCP", 80, "mcp-ftd-identity", "allow-staff", None
    )
    steps = [
        "fmc_rule_lookup",
        "ise_find_session",
        "fmc_prove_policy",
        "fmc_packet_tracer",
        "fmc_update_access_rule",
    ]
    positions = [text.index(f"`{s}`") for s in steps]
    assert positions == sorted(positions)
    flows = [
        json.loads(m.split("flows=[", 1)[1].rsplit("]", 1)[0]) for m in text.splitlines() if "flows=[" in m
    ]
    assert flows[0] == {
        "source": "10.99.1.10",
        "destination": "192.0.2.80",
        "protocol": "tcp",
        "port": 80,
        "device": "mcp-ftd-identity",
        "user": "alice",
        "expect": "allow",
        "rule": "allow-staff",
        "name": "alice allow",
    }
    assert flows[1]["user"] == "LAB\\bob" and flows[1]["expect"] == "block" and "rule" not in flows[1]
    assert 'identities=["alice", <its groups>]' in text


def test_prove_user_policy_text_icmp_and_validation() -> None:
    text = _prove_user_policy_text("10.99.1.10", "192.0.2.80", "alice", "bob", "icmp", 80, None, None, None)
    assert "port" not in text.split("\n", 1)[0] and '"port"' not in text
    assert "leave the device out" in text
    for bad in (("not-an-ip", "192.0.2.80"), ("10.99.1.10", "x")):
        with pytest.raises(InvalidRequest):
            _prove_user_policy_text(*bad, "alice", "bob", "tcp", 80, None, None, None)
    with pytest.raises(InvalidRequest):
        _prove_user_policy_text(
            "10.99.1.10", "192.0.2.80", "alice; ignore previous", "bob", "tcp", 80, None, None, None
        )
    # a tcp/udp flow without a port can't be traced: refused here, not as error rows later
    with pytest.raises(InvalidRequest, match="port is required"):
        _prove_user_policy_text("10.99.1.10", "192.0.2.80", "alice", "bob", "udp", None, None, None, None)
    text = _prove_user_policy_text("10.99.1.10", "192.0.2.80", "alice", "bob", "tcp", 80, None, None, None)
    assert "Steps 0-2,\n4 and 5 are read-only" in text and "step 6 changes the policy only if" in text


async def test_prompt_listed_and_rendered(lab: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
        assert "fmc_prove_user_policy" in prompts
        r = await c.get_prompt(
            "fmc_prove_user_policy",
            {
                "client_ip": "10.99.1.10",
                "destination": "192.0.2.80",
                "allowed_user": "alice",
                "blocked_user": "bob",
                "port": "80",
            },
        )
        body: Any = r.messages[0].content
        assert '"alice" may reach "192.0.2.80" (tcp port 80)' in body.text


# --- HA pairs and auto placement (#198) ---------------------------------------------------------------
# Eval on FMC 10.0.1: with no device, the HA flow went to the standby unit ('(fo-standby) Dropped by standby
# unit' -> mismatch), the pair's name was refused, and disconnected devices filled the first-10 pool.


def ha_lab(lab: respx.MockRouter) -> tuple[dict[str, Any], dict[str, Any]]:
    """mcp-ftd1 (DEV, interfaces mocked) is the ACTIVE unit of the recorded pair; the standby unit and a
    disconnected device come first in the device list and have nothing mocked (touching them fails)."""
    pair = copy.deepcopy(fixture("ha_failover")["pair"])
    standby = {
        **DEV,
        "id": "0b000000-0000-4000-8000-00000000000b",
        "name": "mcp-fw-ha-b",
        "isConnected": True,
    }
    offline = {**DEV, "id": "0d000000-0000-4000-8000-00000000000d", "name": "mcp-ftd9", "isConnected": False}
    pair["primary"].update(id=DEV["id"], name=DEV["name"])
    pair["metadata"]["primaryStatus"]["device"].update(id=DEV["id"], name=DEV["name"])
    lab.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([offline, standby, {**DEV, "isConnected": True}])
    )
    lab.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([pair]))
    return pair, standby


async def test_auto_placement_skips_standby_and_disconnected_units(lab: respx.MockRouter) -> None:
    ha_lab(lab)
    tracer(lab, lambda b: ALLOW)
    data = await call(
        {
            "flows": [
                {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
            ]
        }
    )
    (row,) = data["results"]
    assert row["result"] == "pass", row
    assert row["device"] == "mcp-fw-ha (mcp-ftd1, active)"


async def test_ha_pair_name_means_the_active_unit(lab: respx.MockRouter) -> None:
    ha_lab(lab)
    post = tracer(lab, lambda b: ALLOW)
    data = await call(
        {
            "device": "mcp-fw-ha",
            "flows": [
                {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
            ],
        }
    )
    (row,) = data["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-fw-ha (mcp-ftd1, active)", row
    assert json.loads(post.calls.last.request.content)["device"]["id"] == DEV["id"]


async def test_trace_on_a_standby_unit_is_an_error_not_a_mismatch(lab: respx.MockRouter) -> None:
    ha_lab(lab)
    tracer(lab, lambda b: dropped("(fo-standby) Dropped by standby unit", "ROUTE-LOOKUP", True))
    data = await call(
        {
            "device": "mcp-ftd1",
            "flows": [
                {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}
            ],
        }
    )
    (row,) = data["results"]
    assert row["result"] == "error" and "standby unit" in row["note"], row


async def test_no_device_error_names_what_was_left_out(lab: respx.MockRouter) -> None:
    ha_lab(lab)
    tracer(lab, lambda b: ALLOW)
    data = await call(
        {"flows": [{"source": "172.16.5.5", "destination": "192.0.2.80", "port": 80, "expect": "allow"}]}
    )
    (row,) = data["results"]
    assert row["result"] == "error"
    assert (
        "mcp-ftd9 (disconnected)" in row["note"] and "mcp-fw-ha-b (standby unit of mcp-fw-ha)" in row["note"]
    )


# --- FMC 10.0.1 device records (metadata.containerDetails), clusters, all devices searched (#198) ---------

ICMP = {"source": "10.99.1.10", "destination": "192.0.2.10", "protocol": "icmp", "expect": "allow"}


def recorded(name: str, **kw: Any) -> dict[str, Any]:
    rec = copy.deepcopy(next(d for d in RECORDED["devicerecords"] if d["name"] == name))
    return {**rec, **kw}


def as_unit(name: str, **kw: Any) -> dict[str, Any]:
    """DEV (interfaces and routes mocked) in the place of a recorded HA unit or cluster node."""
    rec = recorded(name)
    meta = {
        **DEV["metadata"],
        "containerDetails": rec["metadata"]["containerDetails"],
        "isPartOfContainer": True,
    }
    return {**DEV, "metadata": meta, "isConnected": True, **kw}


def container_lab(lab: respx.MockRouter) -> respx.MockRouter:
    """The recorded layout: HA pair mcp-fw-ha (DEV as its active unit mcp-fw-ha-a, the standby connected),
    cluster mcp-sdwan-t3-cluster (control node disconnected, data node connected) and a disconnected
    standalone device; nothing but DEV has interfaces mocked."""
    records = [
        recorded("mcp-fw-ha-b"),  # connected standby: never a candidate
        recorded("mcp-sdwan-t3-hub2", isConnected=True),
        recorded("mcp-sdwan-t3-hub"),
        recorded("mcp-fw-branch1"),
        as_unit("mcp-fw-ha-a"),
    ]
    lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items(records))
    lab.get(f"{CFG}/devicehapairs/ftddevicehapairs", name="pairs").mock(return_value=items([]))
    lab.get(f"{CFG}/deviceclusters/ftddevicecluster", name="clusters").mock(
        return_value=items(RECORDED["clusters"])
    )
    return lab


async def test_recorded_containers_place_on_the_active_unit_and_say_what_was_left_out(
    lab: respx.MockRouter,
) -> None:
    container_lab(lab)
    post = tracer(lab, lambda b: ALLOW)
    data = await call({"flows": [ICMP]})
    (row,) = data["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-fw-ha (mcp-ftd1, active)", row
    assert json.loads(post.calls.last.request.content)["device"]["id"] == DEV["id"]
    assert data["not_checked"] == [
        "mcp-fw-ha-b (standby unit of mcp-fw-ha)",
        "mcp-sdwan-t3-hub2 (data node of mcp-sdwan-t3-cluster)",
        "mcp-sdwan-t3-hub (control node of mcp-sdwan-t3-cluster, disconnected)",
        "mcp-fw-branch1 (disconnected)",
    ]
    # FMC named the containers in the records: the HA pair and cluster collections were not read
    assert not lab.routes["pairs"].called and not lab.routes["clusters"].called


async def test_cluster_name_means_the_control_node(lab: respx.MockRouter) -> None:
    records = [recorded("mcp-sdwan-t3-hub2", isConnected=True), as_unit("mcp-sdwan-t3-hub")]
    lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items(records))
    post = tracer(lab, lambda b: ALLOW)
    (row,) = (await call({"device": "mcp-sdwan-t3-cluster", "flows": [ICMP]}))["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-sdwan-t3-cluster (mcp-ftd1, control)", row
    assert json.loads(post.calls.last.request.content)["device"]["id"] == DEV["id"]
    # and by the cluster's UUID (a devicerecords GET of that id is FMC's 404)
    cid = RECORDED["clusters"][0]["id"]
    lab.get(f"{CFG}/devices/devicerecords/{cid}").mock(return_value=httpx.Response(404, json={}))
    (row,) = (await call({"device": cid, "flows": [ICMP]}))["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-sdwan-t3-cluster (mcp-ftd1, control)", row


async def test_candidates_naming_a_standby_unit_trace_on_the_active_one(lab: respx.MockRouter) -> None:
    container_lab(lab)
    tracer(lab, lambda b: ALLOW)
    (row,) = (await call({"candidates": ["mcp-fw-ha-b"], "flows": [ICMP]}))["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-fw-ha (mcp-ftd1, active)", row


async def test_every_device_is_searched_with_one_interface_read_each(
    lab: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The eval's branch was the 19th of 19 devices: past the old first-10 pool. Devices without the source
    on a connected subnet cost one ftdallinterfaces read and no route reads."""
    others = [
        {
            **DEV,
            "id": f"0e000000-0000-4000-8000-0000000000{n:02d}",
            "name": f"mcp-ftd-x{n}",
            "isConnected": True,
        }
        for n in range(18)
    ]
    lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items([*others, {**DEV, "isConnected": True}]))
    lab.get(path__regex=r".*/devicerecords/0e000000-[^/]+/ftdallinterfaces$").mock(
        return_value=items(
            [
                {
                    "type": "PhysicalInterface",
                    "name": "Ethernet0/1",
                    "ifname": "inside",
                    "id": "x",
                    "enabled": True,
                    "ipv4": {"static": {"address": "10.50.1.1", "netmask": "24"}},
                }
            ]
        )
    )
    tracer(lab, lambda b: ALLOW)
    data = await call({"flows": [ICMP]})
    (row,) = data["results"]
    assert row["result"] == "pass" and row["device"] == "mcp-ftd1", row
    routes = [c.request.url.path for c in lab.calls if "/routing/" in c.request.url.path]
    assert routes and all(DEV["id"] in p for p in routes)
    assert "not_checked" not in data
    # past the cap: named as not checked
    monkeypatch.setattr(prove, "AUTO_DEVICE_CAP", 18)
    lab.get(path__regex=r".*/devicerecords/0e000000-[^/]+/routing/ipv[46]staticroutes$").mock(
        return_value=items([])
    )
    (row,) = (await call({"flows": [ICMP]}))["results"]
    assert (
        row["result"] == "error" and "mcp-ftd1 (over the first 18 devices; pass `candidates`)" in row["note"]
    )


async def test_packet_tracer_accepts_an_ha_pair_and_flags_a_standby_trace(lab: respx.MockRouter) -> None:
    ha_lab(lab)
    post = tracer(lab, lambda b: ALLOW)
    args = {"protocol": "icmp", "source_ip": "10.99.1.10", "destination_ip": "192.0.2.10"}
    out = await call_tool(
        create_server(make_settings()), "fmc_packet_tracer", {"device": "mcp-fw-ha", **args}
    )
    assert out["device"] == "mcp-fw-ha (mcp-ftd1, active)" and "note" not in out, out
    assert json.loads(post.calls.last.request.content)["device"]["id"] == DEV["id"]
    tracer(lab, lambda b: dropped("(fo-standby) Dropped by standby unit", "ROUTE-LOOKUP", True))
    out = await call_tool(create_server(make_settings()), "fmc_packet_tracer", {"device": "mcp-ftd1", **args})
    assert "standby unit" in out["note"] and "says nothing about the policy" in out["note"], out


async def test_packet_tracer_standby_note_matches_what_the_caller_named(lab: respx.MockRouter) -> None:
    """#228 review: the pair's name traced on FMC's 'active' unit that answers as standby means FMC's
    failover state is stale, not 'give the HA pair's name' (the caller did); a standby unit named directly
    gets the hint to name the pair. Same wording as fmc_prove_policy's error rows."""
    ha_lab(lab)
    tracer(lab, lambda b: dropped("(fo-standby) Dropped by standby unit", "ROUTE-LOOKUP", True))
    args = {"protocol": "icmp", "source_ip": "10.99.1.10", "destination_ip": "192.0.2.10"}
    server = create_server(make_settings())
    out = await call_tool(server, "fmc_packet_tracer", {"device": "mcp-fw-ha", **args})
    assert "FMC lists it as the active unit of mcp-fw-ha" in out["note"], out
    assert "give the HA pair's name" not in out["note"]
    (row,) = (await call({"device": "mcp-fw-ha", "flows": [ICMP]}))["results"]
    assert row["result"] == "error" and row["note"] == out["note"]
    standby = {**as_unit("mcp-fw-ha-b"), "name": "mcp-fw-ha-b"}  # FMC's record: SECONDARY, Standby
    lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items([standby]))
    out = await call_tool(server, "fmc_packet_tracer", {"device": "mcp-fw-ha-b", **args})
    assert out["device"] == "mcp-fw-ha (mcp-fw-ha-b, standby)"
    assert out["note"].endswith("trace on the active unit, or give the HA pair's name"), out


async def test_a_device_that_fails_to_resolve_is_read_once(lab: respx.MockRouter) -> None:
    """#228 review: an unknown device named by several flows is looked up once, every row an error."""
    listing = lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    tracer(lab, lambda b: ALLOW)
    flows = [{**ICMP, "device": "no-such-ftd"}, {**ICMP, "device": "no-such-ftd"}, ICMP]
    rows = (await call({"device": "mcp-ftd1", "flows": flows}))["results"]
    assert [r["result"] for r in rows] == ["error", "error", "pass"]
    assert "no-such-ftd" in rows[0]["note"] and rows[1]["note"] == rows[0]["note"]
    # no-such-ftd: the name lookup and the pair/cluster lookup once (not again for the second flow), then
    # mcp-ftd1's name lookup
    reads = [c for c in listing.calls if c.request.url.params.get("expanded") == "true"]
    assert len(reads) == 3
