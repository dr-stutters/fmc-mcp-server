"""F68: fleet show commands (bulkcommands with the per-device fallback FMC 10.0.1 needs) and device groups
(CRUD, and group names in the fleet tools), against the live-recorded shapes in tests/fixtures/fleet_show.json
(the bulk task shape is built from the 10.0.1 schema, see its _source)."""

import asyncio
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server

from .conftest import CFG, ConcurrentFmc, fixture, items, make_settings

FX = fixture("fleet_show")
A, B, C, D = (f"a0000000-0000-4000-8000-00000000000{x}" for x in "abcd")
HA_ID, HA_A, HA_B = (
    "b0000000-0000-4000-8000-000000000001",
    "b0000000-0000-4000-8000-0000000000aa",
    "b0000000-0000-4000-8000-0000000000bb",
)
GROUP_ID = "c0000000-0000-4000-8000-000000000001"


def dev(i: str, name: str, connected: bool = True, **kw: Any) -> dict[str, Any]:
    return {
        "id": i,
        "name": name,
        "type": "Device",
        "isConnected": connected,
        "license_caps": ["ESSENTIALS"],
        **kw,
    }


def unit(i: str, name: str, role: str, status: str) -> dict[str, Any]:
    box = {"id": HA_ID, "name": "fw-ha", "type": "DeviceHAPair", "role": role, "status": status}
    return dev(i, name, metadata={"containerDetails": box})


DEVICES = [
    dev(A, "ftd-a"),
    dev(B, "ftd-b"),
    dev(C, "ftd-c"),
    dev(D, "ftd-d", connected=False),
    unit(HA_A, "fw-ha-a", "PRIMARY", "Active"),
    unit(HA_B, "fw-ha-b", "SECONDARY", "Standby"),
]
BY_ID = {d["id"]: d for d in DEVICES}
GROUP = {
    "id": GROUP_ID,
    "type": "DeviceGroup",
    "name": "branches",
    "members": [
        {"id": A, "type": "Device", "name": "ftd-a"},
        {"id": B, "type": "Device", "name": "ftd-b"},
        {"id": HA_ID, "type": "DeviceHAPair", "name": "fw-ha"},
    ],
    "metadata": {
        "domain": {"id": "e276abec-e0f2-11e3-8169-6d9ed49b625f", "name": "Global", "type": "Domain"}
    },
}
BULK = f"{CFG}/devices/devicerecords/operational/bulkcommands"


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def cmd_path(i: str) -> str:
    return f"{CFG}/devices/devicerecords/{i}/operational/commands"


@pytest.fixture
def fleet(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items(DEVICES))
    for d in DEVICES:
        fmc.get(f"{CFG}/devices/devicerecords/{d['id']}").mock(return_value=httpx.Response(200, json=d))
    fmc.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=items([GROUP]))
    fmc.get(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP)
    )
    fmc.get(f"{CFG}/devices/devicerecords/{HA_ID}").mock(return_value=httpx.Response(404, json={}))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
    fmc.get(f"{CFG}/deviceclusters/ftddevicecluster").mock(return_value=items([]))
    return fmc


def version_text(name: str, uid: str | None = None) -> str:
    """The recorded 'show version' as device `name` prints it: its banner and its own UUID line."""
    out = FX["show_version_200"]["items"][0]["commandOutput"].replace("ftd-a", name)
    return out.replace(A, uid or next((d["id"] for d in DEVICES if d["name"] == name), A))


def show_ok(name: str, text: str | None = None) -> httpx.Response:
    return items(
        [{"commandInput": "show version", "commandOutput": text or version_text(name), "type": "command"}]
    )


# --- fleet show commands ------------------------------------------------------------------------------


async def test_feature_flag_403_falls_back_per_device_and_is_remembered(fleet: respx.MockRouter) -> None:
    """FMC 10.0.1 refuses bulkcommands (feature flag): one POST, then one GET per connected device; the
    unreachable device's sftunnel 500 is its row (sent once, not retried), the disconnected one gets no
    request, and the next call goes straight to the per-device path."""
    bulk = fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    ga = fleet.get(cmd_path(A)).mock(return_value=show_ok("ftd-a"))
    gb = fleet.get(cmd_path(B)).mock(return_value=show_ok("ftd-b"))
    gc = fleet.get(cmd_path(C)).mock(return_value=httpx.Response(500, json=FX["sftunnel_500"]))
    gd = fleet.get(cmd_path(D)).mock(return_value=show_ok("ftd-d"))
    args = {"devices": ["ftd-a", "ftd-b", "ftd-c", "ftd-d"], "command": "show version", "match": " days "}
    async with Client(server(retries=2)) as c:
        out = await run(c, "fmc_run_show_command", args)
        again = await run(c, "fmc_run_show_command", {**args, "devices": ["ftd-a"]})
    assert bulk.call_count == 1
    assert json.loads(bulk.calls.last.request.content) == {"command": "show version", "devices": [A, B, C]}
    assert (ga.call_count, gb.call_count, gc.call_count, gd.call_count) == (2, 1, 1, 0)
    assert out["path"] == "per-device" and "Feature Flag" in out["notes"][0]
    assert "FMC_USERNAME" not in out["notes"][0]  # a feature flag, not a login problem
    assert out["devices"] == 4 and out["succeeded"] == 2 and out["failed"] == ["ftd-c", "ftd-d"]
    rows = {r["device"]: r for r in out["results"]}
    assert rows["ftd-a"]["ok"] and rows["ftd-a"]["output"] == "ftd-a up 2 days 9 hours"
    assert rows["ftd-a"]["matched_lines"] == 1 and out["devices_matching"] == ["ftd-a", "ftd-b"]
    assert (
        "can't reach the device" in rows["ftd-c"]["error"] and "SFTunnelException" in rows["ftd-c"]["error"]
    )
    assert "disconnected" in rows["ftd-d"]["error"]
    assert again["path"] == "per-device" and bulk.call_count == 1
    assert ga.calls.last.request.url.params["command"] == "show version"


async def test_fmc_mixing_concurrent_answers_cannot_mix_up_rows(fleet: respx.MockRouter) -> None:
    """Live 2026-10-21 (concurrent_mixup, run 1): eight requests at once gave all six rows one device's
    'UUID : ...' line. The per-device path now sends one request at a time, so each row is its own."""
    rec = FX["concurrent_mixup"]["runs"][0]
    assert set(rec["answered_with"].values()) == {"spoke2"}  # what FMC did with concurrent requests
    fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    names = {A: "ftd-a", B: "ftd-b", C: "ftd-c", HA_A: "fw-ha-a", HA_B: "fw-ha-b"}
    fmc = ConcurrentFmc({i: version_text(n) for i, n in names.items()}).mount(fleet)
    args = {"devices": ["ftd-a", "ftd-b", "ftd-c", "fw-ha"], "command": rec["command"], "match": rec["match"]}
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", args)
    assert fmc.peak == 1 and len(fmc.calls) == 5
    assert {r["device"]: r["output"] for r in out["results"]} == {
        n: f"UUID                      : {i}" for i, n in names.items()
    }


async def test_fleet_ip_brief_rows_carry_each_devices_addresses(fleet: respx.MockRouter) -> None:
    """Live (concurrent_mixup, run 3): a group's 'show interface ip brief' gave every member the hub's
    addresses. Recorded outputs on two devices: each row has its own."""
    rec = FX["concurrent_mixup"]
    assert set(rec["runs"][2]["answered_with"].values()) == {"hub"}
    hub, spoke = rec["show_interface_ip_brief"]["hub"], rec["show_interface_ip_brief"]["spoke1"]
    fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    fmc = ConcurrentFmc({A: hub, B: spoke}).mount(fleet)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_run_show_command",
            {"devices": ["ftd-a", "ftd-b"], "command": "show interface ip brief", "match": "Ethernet0/0"},
        )
    rows = {r["device"]: r["output"] for r in out["results"]}
    assert fmc.peak == 1
    assert "192.0.2.66" in rows["ftd-a"] and "192.0.2.2 " in rows["ftd-b"]


async def test_concurrent_tool_calls_share_one_show_lock(fleet: respx.MockRouter) -> None:
    """Two sessions' show commands at the same moment still reach FMC one after the other."""
    fmc = ConcurrentFmc({A: version_text("ftd-a"), B: version_text("ftd-b")}).mount(fleet)
    async with Client(server()) as c:
        a, b = await asyncio.gather(
            run(c, "fmc_run_show_command", {"device": "ftd-a", "command": "show version", "match": "UUID"}),
            run(c, "fmc_run_show_command", {"device": "ftd-b", "command": "show version", "match": "UUID"}),
        )
    assert fmc.peak == 1
    assert A in a["output"] and B in b["output"]


async def test_an_answer_naming_another_device_is_asked_again(fleet: respx.MockRouter) -> None:
    """An answer whose UUID line names another device (another API client's request ran at the same
    time) is sent once more; a second wrong answer is that device's failure, never its output."""
    fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    ga = fleet.get(cmd_path(A)).mock(side_effect=[show_ok("ftd-b"), show_ok("ftd-a")])
    gb = fleet.get(cmd_path(B)).mock(return_value=show_ok("ftd-c"))
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", {"devices": ["ftd-a", "ftd-b"], "command": "show version"})
        with pytest.raises(ToolError, match=rf"twice with the output of device {C}"):
            await run(c, "fmc_run_show_command", {"device": "ftd-b", "command": "show version"})
    assert ga.call_count == 2 and gb.call_count == 4
    rows = {r["device"]: r for r in out["results"]}
    assert rows["ftd-a"]["ok"] and f"UUID                      : {A}" in rows["ftd-a"]["output"]
    assert not rows["ftd-b"]["ok"] and "mixes up show commands" in rows["ftd-b"]["error"]
    assert out["failed"] == ["ftd-b"]


async def test_a_wedged_device_holds_the_show_lock_for_one_request_not_its_retries(
    fleet: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device whose show command times out is retried (retries=2) with the back-off spent outside the show
    lock: another device's command goes in between, so a wedged but connected FTD delays the others by one
    request (at most SHOW_TIMEOUT), not by every retry (~6 min with 120 s and two retries)."""
    monkeypatch.setattr("fmc_mcp.tools.troubleshoot.SHOW_BACKOFF", 0.01)
    order: list[str] = []
    first = asyncio.Event()

    async def wedged(request: httpx.Request) -> httpx.Response:
        order.append("a")
        if not first.is_set():
            first.set()
            await asyncio.sleep(0.3)  # holds the lock while ftd-b's call arrives and waits for it
        raise httpx.ReadTimeout("no answer", request=request)

    def fine(request: httpx.Request) -> httpx.Response:
        order.append("b")
        return show_ok("ftd-b")

    fleet.get(cmd_path(A)).mock(side_effect=wedged)
    fleet.get(cmd_path(B)).mock(side_effect=fine)
    async with Client(server(retries=2)) as c:
        slow = asyncio.create_task(
            c.call_tool(
                "fmc_run_show_command", {"device": "ftd-a", "command": "show version"}, raise_on_error=False
            )
        )
        await first.wait()
        b = await run(
            c, "fmc_run_show_command", {"device": "ftd-b", "command": "show version", "match": "UUID"}
        )
        a = await slow
    assert order == ["a", "b", "a", "a"]  # the lock held across retries gave a, a, a, b
    assert a.is_error and "timed out" in a.content[0].text  # type: ignore[union-attr]
    assert B in b["output"]


def banner_only(name: str) -> str:
    """'show version' as device `name` prints it, without its UUID line (only the banner names it)."""
    return "\n".join(ln for ln in version_text(name).splitlines() if not ln.startswith("UUID"))


async def test_an_answer_whose_banner_names_another_device_of_the_run_is_a_failure(
    fleet: respx.MockRouter,
) -> None:
    """Identity canary at no cost: an answer whose 'show version' banner names another device of the run is
    that row's failure, never its output. A hostname outside the run, or an HA peer's (units may print the
    same hostname), is no evidence."""
    fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    answers = {A: "ftd-b", B: "ftd-b", C: "firepower", HA_A: "fw-ha-b", HA_B: "fw-ha-b"}
    for i, banner in answers.items():
        fleet.get(cmd_path(i)).mock(return_value=show_ok(BY_ID[i]["name"], banner_only(banner)))
    args = {"devices": ["ftd-a", "ftd-b", "ftd-c", "fw-ha"], "command": "show version"}
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", args)
    rows = {r["device"]: r for r in out["results"]}
    assert out["failed"] == ["ftd-a"]
    assert "another device's output (its 'show version' banner names 'ftd-b')" in rows["ftd-a"]["error"]
    assert all(rows[n]["ok"] for n in ("ftd-b", "ftd-c", "fw-ha-a", "fw-ha-b"))


async def test_a_bulk_answer_naming_another_device_is_a_failure(fleet: respx.MockRouter) -> None:
    """The same canary on bulkcommands answers (where FMC enables it): a device's row whose UUID line names
    another device is a failure."""
    rows = [
        {"device": {"id": A}, "commandOutput": version_text("ftd-b")},
        {"device": {"id": B}, "commandOutput": version_text("ftd-b")},
    ]
    fleet.post(BULK).mock(return_value=items(rows))
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", {"devices": [A, B], "command": "show version"})
    got = {r["device"]: r for r in out["results"]}
    assert out["path"] == "bulkcommands" and out["failed"] == ["ftd-a"]
    assert f"its UUID line names device {B}" in got["ftd-a"]["error"] and got["ftd-b"]["ok"]


async def test_bulk_task_shape_from_the_schema(fleet: respx.MockRouter) -> None:
    """Where FMC enables bulkcommands: the answer is a task whose subTasks carry each device's output (by the
    10.0.1 schema); a device the task doesn't mention is asked on its own."""
    shape = FX["bulk_task_schema"]
    bulk = fleet.post(BULK).mock(return_value=httpx.Response(202, json=shape["response"]))
    task = fleet.get(f"{CFG}/job/taskstatuses/{shape['task']['id']}").mock(
        return_value=httpx.Response(200, json=shape["task"])
    )
    ga = fleet.get(cmd_path(A)).mock(return_value=show_ok("ftd-a"))
    gc = fleet.get(cmd_path(C)).mock(return_value=show_ok("ftd-c", "ftd-c up 1 day"))
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", {"devices": [A, B, C], "command": "show version"})
    assert bulk.call_count == 1 and task.call_count == 1
    assert ga.call_count == 0 and gc.call_count == 1  # C: not in the task's subTasks
    assert out["path"] == "bulkcommands + per-device"
    rows = {r["device"]: r for r in out["results"]}
    assert rows["ftd-a"]["ok"] and "9.24(1)" in rows["ftd-a"]["output"]
    assert not rows["ftd-b"]["ok"] and "Cannot establish" in rows["ftd-b"]["error"]
    assert rows["ftd-c"]["output"] == "ftd-c up 1 day"


async def test_group_and_ha_pair_run_on_their_units(fleet: respx.MockRouter) -> None:
    fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    for i, n in ((A, "ftd-a"), (B, "ftd-b"), (HA_A, "fw-ha-a"), (HA_B, "fw-ha-b")):
        fleet.get(cmd_path(i)).mock(return_value=show_ok(n, f"This host: {n}\nOther host: peer"))
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", {"group": "branches", "command": "show failover state"})
        pair = await run(c, "fmc_run_show_command", {"devices": ["fw-ha"], "command": "show failover state"})
    assert [r["device"] for r in out["results"]] == ["ftd-a", "ftd-b", "fw-ha-a", "fw-ha-b"]
    assert out["groups"] == {"branches": ["ftd-a", "ftd-b", "fw-ha-a", "fw-ha-b"]}
    assert [r["device"] for r in pair["results"]] == ["fw-ha-a", "fw-ha-b"]
    assert all(r["ok"] and "Other host" in r["output"] for r in out["results"])


async def test_checks_before_any_call(fleet: respx.MockRouter) -> None:
    bulk = fleet.post(BULK).mock(return_value=httpx.Response(403, json=FX["bulk_refused_403"]))
    many = [dev(f"d0000000-0000-4000-8000-{i:012d}", f"spoke{i}") for i in range(26)]
    fleet.get(f"{CFG}/devices/devicerecords").mock(return_value=items(many))
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="at most 25"):
            await run(c, "fmc_run_show_command", {"devices": [d["name"] for d in many], "command": "show ip"})
        with pytest.raises(ToolError, match="not both"):
            await run(
                c, "fmc_run_show_command", {"device": "spoke1", "group": "branches", "command": "show ip"}
            )
        with pytest.raises(ToolError, match="Pass device, devices or group"):
            await run(c, "fmc_run_show_command", {"command": "show ip"})
        with pytest.raises(ToolError, match="not supported by FMC's command API"):
            await run(c, "fmc_run_show_command", {"devices": ["spoke1"], "command": "show bgp summary"})
        with pytest.raises(ToolError, match=r"'nope', 'spoke99'"):
            await run(
                c, "fmc_run_show_command", {"devices": ["spoke1", "nope", "spoke99"], "command": "show ip"}
            )
    assert bulk.call_count == 0


async def test_single_device_path_is_unchanged(fleet: respx.MockRouter) -> None:
    bulk = fleet.post(BULK)
    get = fleet.get(cmd_path(A)).mock(return_value=show_ok("ftd-a"))
    async with Client(server()) as c:
        out = await run(
            c, "fmc_run_show_command", {"device": "ftd-a", "command": "show version", "match": "Serial"}
        )
    assert set(out) == {"device", "command", "output", "matched_lines"} and out["matched_lines"] == 1
    assert get.call_count == 1 and bulk.call_count == 0


async def test_run_fleet_several_commands_one_device_at_a_time(fleet: respx.MockRouter) -> None:
    """The runner F73 builds on: several commands on several devices, one row per device and command."""
    from fmc_mcp.client import FmcApp
    from fmc_mcp.tools.fleet import _bulk_off, run_fleet

    fleet.get(cmd_path(A)).mock(side_effect=lambda r: show_ok("ftd-a", f"a {r.url.params['command']}"))
    fleet.get(cmd_path(B)).mock(side_effect=lambda r: show_ok("ftd-b", f"b {r.url.params['command']}"))
    app = FmcApp(make_settings())
    _bulk_off[app] = "test: bulk off"
    try:
        run = await run_fleet(
            None,  # type: ignore[arg-type]
            app,
            [BY_ID[A], BY_ID[B], BY_ID[D]],
            ["show route", "show crypto ikev2 sa"],
            None,
        )
    finally:
        await app.aclose()
    assert run.path == "per-device"
    assert [(r["device"], r["command"], r["ok"]) for r in run.rows] == [
        ("ftd-a", "show route", True),
        ("ftd-a", "show crypto ikev2 sa", True),
        ("ftd-b", "show route", True),
        ("ftd-b", "show crypto ikev2 sa", True),
        ("ftd-d", "show route", False),
        ("ftd-d", "show crypto ikev2 sa", False),
    ]
    assert run.rows[1]["text"] == "a show crypto"


# --- device groups --------------------------------------------------------------------------------------


async def test_list_device_groups(fleet: respx.MockRouter) -> None:
    async with Client(server()) as c:
        rows = await run(c, "fmc_list_device_groups", {"response_format": "json"})
        one = await run(c, "fmc_list_device_groups", {"group": "BRANCHES", "response_format": "json"})
    row = rows["results"][0]
    assert row["name"] == "branches" and row["member_count"] == 3 and row["pairs_and_clusters"] == ["fw-ha"]
    assert one["members"][2] == {"id": HA_ID, "type": "DeviceHAPair", "name": "fw-ha"}


async def test_create_group_maps_units_to_their_pair_and_flags_moves(fleet: respx.MockRouter) -> None:
    post = fleet.post(f"{CFG}/devicegroups/devicegrouprecords").mock(
        return_value=httpx.Response(201, json={**GROUP, "id": "new", "name": "t1"})
    )
    args = {"name": "t1", "devices": ["ftd-c", "fw-ha-b", "ftd-a"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_device_group", args)
        dup = await run(c, "fmc_create_device_group", {**args, "name": "Branches"})
        await run(c, "fmc_create_device_group", {**args, "confirm": preview["confirm"]})
    assert preview["status"] == "preview" and preview["preview"]["members"] == ["ftd-c", "fw-ha", "ftd-a"]
    assert "fw-ha-b is a unit of fw-ha" in preview["preview"]["notes"][0]
    moves = " ".join(preview["side_effects"])
    assert "fw-ha is in device group 'branches'" in moves and "ftd-a is in device group" in moves
    assert dup["status"] == "blocked"
    assert json.loads(post.calls.last.request.content) == {
        "name": "t1",
        "type": "DeviceGroup",
        "members": [
            {"id": C, "type": "Device", "name": "ftd-c"},
            {"id": HA_ID, "type": "DeviceHAPair", "name": "fw-ha"},
            {"id": A, "type": "Device", "name": "ftd-a"},
        ],
    }


async def test_update_group_add_remove_and_unknown(fleet: respx.MockRouter) -> None:
    put = fleet.put(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP)
    )
    args = {"group": "branches", "add": ["ftd-c"], "remove": ["fw-ha-a", "ftd-b"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_device_group", args)
        bad = await run(c, "fmc_update_device_group", {"group": "branches", "remove": ["ftd-c"]})
        none = await run(c, "fmc_update_device_group", {"group": "branches", "add": ["ftd-a"]})
        with pytest.raises(ToolError, match="No device, HA pair or cluster named 'ghost'"):
            await run(c, "fmc_update_device_group", {"group": "branches", "add": ["ghost"]})
        await run(c, "fmc_update_device_group", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert p["added"] == ["ftd-c"] and p["removed"] == ["fw-ha", "ftd-b"]
    assert p["members_after"] == ["ftd-a", "ftd-c"]
    assert bad["status"] == "blocked" and "ftd-c is not in 'branches'" in bad["blockers"][0]
    assert none["status"] == "blocked" and none["blockers"] == ["Nothing to change."]
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == GROUP_ID and [m["id"] for m in body["members"]] == [A, C]


async def test_delete_group(fleet: respx.MockRouter) -> None:
    delete = fleet.delete(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP)
    )
    async with Client(server()) as c:
        preview = await run(c, "fmc_delete_device_group", {"group": GROUP_ID})
        done = await run(c, "fmc_delete_device_group", {"group": GROUP_ID, "confirm": preview["confirm"]})
    assert "ungrouped: ftd-a, ftd-b, fw-ha" in preview["side_effects"][0]
    assert delete.call_count == 1 and done["result"]["deleted"] == "branches"


async def test_a_name_that_is_both_device_and_group_is_refused(fleet: respx.MockRouter) -> None:
    clash = {**GROUP, "name": "ftd-a"}
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=items([clash]))
    fleet.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([]))
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="name of a device and of a device group"):
            await run(c, "fmc_deploy", {"devices": ["ftd-a"]})
        out = await run(c, "fmc_deploy", {"devices": ["group:ftd-a"]})
        with pytest.raises(ToolError, match="No device group 'nope'"):
            await run(c, "fmc_deploy", {"devices": ["group:nope"]})
    assert out["status"] == "blocked" and out["preview"]["groups"]["ftd-a"] == ["ftd-a", "ftd-b", "fw-ha"]


# --- group names in the fleet tools ------------------------------------------------------------------


def pending(i: str, name: str, kind: str = "Device") -> dict[str, Any]:
    return {
        "name": name,
        "device": {"id": i, "name": name, "type": kind},
        "version": "1791980000000",
        "canBeDeployed": True,
        "upToDate": False,
        "policyStatusList": [{"policy": {"type": "AccessPolicy", "name": "acp"}, "upToDate": False}],
    }


async def test_deploy_by_group_skips_members_without_pending_changes(fleet: respx.MockRouter) -> None:
    fleet.get(f"{CFG}/deployment/deployabledevices").mock(
        return_value=items([pending(A, "ftd-a"), pending(HA_ID, "fw-ha", "DeviceHAPair")])
    )
    fleet.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
    fleet.get(f"{CFG}/devicehapairs/ftddevicehapairs/{HA_ID}").mock(
        return_value=httpx.Response(
            200, json={"id": HA_ID, "name": "fw-ha", "primary": {"id": HA_A}, "secondary": {"id": HA_B}}
        )
    )
    post = fleet.post(f"{CFG}/deployment/deploymentrequests").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "t9"}}})
    )
    async with Client(server()) as c:
        preview = await run(c, "fmc_deploy", {"devices": ["branches"], "wait": False})
        await run(c, "fmc_deploy", {"devices": ["branches"], "wait": False, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert [d["device"] for d in p["devices"]] == ["ftd-a", "fw-ha"]
    assert p["skipped_no_pending_changes"] == ["ftd-b"] and p["groups"]["branches"] == [
        "ftd-a",
        "ftd-b",
        "fw-ha",
    ]
    assert json.loads(post.calls.last.request.content)["deviceList"] == [A, HA_ID]


async def test_assign_policy_by_group(fleet: respx.MockRouter) -> None:
    acp = {"id": "00000000-0000-0ed3-0000-000000000001", "name": "acp-new", "type": "AccessPolicy"}
    fleet.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    fleet.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    fleet.get(f"{CFG}/devicehapairs/ftddevicehapairs/{HA_ID}").mock(
        return_value=httpx.Response(200, json={"id": HA_ID, "name": "fw-ha", "type": "DeviceHAPair"})
    )
    post = fleet.post(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(201, json={}))
    args = {"kind": "access", "policy": "acp-new", "devices": ["group:branches"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    assert [ch["device"] for ch in preview["preview"]["changes"]] == ["ftd-a", "ftd-b", "fw-ha"]
    targets = json.loads(post.calls.last.request.content)["targets"]
    assert targets == [
        {"id": A, "type": "Device"},
        {"id": B, "type": "Device"},
        {"id": HA_ID, "type": "DeviceHAPair"},
    ]


async def test_backup_by_group_uses_units(fleet: respx.MockRouter) -> None:
    post = fleet.post(f"{CFG}/backup/operational/devicebackup").mock(
        return_value=httpx.Response(202, json={})
    )
    args = {"devices": ["group:branches"], "wait": False}
    async with Client(server()) as c:
        preview = await run(c, "fmc_backup_devices", args)
        await run(c, "fmc_backup_devices", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["devices"] == ["ftd-a", "ftd-b", "fw-ha-a", "fw-ha-b"]
    assert [d["id"] for d in json.loads(post.calls.last.request.content)["devices"]] == [A, B, HA_A, HA_B]


async def test_licences_by_group_one_preview(fleet: respx.MockRouter) -> None:
    fleet.get(f"{CFG}/devices/devicerecords/{B}").mock(
        return_value=httpx.Response(200, json={**BY_ID[B], "license_caps": ["ESSENTIALS", "IPS"]})
    )
    puts = {
        i: fleet.put(f"{CFG}/devices/devicerecords/{i}").mock(return_value=httpx.Response(200, json={}))
        for i in (A, B, HA_A, HA_B)
    }
    args = {"device": "branches", "add": ["IPS"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_device_licenses", args)
        done = await run(c, "fmc_set_device_licenses", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert [ch["device"] for ch in p["changes"]] == ["ftd-a", "fw-ha-a", "fw-ha-b"] and p["unchanged"] == [
        "ftd-b"
    ]
    assert preview["blast_radius"] == 3
    assert puts[B].call_count == 0 and all(puts[i].call_count == 1 for i in (A, HA_A, HA_B))
    assert json.loads(puts[A].calls.last.request.content)["license_caps"] == ["ESSENTIALS", "IPS"]
    assert done["result"]["group"] == "branches" and len(done["result"]["updated"]) == 3


async def test_device_metrics_by_group_runs_each_member(fleet: respx.MockRouter) -> None:
    metrics = fleet.get(f"{CFG}/health/metrics").mock(return_value=httpx.Response(200, json={"items": []}))
    async with Client(server()) as c:
        args = {"device": "branches", "metric": "cpu", "since": "30m"}
        out = await run(c, "fmc_device_metrics", {**args, "response_format": "json"})
        md = (await c.call_tool("fmc_device_metrics", args)).content[0].text  # type: ignore[union-attr]
    assert out["group"] == "branches" and out["devices"] == 4
    assert [r["device"] for r in out["results"]] == ["ftd-a", "ftd-b", "fw-ha-a", "fw-ha-b"]
    assert all(r["result"]["device"] == r["device"] for r in out["results"])
    assert metrics.call_count == 8  # one family (cpu) per member, twice
    assert md.startswith("**Device group branches**: 4 device(s)") and "### fw-ha-b" in md
    asked = {c.request.url.params["filter"].split(";")[0] for c in metrics.calls}
    assert asked == {f"deviceUUIDs:{i}" for i in (A, B, HA_A, HA_B)}


def test_health_review_takes_a_group_and_uses_fleet_calls() -> None:
    from fmc_mcp.tools.prompts import _health_review_text

    text = _health_review_text("Global/mcp-test-leaf", None, 24, group="mcp-w6-t1")
    assert 'devices of device group "mcp-w6-t1"' in text
    assert '`fmc_list_device_groups` with group="mcp-w6-t1"' in text
    assert 'device="group:mcp-w6-t1" runs it on every device of the group' in text
    assert "command='show crypto ikev2 sa'" in text and "command='show failover state'" in text
    plain = _health_review_text(None, None, 24)
    assert "group:" not in plain and "one fleet call" in plain


# --- review fixes ---------------------------------------------------------------------------------------


async def test_moves_are_found_when_the_group_list_has_no_members(fleet: respx.MockRouter) -> None:
    """The spec's list example has no `members` (only name/id/type): the 'in another group' warning must
    read each group instead of finding nothing."""
    bare = {k: GROUP[k] for k in ("id", "type", "name")}
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=items([bare]))
    one = fleet.get(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP)
    )
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_device_group", {"name": "t1", "devices": ["ftd-a", "ftd-c"]})
        listed = await run(c, "fmc_list_device_groups", {"response_format": "json"})
    assert any("ftd-a is in device group 'branches'" in s for s in preview["side_effects"])
    assert not any("ftd-c" in s for s in preview["side_effects"])
    assert listed["results"][0]["member_count"] == 3 and one.called


async def test_list_device_groups_reads_members_for_the_page_only(fleet: respx.MockRouter) -> None:
    bare = [
        {"id": f"c0000000-0000-4000-8000-00000000010{i}", "type": "DeviceGroup", "name": f"g{i}"}
        for i in range(3)
    ]
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=items(bare))
    reads = [
        fleet.get(f"{CFG}/devicegroups/devicegrouprecords/{g['id']}").mock(
            return_value=httpx.Response(
                200, json={**g, "members": [{"id": A, "type": "Device", "name": "ftd-a"}]}
            )
        )
        for g in bare
    ]
    async with Client(server()) as c:
        out = await run(c, "fmc_list_device_groups", {"limit": 1, "offset": 1, "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["g1"] and out["results"][0]["members"] == ["ftd-a"]
    assert [r.call_count for r in reads] == [0, 1, 0]


async def test_update_group_preview_shows_rename_and_description(fleet: respx.MockRouter) -> None:
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json={**GROUP, "description": "old text"})
    )
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords").mock(
        return_value=items([{**GROUP, "description": "old text"}])
    )
    put = fleet.put(f"{CFG}/devicegroups/devicegrouprecords/{GROUP_ID}").mock(
        return_value=httpx.Response(200, json=GROUP)
    )
    args = {"group": "branches", "description": "new text", "new_name": "spokes"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_device_group", args)
        only_desc = await run(c, "fmc_update_device_group", {"group": "branches", "description": "new text"})
        await run(c, "fmc_update_device_group", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert p["name"] == {"from": "branches", "to": "spokes"}
    assert p["description"] == {"from": "old text", "to": "new text"}
    assert "description changed" in only_desc["action"] and only_desc["status"] == "preview"
    body = json.loads(put.calls.last.request.content)
    assert body["name"] == "spokes" and body["description"] == "new text" and len(body["members"]) == 3


GROUPS_FMC10 = fixture("device_groups_fmc10")


def recorded_group(fleet: respx.MockRouter) -> tuple[dict[str, Any], respx.Route]:
    """FMC 10.0.1's expanded device-group list as recorded live (members included), and the per-group
    GET route (never needed for it)."""
    listing = GROUPS_FMC10["list_expanded"]
    grp = listing["items"][0]
    fleet.get(f"{CFG}/devicegroups/devicegrouprecords").mock(return_value=httpx.Response(200, json=listing))
    one = fleet.get(f"{CFG}/devicegroups/devicegrouprecords/{grp['id']}").mock(
        return_value=httpx.Response(200, json=GROUPS_FMC10["get_after_description_put"])
    )
    return grp, one


async def test_recorded_group_list_carries_members(fleet: respx.MockRouter) -> None:
    grp, one = recorded_group(fleet)
    async with Client(server()) as c:
        rows = await run(c, "fmc_list_device_groups", {"response_format": "json"})
        full = await run(c, "fmc_list_device_groups", {"group": grp["name"], "response_format": "json"})
    assert rows["results"][0]["members"] == ["spoke1", "spoke2", "spoke3", "hub"]
    assert [m["type"] for m in full["members"]] == ["Device"] * 4
    assert one.call_count == 0  # the expanded list has the members: no per-group read


async def test_description_fmc_10_drops_is_reported(fleet: respx.MockRouter) -> None:
    """FMC 10.0.1 answers a device-group PUT or POST that carries a description without it (and keeps
    none): the preview says FMC may not store it, and the result warns instead of implying it was set."""
    grp, _ = recorded_group(fleet)
    sent = GROUPS_FMC10["put_with_description_sent"]
    put = fleet.put(f"{CFG}/devicegroups/devicegrouprecords/{grp['id']}").mock(
        return_value=httpx.Response(200, json=GROUPS_FMC10["put_with_description_answer"])
    )
    fleet.post(f"{CFG}/devicegroups/devicegrouprecords").mock(
        side_effect=[
            httpx.Response(201, json={**GROUPS_FMC10["post_answer"], "name": "new"}),
            httpx.Response(201, json={**GROUPS_FMC10["post_answer"], "name": "kept", "description": sent}),
        ]
    )
    update = {"group": grp["name"], "description": sent}
    create = {"name": "new", "devices": ["ftd-a"], "description": sent}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_device_group", update)
        done = await run(c, "fmc_update_device_group", {**update, "confirm": preview["confirm"]})
        again = await run(c, "fmc_update_device_group", update)  # FMC kept nothing: still a change
        made = await run(c, "fmc_create_device_group", create)
        made = await run(c, "fmc_create_device_group", {**create, "confirm": made["confirm"]})
        kept = await run(c, "fmc_create_device_group", {**create, "name": "kept"})
        kept = await run(c, "fmc_create_device_group", {**create, "name": "kept", "confirm": kept["confirm"]})
    assert json.loads(put.calls.last.request.content)["description"] == sent
    assert "doesn't store device-group descriptions" in preview["preview"]["notes"][0]
    assert done["status"] == "applied" and "did not keep the description" in done["result"]["warning"]
    assert len(done["result"]["members"]) == 4
    assert again["preview"]["description"] == {"from": "", "to": sent}
    assert "did not keep the description" in made["result"]["warning"]
    assert "warning" not in kept["result"]  # an FMC that keeps it: no warning


async def test_licences_by_group_say_what_was_applied_when_one_fails(fleet: respx.MockRouter) -> None:
    fleet.put(f"{CFG}/devices/devicerecords/{A}").mock(return_value=httpx.Response(200, json={}))
    fleet.put(f"{CFG}/devices/devicerecords/{B}").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "Invalid licence"}]}})
    )
    later = [
        fleet.put(f"{CFG}/devices/devicerecords/{i}").mock(return_value=httpx.Response(200, json={}))
        for i in (HA_A, HA_B)
    ]
    args = {"device": "group:branches", "add": ["IPS"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_device_licenses", args)
        with pytest.raises(ToolError) as err:
            await run(c, "fmc_set_device_licenses", {**args, "confirm": preview["confirm"]})
    msg = str(err.value)
    assert "'ftd-b' failed" in msg and "Applied: ['ftd-a']" in msg
    assert "not applied: ['ftd-b', 'fw-ha-a', 'fw-ha-b']" in msg
    assert all(r.call_count == 0 for r in later)
