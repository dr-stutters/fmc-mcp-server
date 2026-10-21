"""F78: fmc_snort_profile, fmc_cpu_profile and fmc_get_profiler_results.

The profiler files are the FMC API spec's own examples (tests/fixtures/profilers.json); the 403 is FMC
10.0.1's live answer for a role without the Snort 3 profiling permission (W6N probe). The run semantics
(start = POST ENABLED, stop = POST DISABLED, poll filter=latest:true for a new file) follow the spec: the
lab role could not record them live."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools import profiling
from fmc_mcp.tools.profiling import (
    CPU,
    SNORT,
    first_item,
    header,
    module_rows,
    parse_time,
    refusal,
    result_view,
    rule_rows,
)

from .conftest import CFG, CHILD, DOMAIN, fixture, items, make_settings

FIX = fixture("profilers")
DEV = "aaaaaaaa-1111-4000-8000-000000000078"
DEVICE = {
    "id": DEV,
    "name": "ftd-prof",
    "type": "Device",
    "isConnected": True,
    "snortEngine": "SNORT3",
    "sw_version": "10.0.0",
    "accessPolicy": {"id": "acp-1", "name": "acp-threat", "type": "AccessPolicy"},
    "metadata": {"snortVersion": "3.9.3.1-61"},
}
TS = f"/api/fmc_troubleshoot/v1/domain/{DOMAIN}"
SNORT_BASE = f"{TS}/snortprofiler/{DEV}/rules"
CPU_BASE = f"{TS}/cpuprofiler/{DEV}/modules"
OLD = FIX["snort_latest"]["items"][0]["profilerFileName"]  # rule_profiling.1685458415.json
NEW = "rule_profiling.1777000000.json"


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, **kw))


async def call(c: Client[Any], tool: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(tool, args)
    if r.structured_content is not None:
        return r.structured_content
    text = r.content[0].text  # type: ignore[union-attr]
    try:
        return json.loads(text)
    except ValueError:
        return text


async def confirmed(tool: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await call(c, tool, args)
        assert preview["status"] == "preview", preview
        return preview, await call(c, tool, {**args, "confirm": preview["confirm"]})


@pytest.fixture
def waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Every pause the tools take (none really waits)."""
    seen: list[float] = []

    async def fake(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(profiling, "pause", fake)
    return seen


def mock_device(fmc: respx.MockRouter, dev: dict[str, Any] | None = None) -> None:
    d = dev or DEVICE
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([d]))
    fmc.get(f"{CFG}/devices/devicerecords/{d['id']}").mock(return_value=httpx.Response(200, json=d))


def finished_file(name: str = NEW) -> dict[str, Any]:
    f = copy.deepcopy(FIX["snort_file"])
    f["profilerFileName"] = name
    return f


class Profiler:
    """FMC's profiler collection as the spec describes it: POST ENABLED starts, POST DISABLED stops and
    writes a new file; GET filter=latest:true answers the newest file (status ENABLED while running)."""

    def __init__(
        self, before: dict[str, Any] | None, after: dict[str, Any], kind: str = "SnortProfiler"
    ) -> None:
        self.before = before
        self.after = after
        self.kind = kind
        self.bodies: list[dict[str, Any]] = []
        self.gets: list[dict[str, str]] = []
        self.stop_after_gets = 0  # GETs after the stop that still say ENABLED

    def state(self) -> dict[str, Any] | None:
        status = self.bodies[-1].get("status") if self.bodies else None
        if status == "ENABLED":
            return {"type": self.kind, "status": "ENABLED", "startTime": "10:00:00 10-21-2026"}
        if status == "DISABLED":
            if self.stop_after_gets > 0:
                self.stop_after_gets -= 1
                return {"type": self.kind, "status": "ENABLED", "startTime": "10:00:00 10-21-2026"}
            return self.after
        return self.before

    def get(self, request: httpx.Request) -> httpx.Response:
        self.gets.append(dict(request.url.params))
        item = self.state()
        return httpx.Response(
            200, json={"items": [item] if item else [], "paging": {"count": 1 if item else 0}}
        )

    def post(self, request: httpx.Request) -> httpx.Response:
        b = json.loads(request.content)
        self.bodies.append(b)
        return httpx.Response(201, json={"type": self.kind, "status": b["status"]})

    def mount(self, fmc: respx.MockRouter, base: str) -> "Profiler":
        fmc.get(base).mock(side_effect=self.get)
        fmc.post(base).mock(side_effect=self.post)
        return self


# --- parsing the profiler files ----------------------------------------------------------------------


def test_rule_rows_rank_the_spec_example_by_time() -> None:
    rows, notes = rule_rows(FIX["snort_file"]["rules"], 25)
    assert [r["rule"] for r in rows] == ["4:57", "4:15"]
    top = rows[0]
    assert top == {
        "rank": 1,
        "rule": "4:57",
        "rev": 1,
        "message": "PROTOCOL-ICMP Microsoft Windows IPv6 DNSSL option record denial of service attempt",
        "time_pct": 0.33,
        "time_us": 15931,
        "checks": 3385,
        "matches": 3385,
        "alerts": 0,
        "avg_check_us": 4,
        "avg_match_us": 4,
        "avg_non_match_us": 0,
        "timeouts": 0,
        "suspends": 0,
    }
    assert notes == []


def test_rule_rows_sum_snort_instances_and_keep_optional_percentages() -> None:
    a = {
        "gid": 1,
        "sid": 9,
        "rev": 2,
        "message": "m",
        "checks": 100,
        "matches": 10,
        "alerts": 1,
        "timeUs": 1000,
    }
    rules = [
        {**a, "instanceId": 1, "ruleTimePercentage": 2.0, "avgMatch": 20, "avgNonMatch": 8},
        {**a, "instanceId": 2, "ruleTimePercentage": 4.0, "avgMatch": 40, "avgNonMatch": 12, "suspends": 1},
        {"gid": 1, "sid": 5, "checks": 50, "timeUs": 400, "instanceId": 1},  # no ruleTimePercentage (schema)
    ]
    rows, notes = rule_rows(rules, 1)
    assert len(rows) == 1  # top=1
    r = rows[0]
    assert r["rule"] == "1:9" and r["time_us"] == 2000 and r["checks"] == 200 and r["instances"] == 2
    assert r["time_pct"] == 3.0  # mean over the file's two instances
    assert r["avg_check_us"] == 10 and r["avg_match_us"] == 30 and r["avg_non_match_us"] == 10
    assert r["suspends"] == 1
    assert "2 Snort instances" in notes[0]
    rows, _ = rule_rows(rules, 5)
    assert "time_pct" not in rows[1]  # FMC gave none for 1:5


def test_module_rows_name_the_caller_and_rank_by_time() -> None:
    rows, notes = module_rows(FIX["cpu_latest"]["items"][0]["modules"], 25)
    assert [(r["module"], r["time_pct"]) for r in rows] == [("daq", 96.49), ("firewall", 0.0)]
    assert any("daq is packet acquisition" in n for n in notes)
    tree = [
        {"name": "detection", "layer": 1, "number": 1, "timeUs": 500, "checks": 10, "totalPercentage": 50.0},
        {"name": "rule_eval", "layer": 2, "number": 2, "timeUs": 400, "checks": 8, "callerPercentage": 80.0},
        {"name": "http_inspect", "layer": 1, "number": 3, "timeUs": 450, "checks": 9},
        {"name": "mpse", "layer": 2, "number": 4, "timeUs": 100, "checks": 9},
    ]
    rows, _ = module_rows(tree, 25)
    by = {r["module"]: r for r in rows}
    assert by["rule_eval"]["caller"] == "detection" and by["mpse"]["caller"] == "http_inspect"
    assert "caller" not in by["detection"]
    assert [r["module"] for r in rows] == ["detection", "http_inspect", "rule_eval", "mpse"]


def test_header_parses_fmc_times() -> None:
    assert parse_time("17:07:45 05-09-2023") == "2023-05-09T17:07:45"
    assert parse_time("not a time") == "not a time"
    h = header(FIX["snort_latest"]["items"][0])
    assert h == {
        "file": OLD,
        "status": "DISABLED",
        "running": False,
        "start": "2023-05-09T17:07:45",
        "end": "2023-05-09T18:07:45",
        "window_s": 3600,
        "access_policy": "ACP1",
        "access_policy_exported": "2023-04-19T10:47:35",
        "snort_version": "3.1.53.0-15",
        "software": "7.5.0 build 1129",
        "vdb": "361",
        "lsp": "lsp-rel-20230417-1250",
    }


def test_empty_items_are_no_file() -> None:
    """FMC 10.0.1 answers {items: [{}]} for an empty troubleshoot collection."""
    assert first_item(FIX["empty_list"]) is None
    assert first_item({"paging": {"count": 0}}) is None
    assert first_item(FIX["snort_latest"])["profilerFileName"] == OLD  # type: ignore[index]


def test_result_view_links_each_rule_to_the_intrusion_tools() -> None:
    out = result_view(SNORT, FIX["snort_file"], 25)
    assert out["summary"].startswith("Costliest rule 4:57 (0.33 % of rule time): 15.9 ms over 3385 checks")
    steps = " ".join(out["next_steps"])
    assert (
        "fmc_find_intrusion_rules(query='4:57')" in steps
        and "fmc_find_intrusion_rules(query='4:15')" in steps
    )
    assert "fmc_set_intrusion_rule_state(policy=<custom intrusion policy>, rules=['4:57', '4:15']" in steps
    assert "'ACP1'" in steps
    empty = result_view(SNORT, {"type": "SnortProfiler", "status": "DISABLED", "rules": []}, 25)
    assert "next_steps" not in empty and "no rules" in empty["notes"][0]
    cpu = result_view(CPU, FIX["cpu_latest"]["items"][0], 25)
    assert cpu["summary"] == "Costliest module after packet acquisition: firewall (0.0 % of Snort's time)."


# --- refusals ------------------------------------------------------------------------------------------


async def test_a_403_is_the_roles_profiling_permission_not_the_credentials(
    fmc: respx.MockRouter, waits: list[float]
) -> None:
    mock_device(fmc)
    fmc.get(SNORT_BASE).mock(return_value=httpx.Response(403, json=FIX["refused"]))
    post = fmc.post(SNORT_BASE).mock(return_value=httpx.Response(201, json={}))
    async with Client(server()) as c:
        out = await call(c, "fmc_snort_profile", {"device": "ftd-prof"})
    assert out["status"] == "blocked"
    text = " ".join(out["blockers"])
    assert "403: The user is not authorized." in text and "Snort 3 profiling permission" in text
    assert "FMC_USERNAME" not in text and "confirm" not in out
    assert out["preview"]["last_run"] == "refused (403)"
    assert not post.called
    async with Client(server()) as c:
        with pytest.raises(ToolError) as e:
            await c.call_tool("fmc_get_profiler_results", {"device": "ftd-prof"})
    assert "Snort 3 profiling permission" in str(e.value) and "FMC_USERNAME" not in str(e.value)


def test_the_live_403_text_names_the_permission() -> None:
    """The deployed server's answer to GET snortprofiler on FMC 10.0.1 (build:profiling, 2026-10-21)."""
    from fmc_mcp._core import AuthError

    live = AuthError(
        "FMC denied access (403) on GET /api/fmc_troubleshoot/v1/domain/d/snortprofiler/x/rules: The user is "
        "not authorized. Check FMC_USERNAME/FMC_PASSWORD and that the account's role allows this operation.",
        403,
    )
    text = refusal(live, SNORT)
    assert text.startswith(
        "FMC refused the Snort rule profiler for this account (403: The user is not authorized.)"
    )
    assert "FMC_USERNAME" not in text


def test_a_feature_flag_403_says_so() -> None:
    from fmc_mcp._core import AuthError

    err = AuthError(
        "Cisco Secure Firewall Management Center denied access (403) on POST /api/x: Feature Flag : "
        "bulk_device_command_execution is disabled for the request. Request is forbidden.. Check "
        "FMC_USERNAME/FMC_PASSWORD and that the account's role allows this operation.",
        403,
    )
    text = refusal(err, CPU)
    assert text.startswith("FMC has the Snort 3 CPU profiler behind a feature flag")
    assert "Request is forbidden." in text and "FMC_USERNAME" not in text


async def test_disconnected_or_snort2_devices_are_blocked(fmc: respx.MockRouter) -> None:
    mock_device(fmc, {**DEVICE, "isConnected": False, "snortEngine": "SNORT2"})
    fmc.get(CPU_BASE).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await call(c, "fmc_cpu_profile", {"device": "ftd-prof"})
    assert out["status"] == "blocked"
    assert any("disconnected" in b for b in out["blockers"])
    assert any("SNORT2" in b and "Snort 3 only" in b for b in out["blockers"])


async def test_cpu_minutes_are_fmcs_range(fmc: respx.MockRouter) -> None:
    async with Client(server()) as c:
        for minutes in (14, 121):
            with pytest.raises(ToolError):
                await c.call_tool("fmc_cpu_profile", {"device": "ftd-prof", "minutes": minutes})


# --- fmc_snort_profile ---------------------------------------------------------------------------------


async def test_snort_preview_states_duration_cost_and_last_run(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    prof = Profiler(FIX["snort_latest"]["items"][0], finished_file()).mount(fmc, SNORT_BASE)
    async with Client(server()) as c:
        out = await call(c, "fmc_snort_profile", {"device": "ftd-prof", "minutes": 3})
    assert out["status"] == "preview" and out["blast_radius"] == 1
    assert out["action"] == "Profile Snort rules on ftd-prof for 3 min"
    p = out["preview"]
    assert p["device"] == "ftd-prof" and p["snort"] == "3.9.3.1-61" and p["access_policy"] == "acp-threat"
    assert p["duration"].startswith("3 min: the server starts the profiler, waits, stops it")
    assert "Snort CPU and per-packet latency go up" in p["cpu_cost"]
    assert p["last_run"]["file"] == OLD
    assert prof.bodies == [] and prof.gets == [{"filter": "latest:true", "expanded": "true"}]


async def test_snort_run_starts_waits_stops_and_ranks(fmc: respx.MockRouter, waits: list[float]) -> None:
    mock_device(fmc)
    prof = Profiler(FIX["snort_latest"]["items"][0], finished_file()).mount(fmc, SNORT_BASE)
    prof.stop_after_gets = 1  # the first read after the stop still says running
    _, out = await confirmed("fmc_snort_profile", {"device": "ftd-prof", "minutes": 2})
    assert out["status"] == "applied"
    assert prof.bodies == [
        {"type": "SnortProfiler", "status": "ENABLED"},
        {"type": "SnortProfiler", "status": "DISABLED"},
    ]
    assert waits == [30.0, 30.0, 30.0, 30.0, profiling.COLLECT_FIRST]  # the window, then one re-read
    r = out["result"]
    assert r["profile"]["file"] == NEW and r["rules_in_file"] == 2
    assert [x["rule"] for x in r["rules"]] == ["4:57", "4:15"]
    assert any("fmc_set_intrusion_rule_state" in s for s in r["next_steps"])


async def test_snort_run_reads_the_file_when_latest_has_no_rules(
    fmc: respx.MockRouter, waits: list[float]
) -> None:
    mock_device(fmc)
    bare = {k: v for k, v in finished_file().items() if k != "rules"}
    Profiler(None, bare).mount(fmc, SNORT_BASE)
    file = fmc.get(f"{SNORT_BASE}/{NEW}").mock(return_value=httpx.Response(200, json=finished_file()))
    _, out = await confirmed("fmc_snort_profile", {"device": "ftd-prof", "minutes": 1})
    assert file.called and out["result"]["rules"][0]["rule"] == "4:57"


async def test_snort_run_stops_the_profiler_when_the_wait_fails(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancelled or failed call never leaves the rule profiler running (it has no duration)."""
    mock_device(fmc)
    prof = Profiler(FIX["snort_latest"]["items"][0], finished_file()).mount(fmc, SNORT_BASE)

    async def broken(seconds: float) -> None:
        raise RuntimeError("client went away")

    monkeypatch.setattr(profiling, "pause", broken)
    async with Client(server()) as c:
        preview = await call(c, "fmc_snort_profile", {"device": "ftd-prof"})
        with pytest.raises(ToolError):
            await c.call_tool("fmc_snort_profile", {"device": "ftd-prof", "confirm": preview["confirm"]})
    assert [b["status"] for b in prof.bodies] == ["ENABLED", "DISABLED"]


async def test_snort_refused_start_sends_no_stop(fmc: respx.MockRouter, waits: list[float]) -> None:
    mock_device(fmc)
    fmc.get(SNORT_BASE).mock(return_value=items([]))
    post = fmc.post(SNORT_BASE).mock(return_value=httpx.Response(403, json=FIX["refused"]))
    async with Client(server()) as c:
        preview = await call(c, "fmc_snort_profile", {"device": "ftd-prof"})
        with pytest.raises(ToolError) as e:
            await c.call_tool("fmc_snort_profile", {"device": "ftd-prof", "confirm": preview["confirm"]})
    assert post.call_count == 1 and waits == []
    assert "Snort 3 profiling permission" in str(e.value)


async def test_snort_already_running_blocks_a_run_but_not_a_stop(
    fmc: respx.MockRouter, waits: list[float]
) -> None:
    mock_device(fmc)
    on = {"type": "SnortProfiler", "status": "ENABLED", "startTime": "09:00:00 10-21-2026"}
    prof = Profiler(on, finished_file()).mount(fmc, SNORT_BASE)
    async with Client(server()) as c:
        out = await call(c, "fmc_snort_profile", {"device": "ftd-prof"})
    assert out["status"] == "blocked"
    assert "already running on ftd-prof (since 2026-10-21T09:00:00)" in out["blockers"][0]
    _, out = await confirmed("fmc_snort_profile", {"device": "ftd-prof", "action": "stop"})
    assert [b["status"] for b in prof.bodies] == ["DISABLED"] and waits == []  # no window
    assert out["result"]["profile"]["file"] == NEW


async def test_snort_run_without_a_new_file_is_incomplete(fmc: respx.MockRouter, waits: list[float]) -> None:
    mock_device(fmc)
    old = FIX["snort_latest"]["items"][0]
    Profiler(old, old).mount(fmc, SNORT_BASE)  # FMC keeps naming the old file
    _, out = await confirmed("fmc_snort_profile", {"device": "ftd-prof", "minutes": 1})
    r = out["result"]
    assert r["complete"] is False and r["latest"]["file"] == OLD
    assert "fmc_get_profiler_results(device='ftd-prof', profiler='snort')" in r["note"]


async def test_snort_profile_in_the_devices_own_domain(fmc: respx.MockRouter, waits: list[float]) -> None:
    """A device in a child domain is profiled there (fmc_troubleshoot paths are per domain)."""
    dev = {**DEVICE, "metadata": {**DEVICE["metadata"], "domain": {"id": CHILD, "name": "Global/Branch"}}}
    mock_device(fmc, dev)
    base = f"/api/fmc_troubleshoot/v1/domain/{CHILD}/snortprofiler/{DEV}/rules"
    Profiler(None, finished_file()).mount(fmc, base)
    async with Client(server()) as c:
        out = await call(c, "fmc_snort_profile", {"device": "ftd-prof"})
    assert out["status"] == "preview" and out["preview"]["device_domain"] == "Global/Branch"


# --- fmc_cpu_profile ------------------------------------------------------------------------------------


async def test_cpu_run_without_wait_returns_once_started(fmc: respx.MockRouter, waits: list[float]) -> None:
    mock_device(fmc)
    prof = Profiler(None, FIX["cpu_latest"]["items"][0], kind="CPUProfiler").mount(fmc, CPU_BASE)
    preview, out = await confirmed("fmc_cpu_profile", {"device": "ftd-prof", "minutes": 20, "wait": False})
    assert preview["preview"]["duration"].startswith("20 min (FMC stops it by itself")
    assert prof.bodies == [{"type": "CPUProfiler", "status": "ENABLED", "duration": 20}]
    r = out["result"]
    assert "ends_about" in r and "fmc_get_profiler_results(device='ftd-prof', profiler='cpu')" in r["next"]
    assert waits == [] and len(prof.gets) == 2  # preview + confirm-time reads only


async def test_cpu_run_waits_for_fmc_and_ranks_modules(fmc: respx.MockRouter, waits: list[float]) -> None:
    mock_device(fmc)
    done = FIX["cpu_latest"]["items"][0]
    prof = Profiler(None, done, kind="CPUProfiler").mount(fmc, CPU_BASE)  # it stops by itself: no stop POST

    def after_duration(request: httpx.Request) -> httpx.Response:
        prof.gets.append(dict(request.url.params))
        started = any(b.get("status") == "ENABLED" for b in prof.bodies)
        item = done if started and sum(waits) >= 15 * 60 else None
        return httpx.Response(200, json={"items": [item] if item else []})

    fmc.get(CPU_BASE).mock(side_effect=after_duration)
    _, out = await confirmed("fmc_cpu_profile", {"device": "ftd-prof"})
    assert [b["status"] for b in prof.bodies] == ["ENABLED"] and prof.bodies[0]["duration"] == 15
    assert sum(waits) == 15 * 60 + profiling.CPU_GRACE
    r = out["result"]
    assert [m["module"] for m in r["modules"]] == ["daq", "firewall"]
    assert r["profile"]["file"] == "cpu_profiling.1778474701.json"


# --- fmc_get_profiler_results ---------------------------------------------------------------------------


async def test_results_latest_as_markdown_and_json(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    fmc.get(SNORT_BASE).mock(return_value=httpx.Response(200, json=FIX["snort_latest"]))
    async with Client(server()) as c:
        md = await call(c, "fmc_get_profiler_results", {"device": "ftd-prof"})
        js = await call(c, "fmc_get_profiler_results", {"device": "ftd-prof", "response_format": "json"})
    assert "| rank | rule |" in md and "| 1 | 4:57 |" in md
    assert js["profile"]["file"] == OLD and js["rules"][0]["rule"] == "4:57"


async def test_results_named_file_running_and_none(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    named = fmc.get(f"{CPU_BASE}/cpu_profiling.1778474701.json").mock(
        return_value=httpx.Response(200, json=FIX["cpu_latest"]["items"][0])
    )
    fmc.get(SNORT_BASE).mock(return_value=httpx.Response(200, json=FIX["empty_list"]))
    fmc.get(CPU_BASE).mock(return_value=items([{"type": "CPUProfiler", "status": "ENABLED"}]))
    async with Client(server()) as c:
        one = await call(
            c,
            "fmc_get_profiler_results",
            {
                "device": "ftd-prof",
                "profiler": "cpu",
                "file": "cpu_profiling.1778474701.json",
                "response_format": "json",
            },
        )
        none = await call(c, "fmc_get_profiler_results", {"device": "ftd-prof", "response_format": "json"})
        on = await call(
            c,
            "fmc_get_profiler_results",
            {"device": "ftd-prof", "profiler": "cpu", "response_format": "json"},
        )
        with pytest.raises(ToolError):
            await c.call_tool("fmc_get_profiler_results", {"device": "ftd-prof", "file": "../../x"})
    assert named.called and one["modules"][0]["module"] == "daq"
    assert "No Snort rule profiler file on ftd-prof yet" in none["note"]
    assert "still running" in on["note"]


async def test_profilers_run_as_mcp_tasks(fmc: respx.MockRouter) -> None:
    async with Client(server(mcp_tasks=True, mcp_enable_dangerous=True)) as c:
        status = (await c.call_tool("fmc_status", {})).structured_content
    assert status is not None
    assert {"fmc_snort_profile", "fmc_cpu_profile"} <= set(status["server"]["tasks"]["tools"])
