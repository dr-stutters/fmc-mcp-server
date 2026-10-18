"""F57: fmc_device_metrics (CPU, memory, throughput, connections, drops over a window from FMC's health
monitor, summarised with peaks, dips and a compact series). Fixture: tests/fixtures/ftd_device_metrics.json,
recorded on FMC 10.0.1 for an idle FTDv; bursts are built on top of it."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools import metrics
from fmc_mcp.tools.metrics import (
    compact,
    increase,
    parse_time,
    prom_series,
    rates,
    summarize,
    window,
)
from fmc_mcp.tools.prompts import _health_review_text

from .conftest import CFG, fixture, items, make_settings

REC = fixture("ftd_device_metrics")
NOW = float(REC["now"])
DEV_ID = "43d57cc8-c9c6-11f1-858d-a03accd83568"
DEVICE = {"id": DEV_ID, "name": "mcp-ftd1", "type": "Device"}


@pytest.fixture(autouse=True)
def _clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metrics, "_now", lambda: NOW)


def server() -> Any:
    return create_server(make_settings(rate_limit=100000))


async def run(c: Client[Any], args: dict[str, Any]) -> Any:
    r = await c.call_tool("fmc_device_metrics", args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mount(fmc: respx.MockRouter, responses: dict[str, Any] | None = None) -> list[str]:
    """The device, and health/metrics answering from the recording by metric name; returns the filters
    asked."""
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEVICE]))
    asked: list[str] = []
    data = {**REC, **(responses or {})}

    def answer(req: httpx.Request) -> httpx.Response:
        flt = req.url.params.get("filter") or ""
        asked.append(flt)
        parts = dict(p.split(":", 1) for p in flt.split(";") if ":" in p)
        key = {"mem": "mem"}.get(parts["metric"], parts["metric"])
        if key == "interface" and parts.get("regexFilter") == "all":
            key = "interface_all"
        body = data.get(key) or {"items": [{"response": '{"status":"success","data":{"result":[]}}'}]}
        return httpx.Response(200, json=body)

    fmc.get(f"{CFG}/health/metrics").mock(side_effect=answer)
    return asked


def prom(series: list[tuple[dict[str, Any], list[tuple[float, float]]]]) -> dict[str, Any]:
    result = [{"metric": labels, "values": [[t, str(v)] for t, v in pts]} for labels, pts in series]
    return {"items": [{"response": json.dumps({"status": "success", "data": {"result": result}})}]}


# --- helpers -------------------------------------------------------------------------------------------
def test_parse_time_and_window() -> None:
    assert parse_time("30m", NOW) == NOW - 1800
    assert parse_time("2h", NOW) == NOW - 7200 and parse_time("1d", NOW) == NOW - 86400
    assert parse_time("2026-10-18T13:40:00Z", NOW) == 1792330800
    assert parse_time("2026-10-18T13:40:00", NOW) == 1792330800  # no zone: UTC
    with pytest.raises(InvalidRequest):
        parse_time("yesterday", NOW)
    assert window("1h", None, NOW) == (int(NOW - 3600), int(NOW), 60)
    assert window("1d", None, NOW)[2] == 1440  # at most 60 samples
    assert window("2h", "1h", NOW) == (int(NOW - 7200), int(NOW - 3600), 60)
    assert window("10m", "2030-01-01T00:00:00Z", NOW)[1] == int(NOW)  # not past now
    with pytest.raises(InvalidRequest):
        window("2m", None, NOW)
    with pytest.raises(InvalidRequest):
        window("31d", None, NOW)


def test_prom_series_recorded() -> None:
    rows = prom_series(REC["cpu"])
    names = [labels["cpu"] for labels, _ in rows]
    assert names == ["lina_avg", "lina_cp_avg", "lina_dp_avg", "snort_avg", "system_avg"]
    assert rows[4][1][0] == (1792330680.0, 14.0) and len(rows[4][1]) == 12
    assert prom_series({"items": [{"response": "not json"}]}) == []
    assert prom_series({}) == []


def test_rates_and_increase_handle_resets_and_late_series() -> None:
    pts = [(0.0, 100.0), (60.0, 160.0), (120.0, 10.0), (180.0, 70.0)]
    assert rates(pts) == [(60.0, 1.0), (120.0, 10 / 60), (180.0, 1.0)]
    assert rates(pts, 8.0)[0] == (60.0, 8.0)
    assert increase(pts, 0.0, 60.0) == 60 + 10 + 60
    late = [(300.0, 1.0), (600.0, 2.0)]  # FMC starts a drop reason's series at its first occurrence
    assert increase(late, 0.0, 60.0) == 2.0
    assert increase(late, 300.0, 60.0) == 1.0
    assert increase([], 0.0, 60.0) == 0.0


def test_summarize_peaks_dips_and_series() -> None:
    flat = [(float(t), 10.0) for t in range(0, 600, 60)]
    s = summarize(flat, 0, 600, 5, percent=True)
    assert s["min"] == s["max"] == s["avg"] == 10.0 and "peaks" not in s and "min_at" not in s
    assert s["series"] == {"start": "1970-01-01T00:00:00Z", "step_s": 120, "values": [10.0] * 5}
    burst = [(float(t), 5.0) for t in range(0, 1200, 60)]
    burst[10] = (600.0, 85.0)
    burst[11] = (660.0, 90.0)
    s = summarize(burst, 0, 1200, 4, percent=True)
    assert s["max"] == 90.0 and s["max_at"] == "1970-01-01T00:11:00Z"
    assert s["peaks"] == [
        {
            "from": "1970-01-01T00:10:00Z",
            "to": "1970-01-01T00:11:00Z",
            "value": 90.0,
            "at": "1970-01-01T00:11:00Z",
        }
    ]
    outage = [(float(t), 1000.0) for t in range(0, 1200, 60)]
    outage[5] = (300.0, 0.0)
    assert summarize(outage, 0, 1200, 4)["dips"][0]["value"] == 0.0
    # small wiggles on a percentage are not peaks (margin 5 points)
    wiggle = [(float(t), 10.0 + (t % 120 == 0)) for t in range(0, 1200, 60)]
    assert "peaks" not in summarize(wiggle, 0, 1200, 4, percent=True)


def test_compact_buckets_gaps() -> None:
    c = compact([(0.0, 1.0), (10.0, 3.0), (90.0, 5.0)], 0, 100, 4)
    assert c == {"start": "1970-01-01T00:00:00Z", "step_s": 25, "values": [2.0, None, None, 5.0]}


# --- the tool, on the recording ------------------------------------------------------------------------
async def test_overview_recorded_idle_device(fmc: respx.MockRouter) -> None:
    asked = mount(fmc)
    async with Client(server()) as c:
        r = await run(c, {"device": "mcp-ftd1", "since": "20m"})
    # one request per family, with FMC's filter syntax
    assert len(asked) == 5
    assert all(f.startswith(f"deviceUUIDs:{DEV_ID};metric:") for f in asked)
    assert any(f.endswith(";regexFilter:.*_avg") and "metric:cpu;" in f for f in asked)
    assert any(f.endswith(";regexFilter:used_percentage_.*") and "metric:mem;" in f for f in asked)
    assert "startTime:1792330800;endTime:1792332000;step:60" in asked[0]
    assert r["window"] == {"from": "2026-10-18T13:40:00Z", "to": "2026-10-18T14:00:00Z", "sample_step_s": 60}
    cpu = r["cpu"]
    assert list(cpu) == ["unit", "data_plane", "control_plane", "snort", "system", "lina"]
    assert cpu["system"]["max"] == 16.0 and cpu["system"]["max_at"] == "2026-10-18T13:56:00Z"
    assert cpu["data_plane"]["max"] == 0.0
    assert r["memory"]["system"]["min"] == 35.34 and r["memory"]["system"]["last"] == 36.03
    assert r["memory"]["data_plane"]["avg"] == 40.26
    # throughput from the counters (bytes -> bit/s): outside is the only data interface recorded
    tp = r["throughput"]
    assert tp["total"]["in_bps"]["max"] == round((183372 - 144389) / 300 * 8)  # 1040 bit/s
    assert tp["interfaces"][0]["interface"] == "outside (Ethernet0/0)"
    assert "series" not in tp["interfaces"][0]["in_bps"]
    conn = r["connections"]
    assert conn["in_use"]["max"] == 3.0 and conn["per_second"]["max"] == 0.0
    assert conn["most_used"] == {"last": 5.0}
    drops = r["drops"]
    assert drops["asp_drops"][0] == {
        "reason": "acl-drop",
        "description": "flow is denied by configured rule",
        "count": 341,
        "per_second": drops["asp_drops"][0]["per_second"],
    }
    assert [d["reason"] for d in drops["asp_drops"]] == ["acl-drop", "sp-security-failed"]
    assert drops["asp_drops"][1]["count"] == 2  # its series appears inside the window
    assert drops["asp_total"] == 343
    assert drops["interfaces"] == [
        {
            "interface": "outside (Ethernet0/0)",
            "drop_packets": 163,
            "drops_per_second": drops["interfaces"][0]["drops_per_second"],
        }
    ]
    assert "findings" not in r
    assert any("spike shorter than sample_step_s" in n for n in r["notes"])


async def test_interface_all_row_is_the_total(fmc: respx.MockRouter) -> None:
    combined = copy.deepcopy(REC["interface"])
    combined["items"] += REC["interface_all"]["items"]
    mount(fmc, {"interface": combined})
    async with Client(server()) as c:
        r = await run(c, {"device": "mcp-ftd1", "since": "20m", "metric": "throughput"})
    assert r["throughput"]["total"]["in_bps"]["max"] == round((258763 - 188847) / 300 * 8)
    assert [i["interface"] for i in r["throughput"]["interfaces"]] == ["outside (Ethernet0/0)"]
    assert set(r) >= {"device", "window", "throughput"} and "cpu" not in r


async def test_one_interface(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        args = {"device": "mcp-ftd1", "since": "20m", "metric": "throughput", "interface": "OUTSIDE"}
        r = await run(c, args)
        bad = await c.call_tool(
            "fmc_device_metrics",
            {"device": "mcp-ftd1", "since": "20m", "metric": "throughput", "interface": "dmz9"},
            raise_on_error=False,
        )
    one = r["throughput"]["interface"]
    assert one["interface"] == "outside (Ethernet0/0)" and "series" in one["in_bps"]
    assert bad.is_error and "outside (Ethernet0/0)" in bad.content[0].text  # type: ignore[union-attr]


async def test_burst_shows_as_peaks_and_findings(fmc: respx.MockRouter) -> None:
    """A traffic burst at 13:50: Snort CPU and throughput peak, CPU over the limit is flagged."""
    t0, step = 1792330800, 60
    snort = [(t0 + i * step, 2.0 if not 10 <= i <= 12 else 93.0) for i in range(21)]
    system = [(t0 + i * step, 10.0) for i in range(21)]
    cpu = prom([({"cpu": "snort_avg"}, snort), ({"cpu": "system_avg"}, system)])
    counter, value = [], 0.0
    for i in range(21):
        value += 1_000 * step if not 10 <= i <= 12 else 5_000_000 * step  # bytes
        counter.append((t0 + i * step, value))
    iface = prom(
        [
            ({"interface": "Ethernet0/1", "interface_name": "inside", "description": "input_bytes"}, counter),
            (
                {"interface": "Ethernet0/0", "interface_name": "outside", "description": "output_bytes"},
                counter,
            ),
        ]
    )
    mount(fmc, {"cpu": cpu, "interface": iface})
    async with Client(server()) as c:
        r = await run(c, {"device": "mcp-ftd1", "since": "20m", "metric": "all", "points": 4})
    snort_cpu = r["cpu"]["snort"]
    assert snort_cpu["max"] == 93.0 and snort_cpu["peaks"][0]["from"] == "2026-10-18T13:50:00Z"
    assert snort_cpu["peaks"][0]["to"] == "2026-10-18T13:52:00Z"
    assert len(snort_cpu["series"]["values"]) == 4
    assert r["findings"] == [
        {
            "severity": "critical",
            "what": "CPU snort",
            "reason": "CPU snort reached 93.0 % at 2026-10-18T13:50:00Z "
            "(average 15.0 %; warning 80, critical 90)",
        }
    ]
    total_in = r["throughput"]["total"]["in_bps"]
    assert total_in["max"] == 40_000_000 and total_in["peaks"][0]["from"] == "2026-10-18T13:50:00Z"
    assert r["throughput"]["interfaces"][0]["interface"] in ("inside (Ethernet0/1)", "outside (Ethernet0/0)")
    assert r["snort"] == {
        "blocked_packets": 0,
        "end_of_flow_events": 37,
        "fast_forwarded_flows": 37,
        "packets_bypassed_snort_busy": 0,
        "packets_bypassed_snort_down": 0,
        "passed_packets": 0,
        "instances": 2,
    }


async def test_no_samples_and_upstream_errors_are_notes(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEVICE]))

    def answer(req: httpx.Request) -> httpx.Response:
        if "metric:cpu;" in (req.url.params.get("filter") or ""):
            return httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
        return httpx.Response(200, json={"items": [{"response": '{"data":{"result":[]}}'}]})

    fmc.get(f"{CFG}/health/metrics").mock(side_effect=answer)
    async with Client(server()) as c:
        r = await run(c, {"device": "mcp-ftd1", "metric": "overview"})
    assert set(r) == {"device", "window", "notes"}
    assert any(n.startswith("cpu: not available") for n in r["notes"])
    assert any(n.startswith("mem: FMC has no samples") for n in r["notes"])


async def test_bad_window_is_refused_before_fmc(fmc: respx.MockRouter) -> None:
    asked = mount(fmc)
    async with Client(server()) as c:
        args = {"device": "mcp-ftd1", "since": "soon"}
        r = await c.call_tool("fmc_device_metrics", args, raise_on_error=False)
    assert r.is_error and "is not a time" in r.content[0].text  # type: ignore[union-attr]
    assert asked == []


def test_health_review_uses_device_metrics() -> None:
    text = _health_review_text("Global", None, 24)
    assert '`fmc_device_metrics` with device=<name>, since="24h", domain="Global"' in text
    assert text.index("`fmc_device_health`") < text.index("`fmc_device_metrics`") < text.index("2. HA")


async def test_single_sample_counters_and_sdwan_pointer(fmc: respx.MockRouter) -> None:
    """One sample per counter (a just-booted device) gives counts but no rates, and no crash."""
    one = prom(
        [
            (
                {"interface": "Ethernet0/0", "interface_name": "outside", "description": "drop_packets"},
                [(NOW, 5.0)],
            ),
            (
                {"interface": "Ethernet0/0", "interface_name": "outside", "description": "input_bytes"},
                [(NOW, 9.0)],
            ),
        ]
    )
    mount(fmc, {"interface": one, "asp_drops": prom([({"asp_drops": "acl-drop"}, [(NOW, 3.0)])])})
    async with Client(server()) as c:
        r = await run(c, {"device": "mcp-ftd1", "since": "20m", "metric": "drops"})
        tools = {t.name: t for t in await c.list_tools()}
    assert r["drops"]["interfaces"] == [{"interface": "outside (Ethernet0/0)", "drop_packets": 5}]
    assert r["drops"]["asp_drops"] == [{"reason": "acl-drop", "description": None, "count": 3}]
    assert "fmc_device_metrics" in str(tools["fmc_sdwan_status"].description)
