"""Device metrics over time (F57): "was the branch firewall busy during the outage?" from FMC's health
monitor (`health/metrics`, a Prometheus range query per metric family), summarised per series (min, avg,
max and when, peaks and dips) with a compact series.

What FMC 10.0.1 answers (recorded live): `cpu` (per core plus lina_avg, lina_dp_avg, lina_cp_avg,
snort_avg, system_avg, in %), `mem` (bytes plus used_percentage_system/lina/snort/swap), `interface` (per
interface and an 'all' row: input/output bytes and packets, drop_packets, errors, ... as counters since the
interface was cleared, plus status gauges), `conn_stats` (connections and xlates in use and the most used,
connections per second all/tcp/udp), `asp_drops` (one counter per accelerated-security-path drop reason)
and `snort` (flows, blocked/bypassed packets, queue use), besides `pathmonitoring` (fmc_sdwan_status),
`disk_stats` and `critical_process`. An unknown metric name answers an empty result. `regexFilter`
matches the label named like the metric (cpu, mem, interface = the hardware name), not the description.
Counters are turned into rates here (difference over time, a reset counts from zero); the samples are
the value at each step, so a spike shorter than the step can fall between two samples.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import json
import math
import re
import statistics
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.devices import DeviceRef

MAX_POINTS = 60  # raw samples asked per series (the step grows with the window)
MIN_STEP = 60
MAX_WINDOW = 30 * 86400
MIN_WINDOW = 300
# (warning, critical) for gauges in %
CPU_LIMITS = (80.0, 90.0)
MEM_LIMITS = (85.0, 95.0)
CPU_SERIES = {
    "lina_dp_avg": "data_plane",
    "lina_cp_avg": "control_plane",
    "snort_avg": "snort",
    "system_avg": "system",
    "lina_avg": "lina",
}
MEM_SERIES = {
    "used_percentage_system": "system",
    "used_percentage_lina": "data_plane",
    "used_percentage_snort": "snort",
    "used_percentage_swap": "swap",
}
# FMC metric family, regexFilter
QUERIES: dict[str, tuple[str, str | None]] = {
    "cpu": ("cpu", ".*_avg"),
    "memory": ("mem", "used_percentage_.*"),
    "interfaces": ("interface", None),
    "connections": ("conn_stats", None),
    "asp_drops": ("asp_drops", None),
    "snort": ("snort", None),
}
VIEWS: dict[str, list[str]] = {
    "overview": ["cpu", "memory", "throughput", "connections", "drops"],
    "cpu": ["cpu"],
    "memory": ["memory"],
    "throughput": ["throughput"],
    "connections": ["connections"],
    "drops": ["drops"],
    "snort": ["snort"],
    "all": ["cpu", "memory", "throughput", "connections", "drops", "snort"],
}
NEEDS = {
    "cpu": ["cpu"],
    "memory": ["memory"],
    "throughput": ["interfaces"],
    "connections": ["connections"],
    "drops": ["asp_drops", "interfaces"],
    "snort": ["snort"],
}
SNORT_COUNTERS = (
    "blocked_packets",
    "passed_packets",
    "packets_bypassed_snort_busy",
    "packets_bypassed_snort_down",
    "start_of_flow_events",
    "end_of_flow_events",
    "fast_forwarded_flows",
    "blacklisted_flows",
)
INTERFACE_RATES = {
    "input_bytes": ("in_bps", 8.0),
    "output_bytes": ("out_bps", 8.0),
    "input_packets": ("in_pps", 1.0),
    "output_packets": ("out_pps", 1.0),
}
INTERFACE_COUNTS = ("drop_packets", "input_errors", "output_errors", "nobuffer", "overrun", "underruns")

Point = tuple[float, float]


def _now() -> float:
    return time.time()


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


_REL = re.compile(r"^(\d+)\s*(m|min|h|d)$", re.I)


def parse_time(value: str, now: float) -> float:
    """'90m', '2h', '1d' (before now) or an ISO 8601 time ('2026-10-18T09:40:00Z'; no zone = UTC)."""
    v = value.strip()
    if m := _REL.match(v):
        unit = {"m": 60, "min": 60, "h": 3600, "d": 86400}[m.group(2).lower()]
        return now - int(m.group(1)) * unit
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        raise InvalidRequest(
            f"{value!r} is not a time: use a duration before now ('30m', '2h', '1d') or an ISO 8601 time "
            "('2026-10-18T09:40:00Z')."
        ) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def window(since: str, until: str | None, now: float) -> tuple[int, int, int]:
    """(start, end, step) in seconds: at most MAX_POINTS samples per series, the step a whole minute."""
    start = parse_time(since, now)
    end = parse_time(until, now) if until else now
    end = min(end, now)
    if end - start < MIN_WINDOW:
        raise InvalidRequest(
            "The window must be at least 5 minutes (since before until, until not in the future)."
        )
    if end - start > MAX_WINDOW:
        raise InvalidRequest("The window can be at most 30 days; FMC keeps a limited history anyway.")
    step = max(MIN_STEP, math.ceil((end - start) / MAX_POINTS / 60) * 60)
    return int(start), int(end), step


def prom_series(data: Any) -> list[tuple[dict[str, Any], list[Point]]]:
    """health/metrics -> [(labels, [(time, value)])] from every item's Prometheus matrix."""
    out: list[tuple[dict[str, Any], list[Point]]] = []
    for item in (data or {}).get("items") or []:
        try:
            prom = json.loads(item.get("response") or "{}")
        except (TypeError, ValueError):
            continue
        for s in (prom.get("data") or {}).get("result") or []:
            pts: list[Point] = []
            for ts, val in s.get("values") or []:
                try:
                    v = float(val)
                except (TypeError, ValueError):
                    continue
                if math.isfinite(v):
                    pts.append((float(ts), v))
            if pts:
                out.append((s.get("metric") or {}, sorted(pts)))
    return out


def rates(points: list[Point], scale: float = 1.0) -> list[Point]:
    """Per-second rates of a counter between consecutive samples (a counter that went down was reset:
    its new value counts from zero), timed at the later sample."""
    out: list[Point] = []
    for (t0, v0), (t1, v1) in zip(points, points[1:], strict=False):
        dt = t1 - t0
        if dt <= 0:
            continue
        delta = v1 - v0 if v1 >= v0 else v1
        out.append((t1, delta / dt * scale))
    return out


def increase(points: list[Point], start: float, step: float) -> float:
    """How much a counter grew over the window; a series that appears inside the window (FMC starts one
    for a drop reason at its first occurrence) counts from zero."""
    if not points:
        return 0.0
    total = points[0][1] if points[0][0] > start + step else 0.0
    for (_, v0), (_, v1) in zip(points, points[1:], strict=False):
        total += v1 - v0 if v1 >= v0 else v1
    return total


def _r(v: float) -> float:
    return round(v, 2) if abs(v) < 1000 else round(v)


def compact(points: list[Point], start: float, end: float, n: int) -> dict[str, Any]:
    """`n` buckets over the window, each the average of its samples (None where FMC has none)."""
    width = (end - start) / n
    buckets: list[list[float]] = [[] for _ in range(n)]
    for t, v in points:
        i = min(n - 1, max(0, int((t - start) / width))) if width > 0 else 0
        buckets[i].append(v)
    return {
        "start": _utc(start),
        "step_s": round(width),
        "values": [_r(sum(b) / len(b)) if b else None for b in buckets],
    }


def _runs(points: list[Point], hit: list[bool], pick: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    run: list[Point] = []
    for p, h in zip([*points, (0.0, 0.0)], [*hit, False], strict=True):
        if h:
            run.append(p)
        elif run:
            t, v = pick(run, key=lambda x: x[1])
            row = {"from": _utc(run[0][0]), "to": _utc(run[-1][0]), "value": _r(v), "at": _utc(t)}
            out.append(row)
            run = []
    return out


def summarize(
    points: list[Point], start: float, end: float, n: int, *, percent: bool = False, series: bool = True
) -> dict[str, Any]:
    """min / avg / max (with when), last, peaks and dips (runs of samples at least two standard
    deviations and a clear margin away from the average: 5 points for a percentage, half the average
    otherwise) and, with `series`, the compact series."""
    vals = [v for _, v in points]
    avg = statistics.fmean(vals)
    sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    hi = max(points, key=lambda p: p[1])
    lo = min(points, key=lambda p: p[1])
    out: dict[str, Any] = {
        "min": _r(lo[1]),
        "avg": _r(avg),
        "max": _r(hi[1]),
        "max_at": _utc(hi[0]),
        "last": _r(vals[-1]),
        "samples": len(vals),
    }
    if lo[1] != hi[1]:
        out["min_at"] = _utc(lo[0])
    margin = 5.0 if percent else 0.5 * abs(avg)
    if sd > 0 and len(vals) >= 3:
        peaks = _runs(points, [v >= avg + 2 * sd and v - avg >= margin for v in vals], max)
        dips = _runs(points, [v <= avg - 2 * sd and avg - v >= margin for v in vals], min)
        if peaks:
            out["peaks"] = peaks[:5]
        if dips:
            out["dips"] = dips[:5]
    if series:
        out["series"] = compact(points, start, end, n)
    return out


def _gauges(
    rows: list[tuple[dict[str, Any], list[Point]]],
    label: str,
    names: dict[str, str],
    start: float,
    end: float,
    n: int,
    limits: tuple[float, float],
    what: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    out: dict[str, Any] = {"unit": "%"}
    for labels, pts in rows:
        key = names.get(str(labels.get(label)))
        if key is None or key in out:
            continue
        out[key] = summarize(pts, start, end, n, percent=True)
        level = (
            "critical"
            if out[key]["max"] >= limits[1]
            else "warning"
            if out[key]["max"] >= limits[0]
            else None
        )
        if level:
            findings.append(
                {
                    "severity": level,
                    "what": f"{what} {key}",
                    "reason": f"{what} {key} reached {out[key]['max']} % at {out[key]['max_at']} "
                    f"(average {out[key]['avg']} %; warning {limits[0]:g}, critical {limits[1]:g})",
                }
            )
    order = [v for v in names.values() if v in out]
    return {"unit": "%", **{k: out[k] for k in order}} if order else {}


def interface_rows(
    rows: list[tuple[dict[str, Any], list[Point]]],
) -> dict[str, dict[str, Any]]:
    """{hardware name: {'name': logical name, 'type': ..., description: points}} for the interface family."""
    out: dict[str, dict[str, Any]] = {}
    for labels, pts in rows:
        hw = str(labels.get("interface") or "")
        if not hw:
            continue
        row = out.setdefault(
            hw, {"name": labels.get("interface_name"), "type": labels.get("interface_type"), "data": {}}
        )
        row["data"][str(labels.get("description"))] = pts
    return out


def _wanted_iface(hw: str, row: dict[str, Any], interface: str | None) -> bool:
    if interface is None:
        return True
    want = interface.strip().lower()
    return want in (hw.lower(), str(row.get("name") or "").lower())


def throughput(
    ifaces: dict[str, dict[str, Any]], interface: str | None, start: float, end: float, n: int
) -> dict[str, Any]:
    """Bits and packets per second in and out: the device total (FMC's 'all' row, else the sum of the
    data interfaces) or one interface, and the busiest interfaces."""
    per: list[dict[str, Any]] = []
    for hw, row in ifaces.items():
        if hw == "all" or hw.endswith("_all") or not _wanted_iface(hw, row, interface):
            continue
        entry: dict[str, Any] = {"interface": f"{row['name']} ({hw})" if row.get("name") else hw}
        for desc, (key, scale) in INTERFACE_RATES.items():
            pts = rates(row["data"].get(desc) or [], scale)
            if pts:
                entry[key] = summarize(pts, start, end, n, series=interface is not None)
        if len(entry) > 1:
            entry["_rank"] = max(
                entry.get("in_bps", {}).get("max", 0), entry.get("out_bps", {}).get("max", 0)
            )
            per.append(entry)
    per.sort(key=lambda e: -e["_rank"])
    for e in per:
        e.pop("_rank")
    out: dict[str, Any] = {"unit": "bit/s and packets/s"}
    if interface is not None:
        if not per:
            known = ", ".join(sorted(f"{r.get('name')} ({hw})" for hw, r in ifaces.items() if hw != "all"))
            raise NotFound(
                f"No interface {interface!r} in FMC's metrics for this device. Known: {known}.", 404
            )
        out["interface"] = per[0]
        return out
    total: dict[str, Any] = {}
    agg = ifaces.get("all")
    for desc, (key, scale) in INTERFACE_RATES.items():
        if agg and agg["data"].get(desc):
            pts = rates(agg["data"][desc], scale)
        else:  # sum the data interfaces' rates per timestamp
            summed: dict[float, float] = {}
            for hw, row in ifaces.items():
                if hw == "all" or hw.endswith("_all") or row.get("type") in ("SubInterface", "Management"):
                    continue
                for t, v in rates(row["data"].get(desc) or [], scale):
                    summed[t] = summed.get(t, 0.0) + v
            pts = sorted(summed.items())
        if pts:
            total[key] = summarize(pts, start, end, n)
    if total:
        out["total"] = total
    out["interfaces"] = per[:8]
    return out


def drops(
    asp: list[tuple[dict[str, Any], list[Point]]],
    ifaces: dict[str, dict[str, Any]],
    interface: str | None,
    start: float,
    end: float,
    step: int,
    n: int,
) -> dict[str, Any]:
    """Accelerated-security-path drops per reason and interface drops/errors, as counts over the window,
    with the drop rate over time for the busiest reasons."""
    out: dict[str, Any] = {}
    reasons = []
    for labels, pts in asp:
        count = increase(pts, start, step)
        if count <= 0:
            continue
        row: dict[str, Any] = {
            "reason": labels.get("asp_drops"),
            "description": labels.get("description"),
            "count": round(count),
        }
        rate = rates(pts)
        if len(rate) >= 3:
            row["per_second"] = summarize(rate, start, end, n, series=False)
        reasons.append(row)
    reasons.sort(key=lambda r: -r["count"])
    if reasons:
        out["asp_drops"] = reasons[:10]
        out["asp_total"] = sum(r["count"] for r in reasons)
    per = []
    for hw, row in ifaces.items():
        if hw == "all" or hw.endswith("_all") or not _wanted_iface(hw, row, interface):
            continue
        counts = {k: round(increase(row["data"].get(k) or [], start, step)) for k in INTERFACE_COUNTS}
        counts = {k: v for k, v in counts.items() if v > 0}
        if counts:
            entry: dict[str, Any] = {
                "interface": f"{row['name']} ({hw})" if row.get("name") else hw,
                **counts,
            }
            drop_rate = rates(row["data"].get("drop_packets") or [])
            if counts.get("drop_packets") and drop_rate:
                entry["drops_per_second"] = summarize(drop_rate, start, end, n, series=False)
            per.append(entry)
    per.sort(key=lambda e: -sum(v for v in e.values() if isinstance(v, int)))
    if per:
        out["interfaces"] = per
    return out


def connections(
    rows: list[tuple[dict[str, Any], list[Point]]], start: float, end: float, n: int
) -> dict[str, Any]:
    names = {
        ("connection", "in_use"): "in_use",
        ("connection", "most_used"): "most_used",
        ("cps", "all"): "per_second",
        ("cps", "tcp"): "tcp_per_second",
        ("cps", "udp"): "udp_per_second",
        ("xlate", "in_use"): "xlates_in_use",
    }
    out: dict[str, Any] = {}
    for labels, pts in rows:
        key = names.get((str(labels.get("conn_stats")), str(labels.get("description"))))
        if key and key not in out:
            keep_series = key in ("in_use", "per_second")
            out[key] = summarize(pts, start, end, n, series=keep_series)
    if "most_used" in out:  # a high-water mark since boot or clear: only its last value means anything
        out["most_used"] = {"last": out["most_used"]["last"]}
    order = [v for v in names.values() if v in out]
    return {k: out[k] for k in order}


def snort(rows: list[tuple[dict[str, Any], list[Point]]], start: float, step: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for labels, pts in rows:
        desc = str(labels.get("description"))
        if labels.get("snort") == "stats" and desc in SNORT_COUNTERS:
            out[desc] = round(increase(pts, start, step))
        elif labels.get("snort") == "instances":
            out["instances"] = int(pts[-1][1])
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Device metrics over time")
    async def fmc_device_metrics(
        ctx: Context,
        device: DeviceRef,
        since: Annotated[
            str,
            Field(
                description="Start of the window: a duration before now ('30m', '2h', '1d') or an ISO 8601 "
                "time ('2026-10-18T09:40:00Z'); at most 30 days"
            ),
        ] = "1h",
        until: Annotated[
            str | None, Field(description="End of the window (same forms as since); default now")
        ] = None,
        metric: Annotated[
            Literal["overview", "cpu", "memory", "throughput", "connections", "drops", "snort", "all"],
            Field(
                description="overview (default: cpu, memory, throughput, connections, drops), one of those, "
                "snort (inspection counters), or all"
            ),
        ] = "overview",
        interface: Annotated[
            str | None,
            Field(description="Throughput and drops of this interface only (logical or hardware name)"),
        ] = None,
        points: Annotated[
            int, Field(ge=4, le=60, description="Values in each compact series (bucket averages)")
        ] = 12,
        domain: Domain = None,
    ) -> Any:
        """Was this firewall busy, and when? CPU (data plane, control plane, Snort, system), memory,
        throughput (bit/s and packets/s in and out, the device total and the busiest interfaces),
        connections (in use, new per second, xlates), drops (accelerated-security-path drop reasons and
        interface drops/errors, as counts over the window) and, on request, Snort counters, from FMC's
        health monitor over a window you choose. Each series is summarised (min, avg, max and when,
        last, peaks and dips: runs well above or below the average) with a compact series of bucket
        averages, and CPU or memory above 80/85 % (critical 90/95 %) is flagged. Use it for "was the
        branch firewall busy during the outage at 09:40?", to see a traffic burst as a CPU and
        throughput peak, or to check a device after a change; current values only: fmc_device_health.
        Read-only; one FMC request per metric family (overview: five). FMC samples every few minutes
        and its newest values can trail the device by up to ~5 minutes; the health modules must be
        enabled in the device's health policy (fmc_get_health_policy)."""
        app: FmcApp = get_client(ctx)
        start, end, step = window(since, until, _now())
        dev = await resolve_device(app, device, domain)
        views = VIEWS[metric]
        families = sorted({f for v in views for f in NEEDS[v]})
        path = await app.config_path("health/metrics", domain)
        data: dict[str, list[tuple[dict[str, Any], list[Point]]]] = {}
        notes: list[str] = []
        for fam in families:
            name, regex = QUERIES[fam]
            flt = f"deviceUUIDs:{dev['id']};metric:{name};startTime:{start};endTime:{end};step:{step}"
            if regex:
                flt += f";regexFilter:{regex}"
            try:
                data[fam] = prom_series(await app.api.get(path, {"filter": flt}, timeout=120))
            except (InvalidRequest, NotFound, UpstreamError) as err:
                notes.append(f"{name}: not available ({err})")
                data[fam] = []
            if not data[fam] and not any(n.startswith(f"{name}:") for n in notes):
                notes.append(
                    f"{name}: FMC has no samples for this window (device not reporting, the health module "
                    "off in its health policy, or the window before FMC's retention)"
                )
        findings: list[dict[str, Any]] = []
        out: dict[str, Any] = {}
        ifaces = interface_rows(data.get("interfaces") or [])
        for view in views:
            if view == "cpu" and data["cpu"]:
                out["cpu"] = _gauges(
                    data["cpu"], "cpu", CPU_SERIES, start, end, points, CPU_LIMITS, "CPU", findings
                )
            elif view == "memory" and data["memory"]:
                out["memory"] = _gauges(
                    data["memory"], "mem", MEM_SERIES, start, end, points, MEM_LIMITS, "memory", findings
                )
            elif view == "throughput" and ifaces:
                out["throughput"] = throughput(ifaces, interface, start, end, points)
            elif view == "connections" and data["connections"]:
                out["connections"] = connections(data["connections"], start, end, points)
            elif view == "drops" and (data["asp_drops"] or ifaces):
                out["drops"] = drops(data["asp_drops"], ifaces, interface, start, end, step, points) or {
                    "note": "no drops in the window"
                }
            elif view == "snort" and data["snort"]:
                out["snort"] = snort(data["snort"], start, step)
        result: dict[str, Any] = {
            "device": dev.get("name"),
            "window": {"from": _utc(start), "to": _utc(end), "sample_step_s": step},
            **out,
        }
        if findings:
            result["findings"] = findings
        notes.append(
            "Samples are the value at each step: a spike shorter than sample_step_s can fall between two; "
            "narrow the window for detail. FMC's newest samples can trail the device by up to ~5 minutes."
        )
        result["notes"] = notes
        return object_result(result, shape=False)
