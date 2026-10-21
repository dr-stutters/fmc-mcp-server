"""Snort 3 rule and CPU profiling on a device (F78): fmc_snort_profile, fmc_cpu_profile and
fmc_get_profiler_results. "Which rules or inspectors burn Snort CPU?" is the first TAC step for high
Snort CPU or latency; the answer feeds fmc_find_intrusion_rules / fmc_set_intrusion_rule_state.

FMC's troubleshoot API (the FMC 7.5 spec, the same on 10.0.1):
- Snort rule profiler: GET|POST `fmc_troubleshoot/.../snortprofiler/{device}/rules`, GET `.../rules/{file}`.
  POST `{type: SnortProfiler, status: ENABLED}` starts it. It has no duration field, so it runs until a POST
  with `status: DISABLED` stops it: fmc_snort_profile starts it, waits, and stops it itself.
- CPU profiler (Snort 3 modules): GET|POST `cpuprofiler/{device}/modules`, GET `.../modules/{file}`. POST
  takes `duration` in minutes (15-120, FMC's default 120) and stops by itself.
- GET `...?filter=latest:true` answers the newest profiler file: a header (status, start/end time as
  'HH:MM:SS MM-DD-YYYY', access policy, VDB, LSP and Snort versions, `profilerFileName`) with `rules[]`
  (the top 100) or `modules[]`. There is no PUT or DELETE.

Not recorded live (W6N probe, FMC 10.0.1, 2026-10-21): the lab's API role got 403 "The user is not
authorized." on all four calls, while packet tracer (the same API family) worked for the same login. So
the stop (POST DISABLED), the shortest run, the POST answer and the real result JSON follow the spec and
its examples. `ruleTimePercentage`, `callerPercentage` and `totalPercentage` appear in the examples but
not in the schemas, so they are optional here. A 403 is reported as the role's missing profiling
permission, not as a credentials problem.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
import logging
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.devices import Membership, resolve_unit
from fmc_mcp.tools.render import object_reply

log = logging.getLogger(__name__)

DEVICES = "devices/devicerecords"
SNORT_MINUTES = (1, 60)  # ours: FMC's rule profiler has no duration (start, wait, stop)
CPU_MINUTES = (15, 120)  # FMC's range for the CPU profiler's duration
TOP_MAX = 100  # FMC keeps the top 100 rules per file
PROGRESS_EVERY = 30.0  # seconds between progress notifications while profiling
CPU_GRACE = 30.0  # seconds after the CPU profiler's own end before its file is read
COLLECT_POLLS = 12  # GETs of the latest file after a run (first after COLLECT_FIRST s, backing off)
COLLECT_FIRST = 10.0
COLLECT_MAX = 30.0
REFUSED = {400, 401, 403, 404, 409, 422}  # FMC refused the start before anything ran
FILE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
CREDENTIALS_HINT = re.compile(
    r"\s*Check \w+USERNAME/\w+PASSWORD and that the account's role allows this operation\.?"
)
FMC_DETAIL = re.compile(r"\((?:401|403)\) on \S+ \S+: (.*)$", re.S)
TIME_FORMATS = ("%H:%M:%S %m-%d-%Y", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
NOT_LIVE = (
    "Built from FMC's API spec: the run semantics (stop, shortest run, result JSON) were not yet recorded "
    "on a live FMC."
)


@dataclass(frozen=True)
class Profiler:
    key: Literal["snort", "cpu"]
    title: str
    segment: str  # fmc_troubleshoot collection
    rows: str  # its sub-collection and the result's list key
    type: str  # the body's `type`
    tool: str


SNORT = Profiler(
    "snort", "Snort rule profiler", "snortprofiler", "rules", "SnortProfiler", "fmc_snort_profile"
)
CPU = Profiler("cpu", "Snort 3 CPU profiler", "cpuprofiler", "modules", "CPUProfiler", "fmc_cpu_profile")
PROFILERS = {"snort": SNORT, "cpu": CPU}

DeviceArg = Annotated[
    str,
    Field(
        description="FTD name or UUID (fmc_list_devices); an HA pair's or cluster's name means its active "
        "unit / control node"
    ),
]
Top = Annotated[int, Field(ge=1, le=TOP_MAX, description="Rows to return, most time first (FMC keeps 100)")]


async def pause(seconds: float) -> None:
    """Wait (tests replace this)."""
    await asyncio.sleep(seconds)


def now() -> float:
    """Wall clock (tests freeze this)."""
    return time.time()


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- errors -----------------------------------------------------------------------------------------


def fmc_detail(err: UpstreamError) -> str:
    """FMC's own words in a core error message, without the core's credentials hint."""
    text = CREDENTIALS_HINT.sub("", str(err)).strip()
    m = FMC_DETAIL.search(text)
    return (m.group(1) if m else text).strip().rstrip(".") + "."


def refusal(err: UpstreamError, prof: Profiler) -> str:
    """Why FMC refused a profiler call (403): the role's missing permission, or a feature flag."""
    detail = fmc_detail(err)
    if "feature flag" in detail.lower():
        return (
            f"FMC has the {prof.title} behind a feature flag on this version (403: {detail}) Feature flags "
            "are an FMC system setting, which this server doesn't change."
        )
    return (
        f"FMC refused the {prof.title} for this account (403: {detail}) The FMC user's role lacks the "
        "Snort 3 profiling permission (FMC's page for it: Devices > Troubleshoot > Snort 3 Profiling); add "
        "it to the role, or run the profile as a user whose role has it. This isn't a login problem when "
        "other calls work with the same account (fmc_packet_tracer is the same API family)."
    )


def refused(err: UpstreamError, prof: Profiler) -> UpstreamError:
    """A 403 becomes AuthError(refusal); other errors are returned unchanged."""
    if err.status_code == 403:
        return AuthError(refusal(err, prof), 403)
    return err


# --- FMC calls --------------------------------------------------------------------------------------


async def profiler_base(app: FmcApp, prof: Profiler, dev: dict[str, Any], domain: str | None) -> str:
    """The profiler's collection for the device, in the domain that owns the device."""
    where = await app.device_domain(DEVICES, str(dev["id"]), await app.domain_uuid(domain))
    return f"/api/fmc_troubleshoot/v1/domain/{where}/{prof.segment}/{dev['id']}/{prof.rows}"


def first_item(resp: Any) -> dict[str, Any] | None:
    """The newest profiler file in a list answer. FMC answers `{items: [{}]}` for some empty troubleshoot
    collections (packettracer/files on 10.0.1), so empty items don't count; a bare object is taken as is."""
    if not isinstance(resp, dict):
        return None
    if "items" not in resp:
        return resp if resp.get("type") or resp.get("profilerFileName") or resp.get("status") else None
    rows = [x for x in resp.get("items") or [] if isinstance(x, dict) and x]
    return rows[0] if rows else None


async def latest(app: FmcApp, base: str) -> dict[str, Any] | None:
    """The newest profiler file (filter=latest:true), or None when the device has none."""
    try:
        resp = await app.api.get(base, params={"filter": "latest:true", "expanded": "true"})
    except NotFound:
        return None
    return first_item(resp)


async def read_file(app: FmcApp, base: str, name: str) -> dict[str, Any]:
    """One profiler file by name. The spec's example of this answer has no `profilerFileName` (only the list
    answer carries it), so the name asked for is kept on it."""
    data = await app.api.get(f"{base}/{name}")
    item = first_item(data)
    if item is None:
        raise NotFound(f"FMC returned no profiler file {name!r}.", 404)
    return {**item, "profilerFileName": item.get("profilerFileName") or name}


def running(item: dict[str, Any] | None) -> bool:
    return str((item or {}).get("status") or "").upper() == "ENABLED"


def finished(item: dict[str, Any] | None, before: str | None) -> bool:
    """A run's file is there: FMC says the profiler is off and names a file other than `before`."""
    if item is None or running(item):
        return False
    name = item.get("profilerFileName")
    return bool(name) and name != before


def body(prof: Profiler, status: str, minutes: int | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"type": prof.type, "status": status}
    if minutes is not None:
        out["duration"] = minutes
    return out


async def post(app: FmcApp, base: str, prof: Profiler, payload: dict[str, Any]) -> dict[str, Any]:
    """POST start/stop; FMC's 403 becomes the role message and an `error` in the answer a refusal."""
    try:
        resp = await app.api.post(base, payload, timeout=120)
    except NotFound as e:
        raise NotFound(
            f"FMC has no {prof.title} for this device (404 on POST {base}): it needs a Snort 3 device and an "
            "FMC and FTD version with Snort 3 profiling.",
            404,
        ) from e
    except UpstreamError as e:
        raise refused(e, prof) from e
    item = first_item(resp) or {}
    if err := item.get("error"):
        what = "start" if payload.get("status") == "ENABLED" else "stop"
        raise UpstreamError(f"FMC couldn't {what} the {prof.title}: {err}", 400)
    return item


async def hold(ctx: Context, seconds: float, message: str) -> None:
    """Wait `seconds`, with a progress notification every PROGRESS_EVERY s (best effort)."""
    done = 0.0
    while done < seconds:
        step = min(PROGRESS_EVERY, seconds - done)
        await pause(step)
        done += step
        with contextlib.suppress(Exception):
            await ctx.report_progress(progress=done, total=seconds, message=message)


STOPS: set["asyncio.Task[Any]"] = set()  # stop POSTs in flight: the loop keeps only weak references


def _stop_done(task: "asyncio.Task[Any]") -> None:
    STOPS.discard(task)
    if not task.cancelled() and (err := task.exception()) is not None:
        log.warning("Stopping the Snort rule profiler failed: %s", err)


async def stop_anyway(app: FmcApp, base: str) -> None:
    """POST status DISABLED however the call ends. The POST is its own task, kept referenced and shielded:
    a cancelled call (tasks/cancel, a client that went away, cancelled again while it waits here) still
    sends it. Its errors are logged, not raised (the call is already failing)."""
    task = asyncio.ensure_future(app.api.post(base, body(SNORT, "DISABLED"), timeout=60))
    STOPS.add(task)
    task.add_done_callback(_stop_done)
    with contextlib.suppress(Exception):
        await asyncio.shield(task)


async def snort_window(ctx: Context, app: FmcApp, base: str, minutes: int, dev_name: str) -> None:
    """Start the rule profiler, wait `minutes`, stop it. FMC's rule profiler has no duration, so a wait that
    fails or is cancelled stops it too; a start FMC refused (REFUSED) sends no stop."""
    on = True  # the profiler may be running: stop it however this ends
    try:
        try:
            await post(app, base, SNORT, body(SNORT, "ENABLED"))
        except UpstreamError as e:
            on = e.status_code not in REFUSED  # FMC refused it: nothing started
            raise
        await hold(ctx, minutes * 60.0, f"Snort rule profiling on {dev_name}")
        try:
            await post(app, base, SNORT, body(SNORT, "DISABLED"))
        except UpstreamError as e:
            raise UpstreamError(
                f"Profiled for {minutes} min, but FMC refused the stop: {e} The rule profiler may still be "
                f"running on {dev_name}: fmc_snort_profile(device='{dev_name}', action='stop').",
                e.status_code,
            ) from e
        on = False
    finally:
        if on:  # cancelled (tasks/cancel, client gone) or failed: never leave it running
            await stop_anyway(app, base)


async def collect(
    app: FmcApp, base: str, prof: Profiler, before: str | None
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(the run's file with its rows, FMC's last latest answer) after a run; the file is None when FMC
    named no new file within COLLECT_POLLS reads."""
    wait = COLLECT_FIRST
    last: dict[str, Any] | None = None
    for n in range(COLLECT_POLLS):
        last = await latest(app, base)
        if last is not None and finished(last, before):
            if not last.get(prof.rows):
                return await read_file(app, base, str(last["profilerFileName"])), last
            return last, last
        if n < COLLECT_POLLS - 1:
            await pause(wait)
            wait = min(COLLECT_MAX, wait * 1.5)
    return None, last


# --- results ----------------------------------------------------------------------------------------


def parse_time(value: Any) -> str | None:
    """FMC's 'HH:MM:SS MM-DD-YYYY' (no zone: the device's clock) as 'YYYY-MM-DDTHH:MM:SS'."""
    if not value:
        return None
    text = str(value).strip()
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue
    return text


def window_seconds(item: dict[str, Any]) -> int | None:
    start, end = parse_time(item.get("startTime")), parse_time(item.get("endTime"))
    try:
        a = datetime.fromisoformat(str(start))
        b = datetime.fromisoformat(str(end))
    except ValueError:
        return None
    return int((b - a).total_seconds())


def header(item: dict[str, Any] | None) -> dict[str, Any] | None:
    """A profiler file without its rows: what ran, when, and on which software."""
    if not item:
        return None
    sw = item.get("swVersion")
    if sw and item.get("swBuild"):
        sw = f"{sw} build {item['swBuild']}"
    out = {
        "file": item.get("profilerFileName"),
        "status": item.get("status"),
        "running": running(item),
        "start": parse_time(item.get("startTime")),
        "end": parse_time(item.get("endTime")),
        "window_s": window_seconds(item),
        "duration_min": item.get("duration"),
        "access_policy": item.get("accessPolicyName"),
        "access_policy_exported": parse_time(item.get("accessPolicyExported")),
        "snort_version": item.get("snortVersion"),
        "software": sw,
        "vdb": item.get("vdb"),
        "lsp": item.get("lsp"),
        "message": item.get("message"),
        "error": item.get("error"),
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


def _num(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _int(v: float) -> int | float:
    return int(v) if float(v).is_integer() else round(v, 2)


def rule_rows(rules: list[dict[str, Any]], top: int) -> tuple[list[dict[str, Any]], list[str]]:
    """The file's rules, one row per gid:sid (Snort instances summed), most time first."""
    instances = {r.get("instanceId") for r in rules}
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in rules:
        groups.setdefault((str(r.get("gid")), str(r.get("sid"))), []).append(r)
    rows: list[dict[str, Any]] = []
    for (gid, sid), rs in groups.items():
        time_us = sum(_num(r.get("timeUs")) for r in rs)
        checks = sum(_num(r.get("checks")) for r in rs)
        matches = sum(_num(r.get("matches")) for r in rs)
        pcts = [_num(r["ruleTimePercentage"]) for r in rs if r.get("ruleTimePercentage") is not None]
        if len(rs) == 1:
            r = rs[0]
            avg_check, avg_match, avg_non = (_num(r.get(k)) for k in ("avgCheck", "avgMatch", "avgNonMatch"))
        else:
            avg_check = time_us / checks if checks else 0.0
            avg_match = (
                sum(_num(r.get("avgMatch")) * _num(r.get("matches")) for r in rs) / matches
                if matches
                else 0.0
            )
            non = checks - matches
            avg_non = (
                sum(_num(r.get("avgNonMatch")) * (_num(r.get("checks")) - _num(r.get("matches"))) for r in rs)
                / non
                if non
                else 0.0
            )
        row: dict[str, Any] = {
            "rule": f"{gid}:{sid}",
            "rev": rs[0].get("rev"),
            "message": rs[0].get("message"),
            "time_pct": round(sum(pcts) / max(len(instances), 1), 2) if pcts else None,
            "time_us": _int(time_us),
            "checks": _int(checks),
            "matches": _int(matches),
            "alerts": _int(sum(_num(r.get("alerts")) for r in rs)),
            "avg_check_us": _int(avg_check),
            "avg_match_us": _int(avg_match),
            "avg_non_match_us": _int(avg_non),
            "timeouts": _int(sum(_num(r.get("timeouts")) for r in rs)),
            "suspends": _int(sum(_num(r.get("suspends")) for r in rs)),
        }
        if len(instances) > 1:
            row["instances"] = len(rs)
        rows.append({k: v for k, v in row.items() if v is not None})
    rows.sort(key=lambda x: (-_num(x["time_us"]), -_num(x["checks"]), x["rule"]))
    notes: list[str] = []
    if len(instances) > 1:
        notes.append(
            f"{len(instances)} Snort instances: time, checks, matches and alerts are summed per rule; "
            "time_pct is the mean of FMC's per-instance ruleTimePercentage (0 where the rule isn't listed)."
        )
    if len(rules) >= TOP_MAX:
        notes.append("FMC keeps only the 100 costliest rule rows per profiler file.")
    return [{"rank": n, **r} for n, r in enumerate(rows[:top], 1)], notes


def module_rows(modules: list[dict[str, Any]], top: int) -> tuple[list[dict[str, Any]], list[str]]:
    """The file's Snort modules with their caller (the module above them in Snort's tree), one row per
    module and place in the tree (instances summed), most time first."""
    by_instance: dict[Any, list[dict[str, Any]]] = {}
    for m in modules:
        by_instance.setdefault(m.get("instanceId"), []).append(m)
    groups: dict[tuple[str, int, str | None], list[dict[str, Any]]] = {}
    for rows in by_instance.values():
        stack: list[str] = []
        for m in sorted(rows, key=lambda x: _num(x.get("number"))):
            layer = max(int(_num(m.get("layer")) or 1), 1)
            caller = stack[layer - 2] if layer > 1 and len(stack) >= layer - 1 else None
            stack = [*stack[: layer - 1], str(m.get("name"))]
            groups.setdefault((str(m.get("name")), layer, caller), []).append(m)
    n_inst = max(len(by_instance), 1)
    out: list[dict[str, Any]] = []
    for (name, layer, caller), ms in groups.items():
        time_us = sum(_num(m.get("timeUs")) for m in ms)
        checks = sum(_num(m.get("checks")) for m in ms)
        total = [_num(m["totalPercentage"]) for m in ms if m.get("totalPercentage") is not None]
        of_caller = [_num(m["callerPercentage"]) for m in ms if m.get("callerPercentage") is not None]
        row: dict[str, Any] = {
            "module": name,
            "layer": layer,
            "caller": caller,
            "time_pct": round(sum(total) / n_inst, 2) if total else None,
            "caller_pct": round(sum(of_caller) / len(of_caller), 2) if of_caller else None,
            "time_us": _int(time_us),
            "checks": _int(checks),
            "avg_check_us": _int(
                _num(ms[0].get("avgCheckUs")) if len(ms) == 1 else (time_us / checks if checks else 0)
            ),
        }
        if n_inst > 1:
            row["instances"] = len(ms)
        out.append({k: v for k, v in row.items() if v is not None})
    out.sort(key=lambda x: (-_num(x["time_us"]), x["layer"], x["module"]))
    notes = [
        "A module's time includes the modules it calls (the rows naming it as caller); time_pct is its share "
        "of Snort's total time, caller_pct its share of the caller's.",
    ]
    if any(r["module"] == "daq" for r in out):
        notes.append(
            "daq is packet acquisition (receiving packets from the data plane): a large daq share on a quiet "
            "device is mostly waiting for traffic, not inspection."
        )
    if n_inst > 1:
        notes.append(
            f"{n_inst} Snort instances: time and checks are summed; time_pct is the mean of FMC's "
            "per-instance totalPercentage."
        )
    return [{"rank": n, **r} for n, r in enumerate(out[:top], 1)], notes


def rule_next_steps(rows: list[dict[str, Any]], item: dict[str, Any]) -> list[str]:
    ids = [str(r["rule"]) for r in rows[:3]]
    if not ids:
        return []
    acp = item.get("accessPolicyName")
    where = f" (rules in {acp!r} carry the intrusion policies: fmc_get_access_policy)" if acp else ""
    finds = ", ".join(f"fmc_find_intrusion_rules(query='{i}')" for i in ids)
    listed = ", ".join(f"'{i}'" for i in ids)
    return [
        f"What each costly rule is (message, default state, rule text): {finds}.",
        "Tune a rule that costs more than it is worth in the custom intrusion policy the access rules use"
        f"{where}: fmc_set_intrusion_rule_state(policy=<custom intrusion policy>, rules=[{listed}], "
        "state='DISABLE') (system policies are read-only: fmc_create_intrusion_policy on top of one first), "
        "then fmc_pending_changes and fmc_deploy.",
        "Rules with timeouts or suspends hit Snort's rule latency limits: those first.",
    ]


def cpu_next_steps(rows: list[dict[str, Any]]) -> list[str]:
    tops = [str(r["module"]) for r in rows if r.get("module") != "daq"][:3]
    out = [
        "Snort CPU over time: fmc_device_metrics(device, metric='cpu') (snort) and metric='snort' (flows, "
        "blocked and bypassed packets)."
    ]
    if any(t in ("detection", "rule_eval", "ips", "search_engine", "fast_pattern") for t in tops):
        out.append("Detection leads: fmc_snort_profile names the rules behind it.")
    elif tops:
        out.append(
            f"The costliest modules are {', '.join(tops)}: their settings are in the network analysis policy "
            "(fmc_get_network_analysis_policy) or the intrusion policy."
        )
    return out


def result_view(prof: Profiler, item: dict[str, Any], top: int) -> dict[str, Any]:
    """A profiler file as the tools return it: header, ranked rows, notes and next steps."""
    rows_in = [x for x in item.get(prof.rows) or [] if isinstance(x, dict) and x]
    out: dict[str, Any] = {"profile": header(item)}
    if prof is SNORT:
        rows, notes = rule_rows(rows_in, top)
        out["rules_in_file"] = len(rows_in)
        if rows:
            t = rows[0]
            share = f" ({t['time_pct']} % of rule time)" if "time_pct" in t else ""
            latency = sum(1 for r in rows if _num(r.get("timeouts")) or _num(r.get("suspends")))
            out["summary"] = (
                f"Costliest rule {t['rule']}{share}: {_num(t['time_us']) / 1000:.1f} ms over "
                f"{t['checks']} checks"
                + (
                    f"; {latency} listed rule(s) hit Snort's latency limits (timeouts/suspends)."
                    if latency
                    else "."
                )
            )
        out["rules"] = rows
        steps = rule_next_steps(rows, item)
    else:
        rows, notes = module_rows(rows_in, top)
        out["modules_in_file"] = len(rows_in)
        work = [r for r in rows if r.get("module") != "daq"]
        if work:
            t = work[0]
            share = f" ({t['time_pct']} % of Snort's time)" if "time_pct" in t else ""
            out["summary"] = f"Costliest module after packet acquisition: {t['module']}{share}."
        out["modules"] = rows
        steps = cpu_next_steps(rows)
    if not rows:
        notes.append(
            f"The file lists no {prof.rows}: Snort saw no traffic to profile in the window (send traffic "
            "through the device's inspected rules while it runs), or FMC kept no data."
        )
    if notes:
        out["notes"] = notes
    if steps and rows:
        out["next_steps"] = steps
    return out


# --- tools --------------------------------------------------------------------------------------------


@dataclass
class Target:
    dev: dict[str, Any]
    member: Membership | None
    base: str
    state: dict[str, Any] | None  # the newest file before the change
    state_error: str | None  # why it couldn't be read
    blockers: list[str]

    @property
    def label(self) -> str:
        name = str(self.dev.get("name"))
        return self.member.label(name) if self.member else name


async def target(app: FmcApp, prof: Profiler, device: str, domain: str | None) -> Target:
    """The device, its profiler collection, the newest file and what blocks a run there."""
    dev, member = await resolve_unit(app, device, domain)
    base = await profiler_base(app, prof, dev, domain)
    blockers: list[str] = []
    name = dev.get("name")
    if dev.get("isConnected") is False:
        blockers.append(
            f"FMC lists {name} as disconnected: it can't run a profiler there (fmc_list_devices)."
        )
    engine = str(dev.get("snortEngine") or "").upper()
    if engine and engine != "SNORT3":
        blockers.append(f"{name} runs {engine}: FMC's Snort profilers are Snort 3 only.")
    state, state_error = None, None
    try:
        state = await latest(app, base)
    except UpstreamError as e:
        if e.status_code == 403:
            blockers.append(refusal(e, prof))
            state_error = "refused (403)"
        else:
            state_error = f"not read: {e}"
    return Target(dev, member, base, state, state_error, blockers)


def device_details(t: Target) -> dict[str, Any]:
    meta = t.dev.get("metadata") or {}
    out = {
        "device": t.label,
        "snort": meta.get("snortVersion") or t.dev.get("snortEngine"),
        "software": t.dev.get("sw_version"),
        "access_policy": (t.dev.get("accessPolicy") or {}).get("name"),
    }
    return {k: v for k, v in out.items() if v}


def last_run(t: Target) -> Any:
    if t.state_error:
        return t.state_error
    return header(t.state) or "none (no profiler file on the device yet)"


def fingerprint(t: Target) -> dict[str, Any]:
    s = t.state or {}
    return {
        "device": t.dev["id"],
        "latest": [s.get("profilerFileName"), s.get("status")],
        "read": t.state_error,
    }


SNORT_COST = (
    "While it runs, Snort times every rule it evaluates on {dev}: Snort CPU and per-packet latency go up for "
    "the whole window, which matters on a device already short of CPU (check headroom first: "
    "fmc_device_metrics(device, metric='cpu')). Run it while representative traffic flows, as briefly as "
    "gives an answer."
)
CPU_COST = (
    "While it runs, Snort times every module (inspector) call on {dev}: Snort CPU and per-packet latency go "
    "up for the whole window, which matters on a device already short of CPU (check headroom first: "
    "fmc_device_metrics(device, metric='cpu')). Run it while representative traffic flows."
)


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Snort rule profiling", destructive=False, task=True)
    async def fmc_snort_profile(
        ctx: Context,
        device: DeviceArg,
        minutes: Annotated[
            int,
            Field(
                ge=SNORT_MINUTES[0],
                le=SNORT_MINUTES[1],
                description="How long to profile (1-60). FMC's rule profiler has no duration of its own: the "
                "server starts it, waits this long and stops it",
            ),
        ] = 5,
        action: Annotated[
            Literal["run", "stop"],
            Field(
                description="run (default): start, wait, stop, read the result. stop: end a run that is "
                "still going (e.g. after the server restarted mid-run) and read its result"
            ),
        ] = "run",
        top: Top = 25,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Which Snort rules burn CPU on this FTD? Runs FMC's Snort 3 rule profiler on the device for
        `minutes`, then returns the rules ranked by the time Snort spent in them: gid:sid, message, share of
        rule time, checks, matches, alerts, average time per check/match/non-match and latency timeouts and
        suspends. Each gid:sid goes straight into fmc_find_intrusion_rules (what the rule is) and
        fmc_set_intrusion_rule_state (disable or change it in a custom intrusion policy); the result names
        the calls. The preview states the duration and the CPU cost of profiling, the device's Snort and
        access policy, and the last run. Profiling changes no configuration and needs no deploy, but makes
        Snort slower while it runs. Needs a connected Snort 3 device and an FMC role with the Snort 3
        profiling permission (403 otherwise; the answer says which). Runs as an MCP background task when
        the server has MCP_TASKS=true; a cancelled call stops the profiler. Results of an earlier run:
        fmc_get_profiler_results. Module (inspector) CPU: fmc_cpu_profile."""
        app: FmcApp = get_client(ctx)
        t = await target(app, SNORT, device, domain)
        dev_name = str(t.dev.get("name"))
        if action == "run" and running(t.state):
            since = (header(t.state) or {}).get("start") or "an unknown time"
            t.blockers.append(
                f"A Snort rule profiler is already running on {dev_name} (since {since}): wait for whoever "
                "started it, or end it with action='stop'."
            )
        before = None if running(t.state) else (t.state or {}).get("profilerFileName")
        details: dict[str, Any] = {**device_details(t), "profiler": SNORT.title}
        if action == "run":
            details["duration"] = (
                f"{minutes} min: the server starts the profiler, waits, stops it and reads the result "
                "(FMC's rule profiler has no duration of its own)"
            )
            details["requests"] = (
                "2 POSTs (start, stop), then up to 13 GETs for the result; none while it runs"
            )
        else:
            details["stop"] = "POST status DISABLED, then the result is read"
            if not running(t.state) and not t.state_error:
                details["note"] = "FMC's newest file says no rule profiler is running; stopping is harmless."
        details["cpu_cost"] = SNORT_COST.format(dev=dev_name)
        details["last_run"] = last_run(t)
        details["verified"] = NOT_LIVE

        async def apply() -> dict[str, Any]:
            start = now()
            if action == "run":
                await snort_window(ctx, app, t.base, minutes, dev_name)
            else:
                await post(app, t.base, SNORT, body(SNORT, "DISABLED"))
            item, last = await collect(app, t.base, SNORT, before)
            out: dict[str, Any] = {
                "device": t.label,
                "profiled": f"{_utc(start)} - {_utc(now())} (server clock)",
            }
            if item is None:
                return {
                    **out,
                    "complete": False,
                    "latest": header(last),
                    "note": f"FMC named no new rule profiler file yet; read it later with "
                    f"fmc_get_profiler_results(device='{dev_name}', profiler='snort').",
                }
            return {**out, **result_view(SNORT, item, top)}

        summary = (
            f"Profile Snort rules on {t.label} for {minutes} min"
            if action == "run"
            else f"Stop the Snort rule profiler on {t.label}"
        )
        return await fmc_preview(
            ctx,
            tool="fmc_snort_profile",
            args={"device": device, "minutes": minutes, "action": action, "top": top, "domain": domain},
            confirm=confirm,
            plan=Plan(
                summary,
                details=details,
                fingerprint=fingerprint(t),
                blockers=t.blockers,
                blast_radius=1,
                side_effects=[
                    "No configuration changes and no deploy; Snort is slower while the profiler runs.",
                    "If the server itself stops mid-run, the profiler keeps running until "
                    f"fmc_snort_profile(device='{dev_name}', action='stop').",
                ],
            ),
            apply=apply,
        )

    @reg.write(title="Snort 3 CPU profiling", destructive=False, task=True)
    async def fmc_cpu_profile(
        ctx: Context,
        device: DeviceArg,
        minutes: Annotated[
            int,
            Field(
                ge=CPU_MINUTES[0],
                le=CPU_MINUTES[1],
                description="How long FMC's CPU profiler runs (15-120 min, FMC's range); it stops by itself",
            ),
        ] = 15,
        action: Annotated[
            Literal["run", "stop"],
            Field(description="run (default): start it (and wait, see `wait`). stop: end a run early"),
        ] = "run",
        wait: Annotated[
            bool,
            Field(
                description="Wait for the run and return the result (default). false: return once it has "
                "started; read the result later with fmc_get_profiler_results"
            ),
        ] = True,
        top: Top = 25,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Which Snort 3 modules (inspectors, detection, packet acquisition) use the CPU on this FTD? Runs
        FMC's Snort 3 CPU profiler on the device for `minutes` (15-120: FMC's range, so at least a quarter
        of an hour) and returns the modules ranked by time: share of Snort's total time and of the caller's,
        time, checks, average per check and the calling module. The preview states the duration and the CPU
        cost of profiling, the device's Snort and access policy, and the last run. No configuration changes
        and no deploy, but Snort is slower while it runs. With wait=false it returns once started;
        fmc_get_profiler_results(profiler='cpu') reads the result after the run. Needs a connected Snort 3
        device and an FMC role with the Snort 3 profiling permission (403 otherwise; the answer says which).
        Runs as an MCP background task when the server has MCP_TASKS=true. A cancelled call leaves the
        profiler to end by itself; action='stop' ends it early. Rule-level cost: fmc_snort_profile."""
        app: FmcApp = get_client(ctx)
        t = await target(app, CPU, device, domain)
        dev_name = str(t.dev.get("name"))
        if action == "run" and running(t.state):
            h = header(t.state) or {}
            since = h.get("start") or "an unknown time"
            length = f", {h['duration_min']} min" if h.get("duration_min") else ""
            t.blockers.append(
                f"A CPU profiler is already running on {dev_name} (since {since}{length}): it ends by "
                "itself; read it then with fmc_get_profiler_results, or end it with action='stop'."
            )
        before = None if running(t.state) else (t.state or {}).get("profilerFileName")
        details: dict[str, Any] = {**device_details(t), "profiler": CPU.title}
        if action == "run":
            details["duration"] = f"{minutes} min (FMC stops it by itself; its range is 15-120 min)"
            details["wait"] = (
                f"yes: about {minutes} min, then up to 13 GETs for the result"
                if wait
                else "no: returns once it has started"
            )
        else:
            details["stop"] = (
                "POST status DISABLED (the only stop FMC's API offers; not documented as one), then the "
                "result is read"
            )
            if not running(t.state) and not t.state_error:
                details["note"] = "FMC's newest file says no CPU profiler is running; stopping is harmless."
        details["cpu_cost"] = CPU_COST.format(dev=dev_name)
        details["last_run"] = last_run(t)
        details["verified"] = NOT_LIVE

        async def apply() -> dict[str, Any]:
            start = now()
            out: dict[str, Any] = {"device": t.label}
            if action == "run":
                started = await post(app, t.base, CPU, body(CPU, "ENABLED", minutes))
                out["started"] = f"{_utc(start)} (server clock)"
                if not wait:
                    return {
                        **out,
                        "ends_about": _utc(start + minutes * 60),
                        "fmc_answer": header(started),
                        "next": f"fmc_get_profiler_results(device='{dev_name}', profiler='cpu') after that; "
                        f"fmc_cpu_profile(device='{dev_name}', action='stop') ends it early.",
                    }
                await hold(ctx, minutes * 60.0 + CPU_GRACE, f"Snort 3 CPU profiling on {dev_name}")
            else:
                await post(app, t.base, CPU, body(CPU, "DISABLED"))
            item, last = await collect(app, t.base, CPU, before)
            if item is None:
                return {
                    **out,
                    "complete": False,
                    "latest": header(last),
                    "note": f"FMC named no new CPU profiler file yet; read it later with "
                    f"fmc_get_profiler_results(device='{dev_name}', profiler='cpu').",
                }
            return {**out, **result_view(CPU, item, top)}

        summary = (
            f"Profile Snort 3 module CPU on {t.label} for {minutes} min"
            if action == "run"
            else f"Stop the CPU profiler on {t.label}"
        )
        return await fmc_preview(
            ctx,
            tool="fmc_cpu_profile",
            args={
                "device": device,
                "minutes": minutes,
                "action": action,
                "wait": wait,
                "top": top,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                summary,
                details=details,
                fingerprint=fingerprint(t),
                blockers=t.blockers,
                blast_radius=1,
                side_effects=[
                    "No configuration changes and no deploy; Snort is slower while the profiler runs.",
                    f"It runs on the device for the full {minutes} min even if this call ends or is "
                    "cancelled.",
                ]
                if action == "run"
                else ["No configuration changes and no deploy."],
            ),
            apply=apply,
        )

    @reg.read(title="Snort profiler results")
    async def fmc_get_profiler_results(
        ctx: Context,
        device: DeviceArg,
        profiler: Annotated[
            Literal["snort", "cpu"],
            Field(description="snort: the rule profiler (fmc_snort_profile); cpu: the module profiler"),
        ] = "snort",
        file: Annotated[
            str | None,
            Field(
                description="A profiler file name (e.g. rule_profiling.1685458415.json, from an earlier "
                "result); default: the newest"
            ),
        ] = None,
        top: Top = 25,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Read the result of a Snort rule or CPU profiler run on an FTD without starting one: the newest
        file (or a named one) with when it ran and on which software, and the rules (gid:sid, ready for
        fmc_find_intrusion_rules / fmc_set_intrusion_rule_state) or Snort modules ranked by time. Says when
        a profiler is still running. For a run that fmc_cpu_profile(wait=false) started, or one whose wait
        ended early. Read-only, one or two requests. Needs an FMC role with the Snort 3 profiling
        permission (403 otherwise; the answer says which). New runs: fmc_snort_profile, fmc_cpu_profile."""
        if file is not None and not FILE_NAME.match(file.strip()):
            raise InvalidRequest(
                f"{file!r} is not a profiler file name (e.g. rule_profiling.1685458415.json)."
            )
        app: FmcApp = get_client(ctx)
        prof = PROFILERS[profiler]
        dev, member = await resolve_unit(app, device, domain)
        label = member.label(str(dev.get("name"))) if member else str(dev.get("name"))
        base = await profiler_base(app, prof, dev, domain)
        try:
            item = await read_file(app, base, file.strip()) if file else await latest(app, base)
        except UpstreamError as e:
            raise refused(e, prof) from e
        out: dict[str, Any] = {"device": label, "profiler": prof.title}
        if item is None:
            out["note"] = f"No {prof.title} file on {dev.get('name')} yet: start a run with {prof.tool}."
            return object_reply(out, fmt=response_format)
        if running(item):
            out["profile"] = header(item)
            out["note"] = f"The {prof.title} is still running; read again after it stops."
            return object_reply(out, fmt=response_format)
        if not item.get(prof.rows) and item.get("profilerFileName") and not file:
            try:
                item = await read_file(app, base, str(item["profilerFileName"]))
            except UpstreamError as e:
                raise refused(e, prof) from e
        out.update(result_view(prof, item, top))
        return object_reply(out, fmt=response_format)
