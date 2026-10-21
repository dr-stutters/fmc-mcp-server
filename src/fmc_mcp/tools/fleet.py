"""Show commands on one device or a fleet (F68): `fmc_run_show_command` and the bulk runner other tools reuse.

FMC 10.0.1's `devices/devicerecords/operational/bulkcommands` (one command on up to 25 devices, answered as a
task) sits behind the feature flag `bulk_device_command_execution`, off by default: FMC answers 403 "Feature
Flag ... is disabled" before contacting any device (live probe, Wave 6). So `run_fleet` tries bulkcommands
once per process and, when FMC refuses it (403/404/405/501), runs the per-device `operational/commands`
instead, one request per device and command, one at a time: FMC 10.0.1 answers concurrent requests with
each other's output (Wave 6 live proof: six devices queried eight at a time all got one device's 'show
version'), so troubleshoot.run_show sends every show command of this server alone and re-asks a 'show
version' that names another device's UUID; any row whose UUID line or 'show version' banner names another
device of the run (bulk or per device) is a failure, not output. Devices FMC reports disconnected are
reported without a request; a device FMC can't reach answers HTTP 500 with an SFTunnelException, which
becomes that device's failure row. The bulk answer's per-device shape (`metadata.task` -> TaskStatus
`subTasks` with target and message, by the 10.0.1 schema) is unit-tested from the schema only until an FMC
with the flag on records it.

`run_fleet(ctx, app, devices, commands, domain)` runs several commands on several devices and returns one
row per device and command; `resolve_fleet` turns names, UUIDs, HA pairs, clusters and device groups into
device records with one device listing.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import difflib
import re
import weakref
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, poll_until
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.dangerous import FAILED_WORDS, task_id_of, task_state
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.device_groups import GROUP_PREFIX, Fleet, expand_devices
from fmc_mcp.tools.devices import DEVICES, membership_of, memberships
from fmc_mcp.tools.show_commands import Supported, check_command, supported_commands
from fmc_mcp.tools.troubleshoot import ROUTE_LEGEND, answered_for, banner_name, filter_lines, redact, run_show

BULK = "devices/devicerecords/operational/bulkcommands"
MAX_FLEET = 25  # FMC's bulkcommands cap per request, and this tool's per call
SINGLE_LINES = 200
FLEET_LINES = 25
BULK_REFUSED = {403, 404, 405, 501}  # FMC doesn't offer bulkcommands here: remember and go per device
BULK_WAIT_S = 180.0
SFTUNNEL = re.compile(r"SFTunnel|Cannot establish a connection with the threat defense", re.I)
CREDENTIALS_HINT = re.compile(
    r"\s*Check \w+USERNAME/\w+PASSWORD and that the account's role allows this operation\.?"
)

# FmcApp -> why FMC refused bulkcommands (asked once per server process)
_bulk_off: weakref.WeakKeyDictionary[FmcApp, str] = weakref.WeakKeyDictionary()


@dataclass
class FleetRun:
    """The result of run_fleet."""

    rows: list[dict[str, Any]]  # per device and command, device order then command order:
    # {device, id, command, ok, text (raw output) | error}
    path: str  # "bulkcommands", "per-device" or "bulkcommands + per-device"
    notes: list[str] = field(default_factory=list)
    fmc_matches: list[str] = field(default_factory=list)  # BulkCommand metadata.matches, when FMC sends them


def explain(err: Exception) -> str:
    """A per-device failure in words: FMC's sftunnel 500 means it can't reach the device."""
    text = str(err)
    if SFTUNNEL.search(text):
        return (
            "FMC can't reach the device (SFTunnelException: cannot establish a connection with the threat "
            "defense); check its management connection (fmc_list_devices: connected)."
        )
    return text


def refusal(err: UpstreamError) -> str:
    """Why FMC refused bulkcommands, without the core's credentials hint: a 403 here is FMC 10.0.1's
    feature flag ("Feature Flag : bulk_device_command_execution is disabled"), not a login problem."""
    text = CREDENTIALS_HINT.sub("", str(err)).strip()
    return f"HTTP {err.status_code}: {text}" if err.status_code and str(err.status_code) not in text else text


def shape(text: str, command: str, match: str | None, max_lines: int) -> dict[str, Any]:
    """Output as the tool returns it: secrets masked, the 'show route' legend dropped, lines matching `match`
    kept, at most `max_lines`."""
    text, redacted = redact(text)
    if re.match(r"show\s+(ipv6\s+)?route\b", command.strip(), re.I):
        text = ROUTE_LEGEND.sub("", text)
    output, total, truncated = filter_lines(text, match, max_lines)
    out: dict[str, Any] = {"output": output}
    if not text.strip():
        out["note"] = "The command printed nothing."
    if match:
        out["matched_lines"] = total
    if redacted:
        out["redacted"] = f"{redacted} secret value(s) (passwords, keys, communities) replaced with ********"
    if truncated:
        out["note"] = f"Output truncated to {max_lines} of {total} lines; narrow it with `match`."
    return out


async def resolve_fleet(
    app: FmcApp, refs: list[str], domain: str | None, *, cap: int = MAX_FLEET
) -> tuple[list[dict[str, Any]], Fleet]:
    """Device records (expanded: isConnected, HA/cluster membership) for device names or UUIDs, HA pairs and
    clusters (their units) and device groups (their members' units), in order, duplicates dropped. One
    device listing plus the cached group list; the HA pair and cluster lists only for a name that is no
    device (memberships). More than `cap` devices is refused."""
    records = (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
    fleet = await expand_devices(app, refs, domain, units=True, records=records)
    by_id = {str(d.get("id", "")).lower(): d for d in records}
    out: list[dict[str, Any]] = []
    missing: list[str] = []
    of: dict[str, Any] | None = None

    def add(d: dict[str, Any]) -> None:
        if all(x is not d for x in out):
            out.append(d)

    for ref in fleet.refs:
        low = ref.lower()
        hit = by_id.get(low)
        if hit is None:
            named = [d for d in records if d.get("name") == ref] or [
                d for d in records if str(d.get("name", "")).lower() == low
            ]
            hit = named[0] if len(named) == 1 else None
        if hit is not None:
            add(hit)
            continue
        if of is None:
            of = await memberships(app, records, domain)
        units = [
            d
            for d in records
            if (m := of.get(str(d.get("id")).lower())) and low in (m.container.lower(), m.container_id)
        ]
        if units:
            for d in units:
                add(d)
        else:
            missing.append(ref)
    if missing:
        names = [str(d.get("name")) for d in records]
        close = sorted({c for m in missing for c in difflib.get_close_matches(m, names, n=3, cutoff=0.5)})
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        raise NotFound(
            f"No device, HA pair, cluster or device group named {', '.join(map(repr, missing))}.{hint}", 404
        )
    if not out:
        raise InvalidRequest("No devices to run on (the device group is empty).")
    if len(out) > cap:
        raise InvalidRequest(
            f"{len(out)} devices; one call runs on at most {cap}. Split the list or use a smaller group."
        )
    return out, fleet


def _bulk_outputs(resp: Any, task: dict[str, Any] | None) -> dict[str, tuple[bool, str]]:
    """Device UUID (lower case) -> (ok, output or error) from a bulkcommands answer: `items` rows that name
    their device, then the task's subTasks ({target: {id}, status, message}, FMC 10.0.1 schema)."""
    got: dict[str, tuple[bool, str]] = {}
    rows = resp.get("items") if isinstance(resp, dict) else None
    for item in rows or []:
        if not isinstance(item, dict):
            continue
        dev = item.get("device") or item.get("target") or {}
        did = (dev.get("id") if isinstance(dev, dict) else None) or item.get("deviceId")
        if did and "commandOutput" in item:
            got[str(did).lower()] = (True, str(item.get("commandOutput") or ""))
    for sub in (task or {}).get("subTasks") or []:
        did = (sub.get("target") or {}).get("id")
        if not did or str(did).lower() in got:
            continue
        status = str(sub.get("status") or "")
        failed = any(w in status.lower() for w in FAILED_WORDS)
        got[str(did).lower()] = (not failed, str(sub.get("message") or ("" if not failed else status)))
    return got


async def _bulk(
    ctx: Context, app: FmcApp, devices: list[dict[str, Any]], command: str, domain: str | None
) -> tuple[dict[str, tuple[bool, str]], list[str]]:
    """One bulkcommands request (and its task) for up to MAX_FLEET devices: (outputs by device, matches)."""
    path = await app.config_path(BULK, domain)
    resp = await app.api.post(path, {"command": command, "devices": [d["id"] for d in devices]}, timeout=120)
    meta = (resp.get("metadata") if isinstance(resp, dict) else None) or {}
    task: dict[str, Any] | None = None
    got = _bulk_outputs(resp, None)
    tid = task_id_of(resp)
    if tid and len(got) < len(devices):
        tpath = await app.config_path(f"job/taskstatuses/{tid}", domain)

        async def fetch() -> dict[str, Any]:
            data: dict[str, Any] = await app.api.get(tpath)
            return data

        task = await poll_until(
            fetch,
            done=lambda t: task_state(t)[0],
            describe=lambda t: str(t.get("status") or "running"),
            timeout=BULK_WAIT_S,
            interval=3.0,
            max_interval=10.0,
            ctx=ctx,
            what="bulk show command",
        )
        got = _bulk_outputs(resp, task)
    return got, [str(m) for m in meta.get("matches") or []]


def foreign_output(d: dict[str, Any], text: str, devices: list[dict[str, Any]]) -> str | None:
    """Why an answer for device `d` is another device's output, or None: its 'UUID :' line names another
    device, or its 'show version' banner names another device of this run (not `d`, and not an HA or
    cluster peer of `d`, which may print the same hostname). An identity canary that costs no request:
    most outputs name no device, so a mix-up there stays unseen (one show command at a time prevents
    the server's own)."""
    own = str(d["id"]).lower()
    uid = answered_for(text)
    if uid and uid != own:
        return f"its UUID line names device {uid}"
    name = banner_name(text)
    if not name or name.lower() == str(d.get("name") or "").lower():
        return None
    mine = membership_of(d)
    for o in devices:
        if str(o.get("name") or "").lower() != name.lower() or str(o["id"]).lower() == own:
            continue
        peer = membership_of(o)
        if mine and peer and peer.container_id == mine.container_id:
            continue
        return f"its 'show version' banner names {o.get('name')!r}"
    return None


async def run_fleet(
    ctx: Context,
    app: FmcApp,
    devices: list[dict[str, Any]],
    commands: list[str],
    domain: str | None,
    *,
    supported: Supported | None = None,
    prefer_bulk: bool = True,
) -> FleetRun:
    """Run show commands on device records (from resolve_fleet): every command is checked against FMC's
    allowlist first (InvalidRequest before any call), then bulkcommands is tried per command unless FMC
    refused it before in this process; whatever it doesn't answer runs per device, one request at a time
    (device by device, each device's commands in order: FMC 10.0.1 mixes up the outputs of concurrent
    show commands). An answer that names another device (foreign_output) is a failure. One row per device and
    command; a failure is a row with ok=False, never an exception."""
    for c in commands:
        check_command(c, supported)
    texts = [" ".join(c.split()) for c in commands]
    done: dict[tuple[str, str], tuple[bool, str]] = {}
    notes: list[str] = []
    matches: list[str] = []
    live = []
    for d in devices:
        if d.get("isConnected") is False:
            for c in texts:
                done[(d["id"], c)] = (
                    False,
                    "FMC reports the device disconnected (fmc_list_devices: connected false), so the "
                    "command was not sent.",
                )
        else:
            live.append(d)
    used_bulk = False
    if prefer_bulk and live and app not in _bulk_off:
        try:
            for c in texts:
                for i in range(0, len(live), MAX_FLEET):
                    chunk = live[i : i + MAX_FLEET]
                    got, m = await _bulk(ctx, app, chunk, c, domain)
                    matches += m
                    used_bulk = used_bulk or bool(got)
                    for d in chunk:
                        if (hit := got.get(d["id"].lower())) is not None:
                            done[(d["id"], c)] = hit
        except UpstreamError as e:
            if e.status_code in BULK_REFUSED:
                _bulk_off[app] = refusal(e)
            else:
                notes.append(f"bulkcommands failed ({e}); the rest ran per device.")
    if app in _bulk_off:
        notes.append(f"FMC refused bulkcommands ({_bulk_off[app]}); ran per device.")
    todo = [(d, [c for c in texts if (d["id"], c) not in done]) for d in live]
    todo = [(d, cs) for d, cs in todo if cs]
    # One at a time, never gathered: FMC 10.0.1 answers concurrent operational/commands requests with each
    # other's output (run_show also holds the server-wide show lock).
    for d, cs in todo:
        for c in cs:
            try:
                done[(d["id"], c)] = (True, await run_show(app, d["id"], c, domain, supported, retry=False))
            except (InvalidRequest, UpstreamError) as e:
                done[(d["id"], c)] = (False, explain(e))
    rows = []
    for d in devices:
        for c in texts:
            ok, text = done[(d["id"], c)]
            if ok and (why := foreign_output(d, text, devices)):
                ok, text = (
                    False,
                    f"FMC answered with another device's output ({why}): FMC 10.0.1 mixes up show commands "
                    "that run at the same time (another API client may be running some). Not shown; run "
                    "it again.",
                )
            row: dict[str, Any] = {"device": d.get("name"), "id": d["id"], "command": c, "ok": ok}
            row["text" if ok else "error"] = text
            rows.append(row)
    if not live:
        path = "not sent (no connected device)"
    elif used_bulk:
        path = "bulkcommands + per-device" if todo else "bulkcommands"
    else:
        path = "per-device"
    return FleetRun(rows, path, notes, matches)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Run a show command on devices")
    async def fmc_run_show_command(
        ctx: Context,
        command: Annotated[
            str,
            Field(
                description="A 'show' command FMC passes through, e.g. 'show route', 'show route bgp', "
                "'show interface ip brief', 'show running-config nat', 'show crypto ikev2 sa', "
                "'show failover'"
            ),
        ],
        device: Annotated[
            str | None,
            Field(description="Device name or UUID (from fmc_list_devices); several: devices or group"),
        ] = None,
        devices: Annotated[
            list[str] | None,
            Field(
                min_length=1,
                description="Run on several devices at once (names or UUIDs; an HA pair or cluster means its "
                "units, a device group 'group:<name>' its members); at most 25 in all",
            ),
        ] = None,
        group: Annotated[
            str | None,
            Field(
                description="Run on every device of this device group (name or UUID, fmc_list_device_groups)"
            ),
        ] = None,
        match: Annotated[
            str | None, Field(description="Keep only output lines containing this text (case-insensitive)")
        ] = None,
        max_lines: Annotated[
            int | None,
            Field(
                ge=1,
                le=2000,
                description="Maximum lines returned per device (default 200; 25 per device "
                "for several devices)",
            ),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Run a read-only 'show' command on a managed FTD, or on up to 25 at once (devices, an HA pair or
        cluster, or a device group), through FMC and return the output, to verify that a deployment landed
        or to compare a fleet ('show crypto ikev2 sa' on every spoke in one call). FMC only passes through
        the CLIs its API spec lists for operational/commands (read from the spec at run time; FMC 10.0.1:
        show version, failover, route <option>, crypto <option>, ip, logging, snmp-server, ssl,
        vpn-sessiondb, access-list <name>, rule, aaa-server, ntp, banner, network, firewall, dhcpd state,
        snort3 status), plus show interface and show running-config <section>. Anything else (show bgp,
        show ospf, show path-monitoring, show policy-route, show conn, show xlate, show nat, show arp, plain
        show running-config) is refused here with the alternatives, before FMC is called. Words after the
        second go to FMC as parameters ('show route bgp' = 'show route' + 'bgp'). `match` filters each
        device's lines. Several devices: one row per device with its output or why it failed (disconnected
        devices are not sent the command); FMC's bulkcommands is used where FMC enables it (FMC 10.0.1 keeps
        it behind a feature flag), else one request per device, one at a time (FMC 10.0.1 mixes up the
        outputs of concurrent show commands; about 1-3 s per device); `path` says which ran."""
        app: FmcApp = get_client(ctx)
        supported = await supported_commands(ctx)
        check_command(command, supported)  # refuse an unsupported command before resolving any device
        refs = list(devices or []) + ([f"{GROUP_PREFIX}{group.strip()}"] if group else [])
        if device and device.strip().lower().startswith(GROUP_PREFIX):
            refs, device = [*refs, device], None
        if device and refs:
            raise InvalidRequest("Pass device for one device, or devices / group for several; not both.")
        if not device and not refs:
            raise InvalidRequest("Pass device, devices or group.")
        text = " ".join(command.split())
        if device:
            dev = await resolve_device(app, device, domain)
            raw = await run_show(app, dev["id"], command, domain, supported)
            return {
                "device": dev.get("name"),
                "command": text,
                **shape(raw, command, match, max_lines or SINGLE_LINES),
            }
        records, fleet = await resolve_fleet(app, refs, domain)
        run = await run_fleet(ctx, app, records, [command], domain, supported=supported)
        lines = max_lines or FLEET_LINES
        results = []
        for row in run.rows:
            r: dict[str, Any] = {"device": row["device"], "ok": row["ok"]}
            r.update(shape(row["text"], command, match, lines) if row["ok"] else {"error": row["error"]})
            results.append(r)
        out: dict[str, Any] = {
            "command": text,
            "devices": len(results),
            "succeeded": sum(1 for r in results if r["ok"]),
            "failed": [r["device"] for r in results if not r["ok"]],
            "path": run.path,
        }
        if fleet.groups:
            out["groups"] = fleet.groups
        if match:
            out["match"] = match
            out["devices_matching"] = [r["device"] for r in results if r.get("matched_lines")]
        if run.fmc_matches:
            out["fmc_matches"] = run.fmc_matches
        if run.notes:
            out["notes"] = run.notes
        out["results"] = results
        return out
