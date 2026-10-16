"""Troubleshooting tools (read tier): show commands on the FTD, packet tracer, rule hit counts and
device health. These answer "did my change land?" and "why is this traffic blocked?".

None of them change configuration. fmc_packet_tracer simulates a packet on the device (never
transmitted), and fmc_get_hit_counts can ask FMC to pull fresh counters from the device.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import json
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.catalog import Catalog
from fmc_mcp.client import FmcApp, fmc_error_detail
from fmc_mcp.flow import device_context
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.dangerous import task_id_of, wait_task
from fmc_mcp.tools.device_config import device_interfaces, pick_interface, resolve_device
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.policies import ACCESS, PREFILTER, all_rules, resolve_policy
from fmc_mcp.tools.system import iso

MAX_OUTPUT_LINES = 400
# The command API takes at most two words in `command`; the rest go in `parameters`.
COMMAND_WORDS = 2
UNSAFE = re.compile(r"[|;&`$<>\n\r]")
RULE_ID = re.compile(r"(?:rule-id|Rule ID) (\d+)")
# Phases that only say "passed" unless they drop; hidden from the compact view.
ROUTINE = {
    "CONN-SETTINGS",
    "INSPECT",
    "QOS",
    "IP-OPTIONS",
    "OBJECT_GROUP_SEARCH",
    "FLOW-CREATION",
    "EXTERNAL-INSPECT",
    "ADJACENCY-LOOKUP",
    "NAT-PER-SESSION",
}
REMARK = re.compile(r"rule-id (\d+): (ACCESS POLICY|PREFILTER POLICY|L4 RULE|L7 RULE|RULE): (.+)")
# The 'show route' codes legend (11 lines before every table); the route codes are standard.
ROUTE_LEGEND = re.compile(r"^Codes: .*?\n(?=\s*\n|Gateway of last resort|\S)", re.S | re.M)
HIT_ID_CHUNK = 40  # rule ids per hit-count request (they go in the query string)


def split_command(command: str) -> tuple[str, str | None]:
    """'show running-config access-group' -> ('show running-config', 'access-group')."""
    text = " ".join(command.strip().split())
    if not text.lower().startswith("show "):
        raise InvalidRequest("Only 'show ...' commands are supported (FMC runs them on the device).")
    if UNSAFE.search(text):
        raise InvalidRequest("Pipes, redirects and command separators are not allowed; use `match`.")
    words = text.split(" ")
    head = " ".join(words[:COMMAND_WORDS])
    rest = " ".join(words[COMMAND_WORDS:]) or None
    return head, rest


SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|key|pre-shared-key|community|key-string|authentication-key|"
    r"auth-key|priv(?:\s+(?:aes\s+\d+|3des|des))?|auth\s+(?:md5|sha\S*))(\s+(?:\d+\s+|encrypted\s+|ascii\s+|hex\s+)?)(\S+)"
)


def redact(text: str) -> tuple[str, int]:
    """Mask secrets that `show running-config <section>` prints (aaa, snmp-server, crypto, users)."""
    count = 0

    def mask(m: re.Match[str]) -> str:
        nonlocal count
        if set(m.group(3)) == {"*"}:
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}********"

    return SECRET.sub(mask, text), count


def filter_lines(text: str, match: str | None, max_lines: int) -> tuple[str, int, bool]:
    """(output, total lines, truncated) keeping lines containing `match` (case-insensitive)."""
    lines = text.replace("\r", "").split("\n")
    if match:
        low = match.lower()
        lines = [ln for ln in lines if low in ln.lower()]
    total = len(lines)
    return "\n".join(lines[:max_lines]), total, total > max_lines


def _first_line(text: str | None) -> str | None:
    for ln in (text or "").split("\n"):
        if ln.strip():
            return ln.strip()
    return None


def parse_phase(p: dict[str, Any], verbose: bool) -> dict[str, Any]:
    """One packet-tracer phase, reduced to what explains the verdict."""
    config = str(p.get("config") or "")
    info = str(p.get("additionalInformation") or "")
    row: dict[str, Any] = {
        "phase": p.get("id"),
        "type": p.get("type"),
        "subtype": p.get("subType") or p.get("subtype"),
        "result": p.get("result"),
    }
    rules = []
    for rid, kind, value in REMARK.findall(config):
        rules.append((rid, kind, value.strip()))
    if rules:
        row["rule_id"] = rules[0][0]
        for _, kind, value in rules:
            if kind in ("L4 RULE", "L7 RULE", "RULE"):
                row["rule"] = value
            elif kind in ("ACCESS POLICY", "PREFILTER POLICY"):
                row["policy"] = value
    elif m := RULE_ID.search(config):
        row["rule_id"] = m.group(1)
    if verbose:
        row["config"] = config.strip() or None
        row["info"] = info.strip() or None
    else:
        cfg = [ln.strip() for ln in config.split("\n") if ln.strip() and "remark" not in ln]
        if cfg:
            row["config"] = cfg[0] if len(cfg) == 1 else cfg[:3]
        key = None
        lines = [ln.strip() for ln in info.split("\n") if ln.strip()]
        for words in (("verdict", "Verdict"), ("next-hop", "translate", "Drop", "drop"), ("match",)):
            key = next((ln for ln in lines if any(w in ln for w in words)), None)
            if key:
                break
        if key:
            row["info"] = key
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def summarize_trace(resp: dict[str, Any], verbose: bool) -> list[dict[str, Any]]:
    out = []
    for dr in resp.get("deviceResponse") or []:
        result = dr.get("result") or {}
        phases = [parse_phase(p, verbose) for p in dr.get("phases") or []]
        names = {p["rule_id"]: p["rule"] for p in phases if p.get("rule_id") and p.get("rule")}
        for p in phases:
            if p.get("rule_id") in names and not p.get("rule"):
                p["rule"] = names[p["rule_id"]]
        deciding: list[dict[str, Any]] = []
        for p in phases:
            if p.get("rule_id") and not any(
                d["rule_id"] == p["rule_id"] and d.get("result") == p.get("result") for d in deciding
            ):
                deciding.append(p)
        total = len(phases)
        if not verbose:
            phases = [
                p
                for p in phases
                if str(p.get("result", "")).upper() != "ALLOW"
                or p.get("rule_id")
                or (p.get("type") not in ROUTINE and p.get("subtype") != "per-session" and p.get("info"))
            ]
        dropped = next((p for p in phases if str(p.get("result", "")).upper() == "DROP"), None)
        summary: dict[str, Any] = {
            "device": (dr.get("deviceDetails") or {}).get("name"),
            "unit": (dr.get("unitDetails") or {}).get("name"),
            "action": result.get("action"),
            "input": result.get("inputInterface"),
            "output": result.get("outputInterface"),
            "drop_reason": result.get("dropReason"),
            "drop_detail": result.get("dropDetail") or result.get("dropDetail:"),
            "dropped_at": (
                f"phase {dropped['phase']} {dropped.get('type')}"
                + (
                    f" (rule {dropped.get('rule')!r}, id {dropped.get('rule_id')})"
                    if dropped.get("rule")
                    else ""
                )
                if dropped
                else None
            ),
            "matched_rules": [
                {k: p[k] for k in ("type", "subtype", "rule_id", "rule", "policy", "result") if k in p}
                for p in deciding
            ]
            or None,
            "phases": phases,
            "hidden_phases": (total - len(phases)) or None,
        }
        out.append({k: v for k, v in summary.items() if v not in (None, "", [])})
    return out


def _rule_number(rule_id: Any) -> str:
    return str(rule_id).strip().lstrip("0") or "0"


async def _rule_names(app: FmcApp, policy_name: str, domain: str | None) -> dict[str, str]:
    """{device rule id: rule name} for an access policy; {} when it can't be read."""
    try:
        pol = await resolve_policy(app, "access", policy_name, domain)
        page = await all_rules(app, await app.config_path(f"{ACCESS}/{pol['id']}/accessrules", domain))
    except UpstreamError:  # includes NotFound: naming is best-effort, the trace itself stands
        return {}
    return {_rule_number(str(r.get("id", "")).rsplit("-", 1)[-1]): str(r.get("name")) for r in page.items}


async def name_snort_rules(app: FmcApp, traces: list[dict[str, Any]], domain: str | None) -> None:
    """Name the rule Snort decided on and set `verdict_rule`.

    When a rule needs Snort (dynamic objects, applications, URLs, users), the ACCESS-LIST phase shows
    the first such rule as a 'permit to Snort' and Snort's phase only carries a numeric rule id. FMC
    rule UUIDs end in that id (...-000268434474), so the policy's rules map it back to a name."""
    names_by_policy: dict[str, dict[str, str]] = {}
    for t in traces:
        rules = t.get("matched_rules") or []
        unnamed = [r for r in rules if r.get("rule_id") and not r.get("rule")]
        policy = next((str(r["policy"]) for r in rules if r.get("policy")), None)
        if unnamed and policy:
            policy_name = policy.rsplit(" - ", 1)[0]  # "<policy> - <section>"
            if policy_name not in names_by_policy:
                names_by_policy[policy_name] = await _rule_names(app, policy_name, domain)
            by_id = names_by_policy[policy_name]
            for r in unnamed:
                name = by_id.get(_rule_number(r["rule_id"]))
                if not name:
                    continue
                r["rule"] = name
                for ph in t.get("phases") or []:
                    if ph.get("rule_id") == r["rule_id"] and not ph.get("rule"):
                        ph["rule"] = name
        snort = [r for r in rules if r.get("type") == "SNORT"]
        decider = (snort or rules)[-1] if rules else None
        if decider:
            # Snort's decision wins over the ACCESS-LIST 'send to Snort' permit.
            t["verdict_rule"] = (
                decider.get("rule")
                or f"rule id {decider.get('rule_id')} (not in the policy: default action?)"
            )


def _ts(value: Any) -> str | None:
    v = str(value or "").strip()
    return v or None


def _parse_local(value: Any) -> datetime | None:
    """FMC hit-count times look like ISO UTC ('2026-10-15T15:14:51Z') but are FMC local time."""
    v = str(value or "").strip()
    if not v:
        return None
    try:
        return datetime.strptime(v.rstrip("Z")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def learn_local_offset(fetched: Any, now: float) -> int | None:
    """FMC's local-time offset from UTC in seconds, from the counters' fetch time right after a
    refresh (rounded to 15 minutes; None if it doesn't look like a fresh fetch)."""
    t = _parse_local(fetched)
    if t is None:
        return None
    delta = t.timestamp() - now
    offset = int(round(delta / 900) * 900)
    if abs(offset) > 14 * 3600 or abs(delta - offset) > 300:
        return None
    return offset


def to_utc(value: Any, offset: int | None) -> str | None:
    """A hit-count time in real UTC when the offset is known; else FMC's value without the 'Z'."""
    t = _parse_local(value)
    if t is None:
        return _ts(value)
    if offset is None:
        return t.strftime("%Y-%m-%dT%H:%M:%S") + " (FMC local time)"
    return datetime.fromtimestamp(t.timestamp() - offset, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(resp: Any) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


async def run_show(app: FmcApp, device_id: str, command: str, domain: str | None) -> str:
    head, rest = split_command(command)
    params: dict[str, Any] = {"command": head}
    if rest:
        params["parameters"] = rest
    path = await app.config_path(f"devices/devicerecords/{device_id}/operational/commands", domain)
    resp = await app.api.request("GET", path, params=params, timeout=120, expect="response", ok_status={404})
    if resp.status_code == 404:
        detail = fmc_error_detail(_json(resp)) or ""
        if "command is invalid" in detail.lower():
            raise InvalidRequest(
                f"The FTD rejects {command!r} as invalid. Some sections live outside the data plane "
                "(e.g. NTP); check those with fmc_get_platform_settings instead."
            )
        raise NotFound(f"FMC answered 404 for {command!r}: {detail or 'not found'}", 404)
    data = _json(resp)
    items = (data or {}).get("items") or []
    return "\n".join(str(i.get("commandOutput") or "") for i in items)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Run a show command on a device")
    async def fmc_run_show_command(
        ctx: Context,
        device: DeviceRef,
        command: Annotated[
            str,
            Field(
                description="A 'show' command, e.g. 'show route', 'show nat detail', 'show interface ip "
                "brief', 'show running-config access-group', 'show conn count', 'show failover'"
            ),
        ],
        match: Annotated[
            str | None, Field(description="Keep only output lines containing this text (case-insensitive)")
        ] = None,
        max_lines: Annotated[int, Field(ge=1, le=2000, description="Maximum lines returned")] = 200,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Run a read-only 'show' command on a managed FTD through FMC and return its output, to verify
        that a deployment landed. FMC only allows an approved set, mostly configuration views: show
        version, show route, show interface (ip brief), show failover, and show running-config
        <section> (nat, route, interface, access-group, access-list, object, ...). It refuses
        stateful or bulky commands (show conn, show xlate, show nat, show arp, show access-list,
        plain show running-config): use the device CLI for those. One command per device at a
        time; `match` filters the lines."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        text, redacted = redact(await run_show(app, dev["id"], command, domain))
        if re.match(r"show\s+(ipv6\s+)?route\b", command.strip(), re.I):
            text = ROUTE_LEGEND.sub("", text)
        output, total, truncated = filter_lines(text, match, max_lines)
        out: dict[str, Any] = {
            "device": dev.get("name"),
            "command": " ".join(command.split()),
            "output": output,
        }
        if not text.strip():
            out["note"] = "The command printed nothing."
        if match:
            out["matched_lines"] = total
        if redacted:
            out["redacted"] = (
                f"{redacted} secret value(s) (passwords, keys, communities) replaced with ********"
            )
        if truncated:
            out["note"] = f"Output truncated to {max_lines} of {total} lines; narrow it with `match`."
        return out

    @reg.read(title="Packet tracer")
    async def fmc_packet_tracer(
        ctx: Context,
        device: DeviceRef,
        protocol: Annotated[Literal["tcp", "udp", "icmp"], Field(description="IP protocol")],
        source_ip: Annotated[str, Field(description="Source IPv4/IPv6 address")],
        destination_ip: Annotated[str, Field(description="Destination IPv4/IPv6 address")],
        input_interface: Annotated[
            str | None,
            Field(
                description="Ingress interface: logical name (inside), hardware name or UUID. Default: the "
                "interface whose subnet (or static route) holds the source IP"
            ),
        ] = None,
        destination_port: Annotated[
            int | None, Field(ge=1, le=65535, description="TCP/UDP destination port")
        ] = None,
        source_port: Annotated[
            int, Field(ge=1, le=65535, description="TCP/UDP source port (default 40000)")
        ] = 40000,
        icmp_type: Annotated[int, Field(ge=0, le=255, description="ICMP type (default 8, echo)")] = 8,
        icmp_code: Annotated[int, Field(ge=0, le=255, description="ICMP code")] = 0,
        verbose: Annotated[
            bool, Field(description="Include each phase's full config and additional information")
        ] = False,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Simulate a packet through an FTD (packet-tracer, run by FMC; nothing is transmitted) and
        explain the verdict: allow/drop, the drop reason, the phase that dropped it and the access or
        prefilter rule that matched (name, policy and device rule id), plus route lookup and NAT
        phases. The live answer to "why is this traffic blocked?"; combine with fmc_rule_lookup
        (offline policy walk) and fmc_get_hit_counts. The ingress interface (it must have a logical
        name) is picked from the source IP unless given."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        ifaces = await device_interfaces(app, dev["id"], domain)
        found_by = None
        if not input_interface:
            try:
                src_ip = ipaddress.ip_address(source_ip.strip())
            except ValueError as e:
                raise InvalidRequest(f"Invalid address: {e}") from None
            leg = (await device_context(app, dev, Catalog(app, domain), domain)).leg(src_ip)
            if leg is None:
                raise InvalidRequest(
                    f"No interface or static route on {dev['name']} covers {src_ip}; pass input_interface."
                )
            input_interface, found_by = leg.interface, leg.how
        _, iface = pick_interface(ifaces, input_interface, dev["name"])
        if not iface.get("ifname"):
            raise InvalidRequest(
                f"{iface.get('name')} has no logical name; packet tracer needs a named interface."
            )
        try:
            src = ipaddress.ip_address(source_ip.strip())
            dst = ipaddress.ip_address(destination_ip.strip())
        except ValueError as e:
            raise InvalidRequest(f"Invalid address: {e}") from None
        if src.version != dst.version:
            raise InvalidRequest("Source and destination must both be IPv4 or both IPv6.")
        ip_type = "IPv4" if src.version == 4 else "IPv6"
        body: dict[str, Any] = {
            "device": {"id": dev["id"], "type": dev.get("type") or "Device", "name": dev.get("name")},
            "interface": {"id": iface["id"], "type": iface.get("type"), "name": iface.get("ifname")},
            "protocol": protocol.upper(),
            "sourceIPType": ip_type,
            "sourceIPValue": str(src),
            "destinationIPType": ip_type,
            "destinationIPValue": str(dst),
        }
        if protocol == "icmp":
            body.update(icmpType=icmp_type, icmpCode=icmp_code, icmpID=1)
        else:
            if destination_port is None:
                raise InvalidRequest("destination_port is required for tcp and udp.")
            body.update(sourcePort=str(source_port), destinationPort=str(destination_port))
        where = await app.device_domain("devices/devicerecords", dev["id"], await app.domain_uuid(domain))
        path = f"/api/fmc_troubleshoot/v1/domain/{where}/packettracer/traces"
        resp = await app.api.post(path, body, timeout=180)
        traces = summarize_trace(resp if isinstance(resp, dict) else {}, verbose)
        await name_snort_rules(app, traces, domain)
        flow = f"{protocol} {src}" + (f":{source_port}" if protocol != "icmp" else "")
        flow += f" -> {dst}" + (f":{destination_port}" if protocol != "icmp" else f" type {icmp_type}")
        out: dict[str, Any] = {"flow": flow, "input_interface": iface.get("ifname")}
        if found_by:
            out["input_interface_found_by"] = found_by
        out["results"] = traces
        return out

    @reg.read(title="Rule hit counts")
    async def fmc_get_hit_counts(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control (or prefilter) policy name/UUID")],
        device: DeviceRef,
        kind: Annotated[Literal["access", "prefilter"], Field(description="Policy type")] = "access",
        rule: Annotated[
            str | None, Field(description="Only rules whose name contains this (case-insensitive)")
        ] = None,
        only_zero: Annotated[
            bool, Field(description="Only rules that were never hit (clean-up candidates)")
        ] = False,
        refresh: Annotated[
            bool,
            Field(description="Ask FMC to pull fresh counters from the device first (takes a few seconds)"),
        ] = True,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Per-rule hit counts of an access control or prefilter policy on one device, in rule order:
        hits, first and last hit, and the device rule id (the 'rule-id' that packet tracer and syslog
        show). Includes the default action. Use it to confirm which rule traffic is hitting, or with
        only_zero to find rules nothing has used. With refresh (default) FMC first pulls the counters
        from the device (an operational task; no configuration changes). Times are UTC (FMC reports
        its local time; the offset is learned from the refresh). Packet-tracer runs count as hits."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, kind, policy, domain)
        dev = await resolve_device(app, device, domain)
        coll = ACCESS if kind == "access" else PREFILTER
        sub = "accessrules" if kind == "access" else "prefilterrules"
        hc_path = await app.config_path(f"{coll}/{p['id']}/operational/hitcounts", domain)
        notes: list[str] = []
        refreshed_at: float | None = None
        if refresh:
            try:
                resp = await app.api.put(hc_path, None, params={"filter": f"deviceId:{dev['id']}"})
                tid = task_id_of(resp)
                if tid:  # learn FMC's clock offset only from a refresh that really ran
                    await wait_task(ctx, app, tid, domain, "hit count refresh", limit_s=120)
                    refreshed_at = time.time()
            except UpstreamError as e:
                notes.append(f"Refresh failed ({e}); showing the last counters FMC has.")
        rules = (await all_rules(app, await app.config_path(f"{coll}/{p['id']}/{sub}", domain))).items
        order = {r["id"]: i for i, r in enumerate(rules, 1)}
        # FMC 10.0.1 returns only the default action unless rule ids are listed explicitly.
        ids = [r["id"] for r in rules]
        hits: dict[str, dict[str, Any]] = {}
        chunks = [ids[i : i + HIT_ID_CHUNK] for i in range(0, len(ids), HIT_ID_CHUNK)] or [[]]
        for chunk in chunks:
            flt = f"deviceId:{dev['id']};fetchZeroHitCount:true"
            if chunk:
                flt += f";ids:{','.join(chunk)}"
            page = await app.all(hc_path, {"filter": flt}, cap=5000)
            for h in page.items:
                hits[str((h.get("rule") or {}).get("id"))] = h
        if kind == "access":
            page = await app.all(hc_path, {"filter": f"deviceId:{dev['id']};fetchZeroHitCount:true"}, cap=50)
            for h in page.items:
                hits.setdefault(str((h.get("rule") or {}).get("id")), h)
        last = next((h.get("lastFetchTimeStamp") for h in hits.values() if h.get("lastFetchTimeStamp")), None)
        if refreshed_at is not None:
            learned = learn_local_offset(last, refreshed_at)
            if learned is not None:
                app.local_offset = learned
        tz_offset = app.local_offset
        rows = []
        for rid, h in hits.items():
            r = h.get("rule") or {}
            meta = h.get("metadata") or {}
            name = str(r.get("name") or "")
            if rule and rule.lower() not in name.lower():
                continue
            count = int(h.get("hitCount") or 0)
            if only_zero and count:
                continue
            rows.append(
                {
                    "index": order.get(rid) or meta.get("ruleIndex") or "default",
                    "rule": name,
                    "hits": count,
                    "first_hit": to_utc(h.get("firstHitTimeStamp"), tz_offset),
                    "last_hit": to_utc(h.get("lastHitTimeStamp"), tz_offset),
                    "device_rule_id": meta.get("deviceRuleId"),
                }
            )
        rows.sort(key=lambda x: x["index"] if isinstance(x["index"], int) else 10**9)
        extra: dict[str, Any] = {
            "policy": p.get("name"),
            "device": dev.get("name"),
            "counters_fetched": to_utc(last, tz_offset),
        }
        if tz_offset is None:
            notes.append(
                "FMC reports these times in its local time zone; refresh once to convert them to UTC."
            )
        if notes:
            extra["note"] = " ".join(notes)
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Site-to-site VPN tunnel status")
    async def fmc_list_vpn_tunnels(
        ctx: Context,
        device: Annotated[str | None, Field(description="Only tunnels of this device (name/UUID)")] = None,
        state: Annotated[
            Literal["TUNNEL_UP", "TUNNEL_DOWN", "UNKNOWN"] | None,
            Field(description="Only tunnels in this state"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Site-to-site VPN tunnels FMC monitors, down tunnels first: topology, both peers (device and
        tunnel addresses), state (TUNNEL_UP/DOWN/UNKNOWN), FMC's message and last change, plus up/down
        counts. Use it for "is the VPN to X up?"; the topologies themselves are listed by
        fmc_list_vpn_topologies."""
        app: FmcApp = get_client(ctx)
        filters = []
        if device:
            dev = await resolve_device(app, device, domain)
            filters.append(f"deviceId:{dev['id']}")
        if state:
            filters.append(f"status:{state}")
        params = {"filter": ";".join(filters)} if filters else None
        page = await app.all(await app.config_path("health/tunnelstatuses", domain), params, cap=5000)
        rows = [tunnel_row(t) for t in page.items]
        order = {"TUNNEL_DOWN": 0, "UNKNOWN": 1, "TUNNEL_UP": 2}
        rows.sort(key=lambda r: (order.get(str(r["state"]), 1), str(r["topology"] or "")))
        counts: dict[str, int] = {}
        for r in rows:
            counts[str(r["state"])] = counts.get(str(r["state"]), 0) + 1
        extra: dict[str, Any] = {"states": counts}
        if not page.complete:
            extra["note"] = "Only the first 5000 tunnels were read."
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Device health")
    async def fmc_device_health(
        ctx: Context,
        device: DeviceRef,
        include_green: Annotated[bool, Field(description="Also list modules that are healthy")] = False,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Health of one managed FTD: FMC's overall status and message, every health module that is
        not green (module, status, details, time), counts per status, and current CPU (data plane,
        snort, system) and memory use. Use it after a deployment or when a device shows yellow/red
        in fmc_list_devices."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        if not dev.get("healthStatus") and dev.get("id"):
            dev = await app.api.get(await app.config_path(f"devices/devicerecords/{dev['id']}", domain))
        alerts = await app.all(
            await app.config_path("health/alerts", domain), {"filter": f"deviceUUIDs:{dev['id']}"}, cap=2000
        )
        counts: dict[str, int] = {}
        modules = []
        for a in alerts.items:
            status = str(a.get("status") or "UNKNOWN").upper()
            counts[status] = counts.get(status, 0) + 1
            if include_green or status != "GREEN":
                modules.append(
                    {
                        "module": a.get("moduleID"),
                        "status": status,
                        "details": a.get("details"),
                        "time": iso(a.get("timestamp")),
                    }
                )
        order = {"RED": 0, "CRITICAL": 0, "YELLOW": 1, "WARNING": 1, "UNKNOWN": 2, "GREEN": 3}
        modules.sort(key=lambda m: order.get(str(m["status"]), 2))
        out: dict[str, Any] = {
            "device": dev.get("name"),
            "status": dev.get("healthStatus"),
            "message": dev.get("healthMessage"),
            "connected": dev.get("isConnected"),
            "deployment": dev.get("deploymentStatus"),
            "module_counts": counts,
            "modules": modules,
        }
        out["resources"] = await _resources(app, dev["id"], domain)
        return {k: v for k, v in out.items() if v not in (None, {}, [])}


def tunnel_row(t: dict[str, Any]) -> dict[str, Any]:
    def peer(p: dict[str, Any] | None) -> str | None:
        if not p:
            return None
        name = (p.get("device") or {}).get("name") or (p.get("extranet") or {}).get("name")
        ips = (p.get("ipAddresses") or {}).get("v4") or (p.get("ipAddresses") or {}).get("v6") or []
        return f"{name} ({', '.join(ips)})" if ips else name

    return {
        "topology": (t.get("vpnTopology") or {}).get("name"),
        "peer_a": peer(t.get("peerA")),
        "peer_b": peer(t.get("peerB")),
        "state": t.get("state"),
        "message": t.get("message"),
        "last_change": iso(t.get("lastChange")) if t.get("lastChange") else None,
        "id": t.get("id"),
    }


async def _resources(app: FmcApp, device_id: str, domain: str | None) -> dict[str, Any]:
    """Latest CPU and memory percentages from the health metrics (empty if the modules are off)."""
    now = int(time.time())
    out: dict[str, Any] = {}
    wanted = {
        "cpu": {
            "lina_avg": "cpu_data_plane_pct",
            "snort_avg": "cpu_snort_pct",
            "system_avg": "cpu_system_pct",
        },
        "mem": {
            "used_percentage_system": "mem_system_pct",
            "used_percentage_lina": "mem_data_plane_pct",
            "used_percentage_snort": "mem_snort_pct",
        },
    }
    path = await app.config_path("health/metrics", domain)
    for metric, names in wanted.items():
        flt = f"deviceUUIDs:{device_id};metric:{metric};startTime:{now - 600};endTime:{now};step:300"
        try:
            data = await app.api.get(path, {"filter": flt})
        except UpstreamError:
            continue
        for item in (data or {}).get("items") or []:
            try:
                prom = json.loads(item.get("response") or "{}")
            except ValueError:
                continue
            for series in (prom.get("data") or {}).get("result") or []:
                label = (series.get("metric") or {}).get(metric)
                if label in names and series.get("values"):
                    try:
                        out[names[label]] = round(float(series["values"][-1][1]), 1)
                    except (TypeError, ValueError, IndexError):
                        continue
    return out
