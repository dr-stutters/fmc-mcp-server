"""Prove a policy (F56): a table of expected flows, each traced live on the FTD it crosses, with a
pass / fail / mismatch verdict and the rule that decided it.

Every scenario ends with "prove it"; this replaces N hand-made fmc_packet_tracer calls. It reuses the
packet-tracer helper (troubleshoot.packet_trace: ingress interface from the source, rule names from the
Snort rule ids, `verdict_rule`) and the flow context (fmc_mcp.flow: interfaces, zones and static routes)
to find the device when a flow names none.

User-based flows: the FTD applies user rules from its own user-to-IP mapping, so a flow is traced from
the user's current IP and the Snort identity phase shows which user the device saw there. When a flow
gives a user but no source, the IP comes from the user-to-IP lookups in USER_IP_RESOLVERS: FMC's
identity sessions (identity_sources.user_ips, as fmc_user_ip_lookup reads them).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, Field

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
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import DeviceContext, device_context
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import device_interfaces, resolve_device
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.identity_sources import user_ips
from fmc_mcp.tools.troubleshoot import packet_trace

MAX_FLOWS = 25
AUTO_DEVICE_CAP = 10  # devices whose interfaces and routes are read to place a flow with no device
# The drop of a trace run on an HA standby unit: it drops everything, so says nothing about the policy.
FO_STANDBY = "fo-standby"
# Drops that are the policy's decision (access/prefilter rule, Snort verdict, Security Intelligence).
POLICY_DROP = re.compile(r"acl-drop|snort|firewall|deny|denied|block|sec-?intel|prefilter", re.I)
POLICY_PHASES = ("ACCESS-LIST", "SNORT", "PREFILTER")
IDENTITY = re.compile(r"username: (?P<user>[^,\s]+)(?:.*?AD domain: (?P<realm>[^,\s]+))?", re.S)

# async (app, user, domain) -> the user's current IPs, newest first.
UserIpResolver = Callable[[FmcApp, str, str | None], Awaitable[list[str]]]
USER_IP_RESOLVERS: list[UserIpResolver] = [user_ips]


class Expectation(BaseModel):
    """One flow and the verdict the policy should give it."""

    destination: str = Field(min_length=1, description="Destination IP address")
    expect: Literal["allow", "block"] = Field(description="The verdict the policy should give")
    source: str | None = Field(
        None,
        description="Source IP address; for a user flow, the IP the user is logged in on (omit it to use "
        "the IP of the user's newest FMC identity session, as fmc_user_ip_lookup shows it)",
    )
    port: int | None = Field(None, ge=1, le=65535, description="Destination port (tcp/udp)")
    protocol: Literal["tcp", "udp", "icmp"] = Field("tcp", description="tcp, udp or icmp (echo)")
    user: str | None = Field(
        None,
        description="The user expected on the source IP (AD name, e.g. alice or LAB\\alice): the row checks "
        "the device saw this user",
    )
    device: str | None = Field(
        None, description="FTD or HA pair to trace on (name/UUID); default: the call's device"
    )
    input_interface: str | None = Field(None, description="Ingress interface; default: from the source IP")
    rule: str | None = Field(
        None, description="The rule expected to decide it (name); a different one = mismatch"
    )
    name: str | None = Field(None, description="A label for the row, e.g. 'alice to web'")


Flows = Annotated[
    list[Expectation],
    Field(
        min_length=1,
        max_length=MAX_FLOWS,
        description=f"Flows with their expected verdicts (up to {MAX_FLOWS})",
    ),
]


@dataclass
class Placer:
    """Finds and caches the device each flow is traced on."""

    app: FmcApp
    domain: str | None
    candidates: list[str] | None
    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    contexts: dict[str, DeviceContext] = field(default_factory=dict)
    interfaces: dict[str, list[tuple[str, dict[str, Any]]]] = field(default_factory=dict)
    pool: list[dict[str, Any]] | None = None
    catalog: Catalog | None = None
    ha: list[dict[str, Any]] | None = None
    unit_pair: dict[str, tuple[str, str | None]] = field(default_factory=dict)  # unit id -> (pair, state)
    left_out: list[str] = field(default_factory=list)

    async def pairs(self) -> list[dict[str, Any]]:
        """The domain's HA pairs (read once), and which pair and failover state each unit has."""
        if self.ha is None:
            try:
                self.ha = (
                    await self.app.all(await self.app.config_path(HA_PAIRS, self.domain), cap=500)
                ).items
            except UpstreamError:
                self.ha = []
            for pair in self.ha:
                for unit in ha_units(pair):
                    self.unit_pair[unit["id"]] = (str(pair.get("name")), unit["state"])
        return self.ha

    async def named(self, ref: str) -> dict[str, Any]:
        """A device by name or UUID; an HA pair's name or UUID means its active unit (FMC's failover
        state; the primary when FMC knows no active unit)."""
        if ref not in self.devices:
            try:
                self.devices[ref] = await resolve_device(self.app, ref, self.domain)
            except (InvalidRequest, NotFound):
                want = ref.strip().lower()
                pair = next(
                    (
                        p
                        for p in await self.pairs()
                        if want in (str(p.get("name", "")).lower(), str(p.get("id", "")).lower())
                    ),
                    None,
                )
                units = ha_units(pair) if pair else []
                if not units:
                    raise
                unit = next((u for u in units if unit_kind(u["state"]) == "active"), units[0])
                self.devices[ref] = await resolve_device(self.app, unit["id"], self.domain)
        await self.pairs()
        return self.devices[ref]

    def label(self, dev: dict[str, Any]) -> str:
        """'mcp-fw-ha (mcp-fw-ha-a, active)' for an HA unit, else the device name."""
        name = str(dev.get("name"))
        pair = self.unit_pair.get(str(dev.get("id", "")).lower())
        if not pair:
            return name
        state = unit_kind(pair[1])
        return f"{pair[0]} ({name}, {state})" if state else f"{pair[0]} ({name})"

    async def context(self, dev: dict[str, Any]) -> DeviceContext:
        if dev["id"] not in self.contexts:
            self.catalog = self.catalog or Catalog(self.app, self.domain)
            self.contexts[dev["id"]] = await device_context(self.app, dev, self.catalog, self.domain)
        return self.contexts[dev["id"]]

    async def ifaces(self, dev: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        if dev["id"] not in self.interfaces:
            self.interfaces[dev["id"]] = await device_interfaces(self.app, dev["id"], self.domain)
        return self.interfaces[dev["id"]]

    async def find(self, source: str, destination: str) -> tuple[dict[str, Any], str]:
        """The device a flow crosses: the source on a connected subnet first, then on a static route, and
        the destination reachable through another interface. (device, how it was found)."""
        if self.pool is None:
            if self.candidates:
                self.pool = [await self.named(c) for c in self.candidates]
            else:
                # Connected devices only, and no HA standby unit (it drops every packet it traces).
                page = await self.app.all(await self.app.config_path(DEVICES, self.domain), cap=1000)
                await self.pairs()
                usable = []
                for d in page.items:
                    pair = self.unit_pair.get(str(d.get("id", "")).lower())
                    if d.get("isConnected") is False:
                        self.left_out.append(f"{d.get('name')} (disconnected)")
                    elif pair and unit_kind(pair[1]) == "standby":
                        self.left_out.append(f"{d.get('name')} (standby unit of {pair[0]})")
                    else:
                        usable.append(d)
                self.pool = usable[:AUTO_DEVICE_CAP]
                self.left_out += [
                    f"{d.get('name')} (over the first {AUTO_DEVICE_CAP}; pass `candidates`)"
                    for d in usable[AUTO_DEVICE_CAP:]
                ]
        src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
        best: tuple[int, dict[str, Any], str] | None = None
        for dev in self.pool:
            try:
                dc = await self.context(dev)
            except UpstreamError:
                continue
            ingress, egress = dc.leg(src), dc.leg(dst)
            if ingress is None or egress is None or ingress.interface == egress.interface:
                continue
            score = 2 if ingress.how.startswith("connected") else 1
            if best is None or score > best[0]:
                best = (score, dev, f"{ingress.how} -> {egress.how}")
            if score == 2:
                break  # the source's own subnet: no other device can beat it
        if best is None:
            where = ", ".join(str(d.get("name")) for d in self.pool) or "none"
            skipped = f"; left out: {', '.join(self.left_out)}" if self.left_out else ""
            raise InvalidRequest(
                f"No device routes {source} -> {destination} through two of its interfaces "
                f"(checked: {where}{skipped}); give the flow's device."
            )
        return best[1], best[2]


def ha_units(pair: dict[str, Any] | None) -> list[dict[str, Any]]:
    """An HA pair's units with FMC's failover state (metadata.<side>Status.currentStatus)."""
    meta = (pair or {}).get("metadata") or {}
    out = []
    for side in ("primary", "secondary"):
        unit = (pair or {}).get(side) or {}
        if unit.get("id"):
            state = (meta.get(f"{side}Status") or {}).get("currentStatus")
            out.append({"id": str(unit["id"]).lower(), "name": unit.get("name"), "state": state})
    return out


def unit_kind(state: str | None) -> str | None:
    """'active', 'standby' or FMC's own word ('Failed', ...) for a unit's failover state."""
    s = str(state or "").strip().lower()
    if not s:
        return None
    return "standby" if "standby" in s else "active" if "active" in s else s


def user_seen(trace: dict[str, Any]) -> str | None:
    """The user the Snort identity phase associated with the source ('LAB\\alice'), or None."""
    for ph in trace.get("phases") or []:
        if ph.get("type") == "SNORT" and ph.get("subtype") == "identity":
            m = IDENTITY.search(str(ph.get("info") or ""))
            if m and m["user"].lower() not in ("none", "unknown"):
                realm = m["realm"] if m["realm"] and m["realm"].lower() != "none" else None
                return f"{realm}\\{m['user']}" if realm else m["user"]
    return None


def policy_verdict(trace: dict[str, Any]) -> tuple[str, str | None]:
    """('allow' | 'block' | 'unknown', why the packet still dropped when the policy allowed it)."""
    if str(trace.get("action", "")).lower() == "allow":
        return "allow", None
    reason = str(trace.get("drop_reason") or "")
    dropped_at = str(trace.get("dropped_at") or "")
    if POLICY_DROP.search(reason) or any(p in dropped_at for p in POLICY_PHASES):
        return "block", None
    rules = trace.get("matched_rules") or []
    if any(str(r.get("result", "")).upper() == "ALLOW" for r in rules):
        return "allow", reason or "dropped after the policy allowed it"
    return "unknown", reason or "dropped before the access policy was evaluated"


def _same_user(expected: str, seen: str | None) -> bool:
    if not seen:
        return False
    e, s = expected.lower(), seen.lower()
    return e == s or e.rpartition("\\")[2] == s.rpartition("\\")[2]


def judge(exp: Expectation, trace: dict[str, Any], source: str | None = None) -> dict[str, Any]:
    """The row for one traced flow (`source`: the IP traced, when it came from a user lookup)."""
    verdict, delivery = policy_verdict(trace)
    rule = trace.get("verdict_rule")
    seen = user_seen(trace)
    notes: list[str] = []
    if verdict == "unknown":
        result = "mismatch"
        notes.append(f"not decided by the policy: {delivery}")
    elif verdict != exp.expect:
        result = "fail"
        if trace.get("drop_reason"):
            notes.append(str(trace["drop_reason"]))
    else:
        result = "pass"
        if exp.rule and (rule or "").lower() != exp.rule.lower():
            result = "mismatch"
            notes.append(f"decided by {rule or 'no named rule'}, expected {exp.rule}")
        if delivery:
            result = "mismatch"
            notes.append(f"the policy allows it but the device drops it: {delivery}")
    if exp.user and not _same_user(exp.user, seen):
        if result == "pass":
            result = "mismatch"
        ip = source or exp.source
        whom = "that user" if seen else "an unidentified host"
        notes.append(
            f"the device sees {seen or 'no user'} on {ip}, not {exp.user}: the verdict is for {whom}"
        )
    row: dict[str, Any] = {
        "result": result,
        "expect": exp.expect,
        "verdict": verdict
        + (f" ({trace.get('action')})" if verdict != str(trace.get("action")).lower() else ""),
        "rule": rule,
        "user_seen": seen,
        "note": "; ".join(notes) or None,
    }
    return row


def _flow_label(exp: Expectation, source: str | None) -> str:
    port = f":{exp.port}" if exp.port and exp.protocol != "icmp" else ""
    return f"{exp.protocol} {source or '?'} -> {exp.destination}{port}"


async def _source_for(app: FmcApp, exp: Expectation, domain: str | None) -> str:
    if exp.source:
        return exp.source.strip()
    if not exp.user:
        raise InvalidRequest("The flow needs a source IP (or a user with a user-to-IP lookup).")
    if not USER_IP_RESOLVERS:
        raise InvalidRequest(
            f"No source IP for {exp.user} and no user-to-IP lookup on this server yet: give the IP the "
            "user is logged in on (ISE active sessions show it)."
        )
    for resolve in USER_IP_RESOLVERS:
        ips = await resolve(app, exp.user, domain)
        if ips:
            return ips[0]
    raise InvalidRequest(f"{exp.user} has no active session (no IP found): log the user in first.")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Prove a policy with expected flows")
    async def fmc_prove_policy(
        ctx: Context,
        flows: Flows,
        device: Annotated[
            str | None,
            Field(
                description="FTD to trace every flow on unless the flow names its own (name or UUID; an HA "
                "pair's name means its active unit)"
            ),
        ] = None,
        candidates: Annotated[
            list[str] | None,
            Field(
                description="Devices to choose from for flows without a device (default: the first "
                f"{AUTO_DEVICE_CAP} connected managed devices, HA standby units left out); the one with the "
                "source on a connected subnet wins"
            ),
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Prove that a policy does what it should: give a table of flows (source, destination, port,
        protocol, optional user and device) with the expected verdict (allow or block), and each one is
        run through FMC's packet tracer on the FTD it crosses (the flow's device, the call's device, or
        the candidate whose interfaces and static routes carry it). Returns one row per flow: pass
        (verdict as expected), fail (opposite verdict, with the drop reason), mismatch (right verdict
        for the wrong reason: another rule than `rule`, a non-policy drop such as no route or no ARP
        entry, or not the expected user on the source IP), or error (could not trace); with the
        deciding rule, the user the device saw on the source, the device and ingress interface, and a
        summary (all_passed). User rules are decided from the device's live user-to-IP mapping, so
        a user flow is traced from the IP the user is logged in on: give `source`, or leave it out and
        the IP of the user's newest FMC identity session is used (fmc_user_ip_lookup; the role needs
        Analysis > Users, else that flow is an error row naming the permission). Packet tracer
        simulates the packets (nothing is sent; packet-tracer runs count as rule hits). For one flow in
        depth use fmc_packet_tracer; for the offline view fmc_rule_lookup."""
        app: FmcApp = get_client(ctx)
        placer = Placer(app, domain, candidates)
        rows: list[dict[str, Any]] = []
        for i, exp in enumerate(flows, 1):
            base: dict[str, Any] = {"#": i, "name": exp.name, "user": exp.user}
            try:
                source = await _source_for(app, exp, domain)
                base["flow"] = _flow_label(exp, source)
                dev_ref = exp.device or device
                if dev_ref:
                    dev, found = await placer.named(dev_ref), None
                else:
                    dev, found = await placer.find(source, exp.destination)
                base["device"] = placer.label(dev)
                if found:
                    base["device_found_by"] = found
                ctx_ = await placer.context(dev) if not exp.input_interface else None
                out = await packet_trace(
                    app,
                    dev,
                    exp.protocol,
                    source,
                    exp.destination,
                    input_interface=exp.input_interface,
                    destination_port=exp.port if exp.protocol != "icmp" else None,
                    verbose=True,
                    domain=domain,
                    context=ctx_,
                    interfaces=await placer.ifaces(dev),
                )
            except (InvalidRequest, UpstreamError) as e:
                base.setdefault("flow", _flow_label(exp, exp.source))
                rows.append({**base, "result": "error", "expect": exp.expect, "note": str(e)})
                continue
            traces = out.get("results") or []
            if not traces:
                rows.append(
                    {
                        **base,
                        "result": "error",
                        "expect": exp.expect,
                        "note": "packet tracer returned nothing",
                    }
                )
                continue
            if FO_STANDBY in str(traces[0].get("drop_reason") or ""):
                note = (
                    f"traced on a standby unit ({traces[0].get('drop_reason')}): a standby unit drops "
                    "everything, so this says nothing about the policy; trace on the active unit or give "
                    "the HA pair's name"
                )
                rows.append({**base, "result": "error", "expect": exp.expect, "note": note})
                continue
            row = {**base, **judge(exp, traces[0], source), "input_interface": out.get("input_interface")}
            if len(traces) > 1:
                row["units"] = len(traces)
            rows.append({k: v for k, v in row.items() if v is not None})
        counts = {s: sum(1 for r in rows if r["result"] == s) for s in ("pass", "fail", "mismatch", "error")}
        extra: dict[str, Any] = {
            "flows": len(rows),
            "passed": counts["pass"],
            "failed": counts["fail"],
            "mismatch": counts["mismatch"],
            "errors": counts["error"],
            "all_passed": counts["pass"] == len(rows),
        }
        columns = [
            "#",
            "result",
            "name",
            "flow",
            "user",
            "device",
            "expect",
            "verdict",
            "rule",
            "user_seen",
            "note",
        ]
        return list_result(page_of(rows, limit=MAX_FLOWS), fmt=response_format, extra=extra, columns=columns)
