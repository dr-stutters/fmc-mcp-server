"""Prove a policy (F56): a table of expected flows, each traced live on the FTD it crosses, with a
pass / fail / mismatch verdict and the rule that decided it.

Every scenario ends with "prove it"; this replaces N hand-made fmc_packet_tracer calls. It reuses the
packet-tracer helper (troubleshoot.packet_trace: ingress interface from the source, rule names from the
Snort rule ids, `verdict_rule`) and the flow context (fmc_mcp.flow: interfaces, zones and static routes)
to find the device when a flow names none.

User-based flows: the FTD applies user rules from its own user-to-IP mapping, so a flow is traced from
the user's current IP and the Snort identity phase shows which user the device saw there. When a flow
gives a user but no source, the IP comes from the user-to-IP lookups in USER_IP_RESOLVERS: FMC's
identity sessions (identity_sources.user_ips, as fmc_user_ip_lookup reads them, falling back to the
ancestor domains when a child domain has none: FMC keeps the ISE source's sessions in Global).
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
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.catalog import Catalog
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import DeviceContext, all_interfaces, connected_net, device_context
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import device_interfaces
from fmc_mcp.tools.devices import (
    DEVICES,
    Membership,
    UnitDisconnected,
    memberships,
    resolve_unit,
    traffic_unit,
)
from fmc_mcp.tools.identity_sources import user_ips
from fmc_mcp.tools.troubleshoot import FO_STANDBY, packet_trace, standby_note

MAX_FLOWS = 25
# Devices searched to place a flow with no device: one interface read each (ftdallinterfaces), their
# static routes only for the device with the source on a connected subnet, or when none has.
AUTO_DEVICE_CAP = 30
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
    # (ref, traceable) -> device record / why it failed to resolve
    devices: dict[tuple[str, bool], dict[str, Any]] = field(default_factory=dict)
    members: dict[str, Membership] = field(default_factory=dict)  # unit id -> its HA pair / cluster
    contexts: dict[str, DeviceContext] = field(default_factory=dict)
    scanned: dict[str, list[tuple[str, dict[str, Any]]]] = field(default_factory=dict)  # one read each
    interfaces: dict[str, list[tuple[str, dict[str, Any]]]] = field(default_factory=dict)  # per kind
    pool: list[dict[str, Any]] | None = None
    catalog: Catalog | None = None
    left_out: list[str] = field(default_factory=list)
    failed: dict[tuple[str, bool], InvalidRequest | UpstreamError] = field(default_factory=dict)

    async def named(self, ref: str, traceable: bool = True) -> dict[str, Any]:
        """A device by name or UUID; an HA pair's or cluster's name or UUID means its active unit / control
        node (FMC's failover state; the primary when FMC knows no active unit). `traceable` (a flow's
        device) refuses an HA unit / cluster node FMC lists as disconnected, naming its connected peers
        (#248); candidates are resolved without it, so the pool leaves such a unit out instead. A ref
        that failed to resolve fails the same way for the next flow, without reading FMC again."""
        key = (ref, traceable)
        if key in self.failed:
            raise self.failed[key]
        if key not in self.devices:
            try:
                dev, member = await resolve_unit(self.app, ref, self.domain, traceable=traceable)
            except (InvalidRequest, UpstreamError) as e:
                self.failed[key] = e
                raise
            self.devices[key] = dev
            if member:
                self.members[str(dev.get("id", "")).lower()] = member
        return self.devices[key]

    def member(self, dev: dict[str, Any]) -> Membership | None:
        return self.members.get(str(dev.get("id", "")).lower())

    def label(self, dev: dict[str, Any]) -> str:
        """'mcp-fw-ha (mcp-fw-ha-a, active)' for an HA unit or cluster node, else the device name."""
        name = str(dev.get("name"))
        member = self.member(dev)
        return member.label(name) if member else name

    async def scan(self, dev: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """Every interface of the device in one request (to place flows and find the ingress leg)."""
        if dev["id"] not in self.scanned:
            self.scanned[dev["id"]] = await all_interfaces(self.app, dev["id"], self.domain)
        return self.scanned[dev["id"]]

    async def context(self, dev: dict[str, Any]) -> DeviceContext:
        if dev["id"] not in self.contexts:
            self.catalog = self.catalog or Catalog(self.app, self.domain)
            self.contexts[dev["id"]] = await device_context(
                self.app, dev, self.catalog, self.domain, interfaces=await self.scan(dev)
            )
        return self.contexts[dev["id"]]

    async def ifaces(self, dev: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """The device's interfaces per kind (full hardware names, for packet tracer's interface pick)."""
        if dev["id"] not in self.interfaces:
            self.interfaces[dev["id"]] = await device_interfaces(self.app, dev["id"], self.domain)
        return self.interfaces[dev["id"]]

    async def _pool(self) -> list[dict[str, Any]]:
        """The devices a flow without a device may cross: connected ones, one unit per HA pair (the active
        one) and per cluster (the control node), the first AUTO_DEVICE_CAP of them; why the others are
        left out goes to `left_out`."""
        listing = (await self.app.all(await self.app.config_path(DEVICES, self.domain), cap=1000)).items
        members = await memberships(self.app, listing, self.domain)
        self.members.update(members)
        chosen = [await self.named(c, False) for c in self.candidates] if self.candidates else listing
        usable: list[dict[str, Any]] = []
        seen: set[str] = set()
        for dev in chosen:
            member = self.member(dev)
            if member is not None:
                if member.container_id in seen:
                    continue
                seen.add(member.container_id)
                units = [
                    (d, m)
                    for d in listing
                    if (m := members.get(str(d.get("id", "")).lower()))
                    and m.container_id == member.container_id
                ] or [(dev, member)]
                dev = traffic_unit(units)
                self.left_out += [m.left_out(str(d.get("name"))) for d, m in units if d is not dev]
                member = self.member(dev)
            if dev.get("isConnected") is False:
                name = str(dev.get("name"))
                self.left_out.append(
                    member.left_out(name, "disconnected") if member else f"{name} (disconnected)"
                )
                continue
            usable.append(dev)
        self.left_out += [
            f"{d.get('name')} (over the first {AUTO_DEVICE_CAP} devices; pass `candidates`)"
            for d in usable[AUTO_DEVICE_CAP:]
        ]
        return usable[:AUTO_DEVICE_CAP]

    async def find(self, source: str, destination: str) -> tuple[dict[str, Any], str]:
        """The device a flow crosses: one with the source on a connected subnet first (one interface read
        per device, its static routes only then), else one whose static routes carry the source; the
        destination must leave by another interface. (device, how it was found)."""
        if self.pool is None:
            self.pool = await self._pool()
        src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
        unreadable: list[str] = []

        async def legs(dev: dict[str, Any]) -> str | None:
            try:
                dc = await self.context(dev)
            except UpstreamError as e:
                unreadable.append(f"{dev.get('name')} ({e})")
                return None
            ingress, egress = dc.leg(src), dc.leg(dst)
            if ingress is None or egress is None or ingress.interface == egress.interface:
                return None
            return f"{ingress.how} -> {egress.how}"

        later: list[dict[str, Any]] = []
        for dev in self.pool:
            try:
                connected = connected_net(await self.scan(dev), src)
            except UpstreamError as e:
                unreadable.append(f"{dev.get('name')} ({e})")
                continue
            if connected is None:
                later.append(dev)
            elif how := await legs(dev):
                return dev, how
        for dev in later:  # nobody has the source on a connected subnet: a static route may carry it
            if how := await legs(dev):
                return dev, how
        where = ", ".join(self.label(d) for d in self.pool) or "none"
        skipped = f"; left out: {', '.join(self.left_out)}" if self.left_out else ""
        failed = f"; could not read: {', '.join(dict.fromkeys(unreadable))}" if unreadable else ""
        raise InvalidRequest(
            f"No device routes {source} -> {destination} through two of its interfaces "
            f"(checked: {where}{skipped}{failed}); give the flow's device."
        )


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
    raise InvalidRequest(
        f"{exp.user} has no active session (no IP found in this domain or its ancestors): log the user in "
        "first, or give the flow's source."
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Prove a policy with expected flows")
    async def fmc_prove_policy(
        ctx: Context,
        flows: Flows,
        device: Annotated[
            str | None,
            Field(
                description="FTD to trace every flow on unless the flow names its own (name or UUID; an HA "
                "pair's or cluster's name means its active unit / control node)"
            ),
        ] = None,
        candidates: Annotated[
            list[str] | None,
            Field(
                description="Devices to choose from for flows without a device (default: every managed "
                f"device, up to {AUTO_DEVICE_CAP}; disconnected ones left out, an HA pair or cluster by its "
                "active unit / control node only); the one with the source on a connected subnet wins"
            ),
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Prove that a policy does what it should: give a table of flows (source, destination, port,
        protocol, optional user and device) with the expected verdict (allow or block), and each one is
        run through FMC's packet tracer on the FTD it crosses (the flow's device, the call's device, or
        the candidate whose interfaces and static routes carry it; an HA pair or cluster is traced on its
        active unit / control node; the device column names pair and unit). Returns one row per flow:
        pass (verdict as expected), fail (opposite verdict, with the drop reason), mismatch (right verdict
        for the wrong reason: another rule than `rule`, a non-policy drop such as no route or no ARP
        entry, or not the expected user on the source IP), or error (could not trace: an HA standby unit
        drops everything; a unit FMC lists as disconnected is skipped, its connected peer named);
        with the deciding rule, the user the device saw on the source, the device and ingress interface,
        and a summary (all_passed). User rules are decided from the device's live user-to-IP mapping, so
        a user flow is traced from the IP the user is logged in on: give `source`, or leave it out and
        the IP of the user's newest FMC identity session is used (fmc_user_ip_lookup; in a child domain
        Global's sessions when the child has none; the role needs Analysis > Users, else that flow is an
        error row naming the permission). Packets are simulated (nothing is sent; runs count as rule
        hits). One flow in depth: fmc_packet_tracer; offline fmc_rule_lookup."""
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
                if isinstance(e, UnitDisconnected):
                    base.setdefault("device", e.device)
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
                rows.append(
                    {
                        **base,
                        "result": "error",
                        "expect": exp.expect,
                        "note": standby_note(dev, placer.member(dev), traces[0]),
                    }
                )
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
        if placer.left_out:
            extra["not_checked"] = placer.left_out  # devices auto placement did not consider, and why
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
