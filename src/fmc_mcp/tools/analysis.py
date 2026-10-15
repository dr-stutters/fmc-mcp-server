"""Smart tools: offline rule lookup (which rule would match a flow) and shadowed-rule detection."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, UpstreamError, get_client

from fmc_mcp.catalog import Catalog, IpInterval, ip_contains, parse_ip_value, port_contains
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import access_policy_of, device_context
from fmc_mcp.rules import OPAQUE_CONDITIONS, flatten_access_rule, has_value
from fmc_mcp.tools.common import PROTO_NUMBERS, Domain, block_labels
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.dynamic_objects import mappings_of
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy

PolicyRef = Annotated[str, Field(description="Access control policy name or UUID")]

LIMITS = (
    "Offline, best-effort evaluation of the access control policy only: prefilter rules, NAT, "
    "security intelligence, decryption and inherited parent-policy rules are not evaluated. "
    "Applications, URLs, users, SGTs, VLAN tags and time ranges can't be known from addresses and "
    "ports, so rules using them are reported as 'conditional' (they may match). Dynamic objects are "
    "checked against their current IP mappings. FQDN objects can't be resolved offline. Zones are "
    "only checked when you pass them or a device (then they come from its interfaces and routes)."
)
DYNAMIC_FIELDS = ("sourceDynamicObjects", "destinationDynamicObjects")
DYNAMIC_CAP = 25  # dynamic objects whose mappings are read per lookup


async def dynamic_sets(
    app: FmcApp, rules: list[dict[str, Any]], domain: str | None
) -> dict[str, list[IpInterval] | None]:
    """Current IP mappings of the dynamic objects the rules reference (None: unknown)."""
    ids: list[str] = []
    for r in rules:
        for f in DYNAMIC_FIELDS:
            for o in (r.get(f) or {}).get("objects") or []:
                if o.get("id") and o["id"] not in ids:
                    ids.append(str(o["id"]))
    out: dict[str, list[IpInterval] | None] = {}
    for oid in ids[:DYNAMIC_CAP]:
        try:
            maps, complete = await mappings_of(app, oid, domain)
        except UpstreamError:
            out[oid] = None
            continue
        nets: list[IpInterval] = []
        for m in maps:
            got = parse_ip_value(m)
            if not got:  # not an address: the object can't be evaluated offline
                complete = False
                break
            nets += got
        out[oid] = nets if complete else None
    return out


def _dyn_match(block: Any, ip: IpInterval, sets: dict[str, list[IpInterval] | None]) -> bool | None:
    objs = (block.get("objects") or []) if isinstance(block, dict) else []
    if not objs:
        return True
    hit = False
    for o in objs:
        nets = sets.get(str(o.get("id")))
        if nets is None:
            return None
        hit = hit or ip_contains(nets, [ip])
    return hit


def _ip(value: str, what: str) -> IpInterval:
    try:
        a = ipaddress.ip_address(value.strip())
    except ValueError:
        raise InvalidRequest(f"{what} must be a single IP address, got {value!r}") from None
    return (a.version, int(a), int(a))


def _opaque(rule: dict[str, Any], skip: tuple[str, ...] = ()) -> list[str]:
    return [c for c in OPAQUE_CONDITIONS if c not in skip and has_value(rule.get(c))]


def _zone_match(rule_block: Any, zone: str | None) -> bool | None:
    """True/False, or None when the rule has zones but the caller gave none."""
    names = [n.lower() for n in block_labels(rule_block)]
    if not names:
        return True
    if zone is None:
        return None
    return zone.lower() in names


def _net_match(cat: Catalog, block: Any, ip: IpInterval) -> bool | None:
    if not has_value(block):
        return True
    nets = cat.networks(block)
    if nets is None:
        return None
    return ip_contains(nets, [ip])


def _port_match(cat: Catalog, block: Any, proto: str, port: int | None) -> bool | None:
    """True/False, or None when the rule restricts ports of this protocol but no port was given."""
    if not has_value(block):
        return True
    specs = cat.ports(block)
    if specs is None:
        return None
    same_proto = [s for s in specs if s[0] in ("", proto)]
    if not same_proto:
        return False
    full = 255 if proto in ("1", "58") else 65535
    if any(s[1] <= 0 and s[2] >= full for s in same_proto):
        return True  # every port of this protocol
    if port is None:
        return None
    return any(s[1] <= port <= s[2] for s in same_proto)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Which access rule matches a flow")
    async def fmc_rule_lookup(
        ctx: Context,
        source: Annotated[str, Field(description="Source IP address, e.g. 10.1.1.10")],
        destination: Annotated[str, Field(description="Destination IP address, e.g. 192.0.2.80")],
        port: Annotated[
            int | None, Field(ge=0, le=65535, description="Destination port (or ICMP type); omit for any")
        ] = None,
        protocol: Annotated[str, Field(description="tcp, udp, icmp, or a protocol number")] = "tcp",
        source_port: Annotated[
            int | None, Field(ge=0, le=65535, description="Source port, if relevant")
        ] = None,
        source_zone: Annotated[
            str | None, Field(description="Ingress security zone / interface group name")
        ] = None,
        destination_zone: Annotated[
            str | None, Field(description="Egress security zone / interface group name")
        ] = None,
        include_disabled: Annotated[bool, Field(description="Also evaluate disabled rules")] = False,
        policy: Annotated[
            str | None, Field(description="Access control policy name or UUID; default: the device's")
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="FTD the flow crosses (name or UUID): gives its access policy and, when zones "
                "are omitted, the ingress/egress zones from its interface subnets and static routes"
            ),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Work out offline which access control rule would handle a flow (source, destination,
        protocol/port): returns the first rule that definitely matches, any earlier 'conditional'
        rules that might match first (they also need an application, URL, user, etc.), or the
        policy's default action. Give `device` and it finds the policy and the zones itself (shown
        under `device`); else pass `policy` and the zones. Objects and nested groups are resolved to
        addresses and ports, dynamic objects to their current mappings (a host contained with
        fmc_contain_host matches the quarantine rules). Best-effort: see `limits` in the output (no
        prefilter, NAT or parent policy)."""
        app: FmcApp = get_client(ctx)
        src, dst = _ip(source, "source"), _ip(destination, "destination")
        dev = await resolve_device(app, device, domain) if device else None
        if not policy:
            if dev is None:
                raise InvalidRequest(
                    "Give the access policy (policy=...) or the device the flow crosses (device=...)."
                )
            acp = await access_policy_of(app, dev, domain)
            if acp is None:
                raise InvalidRequest(f"{dev.get('name')} has no access control policy assigned.")
            policy = str(acp["id"])
        proto = PROTO_NUMBERS.get(protocol.strip().upper(), protocol.strip())
        if not proto.isdigit():
            raise InvalidRequest(f"Unknown protocol {protocol!r}: use tcp, udp, icmp or a number.")

        p = await resolve_policy(app, "access", policy, domain)
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        cat = Catalog(app, domain)
        await cat.load_networks()
        await cat.load_ports()
        dev_info: dict[str, Any] | None = None
        if dev is not None and (source_zone is None or destination_zone is None):
            dc = await device_context(app, dev, cat, domain)
            src_leg = dc.leg(ipaddress.ip_address(source.strip()))
            dst_leg = dc.leg(ipaddress.ip_address(destination.strip()))
            if source_zone is None and src_leg and src_leg.zone:
                source_zone = src_leg.zone
            if destination_zone is None and dst_leg and dst_leg.zone:
                destination_zone = dst_leg.zone
            dev_info = {
                "name": dev.get("name"),
                "ingress": src_leg.as_dict() if src_leg else None,
                "egress": dst_leg.as_dict() if dst_leg else None,
            }
        dyn = await dynamic_sets(
            app, [r for r in rules.items if r.get("enabled", True) or include_disabled], domain
        )

        conditional: list[dict[str, Any]] = []
        monitored: list[dict[str, Any]] = []
        match: dict[str, Any] | None = None
        evaluated = 0
        for r in sorted(rules.items, key=_rule_index):
            if not r.get("enabled", True) and not include_disabled:
                continue
            evaluated += 1
            checks = {
                "source_zone": _zone_match(r.get("sourceZones"), source_zone),
                "destination_zone": _zone_match(r.get("destinationZones"), destination_zone),
                "source": _net_match(cat, r.get("sourceNetworks"), src),
                "destination": _net_match(cat, r.get("destinationNetworks"), dst),
                "destination_port": _port_match(cat, r.get("destinationPorts"), proto, port),
                "source_port": _port_match(cat, r.get("sourcePorts"), proto, source_port),
                "source_dynamic_object": _dyn_match(r.get("sourceDynamicObjects"), src, dyn),
                "destination_dynamic_object": _dyn_match(r.get("destinationDynamicObjects"), dst, dyn),
            }
            if any(v is False for v in checks.values()):
                continue
            unknown = [k for k, v in checks.items() if v is None] + _opaque(r, DYNAMIC_FIELDS)
            row = flatten_access_rule(r)
            if unknown:
                conditional.append({**row, "depends_on": unknown})
                continue
            if str(r.get("action", "")).upper() == "MONITOR":
                monitored.append(row)  # MONITOR only logs; evaluation continues
                continue
            match = row
            break

        out: dict[str, Any] = {
            "policy": p.get("name"),
            "flow": {
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "port": port,
                "source_zone": source_zone,
                "destination_zone": destination_zone,
            },
            "rules_evaluated": evaluated,
        }
        if dev_info:
            out["device"] = dev_info
        if match is not None:
            out["verdict"] = f"Rule {match.get('index')} '{match.get('name')}' → {match.get('action')}"
            out["matched_rule"] = match
        else:
            action = (p.get("defaultAction") or {}).get("action")
            out["verdict"] = f"No rule matches definitively → default action {action}"
            out["default_action"] = action
        if monitored:
            out["monitor_rules_logged"] = monitored
        if conditional:
            out["may_match_first"] = conditional[:20]
            out["note"] = (
                "Earlier rules listed in may_match_first could take this flow first, depending on the "
                "listed conditions."
            )
        if not rules.complete or not cat.complete:
            out["warning"] = (
                "Policy or object collections were larger than the scan cap; result may be wrong."
            )
        out["limits"] = LIMITS
        return out

    @reg.read(title="Find shadowed access rules")
    async def fmc_shadowed_rules(
        ctx: Context,
        policy: PolicyRef,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Find access rules that can never match because an earlier enabled rule already covers
        every flow they would match (same or wider zones, networks and ports, and no application, URL
        or user conditions). Reports 'redundant' when both rules have the same action and 'shadowed'
        when the actions differ (likely a policy bug). Best-effort and conservative: rules whose
        objects can't be resolved (FQDN) or that use layer-7/identity conditions are skipped."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        cat = Catalog(app, domain)
        await cat.load_networks()
        await cat.load_ports()

        prepared = []
        skipped = 0
        for r in sorted(rules.items, key=_rule_index):
            if not r.get("enabled", True):
                continue
            dims = _dims(cat, r)
            if dims is None:
                skipped += 1
                continue
            prepared.append((r, dims, bool(_opaque(r))))

        findings = []
        for j, (rb, db, _) in enumerate(prepared):
            for ra, da, opaque_a in prepared[:j]:
                if opaque_a or str(ra.get("action", "")).upper() == "MONITOR":
                    continue  # an earlier L7 rule doesn't cover everything; MONITOR never stops a flow
                if _covers(da, db):
                    same = ra.get("action") == rb.get("action")
                    findings.append(
                        {
                            "rule": _brief(rb),
                            "covered_by": _brief(ra),
                            "kind": "redundant" if same else "shadowed",
                        }
                    )
                    break
        out: dict[str, Any] = {
            "policy": p.get("name"),
            "enabled_rules": len(prepared) + skipped,
            "findings": findings,
            "skipped_unresolvable": skipped,
            "limits": "Offline, conservative containment check of zones, networks and ports only; "
            "inherited rules, prefilter and NAT are not considered.",
        }
        if not findings:
            out["summary"] = "No shadowed or redundant rules found."
        if not rules.complete or not cat.complete:
            out["warning"] = (
                "Policy or object collections were larger than the scan cap; results are partial."
            )
        return out


Dims = dict[str, Any]


def _rule_index(r: dict[str, Any]) -> int:
    idx = (r.get("metadata") or {}).get("ruleIndex")
    return idx if isinstance(idx, int) else 1_000_000


def _dims(cat: Catalog, r: dict[str, Any]) -> Dims | None:
    """Each matching dimension as a comparable value; None for 'any'. None overall if unresolvable."""
    out: Dims = {}
    for key, field in (("sz", "sourceZones"), ("dz", "destinationZones")):
        names = {n.lower() for n in block_labels(r.get(field))}
        out[key] = names or None
    for key, field in (("sn", "sourceNetworks"), ("dn", "destinationNetworks")):
        if has_value(r.get(field)):
            nets = cat.networks(r.get(field))
            if not nets:
                return None
            out[key] = nets
        else:
            out[key] = None
    for key, field in (("sp", "sourcePorts"), ("dp", "destinationPorts")):
        if has_value(r.get(field)):
            ports = cat.ports(r.get(field))
            if not ports:
                return None
            out[key] = ports
        else:
            out[key] = None
    return out


def _covers(a: Dims, b: Dims) -> bool:
    """Rule A matches every flow rule B matches (on zones, networks and ports)."""
    for key in ("sz", "dz"):
        if a[key] is not None and (b[key] is None or not b[key] <= a[key]):
            return False
    for key in ("sn", "dn"):
        if a[key] is not None and (b[key] is None or not ip_contains(a[key], b[key])):
            return False
    for key in ("sp", "dp"):
        if a[key] is not None and (b[key] is None or not port_contains(a[key], b[key])):
            return False
    return True


def _brief(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": (r.get("metadata") or {}).get("ruleIndex"),
        "name": r.get("name"),
        "action": r.get("action"),
        "id": r.get("id"),
    }
