"""Smart tools: offline rule lookup (which rule would match a flow) and shadowed-rule detection."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, get_client

from fmc_mcp.catalog import Catalog, IpInterval, ip_contains, port_contains
from fmc_mcp.client import FmcApp
from fmc_mcp.rules import OPAQUE_CONDITIONS, flatten_access_rule, has_value
from fmc_mcp.tools.common import PROTO_NUMBERS, Domain, block_labels
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy

PolicyRef = Annotated[str, Field(description="Access control policy name or UUID")]

LIMITS = (
    "Offline, best-effort evaluation of the access control policy only: prefilter rules, NAT, "
    "security intelligence, decryption and inherited parent-policy rules are not evaluated. "
    "Applications, URLs, users, SGTs, VLAN tags, dynamic objects and time ranges can't be known "
    "from addresses and ports, so rules using them are reported as 'conditional' (they may match). "
    "FQDN objects can't be resolved offline. Zones are only checked when you pass them."
)


def _ip(value: str, what: str) -> IpInterval:
    try:
        a = ipaddress.ip_address(value.strip())
    except ValueError:
        raise InvalidRequest(f"{what} must be a single IP address, got {value!r}") from None
    return (a.version, int(a), int(a))


def _opaque(rule: dict[str, Any]) -> list[str]:
    return [c for c in OPAQUE_CONDITIONS if has_value(rule.get(c))]


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
    if port is None:
        return None
    return any(s[1] <= port <= s[2] for s in same_proto)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Which access rule matches a flow")
    async def fmc_rule_lookup(
        ctx: Context,
        policy: PolicyRef,
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
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Work out offline which access control rule would handle a flow (source, destination,
        protocol/port, optional zones): returns the first rule that definitely matches, any earlier
        'conditional' rules that might match first (they also need an application, URL, user, etc.),
        or the policy's default action. Objects and nested groups are resolved to addresses and
        ports. Best-effort: see `limits` in the output (no prefilter, NAT or parent policy)."""
        app: FmcApp = get_client(ctx)
        src, dst = _ip(source, "source"), _ip(destination, "destination")
        proto = PROTO_NUMBERS.get(protocol.strip().upper(), protocol.strip())
        if not proto.isdigit():
            raise InvalidRequest(f"Unknown protocol {protocol!r}: use tcp, udp, icmp or a number.")

        p = await resolve_policy(app, "access", policy, domain)
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain))
        cat = Catalog(app, domain)
        await cat.load_networks()
        await cat.load_ports()

        conditional: list[dict[str, Any]] = []
        match: dict[str, Any] | None = None
        evaluated = 0
        for r in rules.items:
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
            }
            if any(v is False for v in checks.values()):
                continue
            unknown = [k for k, v in checks.items() if v is None] + _opaque(r)
            row = flatten_access_rule(r)
            if unknown:
                conditional.append({**row, "depends_on": unknown})
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
        if match is not None:
            out["verdict"] = f"Rule {match.get('index')} '{match.get('name')}' → {match.get('action')}"
            out["matched_rule"] = match
        else:
            action = (p.get("defaultAction") or {}).get("action")
            out["verdict"] = f"No rule matches definitively → default action {action}"
            out["default_action"] = action
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
        for r in rules.items:
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
                if opaque_a:
                    continue  # an earlier L7 rule doesn't cover everything
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
        return out


Dims = dict[str, Any]


def _dims(cat: Catalog, r: dict[str, Any]) -> Dims | None:
    """Each matching dimension as a comparable value; None for 'any'. None overall if unresolvable."""
    out: Dims = {}
    for key, field in (("sz", "sourceZones"), ("dz", "destinationZones")):
        names = {n.lower() for n in block_labels(r.get(field))}
        out[key] = names or None
    for key, field in (("sn", "sourceNetworks"), ("dn", "destinationNetworks")):
        if has_value(r.get(field)):
            nets = cat.networks(r.get(field))
            if nets is None:
                return None
            out[key] = nets
        else:
            out[key] = None
    for key, field in (("sp", "sourcePorts"), ("dp", "destinationPorts")):
        if has_value(r.get(field)):
            ports = cat.ports(r.get(field))
            if ports is None:
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
