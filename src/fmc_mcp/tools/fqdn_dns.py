"""F69: a preview warning when a write uses FQDN objects the devices can't resolve. FMC deploys an access rule
with an FQDN object without complaint, and the rule never matches while the device's platform settings have
no DNS server group. fmc_create_access_rule, fmc_update_access_rule and fmc_create_object (type fqdn) each
call fqdn_dns_check once; it never blocks or fails the write."""

from __future__ import annotations

import logging
from typing import Any

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.policies import policy_assignments

log = logging.getLogger(__name__)

FQDN_TYPE = "FQDN"
GROUP_TYPE = "NetworkGroup"
PS_TYPE = "FTDPlatformSettingsPolicy"
ACP_TYPE = "AccessPolicy"
NETWORK_GROUPS = "object/networkgroups"
PS = "policy/ftdplatformsettingspolicies"  # not imported from platform_settings: object_writes imports this
MAX_GROUPS = 10  # network groups opened to look for FQDN members
MAX_POLICIES = 10  # platform settings policies whose DNS is read
MAX_NAMED = 10  # devices named in the warning; the rest are counted


async def fqdn_dns_check(
    app: FmcApp, body: dict[str, Any], domain: str | None, *, policy: dict[str, Any] | None = None
) -> dict[str, list[str]]:
    """{"warnings": [...]} when `body` (an access rule, or an FQDN object being created) uses FQDN objects
    and a device that would enforce it has no DNS server group in its platform settings; else {}.
    `policy`: the access policy of the rule (its devices are checked); without it, every device that has
    an access policy. A failed lookup only skips the warning."""
    try:
        fqdns = await _fqdns(app, body, domain)
        if not fqdns:
            return {}
        gaps, ps_names = await _devices_without_dns(app, domain, policy)
    except Exception as e:  # noqa: BLE001 - a warning check must never break the write
        log.info("FQDN DNS check skipped: %s", e)
        return {}
    if not gaps:
        return {}
    named = "; ".join(gaps[:MAX_NAMED]) + (
        f"; and {len(gaps) - MAX_NAMED} more devices" if len(gaps) > MAX_NAMED else ""
    )
    fix = (
        f"fmc_configure_dns policy={ps_names[0]!r} servers=[...]"
        if len(ps_names) == 1
        else "fmc_configure_dns on their platform settings policy"
    )
    return {
        "warnings": [
            f"FQDN {', '.join(fqdns)}: a device resolves FQDN objects with the DNS server group of its "
            f"platform settings, and {'this device has' if len(gaps) == 1 else 'these devices have'} none: "
            f"{named}. The change deploys, but rules never match these objects until DNS is set "
            f"({fix}, then fmc_deploy)."
        ]
    }


async def _fqdns(app: FmcApp, body: dict[str, Any], domain: str | None) -> list[str]:
    """Names of the FQDN objects `body` is or references (directly or as members of network groups)."""
    if body.get("type") == FQDN_TYPE:
        return [str(body.get("name"))]
    out: list[str] = []
    groups: list[dict[str, Any]] = []
    for key in ("sourceNetworks", "destinationNetworks"):
        for o in (body.get(key) or {}).get("objects") or []:
            if o.get("type") == FQDN_TYPE:
                out.append(str(o.get("name") or o.get("id")))
            elif o.get("type") == GROUP_TYPE and o.get("id"):
                groups.append(o)
    for g in groups[:MAX_GROUPS]:
        full = await app.api.get(await app.config_path(f"{NETWORK_GROUPS}/{g['id']}", domain))
        for m in (full or {}).get("objects") or []:
            if m.get("type") == FQDN_TYPE:
                out.append(f"{m.get('name') or m.get('id')} (in group {g.get('name')})")
    return list(dict.fromkeys(out))


async def _devices_without_dns(
    app: FmcApp, domain: str | None, policy: dict[str, Any] | None
) -> tuple[list[str], list[str]]:
    """(['<device> (<why>)', ...], names of the platform settings policies without DNS) for the devices
    the access policy (or any access policy) is assigned to."""
    rows = await policy_assignments(app, domain)
    targets: dict[str, str] = {}
    ps_of: dict[str, dict[str, Any]] = {}
    for a in rows:
        pol = a.get("policy") or {}
        for t in a.get("targets") or []:
            tid = str(t.get("id", "")).lower()
            if pol.get("type") == PS_TYPE:
                ps_of[tid] = pol
            elif pol.get("type") == ACP_TYPE and (policy is None or pol.get("id") == policy.get("id")):
                targets[tid] = str(t.get("name") or t.get("id"))
    has_dns: dict[str, bool] = {}
    gaps: list[str] = []
    ps_names: list[str] = []
    for tid, name in sorted(targets.items(), key=lambda kv: kv[1]):
        ps = ps_of.get(tid)
        if ps is None:
            gaps.append(f"{name} (no platform settings policy)")
            continue
        pid = str(ps.get("id"))
        if pid not in has_dns:
            if len(has_dns) >= MAX_POLICIES:
                continue
            dns = (await app.all(await app.config_path(f"{PS}/{pid}/dnssettings", domain), cap=10)).items
            has_dns[pid] = bool(dns and dns[0].get("dnsServerGroups"))
        if not has_dns[pid]:
            label = str(ps.get("name") or pid)
            gaps.append(f"{name} (platform settings {label})")
            if label not in ps_names:
                ps_names.append(label)
    return gaps, ps_names
