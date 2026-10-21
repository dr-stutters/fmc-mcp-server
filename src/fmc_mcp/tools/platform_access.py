"""Platform settings writes beyond syslog (F24): NTP servers, SNMP (v2c community, hosts, location) and
SSH management access, in an FTD platform settings policy. Secrets FMC masks on read are never echoed back."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import hashlib
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field, SecretStr

from fmc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, RefResolver, network_literal
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.platform_settings import PS, PolicyRef, resolve_ps, section

MASK_CHARS = {"*"}
# FMC 10.0.1 refuses anything else with a 400 that echoes the community back (recorded live, W6N live-A:
# "Invalid Community String: <value>. The Community String is a case-sensitive alphanumeric string of up
# to 32 characters; spaces and special characters are not permitted."), so it is checked before sending.
COMMUNITY = re.compile(r"[A-Za-z0-9]{1,32}")
BAD_COMMUNITY = (
    "The SNMP community must be 1 to 32 letters and digits (case-sensitive): FMC refuses spaces and special "
    "characters such as '-' or '_'. The value isn't shown here."
)


def masked(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and set(value) <= MASK_CHARS


async def _single(app: FmcApp, pol_id: str, sub: str, domain: str | None) -> tuple[str, dict[str, Any]]:
    items = await section(app, pol_id, sub, domain)
    if not items:
        raise InvalidRequest(f"The policy has no {sub} section.")
    path = await app.config_path(f"{PS}/{pol_id}/{sub}/{items[0]['id']}", domain)
    return path, items[0]


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure NTP")
    async def fmc_configure_ntp(
        ctx: Context,
        policy: PolicyRef,
        servers: Annotated[
            list[str] | None,
            Field(description="NTP servers (IPs or names) the FTDs sync from; omit or [] to sync via FMC"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set where the FTDs using a platform settings policy get their time: from listed NTP servers, or
        (no servers) from the management center. Takes effect after a deploy; verify with
        fmc_run_show_command('show running-config ntp')."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        path, cur = await _single(app, pol["id"], "ntpsettings", domain)
        want_servers = list(dict.fromkeys(s.strip() for s in servers or [] if s.strip()))
        for srv in want_servers:
            if not network_literal(srv) and not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", srv):
                raise InvalidRequest(f"{srv!r} is not an IP address or host name.")
        mode = "SYNC_VIA_NTP_SERVER" if want_servers else "SYNC_VIA_MGMT_CENTER_NTP"
        before = {
            "mode": cur.get("ntpMode"),
            "servers": [
                s if isinstance(s, str) else str(s.get("value") or s.get("name"))
                for s in cur.get("ntpServerInfos") or []
            ],
        }
        after = {"mode": mode, "servers": want_servers}

        async def apply() -> Any:
            body = {k: v for k, v in editable(await app.api.get(path)).items() if k != "ntpServerInfos"}
            body["ntpMode"] = mode
            if want_servers:
                body["ntpServerInfos"] = want_servers
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_ntp",
            args={"policy": policy, "servers": servers, "domain": domain},
            confirm=confirm,
            owned=[pol],
            plan=Plan(
                f"NTP in {pol.get('name')!r}: " + (", ".join(want_servers) if want_servers else "via FMC"),
                details={"from": before, "to": after},
                fingerprint=before,
                blockers=[] if before != after else ["Nothing to change."],
                side_effects=["Takes effect on the assigned devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Configure SNMP")
    async def fmc_configure_snmp(
        ctx: Context,
        policy: PolicyRef,
        enabled: Annotated[bool | None, Field(description="Turn the SNMP server on or off")] = None,
        community: Annotated[
            SecretStr | None,
            Field(
                description="SNMPv2c community for the server and the v2c hosts: 1-32 letters and digits "
                "(FMC refuses spaces and special characters). FMC never shows it again, so it must be given "
                "whenever SNMP has hosts or a community and anything changes (a different community than "
                "previewed invalidates the confirm)"
            ),
        ] = None,
        location: Annotated[str | None, Field(description="sysLocation")] = None,
        contact: Annotated[str | None, Field(description="sysContact (admin name)")] = None,
        add_hosts: Annotated[
            list[str] | None,
            Field(description="SNMP managers to allow (poll) and send traps to: IP or host object name"),
        ] = None,
        remove_hosts: Annotated[list[str] | None, Field(description="SNMP managers to remove")] = None,
        interfaces: Annotated[
            list[str] | None,
            Field(description="Security zones / interface groups the added hosts are reached through"),
        ] = None,
        trap: Annotated[bool, Field(description="Send traps to the added hosts")] = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Configure SNMP (v2c) in an FTD platform settings policy: on/off, community, location/contact and
        the manager hosts that may poll (and receive traps). The community is write-only: FMC masks it, so
        give it again with every change. Current settings: fmc_get_platform_settings. Takes effect after a
        deploy ('show running-config snmp-server')."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        path, cur = await _single(app, pol["id"], "snmpsettings", domain)
        resolver = RefResolver(app, domain)
        hosts = list(cur.get("snmpMgmtHosts") or [])
        names = {str((h.get("ipAddress") or {}).get("name", "")).lower(): h for h in hosts}
        added: list[dict[str, Any]] = []
        if add_hosts:
            if not interfaces:
                raise InvalidRequest("Give the interfaces (zones) the SNMP managers are reached through.")
            zones = await resolver.block(interfaces, "zone") or {}
            for h in dict.fromkeys(add_hosts):
                lit = network_literal(h)
                ref = (
                    await _find_host(app, lit["value"], domain)
                    if lit and lit["type"] == "Host"
                    else await resolver.obj(h, NETWORK_TYPES)
                )
                if str(ref.get("name", "")).lower() in names:
                    continue
                added.append(
                    {
                        "ipAddress": {k: v for k, v in ref.items() if k in ("id", "type", "name", "value")},
                        "snmpVersion": "SNMPv2c",
                        "poll": True,
                        "trap": trap,
                        "port": "162",
                        "ifSnmpHostMgmt": False,
                        "interfaces": {"objects": zones.get("objects", [])},
                    }
                )
        gone = {h.lower() for h in remove_hosts or []}
        host_names = {str((h.get("ipAddress") or {}).get("name", "")).lower() for h in hosts}
        host_values = {
            str((h.get("ipAddress") or {}).get("value", "")).lower(): str(
                (h.get("ipAddress") or {}).get("name", "")
            ).lower()
            for h in hosts
        }
        gone |= {host_values[g] for g in list(gone) if g in host_values}
        unmatched = sorted(g for g in gone if g not in host_names and g not in host_values)
        kept = [h for h in hosts if str((h.get("ipAddress") or {}).get("name", "")).lower() not in gone]
        removed = [ref_label(h.get("ipAddress") or {}) for h in hosts if h not in kept]
        secret = community.get_secret_value() if community else None
        changing = any(v is not None for v in (enabled, location, contact)) or added or removed or secret
        needs_secret = masked(cur.get("communityString")) or any(
            masked(h.get("communityString")) for h in kept
        )
        blockers = []
        if not changing:
            blockers.append("Nothing to change.")
        if unmatched:
            blockers.append(
                f"No SNMP manager {', '.join(unmatched)} to remove "
                f"(managers: {', '.join(sorted(host_names)) or 'none'})."
            )
        if added and not secret and not cur.get("communityString"):
            blockers.append("New v2c managers need a community: give `community`.")
        if changing and needs_secret and not secret and (cur.get("enableSNMPServers") or enabled):
            blockers.append(
                "FMC masks the SNMP community; give `community` again, or FMC would store the mask as the "
                "community and the managers would stop working."
            )
        if (
            (enabled or (enabled is None and cur.get("enableSNMPServers")))
            and not secret
            and not cur.get("communityString")
        ):
            blockers.append("An enabled SNMP server needs a community.")
        if secret is not None and not COMMUNITY.fullmatch(secret):
            blockers.append(BAD_COMMUNITY)

        async def apply() -> Any:
            body = editable(await app.api.get(path))
            if enabled is not None:
                body["enableSNMPServers"] = enabled
            if location is not None:
                body["location"] = location
            if contact is not None:
                body["sysAdminName"] = contact
            new_hosts = [
                h
                for h in body.get("snmpMgmtHosts") or []
                if str((h.get("ipAddress") or {}).get("name", "")).lower() not in gone
            ] + added
            for h in new_hosts:
                ip = h.get("ipAddress") or {}
                if not ip.get("id"):  # a manager given as an IP with no host object yet
                    made = await app.api.post(
                        await app.config_path("object/hosts", domain),
                        {"name": ip["name"], "type": "Host", "value": ip["value"]},
                    )
                    h["ipAddress"] = {"id": made["id"], "type": "Host", "name": made["name"]}
                if h.get("snmpVersion") in ("SNMPv1", "SNMPv2c"):
                    if secret:
                        h["communityString"] = secret
                    elif masked(h.get("communityString")):
                        h.pop("communityString", None)
            body["snmpMgmtHosts"] = new_hosts
            if secret:
                body["communityString"] = secret
            elif masked(body.get("communityString")):
                body.pop("communityString", None)
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_snmp",
            args={
                "policy": policy,
                "enabled": enabled,
                # binds the confirm to the previewed community without revealing it
                "community": "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:16] if secret else None,
                "location": location,
                "contact": contact,
                "add_hosts": add_hosts,
                "remove_hosts": remove_hosts,
                "interfaces": interfaces,
                "trap": trap,
                "domain": domain,
            },
            confirm=confirm,
            owned=[pol],
            plan=Plan(
                f"SNMP in {pol.get('name')!r}",
                details={
                    "enabled": {"from": cur.get("enableSNMPServers"), "to": enabled}
                    if enabled is not None
                    else None,
                    "community": "set (hidden)" if secret else "unchanged",
                    "location": location,
                    "contact": contact,
                    "add_hosts": [h["ipAddress"]["name"] for h in added] or None,
                    "creates_host_objects": [
                        h["ipAddress"]["name"] for h in added if not h["ipAddress"].get("id")
                    ]
                    or None,
                    "remove_hosts": removed or None,
                    "hosts_after": [ref_label(h.get("ipAddress") or {}) for h in kept]
                    + [h["ipAddress"]["name"] for h in added],
                },
                fingerprint={
                    "enabled": cur.get("enableSNMPServers"),
                    "hosts": sorted(names),
                    "location": cur.get("location"),
                    "contact": cur.get("sysAdminName"),
                },
                blockers=blockers,
                side_effects=["Takes effect on the assigned devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Configure SSH management access")
    async def fmc_configure_ssh_access(
        ctx: Context,
        policy: PolicyRef,
        action: Annotated[Literal["allow", "remove"], Field(description="Add or remove an SSH access entry")],
        network: Annotated[str, Field(description="Source network allowed to SSH (CIDR, IP or object name)")],
        interfaces: Annotated[
            list[str], Field(min_length=1, description="Security zones / interface groups it may SSH through")
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Allow (or remove) SSH to the FTD data interfaces from a network through given zones (platform
        settings > SSH access). The management interface is not affected. Current entries:
        fmc_get_platform_settings. Takes effect after a deploy ('show running-config ssh')."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        base = await app.config_path(f"{PS}/{pol['id']}/sshaccesssettings", domain)
        entries = await section(app, pol["id"], "sshaccesssettings", domain)
        resolver = RefResolver(app, domain)
        zones = await resolver.block(interfaces, "zone") or {}
        zone_names = sorted(z.get("name", "") for z in zones.get("objects", []))
        lit = network_literal(network)
        addr: dict[str, Any] = (
            {"literal": lit["value"]} if lit else {"object": await resolver.obj(network, NETWORK_TYPES)}
        )

        def same(e: dict[str, Any]) -> bool:
            ip = e.get("ipAddress") or {}
            here = ip.get("literal") or ref_label(ip.get("object") or {})
            there = addr.get("literal") or ref_label(addr.get("object") or {})
            mine = sorted(ref_label(z) for z in (e.get("interfaces") or {}).get("objects") or [])
            return str(here) == str(there) and mine == zone_names

        match = [e for e in entries if same(e)]
        blockers = []
        if action == "allow" and match:
            blockers.append("That SSH access entry exists already.")
        if action == "remove" and not match:
            blockers.append("No such SSH access entry.")
        body = {
            "type": "SSHAccessSetting",
            "ipAddress": addr,
            "interfaces": {"objects": zones.get("objects", [])},
        }

        async def apply() -> Any:
            if action == "allow":
                return await applied(app, lambda: app.api.post(base, body))
            return await applied(app, lambda: app.api.delete(f"{base}/{match[0]['id']}"))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_ssh_access",
            args={
                "policy": policy,
                "action": action,
                "network": network,
                "interfaces": interfaces,
                "domain": domain,
            },
            confirm=confirm,
            owned=[pol],
            plan=Plan(
                f"SSH access {action}: {network} via {', '.join(zone_names)} in {pol.get('name')!r}",
                details={"entries_now": len(entries)},
                fingerprint=[e.get("id") for e in entries],
                blockers=blockers,
                side_effects=["Takes effect on the assigned devices after the next deployment."],
            ),
            apply=apply,
        )


async def _find_host(app: FmcApp, ip: str, domain: str | None) -> dict[str, Any]:
    """An existing host object with this address, else a placeholder created on confirm (mcp-host-<ip>);
    SNMP managers must be objects."""
    hosts = await app.api.get(
        await app.config_path("object/hosts", domain), {"filter": f"nameOrValue:{ip}", "expanded": "true"}
    )
    for h in (hosts or {}).get("items", []):
        if h.get("value") == ip:
            return {"id": h["id"], "type": "Host", "name": h["name"]}
    return {"type": "Host", "name": f"mcp-host-{ip.replace(':', '_')}", "value": ip}
