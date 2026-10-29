"""Object write tools (preview-first): create/update/delete objects and groups, security zones."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    Undo,
    ValidationFailed,
    field_changes,
    get_client,
)
from fmc_mcp.catalog import parse_port_query
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview, owner_domain
from fmc_mcp.refs import NETWORK_TYPES, PORT_TYPES, URL_TYPES, RefResolver
from fmc_mcp.tools.common import (
    ROLE_READ_ONLY,
    Domain,
    ObjType,
    block_labels,
    is_system,
    obj_type,
    ref_label,
    resolve_object,
    role_read_only,
    slim,
)
from fmc_mcp.tools.fqdn_dns import fqdn_dns_check
from fmc_mcp.tools.policies import all_rules
from fmc_mcp.undo import ResultId, block_refs, not_reversible, without_none

ValueType = Literal["host", "network", "range", "fqdn", "port", "icmpv4", "url", "vlan_tag"]
GroupKind = Literal["network", "port", "url"]
GROUP_TYPES = {"network": "network_group", "port": "port_group", "url": "url_group"}
GROUP_KINDS = {v: k for k, v in GROUP_TYPES.items()}
VALUE_TYPES = ("host", "network", "range", "fqdn", "port", "icmpv4", "url", "vlan_tag")
MEMBER_TYPES = {"network": NETWORK_TYPES, "port": PORT_TYPES, "url": URL_TYPES}
ObjectRef = Annotated[str, Field(description="Object name or UUID")]
OptionalType = Annotated[
    str | None,
    Field(
        description="Object type (host, network, range, fqdn, network_group, port, port_group, url, "
        "url_group, security_zone, cipher_suite_list, ...); default: search common types (not "
        "cipher_suite_list)"
    ),
]


def editable(obj: dict[str, Any]) -> dict[str, Any]:
    """An object as FMC accepts it back in a PUT (no metadata/links)."""
    return {k: v for k, v in obj.items() if k not in ("metadata", "links")}


async def applied(app: FmcApp, fn: Callable[[], Awaitable[Any]]) -> Any:
    """Run a write, drop cached object catalogs, and return a slim result."""
    result = await fn()
    app.invalidate_cache()
    return slim(result) if isinstance(result, dict | list) else result


def value_fields(t: ObjType, value: str, protocol: str | None) -> dict[str, Any]:
    """The type-specific fields for a value object, validated locally."""
    v = value.strip()
    try:
        if t.key == "host":
            return {"value": str(ipaddress.ip_address(v))}
        if t.key == "network":
            return {"value": str(ipaddress.ip_network(v, strict=False))}
        if t.key == "range":
            a, b = (ipaddress.ip_address(x.strip()) for x in v.split("-", 1))
            if a.version != b.version or int(a) > int(b):
                raise ValueError("start must not be after end")
            return {"value": f"{a}-{b}"}
    except ValueError as e:
        raise InvalidRequest(f"Invalid {t.key} value {value!r}: {e}") from None
    if t.key == "fqdn":
        if "." not in v or " " in v:
            raise InvalidRequest(f"Invalid FQDN {value!r}")
        return {"value": v, "dnsResolution": "IPV4_AND_IPV6"}
    if t.key == "port":
        text = v if "/" in v or not protocol else f"{protocol}/{v}"
        try:
            proto, lo, hi = parse_port_query(text)
        except ValueError:
            raise InvalidRequest(f"Invalid port {value!r}: use 443, 1000-2000 or tcp/443") from None
        names = {"6": "TCP", "17": "UDP"}
        if proto not in names:
            raise InvalidRequest("Port objects need protocol tcp or udp (pass protocol= or 'tcp/443').")
        out: dict[str, Any] = {"protocol": names[proto]}
        if (lo, hi) != (0, 65535):
            out["port"] = str(lo) if lo == hi else f"{lo}-{hi}"
        return out
    if t.key == "icmpv4":
        if v.lower() == "any":
            return {}
        if not v.isdigit() or int(v) > 255:
            raise InvalidRequest(f"ICMP type must be 0-255 or 'any', got {value!r}")
        return {"icmpType": v}
    if t.key == "url":
        if "." not in v:
            raise InvalidRequest(f"Invalid URL {value!r}")
        return {"url": v}
    if t.key == "vlan_tag":
        first, _, last = v.partition("-")
        if not first.isdigit() or (last and not last.isdigit()):
            raise InvalidRequest(f"VLAN tag must be 1-4094 or a range like 100-200, got {value!r}")
        return {"data": {"type": "VlanTagLiteral", "startTag": int(first), "endTag": int(last or first)}}
    raise InvalidRequest(f"{t.key} objects can't be created with fmc_create_object.")


def value_text(t: ObjType, obj: dict[str, Any]) -> str | None:
    """An object's value as fmc_create_object / fmc_update_object take it (the reverse of value_fields),
    or None when it has none those tools can express."""
    if t.key in ("host", "network", "range", "fqdn"):
        return str(obj["value"]) if obj.get("value") else None
    if t.key == "port":
        proto = str(obj.get("protocol") or "").lower()
        if proto not in ("tcp", "udp"):
            return None
        return f"{proto}/{obj.get('port') or '0-65535'}"
    if t.key == "icmpv4":
        return str(obj["icmpType"]) if obj.get("icmpType") not in (None, "", "Any") else "any"
    if t.key == "url":
        return str(obj["url"]) if obj.get("url") else None
    if t.key == "vlan_tag":
        data = obj.get("data") or {}
        lo, hi = data.get("startTag"), data.get("endTag", data.get("startTag"))
        if lo is None:
            return None
        return str(lo) if lo == hi else f"{lo}-{hi}"
    return None


def recreate_undo(t: ObjType, obj: dict[str, Any], domain: str | None) -> Undo | str:
    """The back-out step of deleting `obj`: the create call that makes it again (with a new id; nothing
    referenced it, or the delete would have been blocked), or why one call can't."""
    desc = obj.get("description") or None
    name = obj.get("name")
    if t.key in VALUE_TYPES and (value := value_text(t, obj)) is not None:
        return Undo(
            "fmc_create_object",
            without_none(
                {"type": t.key, "name": name, "value": value, "description": desc, "domain": domain}
            ),
        )
    if t.key in GROUP_KINDS and block_refs(obj):
        args = {"kind": GROUP_KINDS[t.key], "name": name, "members": block_refs(obj), "description": desc}
        return Undo("fmc_create_group", without_none({**args, "domain": domain}))
    if t.key == "security_zone":
        args = {
            "name": name,
            "interface_mode": obj.get("interfaceMode"),
            "description": desc,
            "domain": domain,
        }
        return Undo("fmc_create_security_zone", without_none(args))
    return not_reversible(f"{t.key} object", "its create tool", editable(obj))


async def exists(app: FmcApp, name: str, types: list[str], domain: str | None) -> dict[str, Any] | None:
    try:
        _, obj = await resolve_object(app, name, domain, types, full_fallback=False)
    except NotFound:
        return None
    return obj


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create object")
    async def fmc_create_object(
        ctx: Context,
        type: Annotated[ValueType, Field(description="Object type to create")],
        name: Annotated[
            str, Field(description="New object name (unique per type)", min_length=1, max_length=64)
        ],
        value: Annotated[
            str,
            Field(
                description="host: 10.1.1.5 | network: 10.1.0.0/16 | range: 10.1.1.1-10.1.1.9 | fqdn: "
                "www.example.com | port: 443, 1000-2000 or tcp/443 | icmpv4: type number or any | url: "
                "https://example.com/path | vlan_tag: 100 or 100-200"
            ),
        ],
        protocol: Annotated[
            Literal["tcp", "udp"] | None,
            Field(description="Port objects: protocol when value is just a number"),
        ] = None,
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a host, network, range, FQDN, port, ICMPv4, URL or VLAN-tag object. Preview-first:
        validates the value and checks the name is free; nothing changes until confirmed. Check for an
        existing object with the same value first with fmc_find_object. Groups: fmc_create_group."""
        app: FmcApp = get_client(ctx)
        t = obj_type(type)
        body: dict[str, Any] = {"name": name, "type": t.fmc_type, **value_fields(t, value, protocol)}
        if description:
            body["description"] = description
        blockers = []
        if await exists(app, name, [t.key], domain):
            blockers.append(f"A {t.key} object named {name!r} already exists.")
        path = await app.config_path(t.path, domain)
        details = {"body": body, **await fqdn_dns_check(app, body, domain)}  # F69: FQDN without DNS
        return await fmc_preview(
            ctx,
            tool="fmc_create_object",
            args={
                "type": type,
                "name": name,
                "value": value,
                "protocol": protocol,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {t.key} object {name!r}",
                details=details,
                blockers=blockers,
                undo=Undo(
                    "fmc_delete_object",
                    without_none({"object": ResultId("id"), "type": t.key, "domain": domain}),
                ),
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Update object")
    async def fmc_update_object(
        ctx: Context,
        object: ObjectRef,
        type: OptionalType = None,
        new_name: Annotated[str | None, Field(description="Rename the object")] = None,
        value: Annotated[
            str | None, Field(description="New value (same formats as fmc_create_object; not for groups)")
        ] = None,
        protocol: Annotated[
            Literal["tcp", "udp"] | None, Field(description="Port objects: new protocol")
        ] = None,
        description: Annotated[str | None, Field(description="New description ('' clears it)")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an object's name, value or description (hosts, networks, ranges, FQDNs, ports, URLs,
        VLAN tags; rename/describe groups and zones too). Preview shows the field changes and every
        policy that uses the object (changes reach devices on the next deploy). Group members:
        fmc_update_group."""
        app: FmcApp = get_client(ctx)
        t, current = await resolve_object(app, object, domain, [type] if type else None)
        if is_system(current):
            raise InvalidRequest(f"{current.get('name')!r} is a read-only system object.")
        if role_read_only(current):
            raise InvalidRequest(f"{current.get('name')!r} is {ROLE_READ_ONLY}.")
        if t.key == "cipher_suite_list":
            raise InvalidRequest(
                "FMC's API documents no PUT for cipher suite lists: create a new list "
                "(fmc_create_cipher_suite_list), switch the rules to it (fmc_update_decryption_rule) and "
                "delete this one (fmc_delete_object)."
            )
        desired = editable(current)
        if new_name:
            desired["name"] = new_name
        if value is not None or protocol is not None:
            if t.key == "sla_monitor":
                raise InvalidRequest(
                    "SLA monitors have several values (target, zones, timing): use fmc_update_sla_monitor."
                )
            if t.key not in ("host", "network", "range", "fqdn", "port", "icmpv4", "url", "vlan_tag"):
                raise InvalidRequest(
                    f"{t.key} objects have no single value; use fmc_update_group for members."
                )
            v = value if value is not None else str(current.get("port") or current.get("value") or "")
            fields = value_fields(t, v, protocol or str(current.get("protocol", "")).lower() or None)
            if t.key == "fqdn":
                fields.pop("dnsResolution", None)  # keep the object's resolution setting
            if t.key == "port" and "port" not in fields:
                desired.pop("port", None)  # all ports
            if t.key == "icmpv4" and "icmpType" not in fields:
                desired.pop("icmpType", None)  # any type
                desired.pop("code", None)
            desired.update(fields)
        if description is not None:
            desired["description"] = description
        changes = field_changes(editable(current), desired, replace=True)
        usage = await _usage(app, current, t, domain)
        blockers = [] if changes else ["Nothing to change: the object already has these values."]
        if new_name and new_name != current.get("name") and await exists(app, new_name, [t.key], domain):
            blockers.append(f"A {t.key} named {new_name!r} already exists.")
        path = await app.config_path(f"{t.path}/{current['id']}", domain)
        undo: Undo | str = Undo(
            "fmc_update_object",
            without_none(
                {
                    "object": current["id"],
                    "type": t.key,
                    "new_name": current.get("name") if new_name and new_name != current.get("name") else None,
                    "value": value_text(t, current) if value is not None or protocol is not None else None,
                    "description": (current.get("description") or "") if description is not None else None,
                    "domain": domain,
                }
            ),
        )
        if (value is not None or protocol is not None) and value_text(t, current) is None:
            undo = f"set the old value back by hand with fmc_update_object: {editable(current)}"
        plan = Plan(
            f"Update {t.key} {current.get('name')!r}",
            undo=undo,
            details={"changes": changes, "used_by": usage},
            fingerprint={"current": editable(current), "desired": desired},
            blockers=blockers,
            side_effects=["Affects every policy listed in used_by after the next deployment."]
            if usage
            else [],
        )
        return await fmc_preview(
            ctx,
            tool="fmc_update_object",
            owned=[current],
            args={
                "object": object,
                "type": type,
                "new_name": new_name,
                "value": value,
                "protocol": protocol,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

    @reg.write(title="Delete object", destructive=True)
    async def fmc_delete_object(
        ctx: Context,
        object: ObjectRef,
        type: OptionalType = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an unused object or group (any type, including security zones and, with
        type='cipher_suite_list', cipher suite lists). Preview-first and blocked while anything references it
        (the preview lists the policies/groups, or for a cipher suite list the decryption rules, to fix first)
        or when it is a read-only system object."""
        app: FmcApp = get_client(ctx)
        try:
            t, current = await resolve_object(app, object, domain, [type] if type else None)
        except NotFound as e:
            if type:
                raise
            raise NotFound(f"{e} A cipher suite list: pass type='cipher_suite_list'.", 404) from None
        usage = await _usage(app, current, t, domain)
        blockers = []
        if is_system(current):
            blockers.append("Read-only system object.")
        elif role_read_only(current):
            blockers.append(f"{current.get('name')!r} is {ROLE_READ_ONLY}.")
        if usage:
            names = ", ".join(f"{u['type']} {u['name']}" for u in usage)
            fix = (
                "Point those rules at another list (fmc_update_decryption_rule cipher_suite_lists=[...]) or "
                "delete them first."
                if t.key == "cipher_suite_list"
                else "Remove those references first (see fmc_where_used)."
            )
            blockers.append(f"Still in use by: {names}. {fix}")
        path = await app.config_path(f"{t.path}/{current['id']}", domain)
        plan = Plan(
            f"Delete {t.key} {current.get('name')!r}",
            details={
                "object": {"name": current.get("name"), "type": current.get("type"), "id": current["id"]}
            },
            fingerprint=editable(current),
            blockers=blockers,
            undo=recreate_undo(t, current, domain),
        )
        return await fmc_preview(
            ctx,
            tool="fmc_delete_object",
            owned=[] if is_system(current) else [current],  # a built-in is read-only in Global too
            args={"object": object, "type": type, "domain": domain},
            confirm=confirm,
            plan=plan,
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    @reg.write(title="Create object group")
    async def fmc_create_group(
        ctx: Context,
        kind: Annotated[GroupKind, Field(description="network, port or url group")],
        name: Annotated[str, Field(description="New group name", min_length=1, max_length=64)],
        members: Annotated[
            list[str],
            Field(
                description="Members: object names/UUIDs, or literals (network: 10.1.1.5, 10.1.0.0/16, "
                "10.1.1.1-10.1.1.9; url: https://...). Port groups take port objects only.",
                min_length=1,
            ),
        ],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a network, port or URL group from existing objects and literal values. Preview shows
        each member resolved to its object (unknown names fail with suggestions)."""
        app: FmcApp = get_client(ctx)
        t = obj_type(GROUP_TYPES[kind])
        block = await _members(app, kind, members, domain)
        body: dict[str, Any] = {"name": name, "type": t.fmc_type, **block}
        if description:
            body["description"] = description
        blockers = []
        if await exists(app, name, [t.key], domain):
            blockers.append(f"A {t.key} named {name!r} already exists.")
        path = await app.config_path(t.path, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_group",
            args={
                "kind": kind,
                "name": name,
                "members": members,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {t.key} {name!r}",
                details={"members": block_labels(block), "body": body},
                fingerprint=body,
                blockers=blockers,
                undo=Undo(
                    "fmc_delete_object",
                    without_none({"object": ResultId("id"), "type": t.key, "domain": domain}),
                ),
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Update object group")
    async def fmc_update_group(
        ctx: Context,
        group: Annotated[str, Field(description="Group name or UUID")],
        kind: Annotated[GroupKind, Field(description="network, port or url group")] = "network",
        add: Annotated[
            list[str] | None, Field(description="Members to add (names/UUIDs or literals)")
        ] = None,
        remove: Annotated[
            list[str] | None, Field(description="Members to remove (object names/UUIDs or literal values)")
        ] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add or remove members of a network, port or URL group. Preview shows members before and
        after and the policies using the group (they change on the next deployment). A group can't
        be left empty."""
        app: FmcApp = get_client(ctx)
        t, current = await resolve_object(app, group, domain, [GROUP_TYPES[kind]])
        desired = editable(current)
        objects = list(desired.get("objects") or [])
        literals = list(desired.get("literals") or [])
        missing = []
        for r in remove or []:
            key = r.strip().lower()
            count = len(objects) + len(literals)
            objects = [
                o for o in objects if key not in (str(o.get("name", "")).lower(), str(o.get("id")).lower())
            ]
            literals = [lit for lit in literals if ref_label(lit).lower() != key]
            if len(objects) + len(literals) == count:
                missing.append(r)
        if missing:
            raise InvalidRequest(f"Not members of {current.get('name')!r}: {', '.join(missing)}")
        if add:
            extra = await _members(app, kind, add, domain)
            have = {o.get("id") for o in objects}
            objects += [o for o in extra.get("objects", []) if o.get("id") not in have]
            have_lit = {ref_label(x) for x in literals}
            literals += [x for x in extra.get("literals", []) if ref_label(x) not in have_lit]
        desired["objects"] = objects
        if literals or "literals" in current:
            desired["literals"] = literals
        if not desired["objects"]:
            desired.pop("objects")
        if description is not None:
            desired["description"] = description
        before, after = block_labels(current), block_labels(desired)
        blockers = []
        if not after:
            blockers.append("The group would be empty; delete it with fmc_delete_object instead.")
        if before == after and description is None:
            blockers.append("Nothing to change.")
        usage = await _usage(app, current, t, domain)
        path = await app.config_path(f"{t.path}/{current['id']}", domain)
        old_refs, new_refs = block_refs(current), block_refs(desired)
        undo = Undo(
            "fmc_update_group",
            without_none(
                {
                    "group": current["id"],
                    "kind": kind,
                    "add": [m for m in old_refs if m not in new_refs] or None,
                    "remove": [m for m in new_refs if m not in old_refs] or None,
                    "description": (current.get("description") or "") if description is not None else None,
                    "domain": domain,
                }
            ),
        )
        plan = Plan(
            f"Update {t.key} {current.get('name')!r}",
            undo=undo,
            details={
                "added": [m for m in after if m not in before],
                "removed": [m for m in before if m not in after],
                "members_after": after,
                "used_by": usage,
            },
            fingerprint={"current": editable(current), "desired": desired},
            blockers=blockers,
        )
        return await fmc_preview(
            ctx,
            tool="fmc_update_group",
            owned=[current],
            args={
                "group": group,
                "kind": kind,
                "add": add,
                "remove": remove,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

    @reg.write(title="Create security zone")
    async def fmc_create_security_zone(
        ctx: Context,
        name: Annotated[str, Field(description="Zone name, e.g. inside", min_length=1, max_length=48)],
        interface_mode: Annotated[
            Literal["ROUTED", "SWITCHED", "INLINE", "PASSIVE", "ASA"],
            Field(description="Interface type the zone can hold (ROUTED for normal routed interfaces)"),
        ] = "ROUTED",
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a security zone for use in access, prefilter and NAT rules. Interfaces join the zone
        in the device interface settings. Delete with fmc_delete_object(type='security_zone')."""
        app: FmcApp = get_client(ctx)
        body: dict[str, Any] = {"name": name, "type": "SecurityZone", "interfaceMode": interface_mode}
        if description:
            body["description"] = description
        blockers = []
        if await exists(app, name, ["security_zone"], domain):
            blockers.append(f"A security zone named {name!r} already exists.")
        path = await app.config_path("object/securityzones", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_security_zone",
            args={
                "name": name,
                "interface_mode": interface_mode,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create security zone {name!r}",
                details={"body": body},
                blockers=blockers,
                undo=Undo(
                    "fmc_delete_object",
                    without_none({"object": ResultId("id"), "type": "security_zone", "domain": domain}),
                ),
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )


async def _members(app: FmcApp, kind: str, members: list[str], domain: str | None) -> dict[str, Any]:
    resolver = RefResolver(app, domain)
    block = await resolver.block(members, kind) or {}
    if kind == "port" and block.get("literals"):
        raise InvalidRequest(
            "Port groups take port objects only; create port objects first (fmc_create_object)."
        )
    return block


async def _usage(app: FmcApp, obj: dict[str, Any], t: ObjType, domain: str | None) -> list[dict[str, Any]]:
    """Who references the object. FMC's usage API doesn't support every type (e.g. security zones);
    then this returns [] and FMC itself refuses a delete of an object that is still in use. Cipher suite
    lists: the decryption rules that use them."""
    if t.key == "cipher_suite_list":
        return [cipher_rule_usage(pol, r) for pol, r in await cipher_list_rules(app, obj, domain)]
    if t.key == "sla_monitor":  # FMC's usage API doesn't report route tracking: read the routes
        from fmc_mcp.tools.sla_monitors import routes_tracking  # imported here: avoids an import cycle

        return [
            {
                "type": "IPv4StaticRoute",
                "name": f"{r['device']} ({r['table']}) via {r['gateway']}",
                "id": r["id"],
            }
            for r in await routes_tracking(app, str(obj["id"]), domain)
        ]
    try:
        page = await app.all(
            await app.config_path("object/operational/usage", domain),
            {"filter": f"uuid:{obj['id']};type:{obj.get('type') or t.fmc_type}"},
            cap=1000,
        )
    except ValidationFailed:
        return []
    return [{"type": u.get("type"), "name": u.get("name"), "id": u.get("id")} for u in page.items]


DECRYPTION = "policy/decryptionpolicies"


async def cipher_list_rules(
    app: FmcApp, obj: dict[str, Any], domain: str | None
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """The decryption rules that use a cipher suite list, each with its policy. FMC 10.0.1's usage API
    answers 400 "API not supported for specified type" for CipherSuiteList, so the rules are read: those of
    every decryption policy in the requested domain and in each domain below the list's own (a child domain's
    policies are invisible from its parent)."""
    here = await app.domain_uuid(domain)
    owner = str((owner_domain(obj) or {}).get("id") or here).lower()
    top = next((d["name"] for d in app.domains if d["uuid"].lower() == owner), None)
    domains = [here] + [
        d["uuid"]
        for d in app.domains
        if top and d["name"].startswith(top + "/") and d["uuid"].lower() != here.lower()
    ]
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for dom in domains:
        for p in (await app.all(await app.config_path(DECRYPTION, dom))).items:
            if not p.get("id") or p["id"] in seen:
                continue
            seen.add(p["id"])
            rules = await all_rules(
                app, await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", dom)
            )
            for r in rules.items:
                if obj["id"] in {o.get("id") for o in (r.get("cipherSuiteLists") or {}).get("objects") or []}:
                    out.append((p, r))
    return out


def cipher_rule_usage(policy: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    """A decryption rule that uses a cipher suite list, as a usage entry ('policy / rule')."""
    return {
        "type": "DecryptionPolicyRule",
        "name": f"{policy.get('name')} / {rule.get('name')}",
        "id": rule.get("id"),
    }
