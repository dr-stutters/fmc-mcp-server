"""Inline sets (write tier, preview-first): IPS-only interface pairs on an FTD (F96).

An inline set is FTD as a "bump in the wire" NGIPS: each inline pair joins two interfaces with no IP
address, and traffic between them passes through Snort. In tap mode a copy of the traffic is inspected
and nothing is dropped (a pilot); with tap mode off the access and intrusion policies drop what they
block. The member interfaces need mode INLINE first (fmc_update_interface mode='inline', with a logical
name and no address); an inline security zone on them is what access rules match.

Source: Cisco Secure Firewall Management Center Device Configuration Guide 10.0, "Inline Sets and
Passive Interfaces". Uses devices/devicerecords/{id}/inlinesets (InlineSet: inlinepairs [{first,
second}], tapMode, failOpenSnortDown, failOpenSnortBusy, propogateLinkState (FMC's spelling),
strictTCPEnforcement, mtu). Nothing reaches the FTD until fmc_deploy.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import device_interfaces, diff_rows, pick_interface, resolve_device
from fmc_mcp.tools.devices import (
    DEVICES,
    INLINE_SETS,
    DeviceRef,
    inline_set_row,
    inline_sets,
    interface_row,
    pair_names,
)
from fmc_mcp.tools.object_writes import applied, editable

# Interface kinds that can be an inline pair member (FMC: physical interfaces and EtherChannels).
MEMBER_KINDS = ["physical", "etherchannel"]
# Collections read for the "already used elsewhere" checks (the other kinds only matter as parents).
READ_KINDS = ["physical", "etherchannel", "subinterface"]
TYPES = {"physical": "PhysicalInterface", "etherchannel": "EtherChannelInterface"}

TAP_WARNING = (
    "Tap mode: the FTD inspects a copy of the traffic and drops nothing, whatever the access and "
    "intrusion policies say (events still show what would have been dropped). Turn it off with "
    "fmc_update_inline_set(tap_mode=False) when the pilot is over."
)
INLINE_NOTE = (
    "Inline (tap mode off): traffic between each pair passes through Snort, and what the access and "
    "intrusion policies block is dropped."
)

PairsParam = Annotated[
    list[tuple[str, str]],
    Field(
        description="Interface pairs [[first, second], ...] by hardware name (Ethernet0/2), logical name "
        "or UUID; each interface in one pair only. They need mode INLINE first "
        "(fmc_update_interface mode='inline')",
        min_length=1,
    ),
]
InlineSetRef = Annotated[str, Field(description="Inline set name or UUID (fmc_get_device lists them)")]
MtuParam = Annotated[
    int | None, Field(ge=576, le=9198, description="MTU of the inline set (FMC default 1500)")
]


def pick_set(sets: list[dict[str, Any]], ref: str, device: str) -> dict[str, Any]:
    want = ref.strip().lower()
    for key in ("id", "name"):
        hits = [s for s in sets if str(s.get(key, "")).lower() == want]
        if len(hits) == 1:
            return hits[0]
    names = ", ".join(str(s.get("name")) for s in sets) or "none"
    raise NotFound(f"No inline set {ref!r} on {device}. Inline sets: {names}.", 404)


# --- member checks -------------------------------------------------------------------------------


@dataclass
class Members:
    """The interfaces a set of pairs names, resolved and checked against what the device has."""

    pairs: list[dict[str, Any]] = field(default_factory=list)  # FMC's inlinepairs
    rows: list[dict[str, Any]] = field(default_factory=list)  # each member in plain words
    blockers: list[str] = field(default_factory=list)


def member_ref(kind: str, i: dict[str, Any]) -> dict[str, Any]:
    return {"id": i.get("id"), "type": i.get("type") or TYPES[kind], "name": i.get("name")}


async def zone_modes(app: FmcApp, domain: str | None) -> dict[str, tuple[str, str]]:
    """Zone id -> (name, interfaceMode)."""
    page = await app.all(await app.config_path("object/securityzones", domain), cap=2000)
    return {
        str(z.get("id")): (str(z.get("name")), str(z.get("interfaceMode") or "").upper()) for z in page.items
    }


def check_members(
    items: list[tuple[str, dict[str, Any]]],
    pairs: list[tuple[str, str]],
    device: str,
    zones: dict[str, tuple[str, str]],
    paired: dict[str, str],
) -> Members:
    """Resolve the pairs and list why each member can't join: not a physical interface or EtherChannel,
    management, no INLINE mode, an IP address, a zone that is not INLINE, already in another pair or inline
    set (`paired`: interface id -> the inline set holding it), an EtherChannel member or a subinterface's
    parent."""
    out = Members()
    seen: dict[str, str] = {}
    channel_of = {
        str(m.get("id")): str(i.get("name"))
        for k, i in items
        if k == "etherchannel"
        for m in i.get("selectedInterfaces") or []
    }
    parents = {str(i.get("name")) for k, i in items if k == "subinterface"}
    for first, second in pairs:
        refs = []
        for ref in (first, second):
            kind, i = pick_interface(items, ref, device)
            if kind == "subinterface" and i.get("type") == "PhysicalInterface":
                kind = "physical"
            name = str(interface_row(kind, i)["name"])
            iid = str(i.get("id"))
            zone = i.get("securityZone") or {}
            zname, zmode = zones.get(str(zone.get("id")), (zone.get("name") or zone.get("id"), ""))
            mode = str(i.get("mode") or "NONE").upper()
            ip = interface_row(kind, i).get("ipv4")
            out.rows.append(
                {
                    k: v
                    for k, v in {
                        "interface": name,
                        "logical_name": i.get("ifname"),
                        "mode": mode,
                        "zone": zname,
                        "zone_mode": zmode or None,
                        "ipv4": ip,
                        "enabled": i.get("enabled"),
                    }.items()
                    if v not in (None, "")
                }
            )
            fix = f"fmc_update_interface(interface={name!r}"
            if kind not in MEMBER_KINDS:
                out.blockers.append(f"{name} is a {kind}: only physical interfaces and EtherChannels pair.")
            elif i.get("managementOnly") or name.lower().startswith("management"):
                out.blockers.append(f"{name} is a management interface and can't be in an inline set.")
            else:
                if iid in seen:
                    out.blockers.append(
                        f"{name} is named twice ({seen[iid]}); an interface is in one pair only."
                    )
                if iid in paired:
                    out.blockers.append(f"{name} is already in inline set {paired[iid]!r}.")
                if iid in channel_of:
                    out.blockers.append(
                        f"{name} is a member of {channel_of[iid]}: pair the EtherChannel instead."
                    )
                if name in parents:
                    out.blockers.append(f"{name} has subinterfaces: delete them before pairing it.")
                if ip:
                    out.blockers.append(
                        f"{name} has an IP address ({ip}): an inline interface has none. Clear it "
                        f"with {fix}, ipv4='none', mode='inline') (nothing may route over it: static routes, "
                        "NAT and VPNs on its logical name go too)."
                    )
                if mode != "INLINE":
                    out.blockers.append(
                        f"{name} has mode {mode}{' (routed)' if mode == 'NONE' else ''}: set it with {fix}, "
                        "mode='inline'" + ("" if i.get("ifname") else ", logical_name=...") + ")."
                    )
                elif not i.get("ifname"):
                    out.blockers.append(f"{name} needs a logical name: {fix}, logical_name=...).")
                if zone and zmode and zmode != "INLINE":
                    out.blockers.append(
                        f"{name} is in {zmode} zone {zname!r}: an inline interface takes an INLINE zone "
                        "(fmc_create_security_zone interface_mode='INLINE') or none "
                        f"({fix}, security_zone=...))."
                    )
            seen.setdefault(iid, f"pair {first} / {second}")
            refs.append(member_ref(kind if kind in TYPES else "physical", i))
        if refs[0]["id"] == refs[1]["id"]:
            out.blockers.append(f"A pair needs two different interfaces, not {refs[0]['name']} twice.")
        out.pairs.append({"first": refs[0], "second": refs[1]})
    out.blockers = list(dict.fromkeys(out.blockers))
    return out


def paired_ids(sets: list[dict[str, Any]], skip: str | None = None) -> dict[str, str]:
    """Interface id -> the inline set it is in (leaving out set `skip`)."""
    out: dict[str, str] = {}
    for s in sets:
        if skip and s.get("id") == skip:
            continue
        for p in s.get("inlinepairs") or []:
            for side in ("first", "second"):
                if (p.get(side) or {}).get("id"):
                    out[str(p[side]["id"])] = str(s.get("name"))
    return out


def behaviour_notes(body: dict[str, Any]) -> list[str]:
    notes = [TAP_WARNING if body.get("tapMode") else INLINE_NOTE]
    if not body.get("tapMode"):
        if body.get("failOpenSnortDown") is False:
            notes.append(
                "Fail-open on Snort down is off: traffic between the pairs stops while Snort restarts."
            )
        if body.get("failOpenSnortBusy"):
            notes.append("Fail-open on Snort busy: traffic passes uninspected while Snort is overloaded.")
    elif body.get("strictTCPEnforcement"):
        notes.append("Strict TCP enforcement applies to inline traffic only; in tap mode it drops nothing.")
    if body.get("propogateLinkState") is False:
        notes.append(
            "Link-state propagation is off: when one side of a pair goes down the other stays up, so the "
            "neighbours keep sending into a dead pair instead of failing over."
        )
    return notes


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create inline set")
    async def fmc_create_inline_set(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[str, Field(min_length=1, max_length=48, description="Inline set name")],
        pairs: PairsParam,
        tap_mode: Annotated[
            bool, Field(description="Tap mode: inspect a copy, drop nothing (a pilot before going inline)")
        ] = False,
        fail_open_snort_down: Annotated[
            bool, Field(description="Pass traffic uninspected while Snort is down or restarting")
        ] = True,
        fail_open_snort_busy: Annotated[
            bool, Field(description="Pass traffic uninspected while Snort is too busy to take it")
        ] = False,
        propagate_link_state: Annotated[
            bool, Field(description="Bring a pair's other interface down when one goes down")
        ] = True,
        strict_tcp: Annotated[
            bool, Field(description="Strict TCP enforcement: drop TCP without a full handshake")
        ] = False,
        mtu: MtuParam = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an inline set on an FTD: IPS-only interface pairs ("bump in the wire" behind an existing
        firewall), inline or in tap mode for a pilot, with fail-open on Snort down / busy, link-state
        propagation and strict TCP enforcement. Each member is a physical interface or EtherChannel with
        mode INLINE, a logical name and no IP address (set with fmc_update_interface mode='inline'); an
        INLINE security zone on the members is what access rules match. The preview blocks members with
        an address, a routed (non-INLINE) zone, another mode, or that are already paired, and warns that
        tap mode drops nothing. Deploy with fmc_deploy; check with fmc_run_show_command('show inline-set').
        Change tap mode later with fmc_update_inline_set."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        items = await device_interfaces(app, dev["id"], domain, READ_KINDS)
        sets = await inline_sets(app, dev["id"], domain)
        members = check_members(items, pairs, dev["name"], await zone_modes(app, domain), paired_ids(sets))
        blockers = list(members.blockers)
        if any(str(s.get("name", "")).lower() == name.strip().lower() for s in sets):
            blockers.append(f"{dev['name']} already has an inline set named {name!r}.")
        body: dict[str, Any] = {
            "type": "InlineSet",
            "name": name.strip(),
            "inlinepairs": members.pairs,
            "tapMode": tap_mode,
            "failOpenSnortDown": fail_open_snort_down,
            "failOpenSnortBusy": fail_open_snort_busy,
            "propogateLinkState": propagate_link_state,
            "strictTCPEnforcement": strict_tcp,
        }
        if mtu is not None:
            body["mtu"] = mtu
        if description:
            body["description"] = description
        path = await app.config_path(f"{DEVICES}/{dev['id']}/{INLINE_SETS}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_inline_set",
            args={
                "device": device,
                "name": name,
                "pairs": [list(p) for p in pairs],
                "tap_mode": tap_mode,
                "fail_open_snort_down": fail_open_snort_down,
                "fail_open_snort_busy": fail_open_snort_busy,
                "propagate_link_state": propagate_link_state,
                "strict_tcp": strict_tcp,
                "mtu": mtu,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create inline set {name.strip()} on {dev.get('name')} "
                f"({'tap mode' if tap_mode else 'inline'}, {len(pairs)} pair{'s' * (len(pairs) != 1)})",
                details={
                    "inline_set": inline_set_row(body),
                    "members": members.rows,
                    "warnings": behaviour_notes(body),
                },
                fingerprint=[editable(s) for s in sets],
                blockers=blockers,
                side_effects=[
                    "Takes effect on the device after the next deployment; traffic between each pair then "
                    "passes through the FTD.",
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Update inline set")
    async def fmc_update_inline_set(
        ctx: Context,
        device: DeviceRef,
        inline_set: InlineSetRef,
        tap_mode: Annotated[
            bool | None,
            Field(description="Tap mode on (drop nothing) or off (inline: drop what policy blocks)"),
        ] = None,
        fail_open_snort_down: Annotated[
            bool | None, Field(description="Fail open while Snort is down")
        ] = None,
        fail_open_snort_busy: Annotated[
            bool | None, Field(description="Fail open while Snort is busy")
        ] = None,
        propagate_link_state: Annotated[bool | None, Field(description="Propagate link state")] = None,
        strict_tcp: Annotated[bool | None, Field(description="Strict TCP enforcement")] = None,
        mtu: MtuParam = None,
        add_pairs: Annotated[
            list[tuple[str, str]] | None, Field(description="Pairs to add [[first, second], ...]")
        ] = None,
        remove_pairs: Annotated[
            list[str] | None, Field(description="Pairs to remove, named by either of their interfaces")
        ] = None,
        new_name: Annotated[
            str | None, Field(min_length=1, max_length=48, description="Rename the set")
        ] = None,
        description: Annotated[str | None, Field(description="Description ('' clears it)")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an inline set: tap mode on or off (the pilot-to-production cut-over: tap_mode=False
        starts dropping what the policies block), fail-open, link-state propagation, strict TCP, MTU,
        pairs (add_pairs, checked like fmc_create_inline_set; remove_pairs by either interface) or the
        name. Only the fields you pass change. The preview shows the before/after and what the set will
        do after the next fmc_deploy."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        sets = await inline_sets(app, dev["id"], domain)
        current = pick_set(sets, inline_set, dev["name"])
        item_path = await app.config_path(f"{DEVICES}/{dev['id']}/{INLINE_SETS}/{current['id']}", domain)
        current = await app.api.get(item_path)  # the PUT replaces the whole set
        desired = editable(current)
        for key, value in (
            ("tapMode", tap_mode),
            ("failOpenSnortDown", fail_open_snort_down),
            ("failOpenSnortBusy", fail_open_snort_busy),
            ("propogateLinkState", propagate_link_state),
            ("strictTCPEnforcement", strict_tcp),
            ("mtu", mtu),
        ):
            if value is not None:
                desired[key] = value
        if new_name is not None:
            desired["name"] = new_name.strip()
            if any(
                str(s.get("name", "")).lower() == new_name.strip().lower()
                and s.get("id") != current.get("id")
                for s in sets
            ):
                raise InvalidRequest(f"{dev['name']} already has an inline set named {new_name!r}.")
        if description is not None:
            if description:
                desired["description"] = description
            else:
                desired.pop("description", None)
        blockers: list[str] = []
        rows: list[dict[str, Any]] = []
        if add_pairs or remove_pairs:
            items = await device_interfaces(app, dev["id"], domain, READ_KINDS)
            pairs = list(desired.get("inlinepairs") or [])
            for ref in remove_pairs or []:
                _, iface = pick_interface(items, ref, dev["name"])
                gone = str(iface.get("id"))
                keep = [
                    p
                    for p in pairs
                    if gone not in {str((p.get(s) or {}).get("id")) for s in ("first", "second")}
                ]
                if len(keep) == len(pairs):
                    blockers.append(f"{iface.get('name')} is in no pair of {current.get('name')}.")
                pairs = keep
            if add_pairs:
                taken = paired_ids(sets, skip=current.get("id"))
                for p in pairs:  # the pairs that stay count as taken too
                    for side in ("first", "second"):
                        taken[str((p.get(side) or {}).get("id"))] = str(current.get("name"))
                members = check_members(items, add_pairs, dev["name"], await zone_modes(app, domain), taken)
                blockers += members.blockers
                rows = members.rows
                pairs += members.pairs
            if not pairs:
                blockers.append(
                    "An inline set needs at least one pair: delete it with fmc_delete_inline_set instead."
                )
            desired["inlinepairs"] = pairs
        before, after = inline_set_row(current), inline_set_row(desired)
        changes = diff_rows(before, after)
        if not changes:
            blockers.append("Nothing to change: the inline set already has these settings.")
        notes = behaviour_notes(desired)
        if tap_mode is False and current.get("tapMode"):
            notes.insert(
                0,
                "Leaving tap mode: after the deploy the FTD drops what the access and intrusion policies "
                "block. Check the pilot's events first (fmc_rule_lookup / the intrusion events) for traffic "
                "that should pass.",
            )
        details: dict[str, Any] = {"changes": changes, "warnings": notes}
        if rows:
            details["new_members"] = rows
        return await fmc_preview(
            ctx,
            tool="fmc_update_inline_set",
            args={
                "device": device,
                "inline_set": inline_set,
                "tap_mode": tap_mode,
                "fail_open_snort_down": fail_open_snort_down,
                "fail_open_snort_busy": fail_open_snort_busy,
                "propagate_link_state": propagate_link_state,
                "strict_tcp": strict_tcp,
                "mtu": mtu,
                "add_pairs": [list(p) for p in add_pairs] if add_pairs else add_pairs,
                "remove_pairs": remove_pairs,
                "new_name": new_name,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update inline set {current.get('name')} on {dev.get('name')}",
                details=details,
                fingerprint=editable(current),
                blockers=list(dict.fromkeys(blockers)),
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(item_path, desired)),
        )

    @reg.write(title="Delete inline set", destructive=True)
    async def fmc_delete_inline_set(
        ctx: Context,
        device: DeviceRef,
        inline_set: InlineSetRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an inline set from a device. After the next deployment its pairs no longer bridge:
        traffic that crossed the FTD between them stops (the wire is cut) until the interfaces are
        re-paired or the cabling changes. The member interfaces keep mode INLINE and their logical
        names; reuse them in another set or set them back with fmc_update_interface(mode='routed')."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        sets = await inline_sets(app, dev["id"], domain)
        current = pick_set(sets, inline_set, dev["name"])
        path = await app.config_path(f"{DEVICES}/{dev['id']}/{INLINE_SETS}/{current['id']}", domain)
        pairs = pair_names(current)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_inline_set",
            args={"device": device, "inline_set": inline_set, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete inline set {current.get('name')} on {dev.get('name')}",
                details={"inline_set": inline_set_row(current)},
                fingerprint=editable(current),
                side_effects=[
                    "After the next deployment traffic between "
                    + "; ".join(f"{a} and {b}" for a, b in pairs)
                    + " no longer passes through the FTD (the bump in the wire is removed, not bypassed).",
                    "The member interfaces keep mode INLINE and their logical names.",
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )
