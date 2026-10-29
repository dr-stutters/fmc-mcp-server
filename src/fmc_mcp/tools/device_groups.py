"""Device groups (F68): list, create, change and delete FMC's device groups, and the group resolution the
fleet tools share.

A device group is FMC's folder of devices (Devices > Device Management); its members are devices, HA pairs
and clusters. The tools that take devices accept a group too: 'group:<name or UUID>', or the group's bare
name when no device has that name. A name that is both a device's and a group's is refused, so a deploy
never widens to a whole group by surprise. `expand_devices` turns such a list into member UUIDs (one
cached request for the group list), `as_group` says whether one reference is a group, and `per_member`
runs a single-device read on every member of a group.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import difflib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.devices import CLUSTERS, DEVICES, HA_PAIRS, membership_of, memberships
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.render import object_reply

DEVICE_GROUPS = "devicegroups/devicegrouprecords"
GROUP_PREFIX = "group:"
CONTAINER_TYPES = ("DeviceHAPair", "DeviceCluster")
FANOUT_CONCURRENCY = 4  # members a per_member read runs on at once (each may cost several requests)
FANOUT_MAX = 10  # members per per_member call; more is refused (request budget)

GroupRef = Annotated[str, Field(description="Device group name or UUID (from fmc_list_device_groups)")]
DeviceOrGroup = Annotated[
    str,
    Field(
        description="Device name or UUID (from fmc_list_devices); or a device group, as 'group:<name>' or "
        "the group's name (fmc_list_device_groups): every device in it"
    ),
]
MemberRefs = Annotated[
    list[str] | None,
    Field(
        description="Devices, HA pairs or clusters (names or UUIDs); an HA unit or cluster node means its "
        "pair or cluster"
    ),
]


def _key(ref: str) -> tuple[bool, str]:
    """(written as 'group:...', the name or UUID after the prefix)."""
    text = ref.strip()
    if text.lower().startswith(GROUP_PREFIX):
        return True, text[len(GROUP_PREFIX) :].strip()
    return False, text


def _lookup(groups: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    low = key.lower()
    for hits in (
        [g for g in groups if str(g.get("id", "")).lower() == low],
        [g for g in groups if g.get("name") == key],
        [g for g in groups if str(g.get("name", "")).lower() == low],
    ):
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise InvalidRequest(f"Device group {key!r} is ambiguous; pass its UUID.")
    return None


def member_refs(group: dict[str, Any]) -> list[dict[str, Any]]:
    """A group's members as {id, type, name} (devices, HA pairs, clusters)."""
    out = []
    for m in group.get("members") or []:
        if isinstance(m, dict) and m.get("id"):
            out.append({"id": str(m["id"]), "type": str(m.get("type") or "Device"), "name": m.get("name")})
    return out


def fleet_ids(group: dict[str, Any]) -> list[str]:
    """The UUIDs of a group's members (devices, HA pairs, clusters)."""
    return [m["id"] for m in member_refs(group)]


def group_row(g: dict[str, Any]) -> dict[str, Any]:
    members = member_refs(g)
    row: dict[str, Any] = {
        "name": g.get("name"),
        "members": [m.get("name") or m["id"] for m in members],
        "member_count": len(members),
        "pairs_and_clusters": [m.get("name") or m["id"] for m in members if m["type"] in CONTAINER_TYPES]
        or None,
        "description": g.get("description"),
        "id": g.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def device_groups(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    """Every device group of the domain, expanded (members included); one request, reused for a minute
    and dropped after any write."""
    key = f"devicegroups:{await app.domain_uuid(domain)}"
    hit = app.cache_get(key)
    if hit is not None:
        cached: list[dict[str, Any]] = hit
        return cached
    page = await app.all(await app.config_path(DEVICE_GROUPS, domain), cap=1000)
    app.cache_put(key, page.items)
    return page.items


async def with_members(app: FmcApp, group: dict[str, Any], domain: str | None) -> dict[str, Any]:
    """The group with its members: list rows that lack them are read on their own."""
    if "members" in group or not group.get("id"):
        return group
    full: dict[str, Any] = await app.api.get(await app.config_path(f"{DEVICE_GROUPS}/{group['id']}", domain))
    return full


async def all_with_members(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    """Every device group with its members (for the 'in another group' check of create/update: a list
    row without `members` would otherwise hide a move). Free when the expanded list carries members."""
    return [await with_members(app, g, domain) for g in await device_groups(app, domain)]


async def resolve_group(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """A device group by name or UUID ('group:' prefix optional), with its members."""
    _, key = _key(ref)
    if not key:
        raise InvalidRequest("Empty device group name.")
    groups = await device_groups(app, domain)
    hit = _lookup(groups, key)
    if hit is None:
        names = [str(g.get("name")) for g in groups]
        close = difflib.get_close_matches(key, names, n=5, cutoff=0.5)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        listing = ", ".join(sorted(names)) or "none in this domain"
        raise NotFound(f"No device group {key!r}.{hint} Device groups: {listing}.", 404)
    return await with_members(app, hit, domain)


async def as_group(
    app: FmcApp, ref: str, domain: str | None, *, records: list[dict[str, Any]] | None = None
) -> dict[str, Any] | None:
    """The device group `ref` names, with its members, or None when it names none. 'group:<name or UUID>'
    must name a group (NotFound otherwise); a bare name or UUID is a group when one has it. A bare name
    that is also a device's name is refused: pass 'group:<name>' or the device's UUID. `records`: the
    domain's device records when the caller has them (else listed only for that check)."""
    explicit, key = _key(ref)
    if explicit:
        return await resolve_group(app, ref, domain)
    if not key:
        return None
    try:
        groups = await device_groups(app, domain)
    except UpstreamError:  # an FMC without the device-group API, or a role that can't read it
        return None
    hit = _lookup(groups, key)
    if hit is None:
        return None
    if not is_uuid(key):
        if records is None:
            records = (await app.all(await app.config_path(DEVICES, domain), expanded=False, cap=2000)).items
        if any(str(d.get("name", "")).lower() == key.lower() for d in records):
            raise InvalidRequest(
                f"{key!r} is the name of a device and of a device group. Pass 'group:{key}' for the group, "
                "or the device's UUID for the device."
            )
    return await with_members(app, hit, domain)


async def unit_refs(
    app: FmcApp,
    members: list[dict[str, Any]],
    domain: str | None,
    records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Members with each HA pair and cluster replaced by its units (for tools that run on device records:
    show commands, backups, licences, metrics). One device listing when a container is among them."""
    if not any(m.get("type") in CONTAINER_TYPES for m in members):
        return members
    if records is None:
        records = (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
    of = await memberships(app, records, domain)
    units: dict[str, list[dict[str, Any]]] = {}
    for d in records:
        if box := of.get(str(d.get("id")).lower()):
            units.setdefault(box.container_id, []).append(
                {"id": str(d["id"]), "type": "Device", "name": d.get("name")}
            )
    out: list[dict[str, Any]] = []
    for m in members:
        if m.get("type") not in CONTAINER_TYPES:
            out.append(m)
            continue
        found = units.get(str(m["id"]).lower())
        if not found:
            raise NotFound(f"FMC lists no units for {m.get('type')} {m.get('name') or m['id']!r}.", 404)
        out += found
    return out


@dataclass
class Fleet:
    """Device references after group expansion."""

    refs: list[str]  # in order, duplicates dropped; a group's members as UUIDs
    groups: dict[str, list[str]] = field(default_factory=dict)  # group name -> member names
    grouped: dict[str, str] = field(default_factory=dict)  # member UUID (lower case) -> name

    def from_group(self, ref: str) -> bool:
        return ref.strip().lower() in self.grouped


async def expand_devices(
    app: FmcApp,
    refs: list[str] | None,
    domain: str | None,
    *,
    units: bool = False,
    records: list[dict[str, Any]] | None = None,
) -> Fleet:
    """Device references with every device group among them replaced by its members (as_group decides
    what is a group). units=True: HA pairs and clusters in a group become their units. Costs the cached
    group list; a bare name that is also a group's costs a device listing unless `records` are given."""
    fleet = Fleet([])
    seen: set[str] = set()

    def add(ref: str) -> None:
        k = ref.strip().lower()
        if k and k not in seen:
            seen.add(k)
            fleet.refs.append(ref.strip())

    for ref in refs or []:
        grp = await as_group(app, ref, domain, records=records)
        if grp is None:
            add(ref)
            continue
        members = member_refs(grp)
        if units:
            members = await unit_refs(app, members, domain, records)
        fleet.groups[str(grp.get("name"))] = [str(m.get("name") or m["id"]) for m in members]
        for m in members:
            fleet.grouped[m["id"].lower()] = str(m.get("name") or m["id"])
            add(m["id"])
    return fleet


def _plain(result: Any) -> Any:
    """A tool's return value as data: a ToolResult's structured content, else its text."""
    if isinstance(result, ToolResult):
        if result.structured_content is not None:
            return result.structured_content
        return "\n".join(str(getattr(c, "text", "")) for c in result.content)
    return result


async def per_member(
    app: FmcApp,
    ref: str,
    domain: str | None,
    one: Callable[[str], Awaitable[Any]],
    *,
    what: str,
    cap: int = FANOUT_MAX,
) -> dict[str, Any] | None:
    """When `ref` is a device group: `one(<device UUID>)` on every device in it (HA pairs and clusters by
    their units), FANOUT_CONCURRENCY at a time, as {group, devices, results: [{device, result}], failed:
    [{device, error}]}. None when `ref` is no group: the caller runs on the one device. A group with more
    than `cap` devices is refused (each run costs requests)."""
    grp = await as_group(app, ref, domain)
    if grp is None:
        return None
    name = str(grp.get("name"))
    members = await unit_refs(app, member_refs(grp), domain)
    if not members:
        raise InvalidRequest(f"Device group {name!r} has no devices.")
    if len(members) > cap:
        raise InvalidRequest(
            f"Device group {name!r} has {len(members)} devices; {what} runs on at most {cap} per call (each "
            "device costs FMC requests). Pass a device or a smaller group."
        )
    gate = asyncio.Semaphore(FANOUT_CONCURRENCY)

    async def run(m: dict[str, Any]) -> tuple[dict[str, Any], Any, str | None]:
        async with gate:
            try:
                return m, _plain(await one(m["id"])), None
            except (InvalidRequest, UpstreamError) as e:
                return m, None, str(e)

    done = await asyncio.gather(*(run(m) for m in members))
    out: dict[str, Any] = {
        "group": name,
        "devices": len(members),
        "results": [{"device": m.get("name") or m["id"], "result": r} for m, r, err in done if err is None],
    }
    failed = [{"device": m.get("name") or m["id"], "error": err} for m, _, err in done if err is not None]
    if failed:
        out["failed"] = failed
    return out


def members_markdown(fleet: dict[str, Any], render: Callable[[dict[str, Any]], str]) -> str:
    """A per_member result as markdown: a heading per device with `render(result)`, then the failures."""
    parts = [f"**Device group {fleet['group']}**: {fleet['devices']} device(s)"]
    for r in fleet["results"]:
        body = render(r["result"]) if isinstance(r["result"], dict) else str(r["result"])
        parts.append(f"### {r['device']}\n\n{body}")
    for f in fleet.get("failed") or []:
        parts.append(f"### {f['device']}\n\nFailed: {f['error']}")
    return "\n\n".join(parts)


# --- members for create / update ---------------------------------------------------------------------


async def resolve_members(
    app: FmcApp, refs: list[str], domain: str | None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Group members for device / HA pair / cluster names or UUIDs: ([{id, type, name}], notes). An HA unit
    or cluster node becomes its pair or cluster (FMC groups them as a whole). One device listing; the HA
    pair and cluster lists only for a name that is no device."""
    records = (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
    containers: list[dict[str, Any]] | None = None
    out: list[dict[str, Any]] = []
    notes: list[str] = []
    missing: list[str] = []

    def add(m: dict[str, Any]) -> None:
        if all(x["id"].lower() != m["id"].lower() for x in out):
            out.append(m)

    for ref in refs:
        key = ref.strip()
        low = key.lower()
        dev = next((d for d in records if str(d.get("id", "")).lower() == low), None) or next(
            (d for d in records if str(d.get("name", "")).lower() == low), None
        )
        if dev is not None:
            box = membership_of(dev)
            if box is not None:
                kind = "DeviceHAPair" if box.kind == "ha" else "DeviceCluster"
                add({"id": box.container_id, "type": kind, "name": box.container})
                notes.append(
                    f"{dev.get('name')} is a unit of {box.container}: the group gets {box.container}."
                )
            else:
                add({"id": str(dev["id"]), "type": "Device", "name": dev.get("name")})
            continue
        if containers is None:
            containers = []
            for path, kind in ((HA_PAIRS, "DeviceHAPair"), (CLUSTERS, "DeviceCluster")):
                try:
                    page = await app.all(await app.config_path(path, domain), expanded=False, cap=1000)
                except UpstreamError:
                    continue
                containers += [{**c, "type": kind} for c in page.items]
        box_hit = next(
            (c for c in containers if low in (str(c.get("id", "")).lower(), str(c.get("name", "")).lower())),
            None,
        )
        if box_hit is not None:
            add({"id": str(box_hit["id"]), "type": box_hit["type"], "name": box_hit.get("name")})
        else:
            missing.append(key)
    if missing:
        names = [str(d.get("name")) for d in records] + [str(c.get("name")) for c in containers or []]
        close = sorted({c for m in missing for c in difflib.get_close_matches(m, names, n=3, cutoff=0.5)})
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        raise NotFound(f"No device, HA pair or cluster named {', '.join(map(repr, missing))}.{hint}", 404)
    return out, notes


def current_groups(groups: list[dict[str, Any]], skip: str | None = None) -> dict[str, str]:
    """Member UUID (lower case) -> the name of the group it is in, leaving out group `skip` (an id)."""
    out: dict[str, str] = {}
    for g in groups:
        if skip and str(g.get("id", "")).lower() == skip.lower():
            continue
        for m in member_refs(g):
            out[m["id"].lower()] = str(g.get("name"))
    return out


def _moves(members: list[dict[str, Any]], elsewhere: dict[str, str]) -> list[str]:
    return [
        f"{m.get('name') or m['id']} is in device group {elsewhere[m['id'].lower()]!r} now (FMC keeps a "
        "device in one group: expect it to move)"
        for m in members
        if m["id"].lower() in elsewhere
    ]


def _body(
    name: str, members: list[dict[str, Any]], description: str | None, gid: str | None
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "type": "DeviceGroup",
        "members": [{"id": m["id"], "type": m["type"], "name": m.get("name")} for m in members],
    }
    if gid:
        body["id"] = gid
    if description is not None:
        body["description"] = description
    return body


def _names(members: list[dict[str, Any]]) -> list[str]:
    return [str(m.get("name") or m["id"]) for m in members]


# FMC 10.0.1's DeviceGroup schema has a description, but FMC doesn't keep it: a PUT that sent one was
# answered without it and a re-read had none (Wave 6 live proof). The tools still send it (another FMC
# version may keep it) and say when the answer drops it.
DESCRIPTION_NOTE = (
    "FMC 10.0.1 doesn't store device-group descriptions (it accepts the field and drops it); the result says "
    "whether FMC kept it."
)
DESCRIPTION_DROPPED = (
    "FMC did not keep the description: its answer has none (FMC 10.0.1 doesn't store device-group "
    "descriptions). Everything else was applied."
)


def kept_description(result: Any, description: str | None) -> Any:
    """A create or update result, with a warning when FMC's answer lacks the description it was sent
    (compared without surrounding whitespace, which FMC may trim)."""
    if not description or not description.strip() or not isinstance(result, dict):
        return result
    if str(result.get("description") or "").strip() == description.strip():
        return result
    return {**result, "warning": DESCRIPTION_DROPPED}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List device groups")
    async def fmc_list_device_groups(
        ctx: Context,
        group: Annotated[
            str | None, Field(description="Only this group (name or UUID), with each member's type and id")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC's device groups with their members (devices, HA pairs, clusters), or one group's members
        in full. Fleet tools take a group wherever they take devices: fmc_run_show_command(group=...),
        fmc_deploy / fmc_assign_policy / fmc_backup_devices devices=['group:<name>'], fmc_set_device_licenses,
        fmc_device_metrics and fmc_ftdsdwan_status(branch=...). Empty when the domain has no groups."""
        app: FmcApp = get_client(ctx)
        if group:
            g = await resolve_group(app, group, domain)
            return object_reply({**group_row(g), "members": member_refs(g)}, fmt=response_format)
        groups = sorted(await device_groups(app, domain), key=lambda g: str(g.get("name", "")).lower())
        page = page_of(groups, limit=limit, offset=offset)
        # members of the page's groups only (a list row without them costs a read of that group)
        rows = [group_row(await with_members(app, g, domain)) for g in page.items]
        return list_result(replace(page, items=rows), fmt=response_format)

    @reg.write(title="Create device group")
    async def fmc_create_device_group(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=128, description="Name of the new device group")],
        devices: MemberRefs = None,
        description: Annotated[
            str | None,
            Field(
                description="Description (FMC 10.0.1 doesn't store it on device groups; the result says so)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a device group (FMC's Devices > Device Management folder) with devices, HA pairs or clusters
        as members; an HA unit or cluster node adds its pair or cluster. The preview lists the members and
        any that are in another group now (FMC keeps a device in one group). Groups change nothing on the
        devices themselves: they name a fleet for fmc_run_show_command, fmc_deploy, fmc_assign_policy and
        the other fleet tools."""
        app: FmcApp = get_client(ctx)
        name = name.strip()
        groups = await all_with_members(app, domain)
        members, notes = await resolve_members(app, devices or [], domain)
        blockers = []
        if _lookup(groups, name) is not None:
            blockers.append(
                f"A device group named {name!r} exists already (fmc_update_device_group changes it)."
            )
        moves = _moves(members, current_groups(groups))
        path = await app.config_path(DEVICE_GROUPS, domain)
        body = _body(name, members, description, None)
        if description:
            notes.append(DESCRIPTION_NOTE)

        async def apply() -> Any:
            return kept_description(await applied(app, lambda: app.api.post(path, body)), description)

        return await fmc_preview(
            ctx,
            tool="fmc_create_device_group",
            args={"name": name, "devices": devices, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Create device group {name!r} with {len(members)} member(s)",
                details={
                    "members": _names(members),
                    **({"description": description} if description else {}),
                    **({"notes": notes} if notes else {}),
                },
                fingerprint={"members": [m["id"] for m in members], "moves": moves},
                blockers=blockers,
                side_effects=moves,
            ),
            apply=apply,
        )

    @reg.write(title="Change device group")
    async def fmc_update_device_group(
        ctx: Context,
        group: GroupRef,
        add: MemberRefs = None,
        remove: MemberRefs = None,
        new_name: Annotated[
            str | None, Field(min_length=1, max_length=128, description="Rename the group")
        ] = None,
        description: Annotated[
            str | None,
            Field(
                description="New description ('' clears it; FMC 10.0.1 doesn't store it on device groups, "
                "the result says so)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add devices to a device group, remove them, rename it or change its description. Members are
        devices, HA pairs or clusters (an HA unit or cluster node means its pair or cluster); removed
        devices stay registered, outside any group. The preview lists the members before and after."""
        app: FmcApp = get_client(ctx)
        g = await resolve_group(app, group, domain)
        groups = await all_with_members(app, domain)
        before = member_refs(g)
        added, notes = await resolve_members(app, add or [], domain) if add else ([], [])
        dropped: list[dict[str, Any]] = []
        blockers: list[str] = []
        if remove:
            gone, more = await resolve_members(app, remove, domain)
            notes += more
            ids = {m["id"].lower() for m in before}
            for m in gone:
                if m["id"].lower() in ids:
                    dropped.append(m)
                else:
                    blockers.append(f"{m.get('name') or m['id']} is not in {g.get('name')!r}.")
        drop_ids = {m["id"].lower() for m in dropped}
        after = [m for m in before if m["id"].lower() not in drop_ids]
        have = {m["id"].lower() for m in after}
        new = [m for m in added if m["id"].lower() not in have]
        after += new
        name = (new_name or str(g.get("name"))).strip()
        desc = g.get("description") if description is None else description
        renamed = name != g.get("name")
        redescribed = (desc or "") != (g.get("description") or "")
        changed = bool(new or dropped) or renamed or redescribed
        if not changed and not blockers:
            blockers.append("Nothing to change.")
        if new_name and name.lower() != str(g.get("name", "")).lower() and _lookup(groups, name) is not None:
            blockers.append(f"A device group named {name!r} exists already.")
        moves = _moves(new, current_groups(groups, skip=str(g.get("id"))))
        path = await app.config_path(f"{DEVICE_GROUPS}/{g['id']}", domain)
        body = _body(name, after, desc, str(g["id"]))
        if redescribed and desc:
            notes.append(DESCRIPTION_NOTE)

        async def apply() -> Any:
            return kept_description(await applied(app, lambda: app.api.put(path, body)), desc)

        return await fmc_preview(
            ctx,
            tool="fmc_update_device_group",
            owned=[g],
            args={
                "group": group,
                "add": add,
                "remove": remove,
                "new_name": new_name,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Change device group {g.get('name')!r}: +{len(new)} / -{len(dropped)} member(s)"
                + (f", renamed to {name!r}" if renamed else "")
                + (", description sent (FMC 10.0.1 doesn't keep it)" if redescribed else ""),
                details={
                    "added": _names(new),
                    "removed": _names(dropped),
                    "members_after": _names(after),
                    **({"name": {"from": g.get("name"), "to": name}} if renamed else {}),
                    **(
                        {"description": {"from": g.get("description") or "", "to": desc or ""}}
                        if redescribed
                        else {}
                    ),
                    **({"notes": notes} if notes else {}),
                },
                fingerprint={
                    "members": sorted(m["id"].lower() for m in before),
                    "name": g.get("name"),
                    "description": g.get("description") or "",
                },
                blockers=blockers,
                side_effects=moves
                + (
                    [f"Removed devices stay registered, outside any group: {', '.join(_names(dropped))}"]
                    if dropped
                    else []
                ),
            ),
            apply=apply,
        )

    @reg.write(title="Delete device group", destructive=True)
    async def fmc_delete_device_group(
        ctx: Context, group: GroupRef, domain: Domain = None, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Delete a device group. Its devices stay registered and keep their configuration and policies;
        they are only no longer in a group (FMC shows them ungrouped)."""
        app: FmcApp = get_client(ctx)
        g = await resolve_group(app, group, domain)
        members = _names(member_refs(g))
        path = await app.config_path(f"{DEVICE_GROUPS}/{g['id']}", domain)

        async def apply() -> Any:
            await app.api.delete(path)
            app.invalidate_cache()
            return {"deleted": g.get("name"), "id": g.get("id")}

        return await fmc_preview(
            ctx,
            tool="fmc_delete_device_group",
            owned=[g],
            args={"group": group, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete device group {g.get('name')!r} ({len(members)} member(s))",
                details={"members": members},
                fingerprint={"id": g.get("id"), "members": members},
                side_effects=[f"These stay registered, ungrouped: {', '.join(members)}"] if members else [],
            ),
            apply=apply,
        )
