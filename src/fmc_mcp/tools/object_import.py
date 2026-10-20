"""Bulk object import (F25): many value objects at once, validated in the preview and posted with FMC's
bulk API per type in chunks. mode='sync' (F70) treats the rows as the desired state: existing objects with
another value are updated, group memberships follow the rows, and objects under a name prefix that the rows
no longer list are reported as orphans (fmc_delete_objects removes them)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from fmc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, is_system, obj_type, object_summary, ref_of
from fmc_mcp.tools.object_writes import editable, value_fields

CHUNK = 200
FAMILY = {"host": "network", "network": "network", "range": "network", "fqdn": "network"}
FAMILY_TYPES = {"network": ["host", "network", "range", "fqdn"]}


def canon(kind: str, obj: dict[str, Any]) -> tuple[str, ...]:
    """A comparable form of an object's value (FMC and our normalised fields differ in case and format)."""
    if kind == "port":
        return (str(obj.get("protocol", "")).upper(), str(obj.get("port") or "").strip())
    if kind == "url":
        return (str(obj.get("url", "")).strip().lower().rstrip("/"),)
    v = str(obj.get("value", "")).strip().lower().rstrip(".")
    try:
        if kind in ("host", "network"):
            net = ipaddress.ip_network(v, strict=False)
            return (str(net.network_address) if net.num_addresses == 1 else str(net),)
    except ValueError:
        pass
    return (v,)


MAX_ROWS = 1000
ImportType = Literal["host", "network", "range", "fqdn", "port", "url"]


class ObjectRow(BaseModel):
    """One object to create."""

    name: str = Field(min_length=1, max_length=64)
    type: ImportType
    value: str = Field(
        min_length=1, description="host 10.1.1.5, network 10.1.0.0/16, range a-b, fqdn, tcp/443, URL"
    )
    description: str | None = None
    groups: list[str] | None = Field(
        default=None,
        description="mode='sync': the network, port or URL groups this object belongs to (created if "
        "missing)",
    )


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Import objects")
    async def fmc_import_objects(
        ctx: Context,
        objects: Annotated[
            list[ObjectRow], Field(min_length=1, max_length=MAX_ROWS, description="Objects to create")
        ],
        skip_existing: Annotated[
            bool,
            Field(description="Skip names that exist with the same value (resume or re-run an import)"),
        ] = False,
        mode: Annotated[
            Literal["create", "sync"],
            Field(
                description="create: new objects only. sync: the rows are the desired state (create, "
                "update values and descriptions, group members; report what a prefix holds beyond them)"
            ),
        ] = "create",
        prefix: Annotated[
            str | None,
            Field(
                description="mode='sync': the name prefix this list owns; objects and groups under it "
                "that the rows don't list are reported as orphans (never deleted here)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create many host, network, range, FQDN, port and URL objects in one go (migrations, onboarding).
        The preview validates every value and checks each name against FMC: an existing name with a
        different value is a problem; with the same value it is skipped when skip_existing is set. Posted
        with FMC's bulk API per type, 200 per request.
        mode='sync' makes the rows (an IPAM export, a CSV) the desired state: per row create, update
        (value or description differ) or unchanged; each group a row names (`groups`) ends up holding
        exactly the rows that name it (its literals and nested groups stay), created if missing; with
        `prefix`, objects and groups under it that no row lists are orphans: listed for
        fmc_delete_objects, not deleted. An object can't change type (host to network) by sync."""
        app: FmcApp = get_client(ctx)
        args = {
            "objects": [o.model_dump(exclude_none=True) for o in objects],
            "skip_existing": skip_existing,
            "domain": domain,
        }
        if mode == "sync":
            plan, sync_apply = await _sync(app, objects, prefix, domain)
            return await fmc_preview(
                ctx,
                tool="fmc_import_objects",
                args={**args, "mode": mode, "prefix": prefix},
                confirm=confirm,
                plan=plan,
                apply=sync_apply,
            )
        if prefix:
            raise InvalidRequest("prefix is used with mode='sync' only.")
        if any(o.groups for o in objects):
            raise InvalidRequest("Row groups are used with mode='sync' only.")
        problems: list[str] = []
        skipped: list[str] = []
        bodies: dict[str, list[dict[str, Any]]] = {}
        existing: dict[str, dict[str, dict[str, Any]]] = {}
        seen: set[tuple[str, str]] = set()
        touched: dict[str, str | None] = {}
        for n, row in enumerate(objects, 1):
            t = obj_type(row.type)
            fam = FAMILY.get(t.key, t.key)
            where = f"row {n} ({row.name!r})"
            if (fam, row.name.lower()) in seen:
                problems.append(f"{where}: the name appears twice ({fam} objects share names).")
                continue
            seen.add((fam, row.name.lower()))
            try:
                fields = value_fields(t, row.value, None)
            except InvalidRequest as e:
                problems.append(f"{where}: {e}")
                continue
            for key in FAMILY_TYPES.get(fam, [t.key]):
                if key not in existing:
                    page = await app.all(await app.config_path(obj_type(key).path, domain), cap=50_000)
                    if not page.complete:
                        problems.append(
                            f"FMC has more {key} objects than can be checked; import fewer types at a time."
                        )
                    existing[key] = {str(o.get("name", "")).lower(): o for o in page.items}
            clash = next(
                (
                    (key, existing[key][row.name.lower()])
                    for key in FAMILY_TYPES.get(fam, [t.key])
                    if row.name.lower() in existing[key]
                ),
                None,
            )
            touched[f"{t.key}:{row.name.lower()}"] = clash[1].get("id") if clash else None
            if clash is not None and clash[0] != t.key:
                problems.append(f"{where}: a {clash[0]} object already has that name.")
                continue
            have = clash[1] if clash else None
            if have is not None:
                same = canon(t.key, have) == canon(t.key, fields)
                if same and skip_existing:
                    skipped.append(row.name)
                    continue
                problems.append(
                    f"{where}: a {t.key} with that name exists"
                    + (" (same value; skip_existing=true skips it)" if same else " with a different value")
                )
                continue
            body: dict[str, Any] = {"name": row.name, "type": t.fmc_type, **fields}
            if row.description:
                body["description"] = row.description
            bodies.setdefault(t.key, []).append(body)

        async def apply() -> Any:
            created: list[str] = []
            try:
                for key, items in bodies.items():
                    path = await app.config_path(obj_type(key).path, domain)
                    for i in range(0, len(items), CHUNK):
                        chunk = items[i : i + CHUNK]
                        try:
                            await app.api.post(path, chunk, params={"bulk": "true"})
                        except UpstreamError as e:
                            later = [
                                k
                                for k in bodies
                                if k != key and not any(n in created for n in [b["name"] for b in bodies[k]])
                            ]
                            raise UpstreamError(
                                f"Import stopped after {len(created)} objects (types not attempted: "
                                f"{', '.join(later) or 'none'}); the {key} chunk starting at "
                                f"{chunk[0]['name']!r} failed: {e}. "
                                "Repeat with skip_existing=true to resume.",
                                getattr(e, "status_code", None),
                            ) from e
                        created += [b["name"] for b in chunk]
            finally:
                app.invalidate_cache()
            return {"created": len(created), "by_type": {k: len(v) for k, v in bodies.items()}}

        total = sum(len(v) for v in bodies.values())
        return await fmc_preview(
            ctx,
            tool="fmc_import_objects",
            args=args,
            confirm=confirm,
            plan=Plan(
                f"Create {total} objects",
                details={
                    "by_type": {k: len(v) for k, v in bodies.items()},
                    "first": [b["name"] for v in bodies.values() for b in v][:10],
                    "skipped_existing": skipped[:50] or None,
                    "skipped_count": len(skipped) or None,
                    "problems": problems[:50] or None,
                },
                fingerprint=touched,  # only the names this import touches
                blockers=problems[:20]
                + (["...and more problems"] if len(problems) > 20 else [])
                + (["Nothing to create."] if not total and not problems else []),
                blast_radius=total,
            ),
            apply=apply,
        )


# --- mode='sync' (F70) ------------------------------------------------------------------------------

GROUP_OF = {"network": "network_group", "port": "port_group", "url": "url_group"}
# Member types a sync manages inside a group (the row types); other members (nested groups, ICMP objects)
# and literals are kept.
VALUE_MEMBERS = {
    "network": {"Host", "Network", "Range", "FQDN"},
    "port": {"ProtocolPortObject"},
    "url": {"Url"},
}
ROWS_SHOWN = 300


def _owned_here(obj: dict[str, Any], here: str) -> bool:
    dom = (obj.get("metadata") or {}).get("domain") or {}
    ro = (obj.get("metadata") or {}).get("readOnly") or {}
    if isinstance(ro, dict) and ro.get("state"):
        return False
    return not dom.get("id") or str(dom["id"]).lower() == here


def _updated(
    kind: str, have: dict[str, Any], fields: dict[str, Any], description: str | None
) -> dict[str, Any]:
    """`have` as FMC accepts it back with the row's value (and description) applied."""
    desired = editable(have)
    fields = dict(fields)
    if kind == "fqdn":
        fields.pop("dnsResolution", None)  # keep the object's resolution setting
    if kind == "port" and "port" not in fields:
        desired.pop("port", None)  # all ports
    desired.update(fields)
    if description is not None:
        desired["description"] = description
    return desired


async def _sync(
    app: FmcApp, objects: list[ObjectRow], prefix: str | None, domain: str | None
) -> tuple[Plan, Any]:
    """The plan and apply step of fmc_import_objects(mode='sync')."""
    here = (await app.domain_uuid(domain)).lower()
    pre = (prefix or "").strip().lower() or None
    problems: list[str] = []
    rows: list[dict[str, Any]] = []
    creates: dict[str, list[dict[str, Any]]] = {}
    updates: list[tuple[str, dict[str, Any], dict[str, Any]]] = []  # (type key, current, desired)
    existing: dict[str, dict[str, dict[str, Any]]] = {}
    want_groups: dict[tuple[str, str], dict[str, Any]] = {}  # (group key, lower name) -> name, fam, members
    seen: set[tuple[str, str]] = set()
    row_type: dict[tuple[str, str], str] = {}  # (family, lower name) -> type key

    async def load(key: str) -> dict[str, dict[str, Any]]:
        if key not in existing:
            page = await app.all(await app.config_path(obj_type(key).path, domain), cap=50_000)
            if not page.complete:
                problems.append(
                    f"FMC has more {key} objects than can be checked; sync fewer types at a time."
                )
            existing[key] = {str(o.get("name", "")).lower(): o for o in page.items}
        return existing[key]

    for n, row in enumerate(objects, 1):
        t = obj_type(row.type)
        fam = FAMILY.get(t.key, t.key)
        where = f"row {n} ({row.name!r})"
        low = row.name.lower()
        if (fam, low) in seen:
            problems.append(f"{where}: the name appears twice ({fam} objects share names).")
            continue
        seen.add((fam, low))
        row_type[(fam, low)] = t.key
        try:
            fields = value_fields(t, row.value, None)
        except InvalidRequest as e:
            problems.append(f"{where}: {e}")
            continue
        for g in row.groups or []:
            gkey = GROUP_OF[fam]
            entry = want_groups.setdefault((gkey, g.strip().lower()), {"name": g.strip(), "members": []})
            entry["members"].append(row.name)
        clash = None
        for key in FAMILY_TYPES.get(fam, [t.key]):
            hit = (await load(key)).get(low)
            if hit is not None:
                clash = (key, hit)
                break
        if clash is not None and clash[0] != t.key:
            problems.append(
                f"{where}: a {clash[0]} object has that name; sync can't change an object's type."
            )
            continue
        have = clash[1] if clash else None
        if have is None:
            body: dict[str, Any] = {"name": row.name, "type": t.fmc_type, **fields}
            if row.description:
                body["description"] = row.description
            creates.setdefault(t.key, []).append(body)
            rows.append({"row": n, "name": row.name, "type": t.key, "action": "create", "value": row.value})
            continue
        if is_system(have) or not _owned_here(have, here):
            problems.append(
                f"{where}: {have.get('name')!r} is read-only here (built-in or an ancestor's object)."
            )
            continue
        desired = _updated(t.key, have, fields, row.description)
        same = canon(t.key, have) == canon(t.key, fields) and (
            row.description is None or row.description == (have.get("description") or "")
        )
        if same:
            rows.append({"row": n, "name": row.name, "type": t.key, "action": "unchanged"})
            continue
        updates.append((t.key, have, desired))
        before = object_summary(have).get("value")
        rows.append(
            {
                "row": n,
                "name": row.name,
                "type": t.key,
                "action": "update",
                "value": row.value,
                "from": before,
            }
        )

    groups: list[dict[str, Any]] = []
    group_writes: list[tuple[str, dict[str, Any] | None, dict[str, Any]]] = []  # (key, current, plan)
    for (gkey, glow), info in want_groups.items():
        fam = next(f for f, k in GROUP_OF.items() if k == gkey)
        current = (await load(gkey)).get(glow)
        taken = [k for k in FAMILY_TYPES.get(fam, []) if (await load(k)).get(glow)]
        if taken:
            problems.append(f"group {info['name']!r}: a {fam} object already has that name.")
            continue
        members = list(dict.fromkeys(info["members"]))
        if current is None:
            groups.append({"group": info["name"], "type": gkey, "action": "create", "members": members})
            group_writes.append((gkey, None, {"name": info["name"], "add": members, "remove": []}))
            continue
        if is_system(current) or not _owned_here(current, here):
            problems.append(f"group {info['name']!r} is read-only here (built-in or an ancestor's object).")
            continue
        managed = [
            str(o.get("name")) for o in current.get("objects") or [] if o.get("type") in VALUE_MEMBERS[fam]
        ]
        add = [m for m in members if m.lower() not in {x.lower() for x in managed}]
        remove = [m for m in managed if m.lower() not in {x.lower() for x in members}]
        kept = [
            str(o.get("name"))
            for o in current.get("objects") or []
            if o.get("type") not in VALUE_MEMBERS[fam]
        ] + [str(lit.get("value")) for lit in current.get("literals") or []]
        grow: dict[str, Any] = {
            "group": info["name"],
            "type": gkey,
            "action": "update" if add or remove else "unchanged",
        }
        if add:
            grow["add"] = add
        if remove:
            grow["remove"] = remove
        if kept:
            grow["kept"] = kept
        groups.append(grow)
        if add or remove:
            group_writes.append((gkey, current, {"name": info["name"], "add": add, "remove": remove}))

    orphans: list[dict[str, Any]] = []
    if pre:
        listed = {(k, low) for (fam, low), k in row_type.items()} | set(want_groups)
        for key in sorted({k for k in row_type.values()} | {k for k, _ in want_groups}):
            for low, o in (await load(key)).items():
                if (
                    low.startswith(pre)
                    and (key, low) not in listed
                    and _owned_here(o, here)
                    and not is_system(o)
                ):
                    orphans.append({"object_type": key, **object_summary(o)})

    counts = {a: sum(1 for r in rows if r["action"] == a) for a in ("create", "update", "unchanged")}
    details: dict[str, Any] = {
        "mode": "sync",
        "summary": {
            **counts,
            "groups_changed": len(group_writes),
            "orphans": len(orphans) if pre else None,
            "problems": len(problems) or None,
        },
        "rows": rows[:ROWS_SHOWN],
    }
    if len(rows) > ROWS_SHOWN:
        details["rows_note"] = f"First {ROWS_SHOWN} of {len(rows)} rows shown; summary counts them all."
    if groups:
        details["groups"] = groups
    if pre:
        details["orphans"] = orphans[:ROWS_SHOWN] or None
        if orphans:
            details["orphans_next"] = (
                "fmc_delete_objects(names=[...]) deletes them in one preview (dangerous tier); sync never "
                "does."
            )
    else:
        details["orphans"] = "not checked: pass prefix (the names this list owns) to list orphans"
    if problems:
        details["problems"] = problems[:50]
    total = sum(len(v) for v in creates.values()) + len(updates) + len(group_writes)
    blockers = problems[:20] + (["...and more problems"] if len(problems) > 20 else [])
    if not total and not problems:
        blockers.append("Nothing to change: every row and group is already as listed.")
    fingerprint = {
        "objects": {
            f"{k}:{name}": editable(o)
            for k, objs in existing.items()
            for name, o in objs.items()
            if (FAMILY.get(k, k), name) in row_type or (k, name) in want_groups
        },
        "orphans": sorted(str(o.get("id")) for o in orphans),
    }

    async def apply() -> Any:
        done = {"created": 0, "updated": 0, "groups_created": 0, "groups_updated": 0}
        ids: dict[tuple[str, str], dict[str, Any]] = {}  # (type key, lower name) -> reference
        for key, objs in existing.items():
            for name, o in objs.items():
                ids[(key, name)] = ref_of(o)
        try:
            for key, items in creates.items():
                path = await app.config_path(obj_type(key).path, domain)
                for i in range(0, len(items), CHUNK):
                    chunk = items[i : i + CHUNK]
                    try:
                        resp = await app.api.post(path, chunk, params={"bulk": "true"})
                    except UpstreamError as e:
                        raise _sync_stopped(
                            done, f"the {key} chunk starting at {chunk[0]['name']!r}", e
                        ) from e
                    for o in (resp or {}).get("items") or [] if isinstance(resp, dict) else []:
                        if o.get("id") and o.get("name"):
                            ids[(key, str(o["name"]).lower())] = ref_of(o)
                    done["created"] += len(chunk)
            for key, current, desired in updates:
                path = await app.config_path(f"{obj_type(key).path}/{current['id']}", domain)
                try:
                    await app.api.put(path, desired)
                except UpstreamError as e:
                    raise _sync_stopped(done, f"{key} {current.get('name')!r}", e) from e
                done["updated"] += 1
            for gkey, gcur, change in group_writes:
                fam = next(f for f, k in GROUP_OF.items() if k == gkey)
                refs = []
                for m in change["add"]:
                    key = row_type[(fam, m.lower())]
                    if (key, m.lower()) not in ids:  # the bulk POST answer didn't carry it: read it back
                        page = await app.all(
                            await app.config_path(obj_type(key).path, domain), {"filter": f"nameOrValue:{m}"}
                        )
                        for o in page.items:
                            ids[(key, str(o.get("name", "")).lower())] = ref_of(o)
                    if (key, m.lower()) not in ids:
                        raise _sync_stopped(
                            done, f"group {change['name']!r}", UpstreamError(f"{m!r} not found")
                        )
                    refs.append(ids[(key, m.lower())])
                t = obj_type(gkey)
                try:
                    if gcur is None:
                        body = {"name": change["name"], "type": t.fmc_type, "objects": refs}
                        await app.api.post(await app.config_path(t.path, domain), body)
                        done["groups_created"] += 1
                        continue
                    gbody = editable(gcur)
                    drop = {x.lower() for x in change["remove"]}
                    keep = [
                        o for o in gbody.get("objects") or [] if str(o.get("name", "")).lower() not in drop
                    ]
                    gbody["objects"] = keep + refs
                    await app.api.put(await app.config_path(f"{t.path}/{gcur['id']}", domain), gbody)
                    done["groups_updated"] += 1
                except UpstreamError as e:
                    raise _sync_stopped(done, f"group {change['name']!r}", e) from e
        finally:
            app.invalidate_cache()
        return {**done, "unchanged": counts["unchanged"], "orphans": [o.get("name") for o in orphans] or None}

    plan = Plan(
        f"Sync {len(objects)} objects: {counts['create']} to create, {counts['update']} to update, "
        f"{len(group_writes)} group(s) to change",
        details=details,
        fingerprint=fingerprint,
        blockers=blockers,
        blast_radius=total,
    )
    return plan, apply


def _sync_stopped(done: dict[str, int], what: str, e: UpstreamError) -> UpstreamError:
    applied = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in done.items() if n) or "nothing"
    return UpstreamError(
        f"Sync stopped ({applied} done): {what} failed: {e}. Preview the same sync again to resume: rows "
        "already applied then show as unchanged.",
        getattr(e, "status_code", None),
    )
