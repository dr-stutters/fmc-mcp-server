"""Bulk object import (F25): many value objects at once, validated in the preview and posted with FMC's
bulk API per type in chunks."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field
from stutters_mcp_core import Confirm, InvalidRequest, Plan, ToolRegistrar, UpstreamError, get_client

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, obj_type
from fmc_mcp.tools.object_writes import value_fields

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
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create many host, network, range, FQDN, port and URL objects in one go (migrations, onboarding).
        The preview validates every value and checks each name against FMC: an existing name with a
        different value is a problem; with the same value it is skipped when skip_existing is set. Posted
        with FMC's bulk API per type, 200 per request."""
        app: FmcApp = get_client(ctx)
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
            args={
                "objects": [o.model_dump(exclude_none=True) for o in objects],
                "skip_existing": skip_existing,
                "domain": domain,
            },
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
