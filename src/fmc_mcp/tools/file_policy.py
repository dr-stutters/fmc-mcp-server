"""File and malware policies (F43): read a file policy and its rules, create a policy, add or delete file
rules (detect, block, malware cloud lookup, block malware; by protocol, direction, file type and
category). A file policy acts on the traffic of the ALLOW access rules it is attached to
(fmc_create_access_rule / fmc_update_access_rule file_policy=...)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import difflib
from typing import Annotated, Any, Literal

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
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import all_rules

FILE_POLICIES = "policy/filepolicies"
FILE_TYPES = "object/filetypes"
FILE_CATEGORIES = "object/filecategories"
PolicyRef = Annotated[str, Field(description="File policy name or UUID (fmc_get_file_policy)")]

FileAction = Literal["DETECT", "BLOCK", "MALWARE_CLOUD_LOOKUP", "BLOCK_MALWARE"]
FileProtocol = Literal["ANY", "HTTP", "SMTP", "IMAP", "POP3", "FTP", "SMB"]
FileDirection = Literal["ANY", "UPLOAD", "DOWNLOAD"]
Disposition = Literal["MALWARE", "CUSTOM", "CLEAN", "UNKNOWN"]
Analysis = Literal["spero", "sandbox", "clamscan", "capacity"]

# Our action -> FMC's file rule action (without reset, with reset). FMC 10.0.1's spec lists DETECT,
# BLOCK_WITH_RESET, DETECT_MALWARE and BLOCK_MALWARE_WITH_RESET; its PUT example uses BLOCK.
FMC_ACTIONS: dict[str, tuple[str, str]] = {
    "DETECT": ("DETECT", "DETECT"),
    "BLOCK": ("BLOCK", "BLOCK_WITH_RESET"),
    "MALWARE_CLOUD_LOOKUP": ("DETECT_MALWARE", "DETECT_MALWARE"),
    "BLOCK_MALWARE": ("BLOCK_MALWARE", "BLOCK_MALWARE_WITH_RESET"),
}
ACTION_LABELS = {
    "DETECT": "detect files",
    "BLOCK": "block files",
    "BLOCK_WITH_RESET": "block files (reset)",
    "DETECT_MALWARE": "malware cloud lookup",
    "BLOCK_MALWARE": "block malware",
    "BLOCK_MALWARE_WITH_RESET": "block malware (reset)",
}
MALWARE_ACTIONS = {"MALWARE_CLOUD_LOOKUP", "BLOCK_MALWARE"}
# FMC inspects downloads on HTTP, IMAP, POP3, SMTP, FTP and SMB, uploads on HTTP, SMTP, FTP and SMB.
DOWNLOAD_ONLY = {"IMAP", "POP3"}
UPLOAD_ONLY = {"SMTP"}

SETTINGS = {
    "inspectArchives": "inspect_archives",
    "archiveDepth": "archive_depth",
    "blockEncryptedArchives": "block_encrypted_archives",
    "archiveDepthAction": "block_uninspectable_archives",
    "firstTimeFileAnalysis": "first_time_file_analysis",
    "threatScore": "threat_score",
    "cleanList": "clean_list",
    "customDetectionList": "custom_detection_list",
}


def rule_row(r: dict[str, Any], index: int | None = None) -> dict[str, Any]:
    """One file rule as a compact row (FMC file rules have no names; they are listed in FMC's order)."""
    action = str(r.get("action") or "")
    row: dict[str, Any] = {
        "index": index,
        "action": ACTION_LABELS.get(action, action.lower() or None),
        "fmc_action": action or None,
        "protocol": r.get("protocol"),
        "direction": r.get("direction"),
        "file_types": [ref_label(t) for t in r.get("fileTypes") or []] or None,
        "file_categories": [ref_label(c) for c in r.get("fileCategories") or []] or None,
        "analysis": r.get("analysis") or None,
        "store_files": r.get("storeFiles") or None,
        "description": r.get("description") or None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def settings_row(p: dict[str, Any]) -> dict[str, Any]:
    return {ours: p[fmc] for fmc, ours in SETTINGS.items() if p.get(fmc) is not None}


def usage_of(p: dict[str, Any]) -> Any:
    usage = (p.get("metadata") or {}).get("usage")
    return usage if usage else None


async def file_catalog(app: FmcApp, path: str, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(path, domain), expanded=path == FILE_CATEGORIES)
    return [i for i in page.items if i.get("id") and i.get("name")]


def pick_names(catalog: list[dict[str, Any]], names: list[str], what: str) -> list[dict[str, Any]]:
    """{id, type, name} references for file type or category names (case-insensitive, ids accepted)."""
    by_name = {str(i["name"]).lower(): i for i in catalog}
    by_id = {str(i["id"]): i for i in catalog}
    out: list[dict[str, Any]] = []
    for raw in dict.fromkeys(n.strip() for n in names if n.strip()):
        hit = by_name.get(raw.lower()) or by_id.get(raw)
        if hit is None:
            close = difflib.get_close_matches(raw.upper(), [str(i["name"]) for i in catalog], n=5, cutoff=0.5)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise NotFound(f"No {what} {raw!r}.{hint} fmc_get_file_policy(catalog=true) lists them.", 404)
        out.append({"id": str(hit["id"]), "type": hit.get("type"), "name": hit.get("name")})
    return out


async def resolve_file_policy(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, FILE_POLICIES, ref, "file policy", domain)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="File policies")
    async def fmc_get_file_policy(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="File policy name or UUID; omit to list all file policies")
        ] = None,
        catalog: Annotated[
            bool,
            Field(
                description="List the file categories and the file types in each instead (the names "
                "fmc_create_file_rule takes, e.g. MSEXE, PDF, ZIP, EICAR)"
            ),
        ] = False,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List file (and malware) policies, or show one: its archive and analysis settings and its file
        rules (protocol, direction, file types and categories, action: detect, block, malware cloud lookup
        or block malware). Use it before adding file rules, or to see what an access rule's file policy
        blocks. With catalog=true it lists the file categories and types to use in rules. Build one with
        fmc_create_file_policy + fmc_create_file_rule; which ALLOW rules lack one: fmc_threat_posture."""
        app: FmcApp = get_client(ctx)
        if catalog:
            cats = await file_catalog(app, FILE_CATEGORIES, domain)
            rows = [
                {"category": c.get("name"), "file_types": [ref_label(t) for t in c.get("fileTypes") or []]}
                for c in cats
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        if not policy:
            page = await app.all(await app.config_path(FILE_POLICIES, domain))
            rows = [
                {
                    "name": p.get("name"),
                    **({"description": p["description"]} if p.get("description") else {}),
                    **settings_row(p),
                    "id": p.get("id"),
                }
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_file_policy(app, policy, domain)
        rules = await all_rules(app, await app.config_path(f"{FILE_POLICIES}/{p['id']}/filerules", domain))
        out: dict[str, Any] = {
            "name": p.get("name"),
            "description": p.get("description") or None,
            "settings": settings_row(p) or None,
            "rules": [rule_row(r, i) for i, r in enumerate(rules.items, 1)],
            "used_by": usage_of(p),
            "domain": ((p.get("metadata") or {}).get("domain") or {}).get("name"),
            "id": p.get("id"),
        }
        if not rules.items:
            out["note"] = "No file rules yet: add them with fmc_create_file_rule."
        return object_result({k: v for k, v in out.items() if v is not None}, fmt=response_format)

    @reg.write(title="Create file policy")
    async def fmc_create_file_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New file policy name")],
        description: Annotated[str | None, Field(description="Description")] = None,
        inspect_archives: Annotated[
            bool | None, Field(description="Inspect the files inside archives (zip, rar, ...)")
        ] = None,
        archive_depth: Annotated[
            int | None, Field(ge=1, le=3, description="Nested archive levels to inspect (1-3)")
        ] = None,
        block_encrypted_archives: Annotated[
            bool | None, Field(description="Block archives the device can't open because they are encrypted")
        ] = None,
        block_uninspectable_archives: Annotated[
            bool | None,
            Field(description="Block archives that can't be inspected for other reasons (too deep, corrupt)"),
        ] = None,
        first_time_file_analysis: Annotated[
            bool | None,
            Field(description="Send a file for analysis the first time it is seen (malware cloud lookup)"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty file (and malware) policy. Settings left out keep FMC's defaults. Then add
        rules with fmc_create_file_rule and attach the policy to ALLOW access rules
        (fmc_update_access_rule file_policy=...); it acts on traffic after the next deploy."""
        app: FmcApp = get_client(ctx)
        if not inspect_archives and (
            archive_depth is not None or block_encrypted_archives or block_uninspectable_archives
        ):
            raise InvalidRequest("Archive settings need inspect_archives=true.")
        blockers = []
        try:
            await resolve_file_policy(app, name, domain)
            blockers.append(f"A file policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {"name": name, "type": "FilePolicy"}
        if description:
            body["description"] = description
        given = {
            "inspectArchives": inspect_archives,
            "archiveDepth": archive_depth,
            "blockEncryptedArchives": block_encrypted_archives,
            "archiveDepthAction": block_uninspectable_archives,
            "firstTimeFileAnalysis": first_time_file_analysis,
        }
        body.update({k: v for k, v in given.items() if v is not None})
        path = await app.config_path(FILE_POLICIES, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_file_policy",
            args={
                "name": name,
                "description": description,
                "inspect_archives": inspect_archives,
                "archive_depth": archive_depth,
                "block_encrypted_archives": block_encrypted_archives,
                "block_uninspectable_archives": block_uninspectable_archives,
                "first_time_file_analysis": first_time_file_analysis,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create file policy {name!r}",
                details={"body": body},
                blockers=blockers,
                side_effects=["No effect until an ALLOW access rule uses it and the devices are deployed."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Create file rule")
    async def fmc_create_file_rule(
        ctx: Context,
        policy: PolicyRef,
        action: Annotated[
            FileAction,
            Field(
                description="DETECT logs matching files; BLOCK blocks them; MALWARE_CLOUD_LOOKUP checks each "
                "file's SHA-256 against the Secure Malware Analytics cloud and logs the disposition; "
                "BLOCK_MALWARE blocks files the cloud (or local analysis) calls malware. Malware actions "
                "need the MALWARE_DEFENSE licence and FMC cloud access"
            ),
        ],
        file_types: Annotated[
            list[str] | None,
            Field(description="File type names, e.g. ['MSEXE', 'EICAR'] (fmc_get_file_policy catalog=true)"),
        ] = None,
        file_categories: Annotated[
            list[str] | None,
            Field(description="File category names, e.g. ['Executables', 'Archive']: every type in them"),
        ] = None,
        protocol: Annotated[
            FileProtocol, Field(description="Application protocol the file travels over (SMB = NetBIOS-ssn)")
        ] = "ANY",
        direction: Annotated[
            FileDirection,
            Field(
                description="Transfer direction: DOWNLOAD (to the client), UPLOAD (from the client) or ANY"
            ),
        ] = "ANY",
        reset: Annotated[
            bool,
            Field(
                description="BLOCK / BLOCK_MALWARE: reset the connection after blocking (the client sees "
                "the transfer fail at once instead of timing out)"
            ),
        ] = True,
        store_files: Annotated[
            list[Disposition] | None,
            Field(description="Malware actions: keep files with these dispositions on the device"),
        ] = None,
        analysis: Annotated[
            list[Analysis] | None,
            Field(
                description="Malware actions: extra analysis (spero = Spero for MSEXE, sandbox = dynamic "
                "analysis, clamscan = local malware analysis, capacity = capacity handling)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a file rule to a file policy, e.g. block .exe downloads over HTTP (action BLOCK,
        file_types ['MSEXE'], protocol HTTP, direction DOWNLOAD) or look up every executable in the
        malware cloud. When several rules match a file, FMC applies the strictest action (block, then
        block malware, then malware cloud lookup, then detect), not the rule order. File type and category
        names: fmc_get_file_policy(catalog=true). Takes effect on devices whose ALLOW access rules use the
        policy (fmc_update_access_rule file_policy=...) after the next deploy."""
        app: FmcApp = get_client(ctx)
        if not (file_types or file_categories):
            raise InvalidRequest("Give file_types and/or file_categories (fmc_get_file_policy catalog=true).")
        if (store_files or analysis) and action not in MALWARE_ACTIONS:
            raise InvalidRequest(
                "store_files and analysis only apply to MALWARE_CLOUD_LOOKUP and BLOCK_MALWARE."
            )
        p = await resolve_file_policy(app, policy, domain)
        types = pick_names(await file_catalog(app, FILE_TYPES, domain), file_types or [], "file type")
        cats = pick_names(
            await file_catalog(app, FILE_CATEGORIES, domain), file_categories or [], "file category"
        )
        fmc_action = FMC_ACTIONS[action][1 if reset else 0]
        body: dict[str, Any] = {
            "type": "FileRule",
            "action": fmc_action,
            "protocol": protocol,
            "direction": direction,
        }
        if types:
            body["fileTypes"] = types
        if cats:
            body["fileCategories"] = cats
        if store_files:
            body["storeFiles"] = list(dict.fromkeys(store_files))
        if analysis:
            body["analysis"] = list(dict.fromkeys(analysis))
        blockers: list[str] = []
        if protocol in DOWNLOAD_ONLY and direction == "UPLOAD":
            blockers.append(f"FMC inspects {protocol} only for downloads; use direction DOWNLOAD or ANY.")
        if protocol in UPLOAD_ONLY and direction == "DOWNLOAD":
            blockers.append(f"FMC inspects {protocol} only for uploads; use direction UPLOAD or ANY.")
        base = await app.config_path(f"{FILE_POLICIES}/{p['id']}/filerules", domain)
        existing = await all_rules(app, base)

        def key(r: dict[str, Any]) -> tuple[Any, ...]:
            return (
                r.get("action"),
                r.get("protocol"),
                r.get("direction"),
                sorted(str(t.get("id")) for t in r.get("fileTypes") or []),
                sorted(str(c.get("id")) for c in r.get("fileCategories") or []),
            )

        same = [i for i, r in enumerate(existing.items, 1) if key(r) == key(body)]
        if same:
            blockers.append(f"Rule {same[0]} of {p.get('name')!r} already does exactly this.")
        side = ["Takes effect on devices after the next deployment (only on ALLOW rules using the policy)."]
        if action in MALWARE_ACTIONS:
            side.append(
                "Malware dispositions come from the Secure Malware Analytics cloud: the devices need the "
                "MALWARE_DEFENSE licence (fmc_set_device_licenses) and FMC needs cloud access."
            )
        return await fmc_preview(
            ctx,
            tool="fmc_create_file_rule",
            args={
                "policy": policy,
                "action": action,
                "file_types": file_types,
                "file_categories": file_categories,
                "protocol": protocol,
                "direction": direction,
                "reset": reset,
                "store_files": store_files,
                "analysis": analysis,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add a {ACTION_LABELS[fmc_action]} rule to file policy {p.get('name')!r}",
                details={"rule": rule_row(body), "rules_now": len(existing.items), "body": body},
                fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items]},
                blockers=blockers,
                side_effects=side,
            ),
            apply=lambda: applied(app, lambda: app.api.post(base, body)),
        )

    @reg.write(title="Delete file rule", destructive=True)
    async def fmc_delete_file_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[
            str, Field(description="1-based rule index (as fmc_get_file_policy lists it) or the rule's id")
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one file rule from a file policy (after the next deploy those files pass uninspected
        unless another rule matches). Deleting the whole policy: fmc_delete_policy kind='file' (it must
        not be used by an access rule)."""
        app: FmcApp = get_client(ctx)
        p = await resolve_file_policy(app, policy, domain)
        base = await app.config_path(f"{FILE_POLICIES}/{p['id']}/filerules", domain)
        rules = await all_rules(app, base)
        ref = rule.strip()
        hits = [(i, r) for i, r in enumerate(rules.items, 1) if str(r.get("id")) == ref]
        if not hits and ref.isdigit() and 1 <= int(ref) <= len(rules.items):
            hits = [(int(ref), rules.items[int(ref) - 1])]
        if len(hits) != 1:
            raise NotFound(
                f"No file rule {rule!r} in {p.get('name')!r} "
                f"({len(rules.items)} rules; fmc_get_file_policy lists them).",
                404,
            )
        index, r = hits[0]
        return await fmc_preview(
            ctx,
            tool="fmc_delete_file_rule",
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete file rule {index} ({ACTION_LABELS.get(str(r.get('action')), r.get('action'))}) "
                f"from {p.get('name')!r}",
                details={"rule": rule_row(r, index)},
                # the rule itself and the order: an index points at another rule once the list changes
                fingerprint={"rule": r.get("id"), "order": [x.get("id") for x in rules.items]},
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(f"{base}/{r['id']}")),
        )
