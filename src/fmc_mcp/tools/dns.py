"""DNS policy (F13, slice 3): read DNS policies, block or unblock domains through a DNS policy rule (each
domain becomes a one-entry custom Security Intelligence DNS list), and link a DNS policy to an access
control policy's Security Intelligence."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import hashlib
import re
from typing import Annotated, Any, Literal

import httpx
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, block_labels, resolve_in
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, all_rules

DNS = "policy/dnspolicies"
LISTS = "object/customsidnslists"
RULE = "mcp-dns-block"
PREFIX = "mcp-dns-"
DOMAIN_RE = re.compile(
    r"(?=.{1,253})(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
)
MARKER = ".fmc-mcp.txt"  # file name of the lists this tool uploads (FMC keeps no description for them)
PolicyRef = Annotated[str, Field(description="DNS policy name or UUID (fmc_get_dns_policy)")]


def list_name(domain: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9.-]+", "_", domain)
    if len(clean) <= 50 and clean == domain:
        return PREFIX + clean
    return f"{PREFIX}{clean[:41]}-{hashlib.sha1(domain.encode(), usedforsecurity=False).hexdigest()[:8]}"


def rule_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row = {
        "index": meta.get("ruleIndex"),
        "name": r.get("name"),
        "action": r.get("action"),
        "enabled": r.get("enabled"),
        "dns_lists": block_labels(r.get("dnsLists")) or None,
        "dns_feeds": block_labels(r.get("dnsFeeds")) or None,
        "zones": [z.get("name") for z in r.get("sourceZones") or []] or None,
        "networks": block_labels(r.get("networks")) or None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def upload_list(app: FmcApp, path: str, name: str, domain_name: str) -> dict[str, Any]:
    """Create a custom SI DNS list holding one domain (FMC takes these as a multipart file upload)."""
    req = httpx.Request(
        "POST",
        "http://upload/",
        files={
            "name": (None, name),
            "payloadFile": (f"{name}{MARKER}", f"{domain_name}\n".encode(), "text/plain"),
        },
    )
    content = req.read()
    out: dict[str, Any] = await app.api.request(
        "POST", path, content=content, headers={"Content-Type": req.headers["content-type"]}
    )
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="DNS policies")
    async def fmc_get_dns_policy(
        ctx: Context,
        policy: Annotated[str | None, Field(description="DNS policy name or UUID; omit to list them")] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List DNS policies, or show one with its rules in order (action ALLOW / NXDOMAIN / DROP /
        SINKHOLE / MONITOR, the DNS lists and feeds they match, zones and networks). Access policies use a
        DNS policy through their Security Intelligence settings (fmc_get_security_intelligence)."""
        app: FmcApp = get_client(ctx)
        if not policy:
            page = await app.all(await app.config_path(DNS, domain))
            rows = [
                {"name": p.get("name"), "description": p.get("description"), "id": p.get("id")}
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_in(app, DNS, policy, "DNS policy", domain)
        rules = await all_rules(app, await app.config_path(f"{DNS}/{p['id']}/dnsrules", domain))
        return object_result(
            {"name": p.get("name"), "rules": [rule_row(r) for r in rules.items], "id": p.get("id")},
            fmt=response_format,
        )

    @reg.write(title="Create DNS policy")
    async def fmc_create_dns_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New DNS policy name")],
        description: Annotated[str | None, Field(max_length=200, description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a DNS policy (FMC adds its default allow/block rules). Link it to an access policy with
        fmc_set_dns_policy, then block domains with fmc_dns_block."""
        app: FmcApp = get_client(ctx)
        blockers = []
        try:
            await resolve_in(app, DNS, name, "DNS policy", domain)
            blockers.append(f"A DNS policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {"name": name, "type": "DNSPolicy"}
        if description:
            body["description"] = description
        path = await app.config_path(DNS, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_dns_policy",
            args={"name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(f"Create DNS policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Link DNS policy to access policy")
    async def fmc_set_dns_policy(
        ctx: Context,
        access_policy: Annotated[str, Field(description="Access control policy name or UUID")],
        dns_policy: PolicyRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access control policy's Security Intelligence use a DNS policy. Takes effect on the next
        deploy."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, access_policy, "access policy", domain)
        target = await resolve_in(app, DNS, dns_policy, "DNS policy", domain)
        base = await app.config_path(f"{ACCESS}/{acp['id']}/securityintelligencepolicies", domain)
        page = await app.all(base)
        if not page.items:
            raise InvalidRequest(f"{acp.get('name')!r} has no Security Intelligence settings.")
        si = await app.api.get(f"{base}/{page.items[0]['id']}")
        now = si.get("dnsPolicy") or {}
        path = f"{base}/{si['id']}"

        async def apply() -> Any:
            body = editable(await app.api.get(path))
            dns = dict(body.get("dnsPolicy") or {})
            dns.update({"id": target["id"], "type": "DNSPolicy", "name": target.get("name")})
            dns.pop("links", None)
            body["dnsPolicy"] = dns
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_set_dns_policy",
            args={"access_policy": access_policy, "dns_policy": dns_policy, "domain": domain},
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"{acp.get('name')!r} uses DNS policy {target.get('name')!r}",
                details={"from": now.get("name"), "to": target.get("name")},
                fingerprint={"current": now.get("id"), "target": target["id"]},
                blockers=["Nothing to change."] if now.get("id") == target["id"] else [],
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Block or unblock domains (DNS)")
    async def fmc_dns_block(
        ctx: Context,
        policy: PolicyRef,
        domains: Annotated[
            list[str],
            Field(min_length=1, max_length=50, description="Domains, e.g. bad.example.com or *.evil.test"),
        ],
        action: Annotated[
            Literal["block", "unblock"], Field(description="Add to or remove from the block rule")
        ] = "block",
        mode: Annotated[
            Literal["NXDOMAIN", "DROP"],
            Field(description="How a blocked lookup is answered: NXDOMAIN or silently dropped"),
        ] = "NXDOMAIN",
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Block DNS lookups of domains for every device whose access policy uses this DNS policy: each domain
        becomes a custom Security Intelligence DNS list mcp-dns-<domain> in the rule 'mcp-dns-block' (added
        after FMC's Global do-not-block / block rules on first use). Unblock removes them (and the rule
        when it is empty). Needs a deployment; the FTD then answers the lookups itself."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DNS, policy, "DNS policy", domain)
        wanted = []
        for d in dict.fromkeys(x.strip().lower().rstrip(".") for x in domains):
            if len(d) > 253 or not DOMAIN_RE.fullmatch(d):
                raise InvalidRequest(f"{d!r} is not a domain name.")
            wanted.append(d)
        rules_path = await app.config_path(f"{DNS}/{p['id']}/dnsrules", domain)
        lists_path = await app.config_path(LISTS, domain)
        rules = await all_rules(app, rules_path)
        rule = next((r for r in rules.items if r.get("name") == RULE), None)
        in_rule = {str(o.get("name")) for o in ((rule or {}).get("dnsLists") or {}).get("objects") or []}
        todo = [d for d in wanted if (list_name(d) in in_rule) == (action == "unblock")]
        blockers = [] if todo else ["Nothing to change."]
        if rule and action == "block" and rule.get("action") != mode:
            blockers.append(
                f"The rule {RULE!r} answers with {rule.get('action')}; use mode={rule.get('action')}."
            )
        if rule and (
            (rule.get("dnsFeeds") or {}).get("objects")
            or rule.get("sourceZones")
            or (rule.get("networks") or {}).get("objects")
            or (rule.get("networks") or {}).get("literals")
        ):
            blockers.append(
                f"The rule {RULE!r} has other match criteria (feeds, zones, networks); rename it."
            )
        existing_lists = {str(o.get("name")): o for o in (await app.all(lists_path)).items}
        foreign = [
            list_name(d)
            for d in todo
            if list_name(d) in existing_lists
            and not str(existing_lists[list_name(d)].get("fileName", "")).endswith(MARKER)
        ]
        if foreign and action == "block":
            blockers.append(
                f"DNS lists {', '.join(foreign)} exist but were not made by this tool; rename them."
            )

        async def apply() -> Any:
            created: list[str] = []
            kept_lists: list[str] = []
            refs: list[dict[str, Any]] = []
            body: dict[str, Any]
            result: Any
            current = await app.api.get(f"{rules_path}/{rule['id']}") if rule else None
            try:
                if action == "block":
                    have_now = {str(o.get("name")): o for o in (await app.all(lists_path)).items}
                    for d in todo:
                        name = list_name(d)
                        obj = have_now.get(name)
                        if obj is not None and not str(obj.get("fileName", "")).endswith(MARKER):
                            raise InvalidRequest(
                                f"DNS list {name!r} was not made by this tool; nothing changed."
                            )
                        if obj is None:
                            obj = await upload_list(app, lists_path, name, d)
                            if not isinstance(obj, dict) or not obj.get("id"):
                                raise UpstreamError(f"FMC returned no id for the uploaded DNS list {name!r}.")
                            created.append(obj["id"])
                        refs.append(
                            {"id": obj["id"], "type": obj.get("type", "CustomSIDNSListObject"), "name": name}
                        )
                    if current is None:
                        body = {
                            "name": RULE,
                            "type": "DNSRule",
                            "action": mode,
                            "enabled": True,
                            "dnsLists": {"objects": refs},
                        }
                        result = await app.api.post(rules_path, body)
                    else:
                        body = editable(current)
                        objs = (body.get("dnsLists") or {}).get("objects") or []
                        have_ids = {o.get("id") for o in objs}
                        body["dnsLists"] = {"objects": objs + [r for r in refs if r["id"] not in have_ids]}
                        result = await app.api.put(f"{rules_path}/{current['id']}", body)
                else:
                    if current is None:
                        raise InvalidRequest(f"The rule {RULE!r} is gone; nothing to unblock.")
                    names = {list_name(d) for d in todo}
                    body = editable(current)
                    objs = (body.get("dnsLists") or {}).get("objects") or []
                    keep = [o for o in objs if o.get("name") not in names]
                    if keep or (body.get("dnsFeeds") or {}).get("objects"):
                        body["dnsLists"] = {"objects": keep}
                        result = await app.api.put(f"{rules_path}/{current['id']}", body)
                    else:
                        result = await app.api.delete(f"{rules_path}/{current['id']}")
                    kept_lists = []
                    for o in objs:
                        if o.get("name") in names:
                            mine = str((existing_lists.get(str(o.get("name"))) or {}).get("fileName", ""))
                            try:
                                if not mine.endswith(MARKER):
                                    raise UpstreamError("not made by this tool")
                                await app.api.delete(f"{lists_path}/{o['id']}")
                            except UpstreamError:
                                kept_lists.append(str(o.get("name")))
            except BaseException:
                for oid in created:  # don't leave lists we just uploaded behind
                    with contextlib.suppress(UpstreamError):
                        await app.api.delete(f"{lists_path}/{oid}")
                raise
            finally:
                app.invalidate_cache()
            return {
                "policy": p.get("name"),
                "lists_kept": (kept_lists or None) if action == "unblock" else None,
                "rule": rule_row(result) if isinstance(result, dict) and result.get("name") else None,
                "next": "fmc_deploy to the devices whose access policy uses this DNS policy",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_dns_block",
            args={"policy": policy, "domains": domains, "action": action, "mode": mode, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"DNS {action} {len(todo)} domain(s) in {p.get('name')!r}",
                details={
                    "domains": todo,
                    "unchanged": [d for d in wanted if d not in todo] or None,
                    "rule": RULE
                    + (
                        " (created after FMC's Global allow/block rules)"
                        if rule is None and action == "block"
                        else ""
                    ),
                    "mode": mode if action == "block" else None,
                },
                fingerprint={"rule": (rule or {}).get("id"), "lists": sorted(in_rule)},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )
