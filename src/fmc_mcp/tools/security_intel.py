"""Security Intelligence (F21): read an access policy's SI block/allow lists and block or unblock IPs,
networks and URLs through them (SI drops before access rules and Snort, and logs SI events)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import hashlib
import ipaddress
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, resolve_in
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS

PREFIX = "mcp-si-"
PolicyRef = Annotated[str, Field(description="Access control policy name or UUID")]


MARKER = "Security Intelligence block (fmc_si_block)"


def _entry_name(value: str) -> str:
    """mcp-si-<value>; when the value had to be shortened or changed to fit an FMC name, a short hash of
    it keeps names unique."""
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    if clean == value and len(clean) <= 56:
        return PREFIX + clean
    return f"{PREFIX}{clean[:47]}-{hashlib.sha1(value.encode()).hexdigest()[:8]}"


def classify(value: str) -> tuple[str, str]:
    """('host'|'network'|'url', normalised value) for an IPv4/IPv6 address, CIDR or URL/domain."""
    v = value.strip()
    try:
        net = ipaddress.ip_network(v, strict=True)
    except ValueError as e:
        if "has host bits set" in str(e):
            raise InvalidRequest(
                f"{value!r} has host bits set; give the network ({ipaddress.ip_network(v, strict=False)})."
            ) from None
        net = None
    if net is not None:
        if net.prefixlen == 0 or net.is_loopback or net.is_multicast or net.is_unspecified:
            raise InvalidRequest(
                f"Refusing to Security-Intelligence-block {value!r} (default route, loopback or multicast)."
            )
        if net.prefixlen == net.max_prefixlen:
            return "host", str(net.network_address)
        return "network", str(net)
    if re.match(r"^(https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(/\S*)?$", v):
        return "url", v
    raise InvalidRequest(f"{value!r} is not an IP address, CIDR or URL/domain.")


def _si_rows(si: dict[str, Any]) -> dict[str, Any]:
    def names(block: list[dict[str, Any]] | None, key: str) -> list[str]:
        return [str((e.get(key) or {}).get("name")) for e in (block or [])]

    nets, urls = si.get("networks") or {}, si.get("urls") or {}
    return {
        "network_block": names(nets.get("blocklist"), "network"),
        "network_allow": names(nets.get("allowlist"), "network"),
        "url_block": names(urls.get("blocklist"), "url"),
        "url_allow": names(urls.get("allowlist"), "url"),
        "dns_policy": (si.get("dnsPolicy") or {}).get("name"),
        "logging": (nets.get("blocklistLogging") or {}).get("enableLogging"),
    }


async def _si_policy(app: FmcApp, acp: dict[str, Any], domain: str | None) -> tuple[str, dict[str, Any]]:
    base = await app.config_path(f"{ACCESS}/{acp['id']}/securityintelligencepolicies", domain)
    page = await app.all(base)
    if not page.items:
        raise InvalidRequest(f"{acp.get('name')!r} has no Security Intelligence settings.")
    si = page.items[0]
    return f"{base}/{si['id']}", si


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Security Intelligence settings")
    async def fmc_get_security_intelligence(
        ctx: Context, policy: PolicyRef, domain: Domain = None, response_format: ResponseFormat = "markdown"
    ) -> ToolResult:
        """Show an access policy's Security Intelligence: the network and URL block lists and do-not-block
        lists (Global lists, Talos feeds, custom lists and objects added by fmc_si_block), the DNS policy
        and whether blocks are logged."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
        _, si = await _si_policy(app, acp, domain)
        return object_result({"policy": acp.get("name"), **_si_rows(si)}, fmt=response_format)

    @reg.write(title="Security Intelligence block/unblock")
    async def fmc_si_block(
        ctx: Context,
        policy: PolicyRef,
        entries: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=50,
                description="IPs, CIDRs or URLs/domains to block (e.g. 203.0.113.7, 198.51.100.0/24, "
                "bad.example.com)",
            ),
        ],
        action: Annotated[
            Literal["block", "unblock"], Field(description="Add to or remove from the block list")
        ] = "block",
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Block (or unblock) IPs, networks or URLs with the access policy's Security Intelligence block
        list: SI drops matching traffic before any access rule and logs it as a Security Intelligence event.
        Each entry becomes an object named mcp-si-<value> in the block list (deleted on unblock unless used
        elsewhere). Host bits, /0, loopback and multicast are refused.
        Needs a deployment. For an instant, no-deploy block of a single host use fmc_contain_host."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
        path, si = await _si_policy(app, acp, domain)
        wanted: dict[tuple[str, str], str] = {}
        for e in entries:
            wanted.setdefault(classify(e), e)  # '1.2.3.4' and '1.2.3.4/32' are one entry

        def names_in(si_obj: dict[str, Any]) -> set[str]:
            nets = (si_obj.get("networks") or {}).get("blocklist") or []
            urls = (si_obj.get("urls") or {}).get("blocklist") or []
            return {str((x.get("network") or {}).get("name")) for x in nets} | {
                str((x.get("url") or {}).get("name")) for x in urls
            }

        listed = names_in(si)
        todo = [
            (e, kind, v)
            for (kind, v), e in wanted.items()
            if (_entry_name(v) in listed) == (action == "unblock")
        ]
        done_names = {_entry_name(v) for _, _, v in todo}
        skipped = [e for (_, v), e in wanted.items() if _entry_name(v) not in done_names]
        blockers = (
            []
            if todo
            else [
                "Nothing to change: "
                + ("already blocked." if action == "block" else "none of these is blocked by fmc_si_block.")
            ]
        )
        paths = {
            "host": await app.config_path("object/hosts", domain),
            "network": await app.config_path("object/networks", domain),
            "url": await app.config_path("object/urls", domain),
        }

        created: list[tuple[str, str]] = []

        async def ensure_object(kind: str, value: str, entry: str) -> dict[str, Any]:
            name = _entry_name(value)
            found = await app.api.get(paths[kind], {"filter": f"nameOrValue:{name}", "expanded": "true"})
            for o in (found or {}).get("items", []):
                if o.get("name") == name:
                    have = o.get("url") if kind == "url" else o.get("value")
                    if str(have) != value:
                        raise InvalidRequest(
                            f"An object {name!r} exists with value {have!r}, not {value!r}; rename it."
                        )
                    return {"id": o["id"], "type": o["type"], "name": name}
            body: dict[str, Any] = {"name": name, "description": f"{MARKER}: {entry}"}
            if kind == "url":
                body.update(type="Url", url=value)
            else:
                body.update(type="Host" if kind == "host" else "Network", value=value)
            o = await app.api.post(paths[kind], body)
            created.append((kind, o["id"]))
            return {"id": o["id"], "type": o["type"], "name": name}

        def kind_of(ref: dict[str, Any]) -> str:
            return {"Url": "url", "Host": "host"}.get(str(ref.get("type")), "network")

        async def apply() -> Any:
            fresh = await app.api.get(path)
            body = editable(fresh)
            now = names_in(fresh)
            removed: list[dict[str, Any]] = []
            for entry, kind, value in todo:
                name = _entry_name(value)
                key, section = ("url", "urls") if kind == "url" else ("network", "networks")
                block = body.get(section) or {}
                body[section] = block
                lst = block.get("blocklist") or []
                block["blocklist"] = lst
                if action == "block":
                    if name not in now:  # someone may have added it since the preview
                        lst.append({key: await ensure_object(kind, value, entry)})
                else:
                    removed += [x[key] for x in lst if (x.get(key) or {}).get("name") == name]
                    lst[:] = [x for x in lst if (x.get(key) or {}).get("name") != name]
            try:
                result = await applied(app, lambda: app.api.put(path, body))
            except UpstreamError:
                for kind, oid in created:  # don't leave the objects we just made behind
                    with contextlib.suppress(UpstreamError):
                        await app.api.delete(f"{paths[kind]}/{oid}")
                raise
            for ref in removed:  # delete our helper objects (marker in the description), if unused elsewhere
                with contextlib.suppress(UpstreamError):
                    obj = await app.api.get(f"{paths[kind_of(ref)]}/{ref['id']}")
                    if str(obj.get("description", "")).startswith(MARKER):
                        await app.api.delete(f"{paths[kind_of(ref)]}/{ref['id']}")
            return {
                "policy": acp.get("name"),
                "si": _si_rows(result if isinstance(result, dict) else body),
                "next": "fmc_deploy to the devices using the policy",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_si_block",
            args={"policy": policy, "entries": entries, "action": action, "domain": domain},
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"Security Intelligence {action}: {len(todo)} entries in {acp.get('name')!r}",
                details={
                    "entries": [
                        {"entry": e, "kind": k, "value": v, "object": _entry_name(v)} for e, k, v in todo
                    ],
                    "unchanged": skipped or None,
                    "deploy_needed": True,
                },
                fingerprint=sorted(listed),
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment (fmc_deploy)."],
            ),
            apply=apply,
        )
