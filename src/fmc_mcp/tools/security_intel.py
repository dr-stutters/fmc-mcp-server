"""Security Intelligence (F21, F61): read an access policy's SI block/allow lists with the status of every
threat feed and custom list it uses, block or unblock IPs, networks and URLs (fmc_si_block), create SI
feeds and upload custom lists (IP, URL, DNS), put feeds and lists (Talos categories too) in an access
policy's SI or its DNS policy, and delete them. SI drops before access rules and Snort, and logs SI events."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import contextlib
import difflib
import hashlib
import ipaddress
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

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
)
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, is_system, resolve_in
from fmc_mcp.tools.dns import DNS, DOMAIN_RE, dns_policy_name, inherited_blockers, upload_file
from fmc_mcp.tools.dns import MARKER as DNS_BLOCK_MARKER
from fmc_mcp.tools.dns import rule_row as dns_rule_row
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, all_rules
from fmc_mcp.tools.render import object_reply

PREFIX = "mcp-si-"
PolicyRef = Annotated[str, Field(description="Access control policy name or UUID")]


MARKER = "Security Intelligence block (fmc_si_block)"

# --- F61: feeds and custom lists ---------------------------------------------------------------

Kind = Literal["ip", "url", "dns"]
KINDS: tuple[str, ...] = ("ip", "url", "dns")
LABEL = {"ip": "network", "url": "URL", "dns": "DNS"}
FEEDS = {"ip": "object/sinetworkfeeds", "url": "object/siurlfeeds", "dns": "object/sidnsfeeds"}
FEED_TYPE = {"ip": "SINetworkFeed", "url": "SIURLFeed", "dns": "SIDNSFeed"}
CUSTOM = {"ip": "object/customsiiplists", "url": "object/customsiurllists", "dns": "object/customsidnslists"}
# Every SI list FMC offers (Talos categories, Global/Domain block and do-not-block lists). Never read
# expanded: a Talos category carries tens of thousands of entries.
CATALOG = {"ip": "object/sinetworklists", "url": "object/siurllists", "dns": "object/sidnslists"}
SI_MARKER = ".fmc-mcp-si.txt"  # file name suffix of the lists fmc_upload_si_list uploads
SECTION = {"ip": ("networks", "network"), "url": ("urls", "url")}
WHICH = {"block": "blocklist", "allow": "allowlist"}
DNS_RULE = {"block": "mcp-si-dns-block", "allow": "mcp-si-dns-allow", "monitor": "mcp-si-dns-monitor"}
MAX_LIST_ENTRIES = 5000
POLICY_SCAN_CAP = 50
MONITOR_GAP = (
    "FMC 10.0.1's REST API has no monitor-only flag for network or URL Security Intelligence (a list "
    "entry carries only the list and an optional zone). Set monitor-only in the access policy editor "
    "(Security Intelligence, right-click the entry > Monitor-only), or monitor with a DNS feed or list "
    "(list_type='monitor' adds it to a MONITOR rule of the access policy's DNS policy)."
)
KindArg = Annotated[
    Kind,
    Field(
        description="ip (networks and addresses), url (URLs and domains in HTTP) or dns (domains in "
        "DNS lookups)"
    ),
]


def _norm(name: str) -> str:
    """FMC shows 'Global Block List' in an access policy and 'Global-Block-List' as the object."""
    return re.sub(r"[\s_-]+", "-", name.strip().lower())


def _epoch(ts: Any) -> float | None:
    if not isinstance(ts, int | float) or isinstance(ts, bool) or ts <= 0:
        return None
    return ts / 1000 if ts > 1e12 else float(ts)  # FMC mixes seconds and milliseconds


def _when(ts: Any) -> str | None:
    t = _epoch(ts)
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


def _age(seconds: float) -> str:
    m = int(seconds // 60)
    if m < 120:
        return f"{m} min"
    if m < 48 * 60:
        return f"{m // 60} h"
    return f"{m // 1440} days"


def _valid_entries(meta: dict[str, Any]) -> list[str]:
    """The entries FMC 10.0.1 lists under metadata.validEntries: what it read from the feed URL (it fetches a
    feed when it is created). FMC doesn't fill entryCount or feedUpdateTime for such a feed over REST."""
    got = meta.get("validEntries")
    return [str(e) for e in got] if isinstance(got, list) else []


def feed_status(obj: dict[str, Any], now: float | None = None) -> str:
    """'ok', 'fetched ...', 'not downloaded yet', 'stale ...' or 'downloaded but empty' for an SI feed."""
    meta = obj.get("metadata") or {}
    last = _epoch(meta.get("feedUpdateTime"))
    freq = obj.get("updateFrequency")
    if last is None:
        valid = _valid_entries(meta)
        if valid:
            # FMC 10.0.1 (live): validEntries filled, entryCount 0 and no feedUpdateTime, also after the
            # devices had started to block the feed's entries
            every = f" (every {freq} min)" if isinstance(freq, int) and freq > 0 else ""
            return (
                f"fetched: FMC read {len(valid)} valid entries from the feed URL; FMC 10.0.1 doesn't "
                "report over REST when Security Intelligence loads them (entryCount 0, no update time). "
                f"Devices can take until the feed's next refresh{every} and a deploy to block them: check "
                "with fmc_packet_tracer to one entry (drop reason 'reputation')"
            )
        return "not downloaded yet (FMC fetches a feed when it is created and at every refresh)"
    age = (now or time.time()) - last
    if isinstance(freq, int) and freq > 0 and age > max(2 * freq * 60, 3600):
        return (
            f"stale: last update {_age(age)} ago, refresh every {freq} min "
            "(can FMC reach the feed URL? fmc_list_health_alerts)"
        )
    if meta.get("entryCount") == 0:
        return "downloaded but empty (check the feed's format: one entry per line)"
    return "ok" if isinstance(freq, int) and freq > 0 else "ok (automatic refresh off)"


def source_row(kind: str, source: str, obj: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """One SI feed or custom list as a flat row with its status."""
    meta = obj.get("metadata") or {}
    row: dict[str, Any] = {"name": obj.get("name"), "kind": kind, "source": source}
    if source == "feed":
        row.update(
            url=obj.get("feedURL"),
            refresh_min=obj.get("updateFrequency"),
            entries=meta.get("entryCount"),
            last_update=_when(meta.get("feedUpdateTime")),
            status=feed_status(obj, now),
        )
        valid = _valid_entries(meta)
        if valid:
            row.update(fetched_entries=len(valid), fetched_sample=valid[:5])
    else:
        file_name = str(obj.get("fileName") or "")
        row.update(
            entries=meta.get("entryCount"),
            invalid=meta.get("invalidEntryCount") or None,
            uploaded=_when(meta.get("timestamp")),
            file=file_name or None,
            uploaded_by_this_server=file_name.endswith((SI_MARKER, DNS_BLOCK_MARKER)) or None,
        )
    row["id"] = obj.get("id")
    return {k: v for k, v in row.items() if v is not None}


async def _sources(
    app: FmcApp, kinds: list[str], domain: str | None
) -> list[tuple[str, str, dict[str, Any]]]:
    """(kind, 'feed'|'custom', object) for every SI feed and custom list of these kinds."""
    out: list[tuple[str, str, dict[str, Any]]] = []
    for kind in kinds:
        for source, paths in (("feed", FEEDS), ("custom", CUSTOM)):
            page = await app.all(await app.config_path(paths[kind], domain))
            out += [(kind, source, o) for o in page.items if isinstance(o, dict) and o.get("id")]
    return out


async def _catalog(app: FmcApp, kind: str, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(CATALOG[kind], domain), expanded=False)
    return [o for o in page.items if isinstance(o, dict) and o.get("id")]


async def resolve_sources(
    app: FmcApp, names: list[str], kind: str | None, domain: str | None, *, custom_only: bool = False
) -> list[dict[str, Any]]:
    """Find SI feeds and lists by name or UUID: {'kind', 'source' ('feed'|'custom'|'system'), 'object',
    'ref'}. A custom list FMC also shows among its SI lists is referenced with the type FMC lists it as."""
    kinds = [kind] if kind else list(KINDS)
    pool: list[dict[str, Any]] = []
    for k in kinds:
        catalog = {str(o["id"]).lower(): o for o in await _catalog(app, k, domain)}
        seen: set[str] = set()
        for _, source, obj in await _sources(app, [k], domain):
            oid = str(obj["id"]).lower()
            seen.add(oid)
            listed = catalog.get(oid) or obj
            ref = {"id": obj["id"], "type": listed.get("type") or obj.get("type"), "name": obj.get("name")}
            pool.append({"kind": k, "source": source, "object": obj, "ref": ref})
        if not custom_only:
            pool += [
                {
                    "kind": k,
                    "source": "system",
                    "object": o,
                    "ref": {k2: o.get(k2) for k2 in ("id", "type", "name")},
                }
                for oid, o in catalog.items()
                if oid not in seen
            ]
    found: list[dict[str, Any]] = []
    for raw in dict.fromkeys(n.strip() for n in names):
        if not raw:
            raise InvalidRequest("Empty feed or list name.")
        hits = [c for c in pool if str(c["ref"]["id"]).lower() == raw.lower()] if is_uuid(raw) else []
        hits = hits or [c for c in pool if c["ref"].get("name") == raw]
        hits = hits or [c for c in pool if _norm(str(c["ref"].get("name") or "")) == _norm(raw)]
        if not hits:
            close = difflib.get_close_matches(raw, [str(c["ref"].get("name")) for c in pool], n=5, cutoff=0.5)
            what = "custom feed or list" if custom_only else "Security Intelligence feed or list"
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            scope = f" of kind {kind!r}" if kind else ""
            raise NotFound(f"No {what}{scope} named {raw!r}.{hint}", 404)
        if len(hits) > 1:
            kinds_hit = sorted({h["kind"] for h in hits})
            if len(kinds_hit) > 1:
                raise InvalidRequest(
                    f"{raw!r} exists as a {' and a '.join(kinds_hit)} list or feed; pass kind."
                )
            ids = ", ".join(
                f"{h['ref'].get('name')} ({h['ref'].get('type')}, {h['ref']['id']})" for h in hits
            )
            raise InvalidRequest(f"{raw!r} is ambiguous: {ids}. Pass the id instead.")
        found.append(hits[0])
    return found


def clean_entries(kind: str, entries: list[str]) -> list[str]:
    """Validate and normalise list entries (one per line; '#' starts a comment); duplicates dropped."""
    out: list[str] = []
    for raw in entries:
        for line in str(raw).splitlines():
            v = line.split("#", 1)[0].strip()
            if not v:
                continue
            if kind == "dns":
                d = v.lower().rstrip(".")
                if len(d) > 253 or not DOMAIN_RE.fullmatch(d):
                    raise InvalidRequest(f"{v!r} is not a domain name.")
                out.append(d)
                continue
            what, value = classify(v)
            if kind == "ip" and what == "url":
                raise InvalidRequest(f"{v!r} is not an IP address or CIDR (URLs go in a kind='url' list).")
            if kind == "url" and what != "url":
                raise InvalidRequest(f"{v!r} is not a URL or domain (addresses go in a kind='ip' list).")
            out.append(value)
    out = list(dict.fromkeys(out))
    if not out:
        raise InvalidRequest("No entries to upload.")
    if len(out) > MAX_LIST_ENTRIES:
        raise InvalidRequest(
            f"{len(out)} entries; at most {MAX_LIST_ENTRIES} per upload (serve bigger lists as a feed)."
        )
    return out


def check_feed_url(url: str, what: str = "url") -> str:
    v = url.strip()
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise InvalidRequest(f"{what} must be an http:// or https:// URL, not {url!r}.")
    if parts.username or parts.password:
        raise InvalidRequest(
            f"{what} must not carry credentials (FMC stores and shows the URL); serve the feed without them."
        )
    return v


async def _si_users(app: FmcApp, ref_id: str, kind: str, domain: str | None) -> tuple[list[str], bool]:
    """Access policies (SI) and DNS policies (rules) that reference an SI feed or list."""
    rid = ref_id.lower()
    users: list[str] = []
    if kind in SECTION:
        section, key = SECTION[kind]
        acps = await app.all(await app.config_path(ACCESS, domain), expanded=False)
        complete = acps.complete and len(acps.items) <= POLICY_SCAN_CAP
        for acp in acps.items[:POLICY_SCAN_CAP]:
            base = await app.config_path(f"{ACCESS}/{acp['id']}/securityintelligencepolicies", domain)
            for si in (await app.all(base)).items:
                for which in ("blocklist", "allowlist"):
                    entries = ((si.get(section) or {}).get(which)) or []
                    if any(str((e.get(key) or {}).get("id", "")).lower() == rid for e in entries):
                        users.append(f"access policy {acp.get('name')!r} (SI {which[:-4]} list)")
    else:
        pols = await app.all(await app.config_path(DNS, domain), expanded=False)
        complete = pols.complete and len(pols.items) <= POLICY_SCAN_CAP
        for pol in pols.items[:POLICY_SCAN_CAP]:
            rules = await all_rules(app, await app.config_path(f"{DNS}/{pol['id']}/dnsrules", domain))
            for r in rules.items:
                objs = ((r.get("dnsLists") or {}).get("objects") or []) + (
                    (r.get("dnsFeeds") or {}).get("objects") or []
                )
                if any(str(o.get("id", "")).lower() == rid for o in objs):
                    users.append(f"DNS policy {pol.get('name')!r} rule {r.get('name')!r}")
    return users, complete


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


async def si_summary(app: FmcApp, si: dict[str, Any], domain: str | None) -> dict[str, Any]:
    """_si_rows with the DNS policy's own name, not the SI reference's alias (#204)."""
    rows = _si_rows(si)
    ref = si.get("dnsPolicy") or {}
    if ref.get("id"):
        rows["dns_policy"] = await dns_policy_name(app, ref, domain)
    return rows


async def _si_policy(app: FmcApp, acp: dict[str, Any], domain: str | None) -> tuple[str, dict[str, Any]]:
    base = await app.config_path(f"{ACCESS}/{acp['id']}/securityintelligencepolicies", domain)
    page = await app.all(base)
    if not page.items:
        raise InvalidRequest(f"{acp.get('name')!r} has no Security Intelligence settings.")
    si = page.items[0]
    return f"{base}/{si['id']}", si


async def _set_dns_lists(
    ctx: Context,
    app: FmcApp,
    acp: dict[str, Any],
    si: dict[str, Any],
    found: list[dict[str, Any]],
    which: str,
    action: str,
    dns_answer: str,
    args: dict[str, Any],
    row: Callable[[dict[str, Any]], dict[str, Any]],
    domain: str | None,
    confirm: str | None,
) -> dict[str, Any]:
    dns_ref = si.get("dnsPolicy") or {}
    if not dns_ref.get("id"):
        raise InvalidRequest(
            f"{acp.get('name')!r} uses no DNS policy: fmc_create_dns_policy + fmc_set_dns_policy first."
        )
    pol = await resolve_in(app, DNS, str(dns_ref["id"]), "DNS policy", domain)
    rules_path = await app.config_path(f"{DNS}/{pol['id']}/dnsrules", domain)
    rules = await all_rules(app, rules_path)
    # A DNS policy the domain only inherits (FMC's Default DNS Policy is Global's, and read-only only below
    # Global, FMC 10.0.1) gets #204's wording: the leaf way first, then the owner domain (#250).
    then = {k: v for k, v in args.items() if k != "domain" and v is not None}
    blockers = await inherited_blockers(
        app,
        pol,
        domain,
        rules.items,
        then=("fmc_set_si_lists", then) if action == "add" else None,
        goal=f"add these DNS feeds/lists to {acp.get('name')!r}",
        relink=[acp],
    )
    inherited = bool(blockers)
    if not inherited and is_system(pol):
        blockers.append(
            f"{pol.get('name')!r} is read-only in this domain: create a DNS policy (fmc_create_dns_policy), "
            f"link it to {acp.get('name')!r} (fmc_set_dns_policy), then repeat."
        )
    rule_name = DNS_RULE[which]
    wanted = {"block": dns_answer, "allow": "ALLOW", "monitor": "MONITOR"}[which]
    rule = next((r for r in rules.items if r.get("name") == rule_name), None)

    def ids_of(r: dict[str, Any] | None) -> set[str]:
        objs = (((r or {}).get("dnsLists") or {}).get("objects") or []) + (
            ((r or {}).get("dnsFeeds") or {}).get("objects") or []
        )
        return {str(o.get("id") or "").lower() for o in objs}

    present = ids_of(rule)
    todo = [f for f in found if (str(f["ref"]["id"]).lower() in present) == (action == "remove")]
    if rule and action == "add" and rule.get("action") != wanted:
        blockers.append(
            f"The rule {rule_name!r} answers with {rule.get('action')}, not {wanted}; "
            f"use dns_answer={rule.get('action')!r}."
        )
    if not todo and not blockers:
        blockers.append(
            "Nothing to change: "
            + (
                "all of these are already in the rule."
                if action == "add"
                else "none of these is in the rule."
            )
        )

    async def apply() -> Any:
        current = await app.api.get(f"{rules_path}/{rule['id']}") if rule else None
        lists = [f["ref"] for f in todo if f["source"] != "feed"]
        feeds = [f["ref"] for f in todo if f["source"] == "feed"]
        try:
            if action == "add":
                if current is None:
                    body: dict[str, Any] = {
                        "name": rule_name,
                        "type": "DNSRule",
                        "action": wanted,
                        "enabled": True,
                    }
                    if lists:
                        body["dnsLists"] = {"objects": lists}
                    if feeds:
                        body["dnsFeeds"] = {"objects": feeds}
                    result = await app.api.post(rules_path, body)
                else:
                    body = editable(current)
                    for key, refs in (("dnsLists", lists), ("dnsFeeds", feeds)):
                        cont = dict(body.get(key) or {})
                        objs = list(cont.get("objects") or [])
                        have = {str(o.get("id") or "").lower() for o in objs}
                        objs += [r for r in refs if str(r["id"]).lower() not in have]
                        if objs:
                            body[key] = {**cont, "objects": objs}
                    result = await app.api.put(f"{rules_path}/{current['id']}", body)
            else:
                if current is None:
                    raise InvalidRequest(f"The rule {rule_name!r} is gone; nothing to remove.")
                drop = {str(f["ref"]["id"]).lower() for f in todo}
                body = editable(current)
                left = 0
                for key in ("dnsLists", "dnsFeeds"):
                    cont = dict(body.get(key) or {})
                    objs = [
                        o for o in cont.get("objects") or [] if str(o.get("id") or "").lower() not in drop
                    ]
                    if objs:
                        body[key] = {**cont, "objects": objs}
                    else:
                        body.pop(key, None)
                    left += len(objs) + len(cont.get("literals") or [])
                if left:
                    result = await app.api.put(f"{rules_path}/{current['id']}", body)
                else:
                    result = await app.api.delete(f"{rules_path}/{current['id']}")
        finally:
            app.invalidate_cache()
        return {
            "policy": acp.get("name"),
            "dns_policy": pol.get("name"),
            "rule": dns_rule_row(result) if isinstance(result, dict) and result.get("name") else None,
            "next": "fmc_deploy to the devices using the access policy",
        }

    return await fmc_preview(
        ctx,
        tool="fmc_set_si_lists",
        args=args,
        confirm=confirm,
        owned=[] if inherited else [pol],  # inherited_blockers explains it, the leaf way first
        plan=Plan(
            f"DNS policy {pol.get('name')!r} (used by {acp.get('name')!r}): {action} {len(todo)} DNS "
            f"feed(s)/list(s) " + ("to" if action == "add" else "from") + f" rule {rule_name!r} ({wanted})",
            details={
                "rule": rule_name
                + (" (new, appended after FMC's Global rules)" if rule is None and action == "add" else ""),
                "answer": wanted,
                "entries": [row(f) for f in todo],
                "unchanged": [row(f)["name"] for f in found if f not in todo] or None,
                "deploy_needed": True,
            },
            fingerprint={"rule": (rule or {}).get("id"), "ids": sorted(present)},
            blockers=blockers,
            side_effects=[
                "DNS rules are evaluated in order; an earlier rule that matches the domain wins.",
                "Takes effect on devices after the next deployment (fmc_deploy).",
            ],
        ),
        apply=apply,
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Security Intelligence settings")
    async def fmc_get_security_intelligence(
        ctx: Context,
        policy: Annotated[
            str | None,
            Field(
                description="Access control policy name or UUID; omit to list the domain's SI feeds and "
                "custom lists with their status"
            ),
        ] = None,
        feeds: Annotated[
            bool,
            Field(
                description="With a policy: also show each feed and custom list it uses (6 more API calls)"
            ),
        ] = True,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Show an access policy's Security Intelligence: the network and URL block lists and do-not-block
        lists (Global lists, Talos categories, feeds, custom lists and objects added by fmc_si_block), the
        DNS policy and its rules, whether blocks are logged, and for each feed and custom list it uses the
        entry count, last update and status (a feed FMC can't download shows as stale). Without a policy:
        every SI feed and custom list in the domain with that status (made with fmc_create_si_feed /
        fmc_upload_si_list). Use it to check a feed was fetched before relying on it."""
        app: FmcApp = get_client(ctx)
        now = time.time()
        if not policy:
            rows = [source_row(k, src, o, now) for k, src, o in await _sources(app, list(KINDS), domain)]
            return object_reply(
                {
                    "feeds": [r for r in rows if r["source"] == "feed"] or None,
                    "lists": [r for r in rows if r["source"] != "feed"] or None,
                    "note": None
                    if rows
                    else "No SI feeds or custom lists in this domain. Talos categories are built in; "
                    "put them in a policy with fmc_set_si_lists.",
                },
                fmt=response_format,
            )
        acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
        _, si = await _si_policy(app, acp, domain)
        out: dict[str, Any] = {"policy": acp.get("name"), **await si_summary(app, si, domain)}
        used: dict[str, list[str]] = {}
        for kind, (section, key) in SECTION.items():
            for which in ("blocklist", "allowlist"):
                for e in ((si.get(section) or {}).get(which)) or []:
                    rid = str((e.get(key) or {}).get("id") or "").lower()
                    if rid:
                        used.setdefault(rid, []).append(f"{LABEL[kind]} {which[:-4]} list")
        dns_ref = si.get("dnsPolicy") or {}
        if dns_ref.get("id"):
            rules = await all_rules(app, await app.config_path(f"{DNS}/{dns_ref['id']}/dnsrules", domain))
            out["dns_rules"] = [dns_rule_row(r) for r in rules.items] or None
            for r in rules.items:
                objs = ((r.get("dnsLists") or {}).get("objects") or []) + (
                    (r.get("dnsFeeds") or {}).get("objects") or []
                )
                for o in objs:
                    rid = str(o.get("id") or "").lower()
                    if rid:
                        used.setdefault(rid, []).append(f"DNS rule {r.get('name')!r} ({r.get('action')})")
        if feeds:
            rows, others = [], 0
            for k, src, o in await _sources(app, list(KINDS), domain):
                where = used.get(str(o["id"]).lower())
                if where:
                    rows.append({**source_row(k, src, o, now), "used_as": where})
                else:
                    others += 1
            out["feeds_and_lists"] = rows or None
            if others:
                out["other_feeds_and_lists"] = (
                    f"{others} not used here (fmc_get_security_intelligence without a policy)"
                )
        return object_reply(out, fmt=response_format)

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
                "si": await si_summary(app, result if isinstance(result, dict) else body, domain),
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

    @reg.write(title="Create Security Intelligence feed")
    async def fmc_create_si_feed(
        ctx: Context,
        kind: KindArg,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New feed object name")],
        url: Annotated[
            str,
            Field(description="Where FMC downloads the feed: http(s) URL of a text file, one entry per line"),
        ],
        refresh: Annotated[
            int,
            Field(
                ge=5,
                le=10080,
                description="Minutes between downloads (FMC's editor offers 30 min to 1 week; FMC checks "
                "the value)",
            ),
        ] = 60,
        checksum_url: Annotated[
            str | None,
            Field(description="Optional URL of the feed's MD5 checksum (FMC skips unchanged feeds)"),
        ] = None,
        description: Annotated[str | None, Field(max_length=200, description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a Security Intelligence feed: FMC downloads a list of IPs/networks (kind='ip'), URLs
        (kind='url') or domains (kind='dns') from your server or a third party and refreshes it on a
        schedule. Then put it in a policy with fmc_set_si_lists (ip/url: the access policy's SI block or
        do-not-block list; dns: a rule of its DNS policy) and deploy. fmc_get_security_intelligence shows
        whether FMC fetched it (entries, last update). For a fixed set of entries use fmc_upload_si_list."""
        app: FmcApp = get_client(ctx)
        feed_url = check_feed_url(url)
        checksum = check_feed_url(checksum_url, "checksum_url") if checksum_url else None
        path = await app.config_path(FEEDS[kind], domain)
        taken = [o for _, _, o in await _sources(app, [kind], domain)] + await _catalog(app, kind, domain)
        clash = [o for o in taken if str(o.get("name", "")).lower() == name.strip().lower()]
        body: dict[str, Any] = {
            "name": name.strip(),
            "type": FEED_TYPE[kind],
            "feedURL": feed_url,
            "updateFrequency": refresh,
        }
        if checksum:
            body["checksumURL"] = checksum
        if description:
            body["description"] = description

        async def apply() -> Any:
            out = await app.api.post(path, body)
            app.invalidate_cache()
            row = source_row(kind, "feed", out) if isinstance(out, dict) else {"name": name}
            return {
                "feed": row,
                "next": "fmc_get_security_intelligence() for the download status; fmc_set_si_lists to use it",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_si_feed",
            args={
                "kind": kind,
                "name": name,
                "url": url,
                "refresh": refresh,
                "checksum_url": checksum_url,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {LABEL[kind]} Security Intelligence feed {name.strip()!r}",
                details={"body": body},
                fingerprint=sorted(str(o.get("id")) for o in clash),
                blockers=[f"A {LABEL[kind]} SI feed or list named {name.strip()!r} already exists."]
                if clash
                else [],
                side_effects=[
                    "FMC downloads the feed now and every refresh; the feed URL must be reachable from FMC.",
                    "Nothing is blocked until the feed is in a policy (fmc_set_si_lists) and deployed.",
                ],
            ),
            apply=apply,
        )

    @reg.write(title="Upload Security Intelligence list")
    async def fmc_upload_si_list(
        ctx: Context,
        kind: KindArg,
        name: Annotated[str, Field(min_length=1, max_length=64, description="Custom list name")],
        entries: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=MAX_LIST_ENTRIES,
                description="IPs/CIDRs (ip), URLs or domains (url), or domains (dns); one per item, or "
                "newline-separated text ('#' comments are dropped)",
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Upload a custom Security Intelligence list (a fixed set of IPs/networks, URLs or domains) to FMC,
        or replace the whole content of one this server uploaded before. Entries are checked first (host
        bits, /0, loopback and multicast refused). Then put it in a policy with fmc_set_si_lists and deploy.
        For a list FMC should download and refresh itself use fmc_create_si_feed; to block a few IPs or
        URLs quickly use fmc_si_block."""
        app: FmcApp = get_client(ctx)
        clean = clean_entries(kind, entries)
        lists_path = await app.config_path(CUSTOM[kind], domain)
        have = await _sources(app, [kind], domain)
        current = next((o for _, src, o in have if src == "custom" and o.get("name") == name.strip()), None)
        taken = [o for _, _, o in have] + await _catalog(app, kind, domain)
        blockers = []
        if current is not None and not str(current.get("fileName") or "").endswith(SI_MARKER):
            blockers.append(
                f"A custom {LABEL[kind]} list {name.strip()!r} exists but was not uploaded by "
                "fmc_upload_si_list; pick another name."
            )
        if current is None and any(str(o.get("name", "")).lower() == name.strip().lower() for o in taken):
            blockers.append(f"A {LABEL[kind]} SI feed or list named {name.strip()!r} already exists.")
        text = "\n".join(clean) + "\n"
        file_name = f"{name.strip()}{SI_MARKER}"
        meta = (current or {}).get("metadata") or {}

        async def apply() -> Any:
            if current is not None:
                out = await upload_file(
                    app,
                    f"{lists_path}/{current['id']}",
                    name.strip(),
                    file_name,
                    text,
                    method="PUT",
                    object_id=str(current["id"]),
                )
            else:
                out = await upload_file(app, lists_path, name.strip(), file_name, text)
            app.invalidate_cache()
            got = (out.get("metadata") or {}) if isinstance(out, dict) else {}
            return {
                "list": name.strip(),
                "kind": kind,
                "entries": got.get("entryCount"),
                "invalid": got.get("invalidEntryCount") or None,
                "invalid_lines": got.get("invalidLines") or None,
                "id": out.get("id") if isinstance(out, dict) else None,
                "next": "fmc_set_si_lists to put it in a policy, then fmc_deploy",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_upload_si_list",
            args={"kind": kind, "name": name, "entries": entries, "domain": domain},
            confirm=confirm,
            plan=Plan(
                ("Replace" if current else "Upload")
                + f" custom {LABEL[kind]} SI list {name.strip()!r} ({len(clean)} entries)",
                details={
                    "entries": len(clean),
                    "first": clean[:10],
                    "file": file_name,
                    "replaces": {"entries": meta.get("entryCount"), "uploaded": _when(meta.get("timestamp"))}
                    if current
                    else None,
                },
                fingerprint={"current": (current or {}).get("id"), "at": meta.get("timestamp")},
                blockers=blockers,
                side_effects=["Policies using the list pick up the new content at their next deployment."]
                if current
                else [],
            ),
            apply=apply,
        )

    @reg.write(title="Use SI feeds and lists in a policy")
    async def fmc_set_si_lists(
        ctx: Context,
        policy: PolicyRef,
        names: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=20,
                description="SI feeds or lists by name or UUID: Talos categories (e.g. 'Malware', 'URL CnC', "
                "'DNS Phishing'), feeds (fmc_create_si_feed) and custom lists (fmc_upload_si_list)",
            ),
        ],
        list_type: Annotated[
            Literal["block", "allow", "monitor"],
            Field(
                description="block, allow (do-not-block) or monitor (log only; DNS feeds and lists only, see "
                "the description)"
            ),
        ] = "block",
        action: Annotated[
            Literal["add", "remove"], Field(description="Add to or remove from that list")
        ] = "add",
        kind: Annotated[
            Kind | None, Field(description="ip, url or dns, when a name exists for several kinds")
        ] = None,
        dns_answer: Annotated[
            Literal["NXDOMAIN", "DROP"],
            Field(
                description="list_type='block' with DNS feeds or lists: answer NXDOMAIN or drop the lookup"
            ),
        ] = "NXDOMAIN",
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Put Security Intelligence feeds and lists into an access policy (or take them out). Network and
        URL ones go into the policy's SI block or do-not-block list (SI drops matching traffic before any
        access rule and logs it); DNS ones go into a rule of the DNS policy the access policy uses
        (mcp-si-dns-block / -allow / -monitor, appended after FMC's Global rules). A DNS policy the domain
        only inherits (FMC's Default DNS Policy below Global) is read-only there: the preview gives the way
        with a DNS policy of the domain's own (fmc_create_dns_policy + fmc_set_dns_policy), then the owner
        domain.
        list_type='monitor' (log, don't block) works for DNS only: FMC's REST API has no monitor-only flag for
        network or URL SI. Needs a deployment. Check the result with fmc_get_security_intelligence."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
        path, si = await _si_policy(app, acp, domain)
        found = await resolve_sources(app, names, kind, domain)
        if len({f["kind"] == "dns" for f in found}) > 1:
            raise InvalidRequest(
                "DNS feeds and lists go into the DNS policy, network and URL ones into the access policy's "
                "Security Intelligence: make one call for each."
            )
        args = {
            "policy": policy,
            "names": names,
            "list_type": list_type,
            "action": action,
            "kind": kind,
            "dns_answer": dns_answer,
            "domain": domain,
        }

        def row(f: dict[str, Any]) -> dict[str, Any]:
            return {
                "name": f["ref"].get("name"),
                "kind": f["kind"],
                "source": f["source"],
                "type": f["ref"].get("type"),
            }

        if found[0]["kind"] == "dns":
            return await _set_dns_lists(
                ctx, app, acp, si, found, list_type, action, dns_answer, args, row, domain, confirm
            )

        which = WHICH.get(list_type, "blocklist")
        blockers = [MONITOR_GAP] if list_type == "monitor" else []

        def ids_in(obj: dict[str, Any], kind_: str) -> set[str]:
            section, key = SECTION[kind_]
            entries = ((obj.get(section) or {}).get(which)) or []
            return {str((e.get(key) or {}).get("id") or "").lower() for e in entries}

        todo = [
            f for f in found if (str(f["ref"]["id"]).lower() in ids_in(si, f["kind"])) == (action == "remove")
        ]
        if not todo and not blockers:
            blockers.append(
                "Nothing to change: "
                + (
                    "all of these are already in the list."
                    if action == "add"
                    else "none of these is in the list."
                )
            )

        async def apply() -> Any:
            body = editable(await app.api.get(path))
            for f in todo:
                section, key = SECTION[f["kind"]]
                block = dict(body.get(section) or {})
                entries = list(block.get(which) or [])
                rid = str(f["ref"]["id"]).lower()
                have = {str((e.get(key) or {}).get("id") or "").lower() for e in entries}
                if action == "add" and rid not in have:
                    entries.append({key: f["ref"]})
                elif action == "remove":
                    entries = [e for e in entries if str((e.get(key) or {}).get("id") or "").lower() != rid]
                block[which] = entries
                body[section] = block
            result = await applied(app, lambda: app.api.put(path, body))
            return {
                "policy": acp.get("name"),
                "si": await si_summary(app, result if isinstance(result, dict) else body, domain),
                "next": "fmc_deploy to the devices using the policy",
            }

        logging = (si.get("networks") or {}).get("blocklistLogging") or {}
        side = ["Takes effect on devices after the next deployment (fmc_deploy)."]
        if list_type == "block" and logging and not logging.get("enableLogging"):
            side.append("SI block logging is off in this policy: drops happen but no SI events are logged.")
        return await fmc_preview(
            ctx,
            tool="fmc_set_si_lists",
            args=args,
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"Security Intelligence {list_type} list of {acp.get('name')!r}: {action} {len(todo)} "
                "feed(s)/list(s)",
                details={
                    "list": list_type,
                    "action": action,
                    "entries": [row(f) for f in todo],
                    "unchanged": [row(f)["name"] for f in found if f not in todo] or None,
                    "deploy_needed": True,
                },
                fingerprint={k: sorted(ids_in(si, k)) for k in SECTION},
                blockers=blockers,
                side_effects=side,
            ),
            apply=apply,
        )

    @reg.write(title="Delete Security Intelligence feed or list", destructive=True)
    async def fmc_delete_si_object(
        ctx: Context,
        name: Annotated[str, Field(description="Feed or custom list name or UUID")],
        kind: Annotated[
            Kind | None, Field(description="ip, url or dns, when the name exists for several")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a Security Intelligence feed or custom list (fmc_create_si_feed, fmc_upload_si_list).
        Blocked while an access policy's SI or a DNS policy rule still uses it (the preview names them;
        take it out with fmc_set_si_lists action='remove' first). Talos categories and the Global/Domain
        lists can't be deleted."""
        app: FmcApp = get_client(ctx)
        f = (await resolve_sources(app, [name], kind, domain, custom_only=True))[0]
        obj = f["object"]
        users, complete = await _si_users(app, str(obj["id"]), f["kind"], domain)
        blockers = []
        if is_system(obj):
            blockers.append("Read-only system list.")
        if users:
            blockers.append(
                f"Still used by: {'; '.join(users)}. Remove it first (fmc_set_si_lists action='remove')."
            )
        paths = FEEDS if f["source"] == "feed" else CUSTOM
        path = await app.config_path(f"{paths[f['kind']]}/{obj['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_si_object",
            owned=[obj],
            args={"name": name, "kind": kind, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete {LABEL[f['kind']]} SI {'feed' if f['source'] == 'feed' else 'list'} "
                f"{obj.get('name')!r}",
                details={
                    "object": source_row(f["kind"], f["source"], obj),
                    "usage_checked": "all policies" if complete else f"the first {POLICY_SCAN_CAP} policies",
                },
                fingerprint={"object": editable(obj), "users": users},
                blockers=blockers,
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )
