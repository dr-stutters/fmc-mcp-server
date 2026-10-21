"""Where does a domain, URL or file hash appear? (F79)

One indicator across FMC's policy: FQDN objects, URL objects and URL groups (and the network groups holding
FQDN objects), the access and decryption rules that use them, each access policy's Security Intelligence URL
block and do-not-block lists, DNS policy rules (their custom SI DNS lists, fmc_dns_block's included, and DNS
feeds), and the SI URL and DNS feeds and lists themselves. Built on fmc_find_address's machinery
(find_address.Findings, Match, the policy caps and rule labels): the same ranked rows and columns.

What FMC's REST API can't answer is said in the reply, not guessed: the entries of custom SI lists (FMC
returns their counts; the one-domain lists fmc_dns_block makes are matched by name), Talos categories, URL
categories and reputation in rules, and file hashes (FMC 10.0.1 has no file-list endpoints, and Threat
Intelligence Director observables are not read). Every collection read counts against max_requests.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from dataclasses import dataclass, field, replace
from typing import Annotated, Any, Literal, get_args
from urllib.parse import urlsplit

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ResponseFormat, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.catalog import Catalog, parse_ip_value
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import access_policy_of
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.decryption import DECRYPTION
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.dns import DNS, DOMAIN_RE, dns_policy_name, list_name
from fmc_mcp.tools.dns import MARKER as DNS_BLOCK_MARKER
from fmc_mcp.tools.dns import PREFIX as DNS_BLOCK_PREFIX
from fmc_mcp.tools.find_address import POLICY_CAP, Findings, Match, _policies, _rule_where, better
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy

Area = Literal[
    "objects",
    "si_lists",
    "security_intelligence",
    "dns_rules",
    "access_rules",
    "decryption_rules",
]
AREAS: tuple[str, ...] = get_args(Area)
AREA_ORDER = {a: i for i, a in enumerate(AREAS)}

OBJECTS = ("object/fqdns", "object/urls", "object/urlgroups", "object/networkgroups")
FEEDS = {"url": "object/siurlfeeds", "dns": "object/sidnsfeeds"}
CUSTOM = {"url": "object/customsiurllists", "dns": "object/customsidnslists"}
LISTS = {"url": "object/siurllists", "dns": "object/sidnslists"}
KIND_LABEL = {"url": "URL", "dns": "DNS"}
SOURCE_LABEL = {
    "feed": "feed",
    "custom": "custom list",
    "list": "list",
    "talos": "Talos category",
    "tid": "TID list",
    "unknown": "list",
}
# FMC's own block and do-not-block lists ("Global Block List for URL", "Domain-Block-List-for-DNS-<domain>",
# "Descendant-Block-Lists-for-DNS_-_Global"): read by id when a searched policy uses them
OWN_LIST_RE = re.compile(r"^(global|domain|descendant)[\s_-]", re.IGNORECASE)
LIST_CAP = 8  # FMC block/do-not-block lists read by id per call
USERS_SHOWN = 3  # access policies named on a DNS rule row
DEFAULT_REQUESTS = 60
SIDES = (("source", "sourceNetworks"), ("destination", "destinationNetworks"), ("url", "urls"))
HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
HASH_KINDS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HASH_NOTE = (
    "FMC's file lists and TID observables aren't searched: FMC 10.0.1's REST API has no endpoints for "
    "the clean list or the custom detection list, and Threat Intelligence Director reads are not enabled "
    "for this server. File policies (fmc_get_file_policy) act on file types and malware dispositions, "
    "not on hashes named in them; look the hash up in the malware events or your EDR."
)
COLUMNS = ["rank", "match", "area", "where", "side", "via", "value"]
LIMITS = (
    "FMC's configuration, read offline. contains: the configured value is a parent domain of the indicator, "
    "or a shorter URL on the same host; inside: the value is a subdomain of the asked domain or a URL on it. "
    "An FQDN object names one host, so only its exact and inside matches are listed (DNS answers are not "
    "resolved). Not searched: Threat Intelligence Director (TID) indicators and observables; the entries of "
    "Talos categories and of custom SI lists (FMC's REST API returns entry counts only; the one-domain lists "
    "fmc_dns_block makes are matched by their name); URL categories and reputation in rules; per-device "
    "object overrides. FMC's Global and Domain block/do-not-block lists are read when a searched policy uses "
    "them. A child access policy lists its base policy's rules too: those rows say 'inherited from <base>'. "
    "Live verdicts: fmc_packet_tracer."
)


@dataclass(frozen=True)
class Indicator:
    kind: str  # 'domain', 'url' or 'hash'
    text: str  # as searched (lower-case host, scheme and port dropped)
    host: str = ""
    path: str = ""  # '' or '/a/b' (no trailing slash), '?query' kept


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def split_url(text: Any) -> tuple[str, str] | None:
    """(host, path) of a domain, URL or URL-object value ('https://Example.com:8443/a/' -> ('example.com',
    '/a')); None when there is no host name."""
    v = str(text or "").strip()
    if not v:
        return None
    if "://" not in v:
        v = "http://" + v
    try:
        parts = urlsplit(v)
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    path = parts.path.rstrip("/")
    if parts.query:
        path += "?" + parts.query
    return host.rstrip("."), path


def host_relation(have: str, want: str) -> str | None:
    """How a configured host name relates to the asked one: 'exact', 'contains' (a parent domain, or a
    wildcard covering it), 'inside' (a subdomain of it, or a wildcard below it) or None."""
    if have == want:
        return "exact"
    if _is_ip(have) or _is_ip(want):
        return None
    if have.startswith("*."):
        base = have[2:]
        if want.endswith("." + base):
            return "contains"
        return "inside" if base == want or base.endswith("." + want) else None
    if want.endswith("." + have):
        return "contains"
    if have.endswith("." + want):
        return "inside"
    return None


def relation(have: tuple[str, str], want: Indicator) -> str | None:
    """A configured (host, path) against the indicator: exact, contains, inside or None."""
    rel = host_relation(have[0], want.host)
    if rel is None:
        return None
    hp, wp = have[1], want.path
    if rel == "contains":
        return None if hp else "contains"  # example.com/x says nothing about www.example.com
    if rel == "inside":
        return None if wp else "inside"  # a subdomain is another host than the asked URL's
    if hp == wp:
        return "exact"
    if not hp or wp.startswith((hp + "/", hp + "?")):
        return "contains"
    if not wp or hp.startswith((wp + "/", wp + "?")):
        return "inside"
    return None


def parse_indicator(value: str) -> Indicator:
    v = value.strip()
    if HASH_RE.fullmatch(v):
        return Indicator("hash", v.lower())
    if not v or v.lower() in ("any", "any-ipv4", "any-ipv6") or parse_ip_value(v) is not None:
        raise InvalidRequest(
            f"{value!r} is an IP address, network or range: fmc_find_address searches those. "
            "fmc_find_indicator takes a domain (bad.example.com), a URL (http://bad.example.com/x) or a file "
            "hash (MD5, SHA-1, SHA-256)."
        )
    got = split_url(v)
    host, path = got or ("", "")
    if host.startswith("*."):
        host = host[2:]  # '*.evil.test': its subdomains are found as 'inside'
    if not host or not (_is_ip(host) or DOMAIN_RE.fullmatch(host)) or (_is_ip(host) and not path):
        hint = " (an address goes to fmc_find_address)" if host and _is_ip(host) else ""
        raise InvalidRequest(
            f"{value!r} is not a domain, URL or file hash{hint}; e.g. bad.example.com, "
            "http://bad.example.com/payload.exe or a SHA-256."
        )
    return Indicator("url" if path else "domain", host + path, host, path)


def _size(rel: str, got: tuple[str, str]) -> int:
    """Narrowest first: the longest value that contains the indicator, the shortest one inside it."""
    n = len(got[0]) + len(got[1])
    return 0 if rel == "exact" else -n if rel == "contains" else n


@dataclass
class Tracer:
    """Resolves references (FQDN and URL objects, URL and network groups, literals) against the indicator."""

    want: Indicator
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)

    def value(self, text: Any, path: tuple[str, ...] = (), *, fqdn: bool = False) -> Match | None:
        got = split_url(text)
        if got is None:
            return None
        rel = relation(got, self.want)
        if rel is None or (fqdn and rel == "contains" and got[0] != self.want.host):
            return None  # an FQDN object resolves its own name only, not the subdomains below it
        return Match(rel, _size(rel, got), str(text).strip(), path)

    def ref(self, ref: Any, seen: frozenset[str] = frozenset()) -> Match | None:
        """Best match of a reference or literal; a group is followed into its members."""
        if not isinstance(ref, dict):
            return None
        obj = ref
        rid = ref.get("id")
        if rid:
            if rid in seen:
                return None
            obj = self.objects.get(str(rid), ref)
        name = str(obj.get("name") or ref.get("name") or "")
        if "objects" in obj or "literals" in obj:
            inner = seen | {str(rid)} if rid else seen
            best: Match | None = None
            for member in [*(obj.get("objects") or []), *(obj.get("literals") or [])]:
                best = better(best, self.ref(member, inner))
            return replace(best, path=(name, *best.path)) if best and name else best
        here = (name,) if name else ()
        if str(obj.get("type") or "").upper() == "FQDN" and obj.get("value"):
            return self.value(obj["value"], here, fqdn=True)
        if obj.get("url"):
            return self.value(obj["url"], here)
        return None  # hosts, networks, ranges: not a name

    def block(self, block: Any) -> tuple[Match | None, int]:
        """Best match among a rule block's objects and literals, and how many of them match."""
        if not isinstance(block, dict):
            return None, 0
        best: Match | None = None
        count = 0
        for ref in [*(block.get("objects") or []), *(block.get("literals") or [])]:
            m = self.ref(ref)
            if m:
                count += 1
                best = better(best, m)
        return best, count


@dataclass
class Source:
    """An SI feed or list, as far as its entries can be searched."""

    name: str
    kind: str  # 'url' or 'dns'
    source: str  # a SOURCE_LABEL key
    match: Match | None = None
    how: str = "entry"  # how the match was found (the si_lists row's via)
    unreadable: str | None = None  # why its entries weren't searched

    @property
    def label(self) -> str:
        return f"{KIND_LABEL[self.kind]} {SOURCE_LABEL[self.source]} {self.name}"


@dataclass(kw_only=True)
class Sweep(Findings):
    tracer: Tracer
    budget: int
    used: int = 0
    sources: dict[str, Source] = field(default_factory=dict)  # feed/list id (lower case) -> Source
    lists_read: int = 0
    dns_users: dict[str, list[str]] = field(default_factory=dict)  # DNS policy id -> access policies
    dns_refs: dict[str, dict[str, Any]] = field(default_factory=dict)  # DNS policy id -> reference
    skipped: list[str] = field(default_factory=list)  # what the request budget left out
    category_rules: int = 0
    children: bool | None = None  # whether the searched domain has child domains (read once)

    def spend(self, what: str, n: int = 1) -> bool:
        if self.used + n > self.budget:
            self.skipped.append(what)
            return False
        self.used += n
        return True


def _entries_match(t: Tracer, entries: list[Any]) -> Match | None:
    best: Match | None = None
    for e in entries:
        best = better(best, t.value(e))
    return best


async def _collection(s: Sweep, path: str, what: str, *, expanded: bool = True) -> list[dict[str, Any]]:
    """One collection within the budget; [] with a warning when FMC refuses it."""
    if not s.spend(what):
        return []
    try:
        page = await s.app.all(await s.app.config_path(path, s.domain), expanded=expanded)
    except UpstreamError as e:
        s.warnings.append(f"{what} could not be read ({e}).")
        return []
    if not page.complete:
        s.warnings.append(f"{what}: more items than were read.")
    return [o for o in page.items if isinstance(o, dict) and o.get("id")]


def _dns_block_domains(name: str, want: Indicator) -> list[str]:
    """The domain an fmc_dns_block list holds, from its name (mcp-dns-<domain>; a long or unusual domain
    gets a hashed name, which is matched against the indicator's own domain, its parents and wildcards)."""
    plain = name[len(DNS_BLOCK_PREFIX) :]
    if list_name(plain) == name:
        return [plain]
    labels = want.host.split(".")
    parents = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    return [d for p in parents for d in (p, "*." + p) if list_name(d) == name]


async def _load_sources(s: Sweep, kinds: list[str]) -> None:
    """The domain's SI feeds (their fetched entries) and custom lists (fmc_dns_block's by name)."""
    feeds = custom = 0
    for kind in kinds:
        for o in await _collection(s, FEEDS[kind], f"SI {KIND_LABEL[kind]} feeds"):
            feeds += 1
            src = Source(str(o.get("name")), kind, "feed", how="fetched entry")
            entries = (o.get("metadata") or {}).get("validEntries")
            if isinstance(entries, list):
                src.match = _entries_match(s.tracer, entries)
            else:
                src.unreadable = "FMC lists no fetched entries: not downloaded yet?"
            s.sources[str(o["id"]).lower()] = src
        for o in await _collection(s, CUSTOM[kind], f"custom SI {KIND_LABEL[kind]} lists"):
            custom += 1
            name = str(o.get("name"))
            src = Source(name, kind, "custom", how="list name (fmc_dns_block list)")
            meta = o.get("metadata") or {}
            mine = kind == "dns" and str(o.get("fileName") or "").endswith(DNS_BLOCK_MARKER)
            if mine and name.startswith(DNS_BLOCK_PREFIX):
                src.match = _entries_match(s.tracer, _dns_block_domains(name, s.tracer.want))
            else:
                count = meta.get("entryCount")
                have = f"{count} entries; " if count is not None else ""
                src.unreadable = f"{have}FMC returns the count, not the entries"
            s.sources[str(o["id"]).lower()] = src
    s.searched["si_feeds"] = feeds
    s.searched["si_custom_lists"] = custom


async def source_of(s: Sweep, ref: dict[str, Any]) -> Source:
    """The feed or list a policy references (FMC's own block lists are read by id on first use)."""
    rid = str(ref.get("id") or "").lower()
    if rid in s.sources:
        return s.sources[rid]
    name = str(ref.get("name") or rid)
    kind = "dns" if "DNS" in str(ref.get("type") or "").upper() else "url"
    if name.upper().startswith("TID "):
        src = Source(name, kind, "tid", unreadable="Threat Intelligence Director's list (TID isn't searched)")
    elif "FEED" in str(ref.get("type") or "").upper():
        src = Source(name, kind, "unknown", unreadable="not among the domain's SI feeds")
    elif not OWN_LIST_RE.match(name):
        src = Source(name, kind, "talos", unreadable="Talos keeps its entries")
    else:
        src = Source(name, kind, "list", how="list entry")
        if name.lower().startswith("descendant") and not await _has_child_domains(s):
            pass  # the child domains' lists, seen from a domain without children (FMC 10.0.1 answers 404)
        elif s.lists_read >= LIST_CAP or not rid:
            src.unreadable = f"not read (at most {LIST_CAP} of FMC's block lists per call)"
        elif not s.spend(f"SI list {name}"):
            src.unreadable = "not read (request budget)"
        else:
            s.lists_read += 1
            try:
                obj = await s.app.api.get(await s.app.config_path(f"{LISTS[kind]}/{ref['id']}", s.domain))
            except UpstreamError as e:
                obj = None
                gone = e.status_code == 404
                src.unreadable = "not visible from this domain" if gone else f"could not be read ({e})"
            meta = (obj or {}).get("metadata") or {}
            entries = meta.get("validEntries")
            if isinstance(entries, list):
                src.match = _entries_match(s.tracer, entries)
            elif obj is not None and meta.get("entryCount"):
                src.unreadable = f"{meta['entryCount']} entries; FMC returns the count, not the entries"
    s.sources[rid] = src
    return src


async def _has_child_domains(s: Sweep) -> bool:
    if s.children is None:
        here = await s.app.domain_name(await s.app.domain_uuid(s.domain))
        s.children = any(str(d.get("name")).startswith(f"{here}/") for d in s.app.domains)
    return s.children


def _objects(s: Sweep, cat: Catalog) -> None:
    count = 0
    for obj in cat.objects.values():
        count += 1
        m = s.tracer.ref(obj)
        if m:
            via = " > ".join(m.path[1:]) or "value"
            s.add("objects", m, f"{obj.get('type')} {obj.get('name')}", via=via)
    s.searched["objects"] = count


def _rule_rows(s: Sweep, area: str, p: dict[str, Any], rules: list[dict[str, Any]], action_key: str) -> None:
    policy = str(p.get("name"))
    for r in rules:
        meta = r.get("metadata") or {}
        idx = meta.get("ruleIndex", r.get("ruleIndex"))
        # a child policy's inherited rules are labelled with their base (FMC lists them under the child too)
        where = _rule_where(
            policy, {**r, "metadata": {**meta, "ruleIndex": idx}}, r.get(action_key), p.get("id")
        )
        if (r.get("urls") or {}).get("urlCategoriesWithReputation"):
            s.category_rules += 1
        for side, key in SIDES:
            m, n = s.tracer.block(r.get(key))
            if m:
                via = " > ".join(m.path) or "literal"
                if n > 1:
                    via += f" (+{n - 1} more)"
                s.add(area, m, where, side, via)


async def _policy_rules(s: Sweep, area: str, base: str, sub: str, p: dict[str, Any], action_key: str) -> int:
    name = str(p.get("name"))
    if not s.spend(f"rules of {name}"):
        return 0
    try:
        rules = await all_rules(s.app, await s.app.config_path(f"{base}/{p['id']}/{sub}", s.domain))
    except UpstreamError as e:
        s.warnings.append(f"Rules of {name!r} could not be read ({e}).")
        return 0
    if not rules.complete:
        s.warnings.append(f"{name!r} has more rules than were read.")
    _rule_rows(s, area, p, rules.items, action_key)
    return len(rules.items)


async def _security_intelligence(s: Sweep, acp: dict[str, Any], report: bool) -> bool:
    """An access policy's SI URL block/do-not-block lists (rows when `report`) and the DNS policy it uses."""
    name = str(acp.get("name"))
    for si in await _collection(s, f"{ACCESS}/{acp['id']}/securityintelligencepolicies", f"SI of {name}"):
        dns = si.get("dnsPolicy") or {}
        if dns.get("id"):
            did = str(dns["id"]).lower()
            s.dns_users.setdefault(did, []).append(name)
            s.dns_refs.setdefault(did, dns)
        if report:
            await _si_url_lists(s, name, si)
        return True
    return False


async def _si_url_lists(s: Sweep, acp: str, si: dict[str, Any]) -> None:
    for which, side in (("blocklist", "block"), ("allowlist", "do-not-block")):
        for entry in ((si.get("urls") or {}).get(which)) or []:
            ref = entry.get("url") or {}
            if str(ref.get("type")) in ("Url", "UrlGroup") or str(ref.get("id")) in s.tracer.objects:
                m = s.tracer.ref(ref)  # fmc_si_block's URL objects, or a URL group
                via = " > ".join(m.path) if m else ""
            else:
                src = await source_of(s, ref)
                m, via = src.match, src.label
            if m:
                s.add("security_intelligence", m, f"{acp}: Security Intelligence URL list", side, via)


async def _dns_rules(s: Sweep, pol: dict[str, Any]) -> int:
    name = str(pol.get("name"))
    if not s.spend(f"rules of DNS policy {name}"):
        return 0
    try:
        rules = await all_rules(s.app, await s.app.config_path(f"{DNS}/{pol['id']}/dnsrules", s.domain))
    except UpstreamError as e:
        s.warnings.append(f"Rules of DNS policy {name!r} could not be read ({e}).")
        return 0
    users = s.dns_users.get(str(pol["id"]).lower())
    for r in rules.items:
        idx = (r.get("metadata") or {}).get("ruleIndex")
        where = f"DNS policy {name} #{idx} {r.get('name')} ({r.get('action')})"
        if r.get("enabled") is False:
            where += " [disabled]"
        if users:
            more = f" and {len(users) - USERS_SHOWN} more" if len(users) > USERS_SHOWN else ""
            where += f" [access policies: {', '.join(users[:USERS_SHOWN])}{more}]"
        for key, side in (("dnsLists", "dns list"), ("dnsFeeds", "dns feed")):
            for o in (r.get(key) or {}).get("objects") or []:
                if not isinstance(o, dict) or not o.get("id"):
                    continue
                src = await source_of(s, o)
                if src.match:
                    s.add("dns_rules", src.match, where, side, src.label)
    return len(rules.items)


def _not_checked(s: Sweep) -> list[str]:
    out: list[str] = []
    groups: dict[str, list[str]] = {}
    for src in s.sources.values():
        if src.unreadable:
            groups.setdefault(src.source, []).append(f"{src.label} ({src.unreadable})")
    for source in ("custom", "list", "feed", "talos", "tid", "unknown"):
        names = sorted(groups.get(source, []))
        if names:
            shown = "; ".join(names[:8]) + (f"; and {len(names) - 8} more" if len(names) > 8 else "")
            out.append(f"entries not searched: {shown}")
    if s.category_rules:
        out.append(
            f"URL categories and reputation in {s.category_rules} rule(s) aren't resolved to domains offline"
        )
    return out


def _budget_warning(s: Sweep) -> None:
    if not s.skipped:
        return
    shown = ", ".join(s.skipped[:8]) + (f" and {len(s.skipped) - 8} more" if len(s.skipped) > 8 else "")
    s.warnings.append(
        f"Stopped at max_requests={s.budget}; not read: {shown}. Narrow with access_policy or device, or "
        "raise max_requests (FMC allows about 120 requests a minute, shared with every other client)."
    )


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Find where a domain, URL or hash appears")
    async def fmc_find_indicator(
        ctx: Context,
        value: Annotated[
            str,
            Field(
                description="A domain (bad.example.com), a URL (http://bad.example.com/payload.exe) or a "
                "file hash (MD5, SHA-1, SHA-256); IP addresses go to fmc_find_address"
            ),
        ],
        areas: Annotated[
            list[Area] | None,
            Field(
                description="Where to look (default: everywhere): objects, si_lists, security_intelligence, "
                "dns_rules, access_rules, decryption_rules"
            ),
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="Only this FTD (name or UUID): its access policy's rules and Security "
                "Intelligence, its DNS policy and its decryption policy"
            ),
        ] = None,
        access_policy: Annotated[
            str | None,
            Field(
                description="Only this access control policy (and the DNS and decryption policies it uses)"
            ),
        ] = None,
        max_requests: Annotated[
            int,
            Field(
                ge=15,
                le=300,
                description="FMC requests this call may make (one per collection read); what doesn't fit "
                "is named in the warning",
            ),
        ] = DEFAULT_REQUESTS,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """'Where does bad.example.com appear?' in one call, the SOC's domain and URL sweep
        (fmc_find_address does IPs): FQDN and URL objects, URL groups and network groups holding FQDN
        objects; access and decryption rules using them (source, destination or URL condition, through
        any group chain); each access policy's Security Intelligence URL block/do-not-block lists
        (fmc_si_block's objects, URL feeds, FMC's Global and Domain lists); DNS policy rules with their SI
        DNS lists and feeds (fmc_dns_block's lists included, naming the access policies using the DNS
        policy); and every SI URL/DNS feed whose fetched entries hold it. Ranked like fmc_find_address:
        exact, then values inside it (subdomains, URLs on it), then the narrowest values containing it
        (a parent domain, a shorter URL); each row says where (policy, rule index and action, SI list, DNS
        rule) and via which object, list or feed. A file hash is answered at once: FMC's file lists and
        TID observables aren't searched. `not_checked` names what FMC's REST API doesn't return (Talos
        categories, custom SI list entries, URL categories in rules). Budget-aware: about 11 collection
        reads plus 2 per access policy and 1 per DNS and decryption policy (25 per kind), objects and SI
        first, within max_requests (default 60; a warning names what didn't fit); narrow with device or
        access_policy. Offline configuration (see `limits`); live verdicts: fmc_packet_tracer."""
        app: FmcApp = get_client(ctx)
        want = parse_indicator(value)
        if want.kind == "hash":
            kind = f"{HASH_KINDS[len(want.text)]} file hash"
            return Findings(app=app, domain=domain).result(
                {"indicator": want.text, "kind": kind},
                limits=LIMITS,
                notes={"not_checked": [HASH_NOTE]},
                limit=limit,
                offset=offset,
                fmt=response_format,
            )
        wanted = set(areas or AREAS)
        s = Sweep(app=app, domain=domain, area_order=AREA_ORDER, tracer=Tracer(want), budget=max_requests)
        cat = Catalog(app, domain)
        s.used += await cat.load(*OBJECTS)
        s.tracer.objects = cat.objects
        if not cat.complete:
            s.warnings.append(
                "The object catalog was larger than the scan cap; some objects were not resolved."
            )
        if "objects" in wanted:
            _objects(s, cat)
        kinds = [k for k, a in (("url", "security_intelligence"), ("dns", "dns_rules")) if a in wanted]
        if "si_lists" in wanted:
            kinds = ["url", "dns"]
        if kinds:
            await _load_sources(s, kinds)

        dev = None
        if device:
            s.used += 1
            dev = await resolve_device(app, device, domain)
        narrowed = bool(access_policy) or dev is not None
        acps: list[dict[str, Any]] = []
        need_si = "security_intelligence" in wanted or (narrowed and "dns_rules" in wanted)
        if access_policy:
            s.used += 1
            acps = [await resolve_policy(app, "access", access_policy, domain)]
        elif dev is not None:
            s.used += 0 if dev.get("accessPolicy") else 1  # access_policy_of re-reads a bare record
            ref = await access_policy_of(app, dev, domain)
            if ref:
                s.used += 1
                acps = [await resolve_policy(app, "access", str(ref["id"]), domain)]
        elif need_si or "access_rules" in wanted:
            if s.spend("access policies"):
                acps = await _policies(s, "access", ACCESS, None, "access policies")
        # Security Intelligence first (it names the DNS policies' users), then DNS rules, then the rule scans
        si_read = 0
        if need_si:
            for p in acps:
                si_read += await _security_intelligence(s, p, "security_intelligence" in wanted)
            s.searched["si_policies"] = si_read

        if "dns_rules" in wanted:
            if narrowed:
                dns_pols = []
                for ref in s.dns_refs.values():
                    # the SI reference can carry another name than the policy's own (#204)
                    own = await dns_policy_name(app, ref, domain) if s.spend("DNS policy name") else None
                    dns_pols.append({**ref, "name": own or ref.get("name")})
            else:
                dns_pols = await _collection(s, DNS, "DNS policies", expanded=False)
                if len(dns_pols) > POLICY_CAP:
                    s.warnings.append(f"Only the first {POLICY_CAP} DNS policies were searched.")
                    dns_pols = dns_pols[:POLICY_CAP]
            s.searched["dns_policies"] = len(dns_pols)
            s.searched["dns_rules"] = sum([await _dns_rules(s, p) for p in dns_pols])

        if "access_rules" in wanted:
            rules_read = 0
            for p in acps:
                rules_read += await _policy_rules(s, "access_rules", ACCESS, "accessrules", p, "action")
            s.searched["access_policies"] = len(acps)
            s.searched["access_rules"] = rules_read

        if "decryption_rules" in wanted:
            if narrowed:
                dec_pols: list[dict[str, Any]] = []
                for a in acps:
                    link = a.get("decryptionPolicySetting") or {}
                    if link.get("id") and all(str(d["id"]) != str(link["id"]) for d in dec_pols):
                        dec_pols.append(link)
            else:
                dec_pols = await _collection(s, DECRYPTION, "decryption policies", expanded=False)
                if len(dec_pols) > POLICY_CAP:
                    s.warnings.append(f"Only the first {POLICY_CAP} decryption policies were searched.")
                    dec_pols = dec_pols[:POLICY_CAP]
            s.searched["decryption_policies"] = len(dec_pols)
            s.searched["decryption_rules"] = sum(
                [
                    await _policy_rules(
                        s, "decryption_rules", DECRYPTION, "decryptionpolicyrules", p, "ruleAction"
                    )
                    for p in dec_pols
                ]
            )

        if "si_lists" in wanted:
            for src in s.sources.values():
                if src.match:
                    s.add("si_lists", src.match, f"SI {src.label}", via=src.how)
        if s.lists_read:
            s.searched["si_lists_read"] = s.lists_read
        s.searched["requests"] = s.used
        _budget_warning(s)
        not_checked = _not_checked(s)
        return s.result(
            {"indicator": want.text, "kind": want.kind},
            limits=LIMITS,
            notes={"not_checked": not_checked} if not_checked else None,
            limit=limit,
            offset=offset,
            fmt=response_format,
            columns=COLUMNS,
        )
