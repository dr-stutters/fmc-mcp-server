"""Policy bundles (F44): one access policy with everything it references, as a versioned YAML document
keyed by name, and a diff of two bundles (or a bundle against the live FMC) that F45's importer reuses as
its planner.

Bundle layout (schema 1), every id, link and metadata block stripped:

    schema: 1
    meta: {policy, domain, fmc_version, server, exported_at, digest}
    access_policy: {name, description, default_action, settings, categories, rules: [...]}
    prefilter_policy / decryption_policy / identity_policy: {name, ..., rules: [...]} or {name, system: true}
    nat_policies: {<name>: {description, rules: [...]}}
    intrusion_policies: {<name>: {system: true} | {base_policy, inspection_mode, overrides, ...}}
    objects: {<FMC type>: {<name>: {...}}}          # every object used, groups expanded recursively
    security_zones / interface_groups / time_ranges: {<name>: {...}}

Rules keep their order; access rules use fmc_export_access_rules' row format (rule_io.export_row) plus
`raw` for the settings that format can't carry, so nothing is dropped. Mappings are sorted by name and
condition lists are sorted, so two exports of an unchanged policy differ only in meta.exported_at, and
meta.digest (sha256 of everything else) is identical.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import hashlib
import json
import re
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ToolRegistrar, get_client
from fmc_mcp._core.formatting import max_chars
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, domain_path, is_builtin_object, type_for
from fmc_mcp.tools.intrusion import IPS
from fmc_mcp.tools.policies import ACCESS, NAT, PREFILTER, all_rules, policy_assignments, resolve_policy
from fmc_mcp.tools.rule_io import CONDITIONS, UNSUPPORTED, export_row

SCHEMA = 1
OBJECT_CAP = 20_000
MAX_OVERRIDES = 500
DECRYPTION = "policy/decryptionpolicies"
IDENTITY = "policy/identitypolicies"
DEFAULT_PREFILTER = "Default Prefilter Policy"

# Keys stripped everywhere: FMC's identity and bookkeeping, not configuration.
STRIP = frozenset({"id", "links", "metadata"})
# Access rule fields export_row carries in its own columns (everything else goes to `raw`).
REBUILT = frozenset(
    {"type", "name", "action", "enabled", "logBegin", "logEnd", "ipsPolicy"}
    | {field for _, field in CONDITIONS.values()}
)
NAT_SECTIONS = {"BEFORE_AUTO": 0, "AUTO": 1, "AFTER_AUTO": 2}
# Bundle sections holding a policy (settings + ordered rules), in diff order.
POLICY_SECTIONS = ("access_policy", "prefilter_policy", "decryption_policy", "identity_policy")
# Bundle sections holding name-keyed items.
KEYED_SECTIONS = ("intrusion_policies", "security_zones", "interface_groups", "time_ranges")
# FMC reference types that get their own top-level section instead of `objects`.
SPECIAL = {"securityzone": "security_zones", "interfacegroup": "interface_groups", "timerange": "time_ranges"}

BundleRef = Annotated[
    str,
    Field(
        description="Bundle YAML text from fmc_export_policy_bundle, or the file name of a bundle in "
        "FMC_BUNDLE_DIR"
    ),
]

_EMPTY: tuple[Any, ...] = (None, "", [], {})


# --- normalising ---------------------------------------------------------------------------------


def clean(value: Any, *, nested: bool = False) -> Any:
    """Configuration only: ids, links and metadata stripped, empty values and link-only collections
    ({refType: list}) dropped, keys sorted (FMC doesn't keep key order stable between responses), and
    the members of `objects` / `literals` sorted (they are sets). A nested reference keeps its name and
    type (and nested structure such as a zone interface's device), not the copies of the referenced
    object's fields that expanded listings add."""
    if isinstance(value, list):
        return [c for c in (clean(v, nested=nested) for v in value) if c not in _EMPTY]
    if not isinstance(value, dict):
        return value
    if "refType" in value:
        return None
    is_ref = nested and bool(value.get("id")) and "name" in value and "type" in value
    out: dict[str, Any] = {}
    for k in sorted(value):
        if k in STRIP:
            continue
        v = value[k]
        if is_ref and k not in ("name", "type") and not isinstance(v, dict | list):
            continue
        c = clean(v, nested=True)
        if k in ("objects", "literals") and isinstance(c, list):
            c = sorted(c, key=_sort_key)
        if c not in _EMPTY:
            out[k] = c
    return out


def _sort_key(item: Any) -> str:
    return json.dumps(item, sort_keys=True, default=str)


def access_rule(r: dict[str, Any]) -> dict[str, Any]:
    """An access rule in fmc_export_access_rules' row format (without the index: position is the list
    order) plus `raw`: every other setting, cleaned, so the bundle never loses part of a rule."""
    row = export_row(r)
    row.pop("index", None)
    row = {"name": row.pop("name", None), **row}
    for col in UNSUPPORTED:  # kept whole in `raw` (realms, application filters, ...)
        row.pop(col, None)
    for col in (*CONDITIONS, "not_importable"):
        if isinstance(row.get(col), list):
            row[col] = sorted(row[col])
    raw: dict[str, Any] = {}
    for field, value in r.items():
        if field in STRIP:
            continue
        if field not in REBUILT:
            c = clean(value, nested=True)
            if c not in _EMPTY:
                raw[field] = c
        elif isinstance(value, dict) and field != "ipsPolicy":
            # Condition blocks: export_row keeps objects and literals as labels; anything else (URL
            # categories) and ICMP codes, which the labels can't carry, stay here.
            extra = {k: v for k, v in value.items() if k not in ("objects", "literals")}
            if any(lit.get("code") not in (None, "") for lit in value.get("literals") or []):
                extra = value
            c = clean(extra, nested=True)
            if c not in _EMPTY:
                raw[field] = c
    if raw:
        row["raw"] = {k: raw[k] for k in sorted(raw)}
    return row


def generic_rule(r: dict[str, Any]) -> dict[str, Any]:
    """Prefilter, NAT, decryption and identity rules: name and section first, then every setting."""
    meta = r.get("metadata") or {}
    head: dict[str, Any] = {}
    if r.get("name"):
        head["name"] = r["name"]
    if meta.get("section"):
        head["section"] = str(meta["section"]).lower()
    cat = meta.get("category")
    if cat not in (None, "", "--Undefined--"):
        head["category"] = cat
    body = clean({k: v for k, v in r.items() if k != "name"})
    return {**head, **body}


def rule_order(r: dict[str, Any]) -> tuple[int, int]:
    meta = r.get("metadata") or {}
    section = NAT_SECTIONS.get(str(meta.get("section") or "").upper(), 0)
    index = meta.get("ruleIndex") or meta.get("index") or r.get("ruleIndex") or 0
    try:
        return section, int(index)
    except (TypeError, ValueError):
        return section, 0


def ordered(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(rules, key=rule_order)


def is_system(policy: dict[str, Any]) -> bool:
    """FMC's built-in policies. Not metadata.readOnly: that depends on the API user's role too (a
    read-only user sees everything as read-only), and a bundle must not depend on who exported it."""
    return bool(policy.get("isSystemDefined"))


def object_entry(obj: dict[str, Any], domain_name: str) -> dict[str, Any]:
    """One object of the bundle, in full (built-in ones too: their values are what rules match). Objects
    inherited from an ancestor domain name it (as fmc_list_domains does: FMC's metadata says 'Global \\ leaf'
    for 'Global/leaf'); FMC's built-ins don't (every domain has them, so a leaf's export and Global's say the
    same about HTTP)."""
    entry = clean({k: v for k, v in obj.items() if k not in ("name", "type")})
    meta = obj.get("metadata") or {}
    owner = domain_path(str((meta.get("domain") or {}).get("name") or ""))
    if owner and owner != domain_path(domain_name) and not is_builtin_object(obj):  # not readOnly: role-bound
        entry["domain"] = owner
    return dict(entry)


def refs_in(value: Any) -> list[dict[str, Any]]:
    """Every {id, type} reference inside a (raw FMC) structure."""
    out: list[dict[str, Any]] = []
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            if v.get("id") and v.get("type"):
                out.append(v)
            stack.extend(x for k, x in v.items() if k not in ("links", "metadata"))
    return out


# --- serialising ---------------------------------------------------------------------------------


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str)


def dump(data: Any) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=10_000)


def digest_of(bundle: dict[str, Any]) -> str:
    """sha256 of the bundle without meta.exported_at / meta.digest: equal for an unchanged policy."""
    meta = {k: v for k, v in (bundle.get("meta") or {}).items() if k not in ("exported_at", "digest")}
    body = dump({**bundle, "meta": meta})
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


def parse_bundle(text: str, bundle_dir: Path | None) -> dict[str, Any]:
    """A bundle from YAML text, or from a file name inside FMC_BUNDLE_DIR (never a path outside it)."""
    name = text.strip()
    if bundle_dir and "\n" not in name and re.fullmatch(r"[\w.@+-]+\.ya?ml", name):
        path = (bundle_dir / name).resolve()
        if path.parent == bundle_dir.resolve() and path.is_file():
            text = path.read_text()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Not a policy bundle: the YAML doesn't parse ({e}).") from None
    if not isinstance(data, dict) or "schema" not in data:
        raise InvalidRequest(
            "Not a policy bundle (no `schema`): pass the YAML from fmc_export_policy_bundle, or the name "
            "of a bundle file in FMC_BUNDLE_DIR."
        )
    if data["schema"] != SCHEMA:
        raise InvalidRequest(
            f"Bundle schema {data['schema']!r} isn't supported (this server reads {SCHEMA})."
        )
    return data


# --- export --------------------------------------------------------------------------------------


def server_version() -> str:
    try:
        return f"fmc-mcp-server {version('fmc-mcp-server')}"
    except PackageNotFoundError:  # pragma: no cover - source tree without metadata
        return "fmc-mcp-server"


class Exporter:
    """Collects one access policy and its dependencies with bulk collection loads (no per-object GETs)."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app = app
        self.domain = domain
        self.raw_rules: list[Any] = []  # every raw FMC structure whose references are bundled
        self.warnings: list[str] = []
        self.acp: dict[str, Any] = {}

    async def _all(self, path: str, params: dict[str, Any] | None = None, cap: int = 10_000) -> list[Any]:
        # Not the analysis tools' 60 s catalog cache: a baseline must show FMC as it is now.
        page = await self.app.all(await self.app.config_path(path, self.domain), params, cap=cap)
        if not page.complete:
            self.warnings.append(f"{path}: FMC returned only the first {len(page.items)} items.")
        return list(page.items)

    async def _get(self, path: str) -> dict[str, Any]:
        data = await self.app.api.get(await self.app.config_path(path, self.domain))
        return dict(data or {})

    async def _rules(self, path: str) -> list[dict[str, Any]]:
        page = await all_rules(self.app, await self.app.config_path(path, self.domain))
        if not page.complete:
            self.warnings.append(f"{path}: FMC returned only the first {len(page.items)} rules.")
        return ordered(page.items)

    async def access_policy(self, acp: dict[str, Any]) -> dict[str, Any]:
        full = self.acp = await self._get(f"{ACCESS}/{acp['id']}")
        rules = await self._rules(f"{ACCESS}/{acp['id']}/accessrules")
        self.raw_rules += rules
        self.raw_rules.append(full.get("defaultAction") or {})
        categories = await self._all(f"{ACCESS}/{acp['id']}/categories")
        settings: dict[str, Any] = {}
        for field, label in (
            ("prefilterPolicySetting", "prefilter_policy"),
            ("decryptionPolicySetting", "decryption_policy"),
            ("sslPolicySetting", "decryption_policy"),
            ("identityPolicySetting", "identity_policy"),
        ):
            if (full.get(field) or {}).get("name"):
                settings[label] = full[field]["name"]
        for field, value in full.items():
            if field in STRIP or field in ("name", "description", "type", "rules", "defaultAction"):
                continue
            if field.endswith("PolicySetting") and field != "loggingPolicySetting":
                continue
            c = clean(value)
            if isinstance(c, dict):
                c.pop("type", None)
            if c not in _EMPTY:
                settings[field] = c
        out: dict[str, Any] = {"name": full.get("name") or acp.get("name")}
        if full.get("description"):
            out["description"] = full["description"]
        out["default_action"] = clean(
            {k: v for k, v in (full.get("defaultAction") or {}).items() if k != "type"}
        )
        out["settings"] = {k: settings[k] for k in sorted(settings)}
        if categories:
            out["categories"] = [c.get("name") for c in ordered(categories) if c.get("name")]
        out["rules"] = [access_rule(r) for r in rules]
        return out

    async def linked_policy(
        self, path: str, rules_path: str, ref: dict[str, Any], *, system_if_empty: str | None = None
    ) -> dict[str, Any] | None:
        if not ref.get("id"):
            return None
        full = await self._get(f"{path}/{ref['id']}")
        rules = await self._rules(f"{path}/{ref['id']}/{rules_path}")
        name = full.get("name") or ref.get("name")
        if (system_if_empty and name == system_if_empty and not rules) or is_system(full):
            return {"name": name, "system": True}
        self.raw_rules += rules
        self.raw_rules.append(full.get("defaultAction") or {})
        body = clean({k: v for k, v in full.items() if k not in ("name", "type", "rules")})
        return {"name": name, **body, "rules": [generic_rule(r) for r in rules]}

    async def nat_policies(self, acp: dict[str, Any], names: list[str] | None) -> dict[str, Any]:
        if names is None:  # the NAT policies of the devices this access policy is assigned to
            assignments = await policy_assignments(self.app, self.domain, cap=2000)
            targets = {
                t.get("id")
                for a in assignments
                if (a.get("policy") or {}).get("id") == acp["id"]
                for t in a.get("targets") or []
            }
            names = sorted(
                {
                    str(a["policy"].get("name"))
                    for a in assignments
                    if (a.get("policy") or {}).get("type") == "FTDNatPolicy"
                    and targets & {t.get("id") for t in a.get("targets") or []}
                }
            )
        out: dict[str, Any] = {}
        for name in names:
            p = await resolve_policy(self.app, "nat", name, self.domain)
            rules = await self._rules(f"{NAT}/{p['id']}/natrules")
            self.raw_rules += rules
            body = clean({k: v for k, v in p.items() if k not in ("name", "type", "rules")})
            out[str(p.get("name"))] = {**body, "rules": [generic_rule(r) for r in rules]}
        return {k: out[k] for k in sorted(out)}

    async def intrusion_policies(self) -> dict[str, Any]:
        wanted = {
            ref["id"]: ref
            for ref in refs_in(self.raw_rules)
            if str(ref.get("type", "")).lower() == "intrusionpolicy"
        }
        if not wanted:
            return {}
        known = {p["id"]: p for p in await self._all(IPS) if p.get("id")}
        out: dict[str, Any] = {}
        for pid, ref in wanted.items():
            p = known.get(pid, ref)
            name = str(p.get("name") or ref.get("name") or pid)
            if p.get("isSystemDefined") or not p.get("basePolicy"):
                out[name] = {"system": True}
                continue
            entry = clean({k: v for k, v in p.items() if k not in ("name", "type", "rules")})
            over = await self._all(
                f"{IPS}/{pid}/intrusionrules",
                {"filter": f"overrides:true;ipspolicy:{pid}"},
                cap=MAX_OVERRIDES,
            )
            if over:
                entry["overrides"] = {
                    f"{r.get('gid')}:{r.get('sid')}": r.get("overrideState")
                    for r in sorted(over, key=lambda r: (int(r.get("gid") or 0), int(r.get("sid") or 0)))
                }
            out[name] = entry
        return {k: out[k] for k in sorted(out)}

    async def objects(self, domain_name: str) -> dict[str, dict[str, Any]]:
        """Every object the collected rules reference, groups expanded recursively, by section."""
        loaded: dict[str, dict[str, Any]] = {}
        done_types: set[str] = set()
        seen: set[str] = set()
        todo = refs_in(self.raw_rules)
        found: dict[str, dict[str, Any]] = {}  # id -> FMC object
        while todo:
            ref = todo.pop()
            rid = str(ref["id"])
            otype = type_for(str(ref.get("type")))
            if rid in seen or otype is None:
                continue
            seen.add(rid)
            if otype.key not in done_types:
                done_types.add(otype.key)
                for o in await self._all(otype.path, cap=OBJECT_CAP):
                    if o.get("id"):
                        loaded[str(o["id"])] = o
            obj = loaded.get(rid)
            if obj is None:
                self.warnings.append(
                    f"{ref.get('type')} {ref.get('name') or rid} wasn't found in {otype.path}."
                )
                continue
            found[rid] = obj
            for member in obj.get("objects") or []:
                if isinstance(member, dict) and member.get("id"):
                    todo.append(member)
        sections: dict[str, dict[str, Any]] = {"objects": {}}
        for obj in found.values():
            fmc_type = str(obj.get("type") or "")
            section = SPECIAL.get(fmc_type.lower())
            bucket = (
                sections.setdefault(section, {}) if section else sections["objects"].setdefault(fmc_type, {})
            )
            bucket[str(obj.get("name"))] = object_entry(obj, domain_name)
        out: dict[str, dict[str, Any]] = {}
        for key in sorted(sections):
            if key == "objects":
                out[key] = {t: {n: v[n] for n in sorted(v)} for t, v in sorted(sections[key].items())}
            else:
                out[key] = {n: sections[key][n] for n in sorted(sections[key])}
        return out


async def build_bundle(
    app: FmcApp, policy: str, domain: str | None, nat: list[str] | None
) -> tuple[dict[str, Any], list[str]]:
    acp = await resolve_policy(app, "access", policy, domain)
    ex = Exporter(app, domain)
    domain_name = await app.domain_name(await app.domain_uuid(domain))
    access = await ex.access_policy(acp)
    full = ex.acp
    bundle: dict[str, Any] = {
        "schema": SCHEMA,
        "meta": {
            "policy": access["name"],
            "domain": domain_name,
            "fmc_version": await app.server_version(),
            "server": server_version(),
        },
        "access_policy": access,
    }
    prefilter = await ex.linked_policy(
        PREFILTER,
        "prefilterrules",
        full.get("prefilterPolicySetting") or {},
        system_if_empty=DEFAULT_PREFILTER,
    )
    if prefilter:
        bundle["prefilter_policy"] = prefilter
    decryption_ref = full.get("decryptionPolicySetting") or full.get("sslPolicySetting") or {}
    decryption = await ex.linked_policy(DECRYPTION, "decryptionpolicyrules", decryption_ref)
    if decryption:
        bundle["decryption_policy"] = decryption
    identity = await ex.linked_policy(IDENTITY, "identityrules", full.get("identityPolicySetting") or {})
    if identity:
        bundle["identity_policy"] = identity
    nat_policies = await ex.nat_policies(acp, nat)
    if nat_policies:
        bundle["nat_policies"] = nat_policies
    intrusion = await ex.intrusion_policies()
    if intrusion:
        bundle["intrusion_policies"] = intrusion
    bundle.update(await ex.objects(domain_name))
    return bundle, ex.warnings


def finish(bundle: dict[str, Any], now: datetime | None = None) -> str:
    """Stamp meta.exported_at and meta.digest and serialise."""
    digest = digest_of(bundle)
    stamp = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle["meta"] = {**bundle["meta"], "exported_at": stamp, "digest": digest}
    return dump(bundle)


def section_counts(bundle: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for key in POLICY_SECTIONS:
        if isinstance(bundle.get(key), dict) and not bundle[key].get("system"):
            counts[f"{key}.rules"] = len(bundle[key].get("rules") or [])
    for name, p in (bundle.get("nat_policies") or {}).items():
        counts[f"nat_policies.{name}.rules"] = len(p.get("rules") or [])
    for key in KEYED_SECTIONS:
        if bundle.get(key):
            counts[key] = len(bundle[key])
    for t, items in (bundle.get("objects") or {}).items():
        counts[f"objects.{t}"] = len(items)
    return counts


def write_file(bundle_dir: Path, policy: str, text: str, stamp: str) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]+", "_", policy).strip("._") or "policy"
    path = bundle_dir / f"{safe}-{stamp.replace(':', '').replace('-', '')}.yaml"
    path.write_text(text)
    return path


# --- diff (the planner F45 reuses) ---------------------------------------------------------------


def field_delta(a: Any, b: Any, prefix: str = "") -> dict[str, dict[str, Any]]:
    """Dotted field paths whose values differ: {"dst_ports": {"from": [...], "to": [...]}}."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: dict[str, dict[str, Any]] = {}
        for k in sorted(set(a) | set(b), key=str):
            out.update(field_delta(a.get(k), b.get(k), f"{prefix}{k}."))
        return out
    if a == b:
        return {}
    return {prefix.rstrip("."): {"from": a, "to": b}}


def _lis(seq: list[int]) -> set[int]:
    """Indexes (into seq) of one longest increasing subsequence."""
    import bisect

    tails: list[int] = []
    tails_at: list[int] = []
    prev = [-1] * len(seq)
    for i, v in enumerate(seq):
        j = bisect.bisect_left(tails, v)
        if j == len(tails):
            tails.append(v)
            tails_at.append(i)
        else:
            tails[j] = v
            tails_at[j] = i
        prev[i] = tails_at[j - 1] if j else -1
    out: set[int] = set()
    i = tails_at[-1] if tails_at else -1
    while i >= 0:
        out.add(i)
        i = prev[i]
    return out


def _unnamed(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if k != "name"}


def _unique_names(items: list[dict[str, Any]]) -> dict[str, int]:
    names: dict[str, list[int]] = {}
    for i, it in enumerate(items):
        if it.get("name"):
            names.setdefault(str(it["name"]), []).append(i)
    return {n: idx[0] for n, idx in names.items() if len(idx) == 1}


def diff_rules(section: str, a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ordered rules: matched by name (unique names), else by position among the unmatched ones.
    Positions are 1-based; `after` names the rule an added or moved one follows in b (None: first)."""
    an, bn = _unique_names(a), _unique_names(b)
    pairs: dict[int, int] = {ai: bn[n] for n, ai in an.items() if n in bn}
    left_a = [i for i in range(len(a)) if i not in pairs]
    used_b = set(pairs.values())
    left_b = {i for i in range(len(b)) if i not in used_b}
    for ai in left_a:
        # Position fallback, at the same place: unnamed rules (NAT) pair up; named ones only when
        # nothing but the name differs (a rename), so two different rules never pass for one.
        if ai not in left_b or a[ai].get("name") in bn or b[ai].get("name") in an:
            continue
        unnamed = not a[ai].get("name") and not b[ai].get("name")
        if unnamed or not field_delta(_unnamed(a[ai]), _unnamed(b[ai])):
            pairs[ai] = ai
            left_b.discard(ai)
    in_a_order = sorted(pairs)
    keep = {in_a_order[i] for i in _lis([pairs[ai] for ai in in_a_order])}

    def label(item: dict[str, Any], pos: int) -> str:
        return str(item.get("name") or f"#{pos + 1}")

    def after(bi: int) -> str | None:
        return label(b[bi - 1], bi - 1) if bi else None

    changes: list[tuple[int, dict[str, Any]]] = []
    for ai in range(len(a)):
        if ai not in pairs:
            changes.append(
                (ai, {"section": section, "op": "removed", "key": label(a[ai], ai), "position": ai + 1})
            )
            continue
        bi = pairs[ai]
        fields = field_delta(a[ai], b[bi])
        moved = ai not in keep
        if not fields and not moved:
            continue
        ch: dict[str, Any] = {
            "section": section,
            "op": "changed" if fields else "moved",
            "key": label(b[bi], bi),
        }
        if fields:
            ch["fields"] = fields
        if moved or ai != bi:
            ch["position"] = {"from": ai + 1, "to": bi + 1}
        if moved:
            ch["after"] = after(bi)
        changes.append((bi, ch))
    for bi in sorted(left_b):
        changes.append(
            (
                bi,
                {
                    "section": section,
                    "op": "added",
                    "key": label(b[bi], bi),
                    "position": bi + 1,
                    "after": after(bi),
                    "value": b[bi],
                },
            )
        )
    return [c for _, c in sorted(changes, key=lambda x: (x[0], x[1]["op"] != "removed"))]


def diff_keyed(section: str, a: dict[str, Any] | None, b: dict[str, Any] | None) -> list[dict[str, Any]]:
    a, b = a or {}, b or {}
    out: list[dict[str, Any]] = []
    for key in sorted(set(a) | set(b)):
        if key not in b:
            out.append({"section": section, "op": "removed", "key": key})
        elif key not in a:
            out.append({"section": section, "op": "added", "key": key, "value": b[key]})
        elif fields := field_delta(a[key], b[key]):
            out.append({"section": section, "op": "changed", "key": key, "fields": fields})
    return out


def diff_policy(section: str, a: dict[str, Any] | None, b: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not a and not b:
        return []
    if not a:
        return [{"section": section, "op": "added", "key": (b or {}).get("name"), "value": b}]
    if not b:
        return [{"section": section, "op": "removed", "key": a.get("name")}]
    out: list[dict[str, Any]] = []
    sa = {k: v for k, v in a.items() if k != "rules"}
    sb = {k: v for k, v in b.items() if k != "rules"}
    if fields := field_delta(sa, sb):
        out.append({"section": section, "op": "changed", "key": b.get("name"), "fields": fields})
    out += diff_rules(f"{section}.rules", list(a.get("rules") or []), list(b.get("rules") or []))
    return out


def diff_bundles(a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """Every change that turns bundle `a` into bundle `b`, in a stable order: policies (settings, then
    rules), NAT policies, then name-keyed sections and objects. meta is ignored."""
    changes: list[dict[str, Any]] = []
    for key in POLICY_SECTIONS:
        changes += diff_policy(key, a.get(key), b.get(key))
    na, nb = a.get("nat_policies") or {}, b.get("nat_policies") or {}
    for name in sorted(set(na) | set(nb)):
        pa = {"name": name, **na[name]} if name in na else None
        pb = {"name": name, **nb[name]} if name in nb else None
        changes += diff_policy(f"nat_policies.{name}", pa, pb)
    for key in KEYED_SECTIONS:
        changes += diff_keyed(key, a.get(key), b.get(key))
    oa, ob = a.get("objects") or {}, b.get("objects") or {}
    for t in sorted(set(oa) | set(ob)):
        changes += diff_keyed(f"objects.{t}", oa.get(t), ob.get(t))
    return changes


def summarise(changes: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for c in changes:
        counts = out.setdefault(c["section"], {})
        counts[c["op"]] = counts.get(c["op"], 0) + 1
    return out


def _meta(bundle: dict[str, Any]) -> dict[str, Any]:
    m = bundle.get("meta") or {}
    return {k: m.get(k) for k in ("policy", "domain", "fmc_version", "exported_at", "digest") if m.get(k)}


def _result(data: dict[str, Any]) -> ToolResult:
    return ToolResult(content=json.dumps(data, default=str), structured_content=data)


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Export a policy bundle")
    async def fmc_export_policy_bundle(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        domain: Domain = None,
        nat_policies: Annotated[
            list[str] | None,
            Field(
                description="NAT policies to include (names or UUIDs). Default: the NAT policies of the "
                "devices the access policy is assigned to; [] for none."
            ),
        ] = None,
        include_text: Annotated[
            bool,
            Field(description="Return the YAML in the result (false: only write the FMC_BUNDLE_DIR file)"),
        ] = True,
        offset: Annotated[
            int,
            Field(ge=0, description="Character offset into a bundle too big for one result (next_offset)"),
        ] = 0,
    ) -> ToolResult:
        """Export an access policy with everything it depends on as one versioned YAML bundle (schema 1):
        settings, default action and rules in order (fmc_export_access_rules' row format, plus `raw` for
        settings that format can't carry), the prefilter, decryption, identity, NAT and intrusion policies
        it uses (custom ones in full, system ones by name), every object it references with groups
        expanded, security zones, interface groups and time ranges. Ids and links are stripped and items
        keyed by name in a stable order: re-exporting an unchanged policy gives the same `digest` (only
        meta.exported_at differs). For backups, reviews, change records and fmc_diff_policy_bundle.
        Written to a file as well when FMC_BUNDLE_DIR is set."""
        app: FmcApp = get_client(ctx)
        bundle, warnings = await build_bundle(app, policy, domain, nat_policies)
        text = finish(bundle)
        meta = bundle["meta"]
        out: dict[str, Any] = {
            "policy": meta["policy"],
            "domain": meta["domain"],
            "digest": meta["digest"],
            "exported_at": meta["exported_at"],
            "size": len(text),
            "sections": section_counts(bundle),
        }
        bundle_dir = app.settings.bundle_dir
        if bundle_dir is not None and offset == 0:
            out["file"] = str(
                await asyncio.to_thread(write_file, bundle_dir, meta["policy"], text, meta["exported_at"])
            )
        if warnings:
            out["warnings"] = warnings[:20]
        if include_text:
            budget = max(4000, int(max_chars() * 0.8) - 4000)
            chunk = text[offset : offset + budget]
            out["bundle"] = chunk
            if offset + budget < len(text):
                out["next_offset"] = offset + budget
                out["note"] = (
                    "The bundle is larger than one result: call again with offset=next_offset and join the "
                    "parts (the digest changes if FMC changed meanwhile), or set FMC_BUNDLE_DIR."
                )
        elif bundle_dir is None:
            raise InvalidRequest("include_text=false needs FMC_BUNDLE_DIR (nowhere else to put the bundle).")
        return _result(out)

    @reg.read(title="Diff policy bundles")
    async def fmc_diff_policy_bundle(
        ctx: Context,
        a: BundleRef,
        b: Annotated[
            str | None,
            Field(
                description="Second bundle (YAML or a file name in FMC_BUNDLE_DIR). Omit to compare `a` "
                "against a fresh export of the live policy."
            ),
        ] = None,
        policy: Annotated[
            str | None,
            Field(description="Live policy to compare with when `b` is omitted (default: a's meta.policy)"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
    ) -> ToolResult:
        """Compare two policy bundles from fmc_export_policy_bundle, or a bundle with the live policy
        (what changed since the backup?). Per section (access/prefilter/decryption/identity/NAT rules and
        settings, intrusion policies, zones, objects by type): added, removed, changed (field-level
        `fields` {path: {from, to}}) and moved (`position` from/to, `after` = preceding rule). Rules match
        by name, unnamed or renamed ones by position. The changes turn `a` into `b` (or into live)."""
        app: FmcApp = get_client(ctx)
        bundle_dir = app.settings.bundle_dir
        ba = await asyncio.to_thread(parse_bundle, a, bundle_dir)
        if b is not None:
            bb = await asyncio.to_thread(parse_bundle, b, bundle_dir)
            warnings: list[str] = []
        else:
            target = policy or (ba.get("meta") or {}).get("policy")
            if not target:
                raise InvalidRequest("Bundle `a` names no policy; pass `policy` or `b`.")
            live_domain = domain or (ba.get("meta") or {}).get("domain")
            bb, warnings = await build_bundle(
                app, str(target), live_domain, sorted(ba.get("nat_policies") or {})
            )
            finish(bb)
            bb["meta"]["exported_at"] = "live"
        changes = diff_bundles(ba, bb)
        out: dict[str, Any] = {
            "a": _meta(ba),
            "b": _meta(bb),
            "identical": not changes,
            "summary": summarise(changes),
            "total": len(changes),
            "changes": changes[offset : offset + limit],
        }
        if offset + limit < len(changes):
            out["next_offset"] = offset + limit
        if warnings:
            out["warnings"] = warnings[:20]
        text = json.dumps(out, default=str)
        while len(out["changes"]) > 1 and len(text) > max_chars():
            out["changes"] = out["changes"][: len(out["changes"]) // 2]
            out["next_offset"] = offset + len(out["changes"])
            out["truncated"] = True
            text = json.dumps(out, default=str)
        return _result(out)
