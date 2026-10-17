"""Policy bundle import (F45): plan and apply a bundle from fmc_export_policy_bundle in a target domain or
FMC, by name, in dependency order (objects -> zones -> policies -> rules).

What is applied:
- objects: missing ones are created (leaves in bulk per type, then groups level by level); one with the same
  name and value is reused; same name, different value is a conflict unless `update_objects` (then updated,
  which changes every policy using it). Objects inherited from an ancestor domain must exist.
- security zones and interface groups: created when missing, without interfaces (device-specific).
- access policy: created (default action, categories, rules in order, prefilter/identity/decryption links),
  or updated: default action, added rules at their position, changed rules replaced; rules missing from the
  bundle are deleted only with `delete_extra_rules`; reordered existing rules are reported, not moved.
- prefilter and NAT policies: created with their rules when the target has none of that name; an existing one
  is linked (prefilter) or left alone, and a difference is reported.
- must already exist in the target: identity, decryption and intrusion policies, time ranges, realms and their
  users/groups, file policies, variable sets, applications, URL categories, geolocations, syslog/SNMP alerts.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import copy
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import REALM_GROUPS, REALM_USERS, RefResolver
from fmc_mcp.tools.bundle import (
    DECRYPTION,
    IDENTITY,
    BundleRef,
    Exporter,
    diff_rules,
    field_delta,
    generic_rule,
    object_entry,
    parse_bundle,
)
from fmc_mcp.tools.common import OBJECT_TYPES, Domain, type_for
from fmc_mcp.tools.identity import REALMS
from fmc_mcp.tools.intrusion import IPS
from fmc_mcp.tools.policies import ACCESS, NAT, PREFILTER, all_rules
from fmc_mcp.tools.policy_writes import BLOCKING, LogMode, _conditions, _log_fields
from fmc_mcp.tools.rule_io import CONDITIONS

CHUNK = 100
COLLECTION_CAP = 50_000
# Reference types that are not objects in OBJECT_TYPES: where to find them by name in the target.
REF_PATHS = {
    "intrusionpolicy": IPS,
    "filepolicy": "policy/filepolicies",
    "variableset": "object/variablesets",
    "realm": REALMS,
    "realmuser": REALM_USERS,
    "realmusergroup": REALM_GROUPS,
    "accesspolicy": ACCESS,
    "prefilterpolicy": PREFILTER,
    "ftdnatpolicy": NAT,
    "identitypolicy": IDENTITY,
    "decryptionpolicy": DECRYPTION,
    "syslogalert": "policy/syslogalerts",
    "snmpalert": "policy/snmpalerts",
    "isesecuritygrouptag": "object/isesecuritygrouptags",
    "securitygrouptag": "object/securitygrouptags",
    "continent": "object/continents",
    "country": "object/countries",
}
GROUP_TYPES = {"networkgroup", "portobjectgroup", "urlgroup", "vlangrouptag"}
# Ignored when comparing an object in the bundle with the target's: not part of what a rule matches.
COMPARE_SKIP = {"description", "domain", "version", "overridable"}
ZONE_SECTIONS = {"security_zones": "SecurityZone", "interface_groups": "InterfaceGroup"}
# Access policy settings the importer links by name: bundle settings key <-> FMC field.
LINKS = {
    "prefilter_policy": "prefilterPolicySetting",
    "identity_policy": "identityPolicySetting",
    "decryption_policy": "decryptionPolicySetting",
}
LINKS_BY_FIELD = {v: k for k, v in LINKS.items()}
RULE_PATHS = {"prefilter": "prefilterrules", "nat_manual": "manualnatrules", "nat_auto": "autonatrules"}


class BundleImportError(InvalidRequest):
    pass


def _plain(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k not in COMPARE_SKIP}


def deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def group_levels(groups: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Group keys ('Type/name') in creation order: a group comes after every group it contains."""
    deps = {
        key: {
            f"{m.get('type')}/{m.get('name')}"
            for m in entry.get("objects") or []
            if f"{m.get('type')}/{m.get('name')}" in groups
        }
        for key, entry in groups.items()
    }
    levels: list[list[str]] = []
    done: set[str] = set()
    while len(done) < len(deps):
        level = sorted(k for k, d in deps.items() if k not in done and d <= done)
        if not level:
            raise BundleImportError(f"Groups contain each other in a cycle: {sorted(set(deps) - done)}.")
        levels.append(level)
        done |= set(level)
    return levels


class Target:
    """The target domain, looked up by name. Collections are read once and updated as objects are made."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app = app
        self.domain = domain
        self._items: dict[str, dict[str, list[dict[str, Any]]]] = {}

    @staticmethod
    def path_for(fmc_type: str | None) -> str | None:
        t = type_for(fmc_type)
        return t.path if t else REF_PATHS.get(str(fmc_type or "").lower())

    async def items(self, path: str) -> dict[str, list[dict[str, Any]]]:
        if path not in self._items:
            page = await self.app.all(await self.app.config_path(path, self.domain), cap=COLLECTION_CAP)
            by_name: dict[str, list[dict[str, Any]]] = {}
            for o in page.items:
                by_name.setdefault(str(o.get("name", "")).lower(), []).append(o)
            self._items[path] = by_name
        return self._items[path]

    def remember(self, path: str, obj: dict[str, Any]) -> None:
        self._items.setdefault(path, {}).setdefault(str(obj.get("name", "")).lower(), []).insert(0, obj)

    async def find(self, fmc_type: str | None, name: Any, realm: str | None = None) -> dict[str, Any] | None:
        path = self.path_for(fmc_type)
        if path is None or name is None:
            return None
        found = (await self.items(path)).get(str(name).lower()) or []
        if realm:  # realm users and groups repeat across realms
            found = [o for o in found if str((o.get("realm") or {}).get("name", "")).lower() == realm.lower()]
        return found[0] if found else None

    async def resolve(self, value: Any, where: str, *, nested: bool = False) -> Any:
        """A copy with every nested by-name reference ({name, type}, no id) given the target's id (the
        top-level value is the body being written, not a reference)."""
        if isinstance(value, list):
            return [await self.resolve(v, where, nested=True) for v in value]
        if not isinstance(value, dict):
            return value
        out = {k: await self.resolve(v, where, nested=True) for k, v in value.items()}
        if (
            nested
            and "name" in value
            and "type" in value
            and "id" not in value
            and self.path_for(value["type"])
        ):
            realm = (value.get("realm") or {}).get("name") if isinstance(value.get("realm"), dict) else None
            hit = await self.find(value["type"], value["name"], realm)
            if hit is None:
                raise BundleImportError(
                    f"{where}: {value['type']} {value['name']!r} doesn't exist in the target."
                )
            out["id"] = hit["id"]
        return out


def refs_by_type(value: Any) -> set[tuple[str, str, str | None]]:
    """(type, name, realm) of every by-name reference in a bundle section."""
    out: set[tuple[str, str, str | None]] = set()
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            if "name" in v and "type" in v and isinstance(v["type"], str):
                realm = v["realm"].get("name") if isinstance(v.get("realm"), dict) else None
                out.add((v["type"], str(v["name"]), realm))
            stack.extend(v.values())
    return out


class Planner:
    def __init__(
        self,
        app: FmcApp,
        bundle: dict[str, Any],
        policy: str | None,
        domain: str | None,
        update_objects: bool,
        delete_extra_rules: bool,
    ) -> None:
        self.app = app
        self.bundle = bundle
        self.domain = domain
        self.target = Target(app, domain)
        self.update_objects = update_objects
        self.delete_extra = delete_extra_rules
        self.policy_name = policy or (bundle.get("access_policy") or {}).get("name")
        self.blockers: list[str] = []
        self.warnings: list[str] = []
        self.objects: dict[str, list[dict[str, Any]]] = {"create": [], "update": [], "reuse": []}
        self.zones: list[dict[str, Any]] = []
        self.policies: list[dict[str, Any]] = []
        self.rule_changes: list[dict[str, Any]] = []
        self.existing_acp: dict[str, Any] | None = None
        self.live_rules: list[dict[str, Any]] = []

    # --- planning ------------------------------------------------------------------------------

    async def plan(self) -> None:
        if not self.policy_name:
            raise InvalidRequest("The bundle has no access_policy.")
        await self._objects()
        await self._zones()
        await self._prerequisites()
        await self._linked_policies()
        await self._access_policy()

    async def _objects(self) -> None:
        domain_name = await self.app.domain_name(await self.app.domain_uuid(self.domain))
        for fmc_type, items in (self.bundle.get("objects") or {}).items():
            otype = type_for(fmc_type)
            for name, entry in items.items():
                key = {"type": fmc_type, "name": name}
                have = await self.target.find(fmc_type, name)
                if have is None:
                    if entry.get("domain"):
                        self.blockers.append(
                            f"{fmc_type} {name!r} comes from domain {entry['domain']!r}, which the target "
                            "doesn't see; import into a domain below it, or create the object there first."
                        )
                    elif otype is None or not otype.writable:
                        self.blockers.append(
                            f"{fmc_type} {name!r} doesn't exist in the target; create it first."
                        )
                    else:
                        self.objects["create"].append({**key, "entry": entry})
                    continue
                theirs = object_entry(have, domain_name)
                delta = field_delta(_plain(theirs), _plain(entry))
                if not delta:
                    self.objects["reuse"].append(key)
                elif (have.get("metadata") or {}).get("readOnly", {}).get("state"):
                    self.warnings.append(
                        f"{fmc_type} {name!r} is read-only in the target and differs from the bundle "
                        f"({', '.join(delta)}); the target's value is used."
                    )
                    self.objects["reuse"].append(key)
                elif self.update_objects:
                    self.objects["update"].append({**key, "entry": entry, "id": have["id"], "fields": delta})
                else:
                    self.blockers.append(
                        f"{fmc_type} {name!r} exists in the target with a different value "
                        f"({', '.join(delta)}). Rename it in the bundle, or set update_objects=true to "
                        "change it (every policy using it changes too)."
                    )

    async def _zones(self) -> None:
        for section, fmc_type in ZONE_SECTIONS.items():
            for name, entry in (self.bundle.get(section) or {}).items():
                have = await self.target.find(fmc_type, name)
                if have is None:
                    self.zones.append(
                        {"type": fmc_type, "name": name, "interfaceMode": entry.get("interfaceMode")}
                    )
                    if entry.get("interfaces"):
                        self.warnings.append(
                            f"{fmc_type} {name!r} is created without interfaces; assign them per device "
                            "(fmc_update_interface)."
                        )
                elif have.get("interfaceMode") != entry.get("interfaceMode"):
                    self.blockers.append(
                        f"{fmc_type} {name!r} exists with interface mode {have.get('interfaceMode')}, the "
                        f"bundle has {entry.get('interfaceMode')}."
                    )
        for name in self.bundle.get("time_ranges") or {}:
            if await self.target.find("TimeRange", name) is None:
                self.blockers.append(f"Time range {name!r} doesn't exist in the target; create it first.")

    async def _prerequisites(self) -> None:
        """References the importer doesn't create (policies, realms, alerts, ...) must exist."""
        managed = {t.fmc_type.lower() for t in OBJECT_TYPES.values()} | {
            "accesspolicy",
            "prefilterpolicy",
            "ftdnatpolicy",
            "identitypolicy",
            "decryptionpolicy",
        }
        sections = [self.bundle.get("access_policy"), self.bundle.get("prefilter_policy")]
        sections += list((self.bundle.get("nat_policies") or {}).values())
        missing: set[str] = set()
        for fmc_type, name, realm in sorted(refs_by_type(sections), key=str):
            if fmc_type.lower() in managed or Target.path_for(fmc_type) is None:
                continue
            if await self.target.find(fmc_type, name, realm) is None:
                missing.add(f"{fmc_type} {name!r}" + (f" (realm {realm!r})" if realm else ""))
        for name, entry in (self.bundle.get("intrusion_policies") or {}).items():
            if await self.target.find("IntrusionPolicy", name) is None:
                kind = "built-in" if entry.get("system") else "custom"
                missing.add(f"IntrusionPolicy {name!r} ({kind})")
        for label in sorted(missing):
            self.blockers.append(f"{label} doesn't exist in the target; create it first.")

    async def _linked_policies(self) -> None:
        for section, fmc_type in (
            ("identity_policy", "IdentityPolicy"),
            ("decryption_policy", "DecryptionPolicy"),
        ):
            p = self.bundle.get(section)
            if p and await self.target.find(fmc_type, p["name"]) is None:
                self.blockers.append(
                    f"{fmc_type} {p['name']!r} doesn't exist in the target; create it first."
                )
        if self.bundle.get("identity_policy"):
            self.warnings.append(
                f"Select identity policy {self.bundle['identity_policy']['name']!r} in the access policy "
                "editor's Identity step: FMC 10.0's REST API ignores identityPolicySetting."
            )
        pre = self.bundle.get("prefilter_policy")
        if pre:
            have = await self.target.find("PrefilterPolicy", pre["name"])
            if have is None and pre.get("system"):
                self.blockers.append(f"PrefilterPolicy {pre['name']!r} doesn't exist in the target.")
            elif have is None:
                self.policies.append({"kind": "prefilter", "name": pre["name"], "op": "create"})
            else:
                self.policies.append({"kind": "prefilter", "name": pre["name"], "op": "reuse"})
                if not pre.get("system"):
                    await self._compare_existing("prefilter", PREFILTER, "prefilterrules", have, pre)
        for name, p in (self.bundle.get("nat_policies") or {}).items():
            have = await self.target.find("FTDNatPolicy", name)
            if have is None:
                self.policies.append({"kind": "nat", "name": name, "op": "create"})
            else:
                self.policies.append({"kind": "nat", "name": name, "op": "reuse"})
                await self._compare_existing("nat", NAT, "natrules", have, p)

    async def _compare_existing(
        self, kind: str, path: str, sub: str, have: dict[str, Any], want: dict[str, Any]
    ) -> None:
        ex = Exporter(self.app, self.domain)
        rules = await ex._rules(f"{path}/{have['id']}/{sub}")
        live = [generic_rule(r) for r in rules]
        changes = diff_rules(kind, live, list(want.get("rules") or []))
        if changes:
            self.warnings.append(
                f"The target's {kind} policy {have.get('name')!r} differs from the bundle in "
                f"{len(changes)} rule(s); this import doesn't change an existing prefilter or NAT policy."
            )

    async def _access_policy(self) -> None:
        acp = self.bundle["access_policy"]
        have = await self.target.find("AccessPolicy", self.policy_name)
        want_rules = list(acp.get("rules") or [])
        if have is None:
            self.policies.append({"kind": "access", "name": self.policy_name, "op": "create"})
            self.rule_changes = [
                {"section": "access_policy.rules", "op": "added", "key": r.get("name"), "position": i + 1}
                for i, r in enumerate(want_rules)
            ]
            return
        self.existing_acp = have
        ex = Exporter(self.app, self.domain)
        live = await ex.access_policy(have)
        self.live_rules = list(live.get("rules") or [])
        self.policies.append({"kind": "access", "name": self.policy_name, "op": "update"})
        if field_delta(live.get("default_action"), acp.get("default_action")):
            self.policies[-1]["default_action"] = field_delta(
                live.get("default_action"), acp.get("default_action")
            )
        links = {
            k: {"from": (live.get("settings") or {}).get(k), "to": v}
            for k, v in (acp.get("settings") or {}).items()
            if k in LINKS and (live.get("settings") or {}).get(k) != v
        }
        if links:
            self.policies[-1]["links"] = links
        missing_cats = [c for c in acp.get("categories") or [] if c not in (live.get("categories") or [])]
        if missing_cats:
            self.policies[-1]["categories_to_create"] = missing_cats
        changes = diff_rules("access_policy.rules", self.live_rules, want_rules)
        for ch in changes:
            if ch["op"] == "moved" or (ch["op"] == "changed" and ch.get("after") is not None):
                self.warnings.append(
                    f"Rule {ch['key']!r} is at a different position in the bundle; this import doesn't "
                    "reorder existing rules (move it with fmc_update_access_rule move_to)."
                )
            if ch["op"] == "removed" and not self.delete_extra:
                self.warnings.append(
                    f"Rule {ch['key']!r} isn't in the bundle and is kept (delete_extra_rules)."
                )
        self.rule_changes = [
            c
            for c in changes
            if c["op"] in ("added", "changed") or (c["op"] == "removed" and self.delete_extra)
        ]
        entry = self.policies[-1]
        if not self.rule_changes and not {"default_action", "categories_to_create", "links"} & set(entry):
            entry["op"] = "reuse"

    def summary(self) -> dict[str, Any]:
        ops: dict[str, int] = {}
        for c in self.rule_changes:
            ops[c["op"]] = ops.get(c["op"], 0) + 1
        return {
            "target_policy": self.policy_name,
            "objects": {k: len(v) for k, v in self.objects.items() if v},
            "zones_to_create": [f"{z['type']} {z['name']}" for z in self.zones] or None,
            "policies": self.policies,
            "access_rules": ops or None,
        }

    def details(self) -> dict[str, Any]:
        out = self.summary()
        out["objects_to_create"] = [f"{o['type']} {o['name']}" for o in self.objects["create"]][:50] or None
        out["objects_to_update"] = [
            {"object": f"{o['type']} {o['name']}", "fields": o["fields"]} for o in self.objects["update"]
        ] or None
        out["rule_changes"] = [
            {k: v for k, v in c.items() if k in ("op", "key", "position", "after", "fields")}
            for c in self.rule_changes
        ][:100] or None
        if self.warnings:
            out["warnings"] = self.warnings[:30]
        return {k: v for k, v in out.items() if v is not None}

    def count(self) -> int:
        return (
            len(self.objects["create"])
            + len(self.objects["update"])
            + len(self.zones)
            + sum(1 for p in self.policies if p["op"] in ("create", "update"))
            + len(self.rule_changes)
        )

    # --- applying ------------------------------------------------------------------------------

    async def apply(self) -> dict[str, Any]:
        done: list[str] = []
        try:
            await self._apply_objects(done)
            await self._apply_zones(done)
            linked = await self._apply_linked(done)
            await self._apply_access(done, linked)
        except Exception as e:
            raise UpstreamError(
                f"Import stopped after {len(done)} change(s) (last: {', '.join(done[-5:]) or 'none'}): {e}. "
                "Nothing applied is rolled back; plan again to see what is left.",
                getattr(e, "status_code", None),
            ) from e
        finally:
            self.app.invalidate_cache()
        return {
            "target_policy": self.policy_name,
            "applied": len(done),
            "changes": done[:100],
            "next": "fmc_pending_changes, then assign the policy (fmc_assign_policy) and fmc_deploy",
        }

    async def _post(self, path: str, body: Any, params: dict[str, Any] | None = None) -> Any:
        return await self.app.api.post(await self.app.config_path(path, self.domain), body, params=params)

    async def _put(self, path: str, body: Any) -> Any:
        return await self.app.api.put(await self.app.config_path(path, self.domain), body)

    async def _apply_objects(self, done: list[str]) -> None:
        leaves: dict[str, list[dict[str, Any]]] = {}
        groups: dict[str, dict[str, Any]] = {}
        for o in self.objects["create"]:
            if o["type"].lower() in GROUP_TYPES:
                groups[f"{o['type']}/{o['name']}"] = o
            else:
                leaves.setdefault(o["type"], []).append(o)
        for fmc_type, items in leaves.items():
            path = str(Target.path_for(fmc_type))
            bodies = [{"name": o["name"], "type": fmc_type, **_plain(o["entry"])} for o in items]
            for i in range(0, len(bodies), CHUNK):
                await self._create(path, bodies[i : i + CHUNK], done)
        for level in group_levels({k: g["entry"] for k, g in groups.items()}):
            by_type: dict[str, list[dict[str, Any]]] = {}
            for key in level:
                g = groups[key]
                body = {"name": g["name"], "type": g["type"], **_plain(g["entry"])}
                by_type.setdefault(g["type"], []).append(await self.target.resolve(body, key))
            for fmc_type, bodies in by_type.items():
                await self._create(str(Target.path_for(fmc_type)), bodies, done)
        for o in self.objects["update"]:
            path = str(Target.path_for(o["type"]))
            body = {"id": o["id"], "name": o["name"], "type": o["type"], **_plain(o["entry"])}
            body = await self.target.resolve(body, f"{o['type']} {o['name']}")
            await self._put(f"{path}/{o['id']}", body)
            done.append(f"updated {o['type']} {o['name']}")

    async def _create(self, path: str, bodies: list[dict[str, Any]], done: list[str]) -> None:
        resp = await self._post(path, bodies, {"bulk": "true"})
        created = (resp or {}).get("items") if isinstance(resp, dict) else resp
        for obj in created or []:
            if isinstance(obj, dict) and obj.get("id"):
                self.target.remember(path, obj)
        done += [f"created {b['type']} {b['name']}" for b in bodies]

    async def _apply_zones(self, done: list[str]) -> None:
        for z in self.zones:
            path = str(Target.path_for(z["type"]))
            body = {"name": z["name"], "type": z["type"], "interfaceMode": z["interfaceMode"]}
            obj = await self._post(path, body)
            self.target.remember(path, obj or {**body, "id": None})
            done.append(f"created {z['type']} {z['name']}")

    async def _apply_linked(self, done: list[str]) -> dict[str, dict[str, Any]]:
        """Create the prefilter and NAT policies the target lacks; the refs the access policy links to."""
        linked: dict[str, dict[str, Any]] = {}
        for p in self.policies:
            if p["kind"] == "prefilter":
                want = self.bundle["prefilter_policy"]
                if p["op"] == "create":
                    body = {
                        "name": want["name"],
                        "type": "PrefilterPolicy",
                        **({"description": want["description"]} if want.get("description") else {}),
                    }
                    if want.get("defaultAction"):
                        body["defaultAction"] = await self.target.resolve(want["defaultAction"], want["name"])
                    obj = await self._post(PREFILTER, body)
                    self.target.remember(PREFILTER, obj)
                    done.append(f"created prefilter policy {want['name']}")
                    await self._generic_rules(PREFILTER, obj["id"], want, done)
                found = await self.target.find("PrefilterPolicy", want["name"])
                if found:
                    linked["prefilterPolicySetting"] = {
                        "id": found["id"],
                        "type": "PrefilterPolicy",
                        "name": found.get("name"),
                    }
            elif p["kind"] == "nat" and p["op"] == "create":
                want = self.bundle["nat_policies"][p["name"]]
                body = {"name": p["name"], "type": "FTDNatPolicy"}
                if want.get("description"):
                    body["description"] = want["description"]
                obj = await self._post(NAT, body)
                done.append(f"created NAT policy {p['name']}")
                await self._generic_rules(NAT, obj["id"], {**want, "name": p["name"]}, done)
        for section, field, fmc_type in (
            ("identity_policy", "identityPolicySetting", "IdentityPolicy"),
            ("decryption_policy", "decryptionPolicySetting", "DecryptionPolicy"),
        ):
            want = self.bundle.get(section)
            if want:
                found = await self.target.find(fmc_type, want["name"])
                if found:
                    linked[field] = {"id": found["id"], "type": fmc_type, "name": found.get("name")}
        return linked

    async def _generic_rules(self, path: str, pid: str, want: dict[str, Any], done: list[str]) -> None:
        for rule in want.get("rules") or []:
            body = {k: v for k, v in rule.items() if k not in ("section", "category")}
            label = f"{want['name']} rule {rule.get('name') or '#'}"
            body = await self.target.resolve(body, label)
            params: dict[str, Any] = {}
            if path == NAT:
                auto = str(rule.get("type")) == "FTDAutoNatRule"
                sub = RULE_PATHS["nat_auto" if auto else "nat_manual"]
                if not auto and rule.get("section"):
                    params["section"] = rule["section"]
            else:
                sub = RULE_PATHS["prefilter"]
            await self._post(f"{path}/{pid}/{sub}", body, params or None)
            done.append(f"created {label}")

    async def access_body(self, row: dict[str, Any], resolver: RefResolver) -> dict[str, Any]:
        where = f"rule {row.get('name')!r}"
        action = str(row.get("action"))
        body: dict[str, Any] = {
            "name": row.get("name"),
            "type": "AccessRule",
            "action": action,
            "enabled": row.get("enabled", True),
        }
        try:
            conds = await _conditions(
                resolver, {param: row.get(col) for col, (param, _) in CONDITIONS.items()}
            )
        except (InvalidRequest, UpstreamError) as e:
            raise BundleImportError(f"{where}: {e}") from e
        body.update({k: v for k, v in conds.items() if v})
        log = row.get("log") or "none"
        if log == "begin" and action not in BLOCKING:
            body.update({"logBegin": True, "logEnd": False, "sendEventsToFMC": True})
        else:
            modes: dict[str, LogMode] = {
                "none": "none",
                "end": "end",
                "begin": "end",  # block rules log at the start
                "begin_and_end": "begin_and_end",
            }
            body.update(_log_fields(modes.get(str(log), "none"), action))
        if row.get("intrusion_policy"):
            ips = await self.target.find("IntrusionPolicy", row["intrusion_policy"])
            if ips is None:
                raise BundleImportError(
                    f"{where}: intrusion policy {row['intrusion_policy']!r} doesn't exist."
                )
            body["ipsPolicy"] = {"id": ips["id"], "type": "IntrusionPolicy", "name": ips.get("name")}
        raw = await self.target.resolve(copy.deepcopy(row.get("raw") or {}), where)
        return deep_merge(body, raw)

    async def _apply_access(self, done: list[str], linked: dict[str, dict[str, Any]]) -> None:
        acp = self.bundle["access_policy"]
        default = await self.target.resolve(copy.deepcopy(acp.get("default_action") or {}), "default action")
        if self.existing_acp is None:
            body = {"name": self.policy_name, "type": "AccessPolicy", "defaultAction": default}
            if acp.get("description"):
                body["description"] = acp["description"]
            policy = await self._post(ACCESS, body)
            done.append(f"created access policy {self.policy_name}")
            cats = list(acp.get("categories") or [])
        else:
            policy = self.existing_acp
            cats = next(
                (p.get("categories_to_create") or [] for p in self.policies if p["kind"] == "access"), []
            )
        pid = policy["id"]
        for cat in cats:
            await self._post(f"{ACCESS}/{pid}/categories", {"name": cat, "type": "Category"})
            done.append(f"created category {cat}")
        entry = next((p for p in self.policies if p["kind"] == "access"), {})
        if self.existing_acp is not None:  # an existing policy keeps the links the bundle doesn't change
            linked = {f: v for f, v in linked.items() if LINKS_BY_FIELD[f] in entry.get("links", {})}
        if linked or "default_action" in entry:
            # Only the fields that change: FMC refuses a PUT that carries the policy's rules back.
            current = await self.app.api.get(await self.app.config_path(f"{ACCESS}/{pid}", self.domain)) or {}
            policy_body: dict[str, Any] = {
                "id": pid,
                "name": current.get("name") or self.policy_name,
                "type": "AccessPolicy",
                "defaultAction": {**default, "id": (current.get("defaultAction") or {}).get("id")},
                **linked,
            }
            if current.get("description"):
                policy_body["description"] = current["description"]
            await self._put(f"{ACCESS}/{pid}", policy_body)
            done.append(f"updated access policy {self.policy_name} settings")
        await self._apply_rules(pid, done)

    async def _apply_rules(self, pid: str, done: list[str]) -> None:
        resolver = RefResolver(self.app, self.domain)
        want = list(self.bundle["access_policy"].get("rules") or [])
        base = f"{ACCESS}/{pid}/accessrules"
        live = await all_rules(self.app, await self.app.config_path(base, self.domain))
        order = [
            str(r.get("name"))
            for r in sorted(live.items, key=lambda r: (r.get("metadata") or {}).get("ruleIndex") or 0)
        ]
        ids = {str(r.get("name")): r["id"] for r in live.items}
        # FMC files an inserted rule into the section/category of the rule it is inserted before, so an
        # anchor must be in the same place as the new rule.
        place = {str(r.get("name")): _place_of_live(r) for r in live.items}
        want_names = [str(r.get("name")) for r in want]
        by_name = {str(r.get("name")): r for r in want}
        for ch in self.rule_changes:
            name = str(ch["key"])
            if ch["op"] == "removed":
                await self.app.api.delete(await self.app.config_path(f"{base}/{ids[name]}", self.domain))
                order.remove(name)
                done.append(f"deleted rule {name}")
                continue
            row = by_name[name]
            body = await self.access_body(row, resolver)
            if ch["op"] == "changed":
                body["id"] = ids[name]
                await self._put(f"{base}/{ids[name]}", body)
                done.append(f"updated rule {name}")
                continue
            # added: before the next bundle rule in the same place, or right after the previous one, else at
            # the end of its section/category
            group = _place_of_row(row)
            at = want_names.index(name)
            same = [n for n in order if place.get(n) == group]
            anchor = next((n for n in want_names[at + 1 :] if n in same), None)
            prev = next((n for n in reversed(want_names[:at]) if n in same), None)
            params: dict[str, Any] = {}
            if anchor is not None:
                params["insertBefore"] = order.index(anchor) + 1
                order.insert(order.index(anchor), name)
            elif (
                prev is not None
                and order.index(prev) + 1 < len(order)
                and (place.get(order[order.index(prev) + 1]) == group)
            ):
                params["insertBefore"] = order.index(prev) + 2  # right after the rule it follows
                order.insert(order.index(prev) + 1, name)
            else:
                if row.get("category"):
                    params["category"] = row["category"]
                else:
                    params["section"] = row.get("section") or "default"
                pos = max((order.index(n) for n in same), default=len(order) - 1) + 1
                order.insert(pos, name)
            place[name] = group
            created = await self._post(base, body, params)
            ids[name] = (created or {}).get("id", "")
            done.append(f"created rule {name}")


def _place_of_live(r: dict[str, Any]) -> tuple[str, str | None]:
    meta = r.get("metadata") or {}
    cat = meta.get("category")
    return str(meta.get("section") or "default").lower(), None if cat in (None, "", "--Undefined--") else cat


def _place_of_row(row: dict[str, Any]) -> tuple[str, str | None]:
    return str(row.get("section") or "default").lower(), row.get("category") or None


async def make_plan(
    ctx: Context,
    bundle: str,
    policy: str | None,
    domain: str | None,
    update_objects: bool,
    delete_extra_rules: bool,
) -> Planner:
    app: FmcApp = get_client(ctx)
    data = await asyncio.to_thread(parse_bundle, bundle, app.settings.bundle_dir)
    planner = Planner(app, data, policy, domain, update_objects, delete_extra_rules)
    await planner.plan()
    return planner


PolicyName = Annotated[
    str | None,
    Field(description="Access policy to create or update in the target (default: the bundle's policy name)"),
]
UpdateObjects = Annotated[
    bool,
    Field(
        description="Update objects that exist in the target with a different value (changes every policy "
        "using them); default: such conflicts block the import"
    ),
]
DeleteExtra = Annotated[
    bool, Field(description="Delete rules of an existing target policy that aren't in the bundle")
]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Plan a policy bundle import")
    async def fmc_plan_policy_bundle_import(
        ctx: Context,
        bundle: BundleRef,
        policy: PolicyName = None,
        domain: Domain = None,
        update_objects: UpdateObjects = False,
        delete_extra_rules: DeleteExtra = False,
    ) -> dict[str, Any]:
        """What fmc_import_policy_bundle would do with a bundle from fmc_export_policy_bundle in a target
        domain (or another FMC): objects to create, reuse or update (same name, different value is a
        conflict), zones to create, prefilter/NAT policies to create or reuse, the access policy to create or
        update with each rule added, changed or deleted, and blockers: prerequisites the import doesn't
        create (identity, decryption and intrusion policies, time ranges, realms, ...). Read-only."""
        planner = await make_plan(ctx, bundle, policy, domain, update_objects, delete_extra_rules)
        out = planner.details()
        out["changes"] = planner.count()
        if planner.blockers:
            out["blockers"] = planner.blockers[:30]
        out["ready"] = not planner.blockers and planner.count() > 0
        if not planner.count() and not planner.blockers:
            out["note"] = "The target already matches the bundle."
        return out

    @reg.dangerous(title="Import a policy bundle")
    async def fmc_import_policy_bundle(
        ctx: Context,
        bundle: BundleRef,
        policy: PolicyName = None,
        domain: Domain = None,
        update_objects: UpdateObjects = False,
        delete_extra_rules: DeleteExtra = False,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Apply a bundle from fmc_export_policy_bundle to a target domain or FMC (PoC to production, one
        domain to another): creates missing objects and zones, prefilter and NAT policies the target lacks,
        and creates or updates the access policy and its rules, in dependency order and in bulk where FMC
        allows. Stops at the first failure and reports what was applied (nothing is rolled back). The preview
        is fmc_plan_policy_bundle_import's plan. Respects the change window and an open change ticket.
        Nothing reaches devices until you assign the policy and deploy."""
        planner = await make_plan(ctx, bundle, policy, domain, update_objects, delete_extra_rules)
        blockers = list(planner.blockers[:20])
        if not planner.count() and not blockers:
            blockers.append("Nothing to import: the target already matches the bundle.")
        owned = [planner.existing_acp] if planner.existing_acp else []
        source = (planner.bundle.get("meta") or {}).get("policy")
        return await fmc_preview(
            ctx,
            tool="fmc_import_policy_bundle",
            args={
                "bundle": bundle,
                "policy": policy,
                "domain": domain,
                "update_objects": update_objects,
                "delete_extra_rules": delete_extra_rules,
            },
            confirm=confirm,
            owned=owned,
            plan=Plan(
                f"Import bundle {source!r} as {planner.policy_name!r}",
                details=planner.details(),
                fingerprint={
                    "summary": planner.summary(),
                    "rules": [r.get("name") for r in planner.live_rules],
                    "digest": (planner.bundle.get("meta") or {}).get("digest"),
                },
                blockers=blockers,
                blast_radius=planner.count(),
                side_effects=[
                    "Configuration only: assign the policy and deploy to take effect.",
                    "Stops at the first failure; changes already made stay.",
                ]
                + (
                    ["Updated objects change every policy that uses them."]
                    if planner.objects["update"]
                    else []
                ),
            ),
            apply=planner.apply,
        )
