"""F101: fmc_flexconfig_review + fmc_migrate_flexconfig: find FlexConfig that FMC now configures natively,
and run FMC's own FlexConfig migration.

Shapes follow the FMC 10.0.1 OpenAPI: GET policy/flexconfigpolicies(/{objectId}) answers a FlexConfig policy
with name, description and id only (schema FlexConfig: "a container of an ordered list of FlexConfig
objects", but the list is not in the schema), there is no FlexConfig object endpoint, and the devices come
from policy assignments (policy type FlexConfigPolicy). The review therefore reads object names from the
policy record when FMC includes them, else from `objects` (names the user read in the GUI), and says where
the bodies are in the GUI. POST policy/flexconfigpolicies/{containerUUID}/migrate (schema
FlexConfigMigration, `targetDeviceList` of ITarget) starts the migration; its task is followed like other
FMC tasks.

Cisco source: Secure Firewall Management Center Device Configuration Guide 10.0, 'FlexConfig Policies' >
'Migrating FlexConfig Policies' (FlexConfig for natively supported features is not supported by TAC and is
the first thing to break on an upgrade)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from dataclasses import dataclass
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.dangerous import Wait, finish
from fmc_mcp.tools.device_export import resolve_target
from fmc_mcp.tools.policies import policy_assignments

FLEXCONFIG = "policy/flexconfigpolicies"
POLICY_TYPE = "FlexConfigPolicy"
MAX_POLICIES = 50  # a review without a policy or device reads each policy record once
GUI_POLICY = "Devices > FlexConfig > edit '{name}' (Selected Prepend / Append FlexConfigs, in order)"
GUI_OBJECT = "Objects > Object Management > FlexConfig > FlexConfig Object > '{name}' (the CLI it pushes)"
NO_OBJECTS_IN_REST = (
    "FMC's REST API does not return a FlexConfig policy's objects or any object's CLI (the FlexConfig "
    "schema has a name and description only, and there is no FlexConfig object endpoint)."
)


@dataclass(frozen=True)
class Native:
    """A feature FMC 10.0 configures natively that FlexConfig was commonly used for."""

    feature: str
    tokens: tuple[str, ...]  # name tokens (lower case, split on non-alphanumerics) that point at it
    where: str  # where FMC configures it natively
    tool: str | None = None  # this server's tool for it, when there is one


NATIVE: tuple[Native, ...] = (
    Native("EIGRP", ("eigrp",), "Devices > Device Management > Routing > EIGRP"),
    Native(
        "Policy-based routing",
        ("pbr", "policy-route", "policyroute", "policy_route", "policybasedrouting"),
        "Devices > Device Management > Routing > Policy Based Routing",
    ),
    Native("ECMP", ("ecmp",), "Devices > Device Management > Routing > ECMP", "fmc_configure_ecmp_zone"),
    Native(
        "VXLAN",
        ("vxlan", "vtep", "vni", "nve"),
        "Devices > Device Management > Interfaces > VTEP and VNI interfaces",
    ),
    Native(
        "Connection timeouts",
        ("timeout", "timeouts"),
        "Devices > Platform Settings > Timeouts",
    ),
    Native(
        "NetFlow",
        ("netflow", "flow-export"),
        "Devices > Platform Settings > NetFlow",
        "fmc_configure_netflow",
    ),
    Native("BFD", ("bfd",), "Devices > Device Management > Routing > BFD", "fmc_configure_bfd"),
    Native(
        "OSPF",
        ("ospf", "ospfv2", "ospfv3"),
        "Devices > Device Management > Routing > OSPF",
        "fmc_configure_ospf",
    ),
    Native("BGP", ("bgp",), "Devices > Device Management > Routing > BGP", "fmc_configure_bgp"),
    Native(
        "Multicast routing",
        ("multicast", "pim", "igmp"),
        "Devices > Device Management > Routing > Multicast Routing",
    ),
    Native(
        "SLA monitor / route tracking",
        ("sla", "track"),
        "Objects > Object Management > SLA Monitor",
        "fmc_create_sla_monitor",
    ),
    Native("DNS", ("dns",), "Devices > Platform Settings > DNS", "fmc_configure_dns"),
    Native("SNMP", ("snmp",), "Devices > Platform Settings > SNMP", "fmc_configure_snmp"),
    Native("Syslog", ("syslog", "logging"), "Devices > Platform Settings > Syslog", "fmc_configure_syslog"),
    Native("NTP", ("ntp",), "Devices > Platform Settings > Time Synchronization", "fmc_configure_ntp"),
    Native("Banner", ("banner",), "Devices > Platform Settings > Banner", "fmc_set_banner"),
    Native("DHCP", ("dhcp",), "Devices > Device Management > DHCP", "fmc_configure_dhcp"),
    Native("SSH access", ("ssh",), "Devices > Platform Settings > SSH Access", "fmc_configure_ssh_access"),
)

_SPLIT = re.compile(r"[^a-z0-9-]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def tokens(name: str) -> set[str]:
    """Lower-case words of an object name: 'Eigrp_Interface_Configure', 'PBR-outside', 'ospfV3Setup'."""
    spaced = _CAMEL.sub("_", name)
    words = {w for w in _SPLIT.split(spaced.lower()) if w}
    # also the hyphen-free parts ('policy-route' -> 'policy', 'route') and the whole word joined
    for w in list(words):
        if "-" in w:
            words |= {p for p in w.split("-") if p}
    words.add(re.sub(r"[^a-z0-9]", "", name.lower()))
    return words


def native_matches(name: str) -> list[Native]:
    """The native features an object name points at (empty: FlexConfig may still be the only way)."""
    words = tokens(name)
    joined = re.sub(r"[^a-z0-9]", "", name.lower())  # 'VXLANConfigure' has no word break to split on
    return [n for n in NATIVE if any(t in words or (len(t) >= 4 and t in joined) for t in n.tokens)]


def classify(name: str) -> dict[str, Any]:
    hits = native_matches(name)
    row: dict[str, Any] = {"object": name}
    if hits:
        row["native"] = [
            {"feature": n.feature, "configure_in": n.where, **({"tool": n.tool} if n.tool else {})}
            for n in hits
        ]
    else:
        row["native"] = None
    row["gui"] = GUI_OBJECT.format(name=name)
    return row


# FlexConfig object lists as FMC might include them in a policy record (none are in the 10.0.1 schema). The
# tool reads whichever is there, in this order (prepend runs before FMC's own config, append after).
LIST_KEYS = (
    ("prependFlexConfigs", "prepend"),
    ("prependObjects", "prepend"),
    ("appendFlexConfigs", "append"),
    ("appendObjects", "append"),
    ("flexConfigObjects", None),
    ("selectedFlexConfigs", None),
    ("objects", None),
)


def object_names(policy: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The policy's FlexConfig objects in order, as {name, position}, when the record carries them;
    None when it does not (FMC 10.0.1)."""
    found: list[dict[str, Any]] = []
    seen_key = False
    for key, position in LIST_KEYS:
        rows = policy.get(key)
        if not isinstance(rows, list):
            continue
        seen_key = True
        for r in rows:
            name = ref_label(r)
            if name:
                found.append({"name": name, **({"position": position} if position else {})})
    return found if seen_key else None


async def flexconfig_policies(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(FLEXCONFIG, domain), expanded=False)
    return list(page.items)


async def full_policy(app: FmcApp, ref: dict[str, Any] | str, domain: str | None) -> dict[str, Any]:
    if isinstance(ref, str):
        ref = await resolve_in(app, FLEXCONFIG, ref, "FlexConfig policy", domain)
    data: dict[str, Any] = await app.api.get(await app.config_path(f"{FLEXCONFIG}/{ref['id']}", domain))
    return data


def _target(t: dict[str, Any]) -> dict[str, Any]:
    return {"id": t.get("id"), "type": t.get("type") or "Device", "name": t.get("name")}


async def assignments(app: FmcApp, domain: str | None) -> dict[str, list[dict[str, Any]]]:
    """FlexConfig policy UUID (lower case) -> its targets (devices, HA pairs, clusters)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for a in await policy_assignments(app, domain):
        pol = a.get("policy") or {}
        if pol.get("type") != POLICY_TYPE:
            continue
        pid = str(pol.get("id") or a.get("id") or "").lower()
        out.setdefault(pid, []).extend(_target(t) for t in a.get("targets") or [])
    return out


async def target_ids(app: FmcApp, ref: str, domain: str | None) -> tuple[set[str], str]:
    """Ids a device ref can appear under as an assignment target (the device, its HA pair) and its name."""
    dev, ha = await resolve_target(app, ref, domain)
    ids = {str(dev.get("id")).lower()}
    name = str(dev.get("name"))
    if ha:
        ids.add(str(ha.get("id")).lower())
        name = str(ha.get("name"))
    container = ((dev.get("metadata") or {}).get("containerDetails") or {}).get("id")
    if container:
        ids.add(str(container).lower())
    return ids, name


def _matches(t: dict[str, Any], ref: str) -> bool:
    low = ref.strip().lower()
    return str(t.get("id") or "").lower() == low or str(t.get("name") or "").lower() == low


async def review_one(
    app: FmcApp, policy: dict[str, Any], targets: list[dict[str, Any]], extra: list[str], domain: str | None
) -> dict[str, Any]:
    full = await full_policy(app, policy, domain)
    listed = object_names(full)
    row: dict[str, Any] = {
        "policy": full.get("name") or policy.get("name"),
        "id": full.get("id") or policy.get("id"),
        "devices": [t.get("name") or t.get("id") for t in targets] or None,
    }
    if full.get("description"):
        row["description"] = full["description"]
    names: list[dict[str, Any]] = list(listed or [])
    if extra:
        have = {n["name"].lower() for n in names}
        names += [{"name": n, "from": "objects argument"} for n in extra if n.lower() not in have]
    row["objects"] = [{**classify(n["name"]), **{k: v for k, v in n.items() if k != "name"}} for n in names]
    native = [o for o in row["objects"] if o["native"]]
    row["native_candidates"] = len(native)
    if listed is None:
        row["objects_source"] = "objects argument" if extra else "not in REST"
        row["gui"] = GUI_POLICY.format(name=row["policy"])
    else:
        row["objects_source"] = "policy record"
    # The description sometimes says what the policy is for ('EIGRP to the core'): a hint, not an object.
    hint = native_matches(str(full.get("description") or ""))
    if hint:
        row["description_mentions"] = [n.feature for n in hint]
    return row


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Review FlexConfig")
    async def fmc_flexconfig_review(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="FlexConfig policy name or UUID (omit: every FlexConfig policy)")
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="Device or HA pair (name or UUID): review the FlexConfig policy assigned to it"
            ),
        ] = None,
        objects: Annotated[
            list[str] | None,
            Field(
                description="FlexConfig object names read from the FMC GUI (Devices > FlexConfig > the "
                "policy), classified as well: FMC's REST API does not list a policy's objects"
            ),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Find FlexConfig that FMC now configures natively. For each FlexConfig policy (one by name, the
        one on a device, or all): the devices it is assigned to and its FlexConfig objects in order, each
        flagged when its name points at a feature FMC 10.0 has natively (EIGRP, PBR, ECMP, VXLAN,
        timeouts, NetFlow, BFD, OSPF, BGP, DNS, SNMP, syslog, NTP, ...) with where to configure it and
        this server's tool for it. Cisco's guidance is to migrate those: FlexConfig for a native feature
        is not supported by TAC and breaks on upgrades. FMC's REST API returns neither the policy's
        object list nor any object's CLI, so the review says so and gives the GUI path; pass the names
        from the GUI as `objects` to classify them. Next: fmc_device_snapshot, then fmc_migrate_flexconfig
        (dangerous), then fmc_pending_changes."""
        app: FmcApp = get_client(ctx)
        extra = [o.strip() for o in objects or [] if o and o.strip()]
        assigned = await assignments(app, domain)
        notes: list[str] = []
        if policy:
            pols = [await resolve_in(app, FLEXCONFIG, policy, "FlexConfig policy", domain)]
        else:
            pols = await flexconfig_policies(app, domain)
        if device:
            ids, dev_name = await target_ids(app, device, domain)
            on_dev = {
                pid
                for pid, ts in assigned.items()
                if any(str(t.get("id") or "").lower() in ids or _matches(t, device) for t in ts)
            }
            pols = [p for p in pols if str(p.get("id")).lower() in on_dev]
            if not pols:
                return {
                    "device": dev_name,
                    "policies": [],
                    "summary": f"No FlexConfig policy is assigned to {dev_name!r}"
                    + (f" among {policy!r}" if policy else "")
                    + ": nothing to migrate.",
                }
        if len(pols) > MAX_POLICIES:
            notes.append(f"{len(pols)} FlexConfig policies; reviewed the first {MAX_POLICIES}. Name one.")
            pols = pols[:MAX_POLICIES]
        rows = [
            await review_one(app, p, assigned.get(str(p.get("id")).lower(), []), extra, domain) for p in pols
        ]
        out: dict[str, Any] = {"policies": rows}
        if device:
            out["device"] = dev_name
        candidates = sum(r["native_candidates"] for r in rows)
        hidden = [r["policy"] for r in rows if r["objects_source"] == "not in REST"]
        if not rows:
            out["summary"] = "No FlexConfig policies in this domain: nothing to migrate."
        elif candidates:
            out["summary"] = (
                f"{candidates} FlexConfig object(s) match features FMC configures natively. Take "
                "fmc_device_snapshot of the devices, then fmc_migrate_flexconfig(policy, devices) and check "
                "fmc_pending_changes before fmc_deploy."
            )
        elif hidden and not extra:
            out["summary"] = (
                "The FlexConfig objects are not in the REST API: read their names in the GUI and repeat with "
                "objects=[...] to classify them."
            )
        else:
            out["summary"] = (
                "No FlexConfig object name matches a natively supported feature: keep the FlexConfig (still "
                "check each object's CLI in the GUI; a name is only a hint)."
            )
        if hidden:
            notes.append(
                NO_OBJECTS_IN_REST
                + " GUI: "
                + GUI_POLICY.format(name="<policy>")
                + "; "
                + GUI_OBJECT.format(name="<object>")
                + "."
            )
        notes.append(
            "Names are matched, not CLI: an object named for one feature can push others. "
            "fmc_migrate_flexconfig runs FMC's own converter, which reads the CLI."
        )
        out["notes"] = notes
        return out

    @reg.dangerous(title="Migrate FlexConfig to native configuration")
    async def fmc_migrate_flexconfig(
        ctx: Context,
        policy: Annotated[str, Field(description="FlexConfig policy name or UUID")],
        devices: Annotated[
            list[str] | None,
            Field(
                description="Devices or HA pairs (names or UUIDs) the policy is assigned to; omit for every "
                "device it is assigned to"
            ),
        ] = None,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Run FMC's FlexConfig migration for a FlexConfig policy on its devices: FMC converts the
        FlexConfig objects for natively supported features (EIGRP, PBR, ECMP, VXLAN, timeouts, ...) into
        the devices' native routing, interface and platform configuration and takes them out of the
        FlexConfig. Rewrites the devices' routing and interface configuration in FMC: take
        fmc_device_snapshot of the devices first (the preview says so). With wait, follows FMC's task.
        Nothing reaches a device until fmc_deploy: fmc_pending_changes(device) shows the native
        configuration that replaced the FlexConfig. Review first with fmc_flexconfig_review."""
        app: FmcApp = get_client(ctx)
        pol_ref = await resolve_in(app, FLEXCONFIG, policy, "FlexConfig policy", domain)
        pol = await full_policy(app, pol_ref, domain)
        pid = str(pol.get("id") or pol_ref["id"])
        on_policy = (await assignments(app, domain)).get(pid.lower(), [])
        blockers: list[str] = []
        targets: list[dict[str, Any]] = []
        if devices:
            wanted = list(dict.fromkeys(d.strip() for d in devices if d and d.strip()))
            if not wanted:
                raise InvalidRequest("Name at least one device, or omit devices for every assigned device.")
            for ref in wanted:
                hit = next((t for t in on_policy if _matches(t, ref)), None)
                if hit is None:
                    ids, name = await target_ids(app, ref, domain)
                    hit = next((t for t in on_policy if str(t.get("id") or "").lower() in ids), None)
                    if hit is None:
                        blockers.append(
                            f"{name!r} is not assigned to FlexConfig policy {pol.get('name')!r}"
                            + (
                                f" (assigned: {', '.join(str(t.get('name')) for t in on_policy)})."
                                if on_policy
                                else "."
                            )
                        )
                        continue
                if all(str(t.get("id")).lower() != str(hit.get("id")).lower() for t in targets):
                    targets.append(hit)
        else:
            targets = list(on_policy)
            if not targets:
                blockers.append(
                    f"FlexConfig policy {pol.get('name')!r} is not assigned to any device: nothing to "
                    "migrate."
                )

        listed = object_names(pol)
        review = [classify(n["name"]) for n in listed or []]
        warnings: list[str] = []
        if listed is None:
            warnings.append(
                NO_OBJECTS_IN_REST
                + " Check what it holds in the GUI first: "
                + GUI_POLICY.format(name=pol.get("name"))
                + "."
            )
        elif not any(r["native"] for r in review):
            warnings.append(
                "No FlexConfig object name in this policy matches a natively supported feature: FMC may "
                "find nothing to migrate."
            )
        body = {"type": "FlexConfigMigration", "targetDeviceList": [_target(t) for t in targets]}
        path = await app.config_path(f"{FLEXCONFIG}/{pid}/migrate", domain)
        names = [str(t.get("name") or t.get("id")) for t in targets]

        async def apply() -> Any:
            resp = await app.api.post(path, body)
            # Some releases answer with the TaskStatus itself rather than the request + metadata.task.
            if (
                isinstance(resp, dict)
                and not (resp.get("metadata") or {}).get("task")
                and str(resp.get("type") or "").lower() == "taskstatus"
                and resp.get("id")
            ):
                resp = {**resp, "metadata": {"task": {"id": resp["id"]}}}
            result = await finish(ctx, app, resp, wait, domain, "FlexConfig migration")
            if isinstance(result, dict):
                result["next"] = (
                    "fmc_pending_changes(device) for "
                    + ", ".join(repr(n) for n in names)
                    + ": the native entries that replaced the FlexConfig, and the FlexConfig policy "
                    "emptied of them. Then fmc_deploy, and compare with the snapshot (fmc_device_snapshot "
                    "again, or fmc_run_show_command 'show running-config <section>')."
                )
            return result

        details: dict[str, Any] = {
            "policy": pol.get("name"),
            "devices": names,
            "before": (
                "fmc_device_snapshot(devices=["
                + ", ".join(repr(n) for n in names)
                + "]) first: routing table, interfaces and running-config sections to compare after the "
                "deployment."
            ),
            "body": body,
        }
        if listed is not None:
            details["objects"] = review
        if warnings:
            details["warnings"] = warnings
        return await fmc_preview(
            ctx,
            tool="fmc_migrate_flexconfig",
            args={"policy": policy, "devices": devices, "wait": wait, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Migrate FlexConfig policy {pol.get('name')!r} to native configuration on "
                + (", ".join(repr(n) for n in names) or "no devices"),
                details=details,
                fingerprint={
                    "policy": pid,
                    "targets": sorted(str(t.get("id")) for t in targets),
                    "objects": listed,
                },
                blockers=blockers,
                blast_radius=len(targets) or None,
                side_effects=[
                    "FMC rewrites each device's routing, interface and platform configuration with native "
                    "entries for the FlexConfig objects it can convert, and removes those objects from the "
                    "FlexConfig policy (objects it can't convert stay).",
                    "Nothing reaches a device until fmc_deploy; fmc_pending_changes shows what will.",
                ],
            ),
            apply=apply,
            lock_check=False,
        )
