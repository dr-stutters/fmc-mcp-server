"""Flatten FMC access, prefilter and NAT rules into compact rows for the model."""

from typing import Any

from fmc_mcp.rule_conditions import SGT_FIELDS, sgt_labels
from fmc_mcp.rule_conditions import app_labels as app_labels  # re-exported (decryption rules use it)
from fmc_mcp.tools.common import block_labels, ref_label

# Access-rule condition fields: our key -> FMC field.
ACCESS_CONDITIONS = {
    "src_zones": "sourceZones",
    "dst_zones": "destinationZones",
    "src_networks": "sourceNetworks",
    "dst_networks": "destinationNetworks",
    "src_ports": "sourcePorts",
    "dst_ports": "destinationPorts",
    "vlan_tags": "vlanTags",
    "users": "users",
    "src_sgts": "sourceSecurityGroupTags",
    "dst_sgts": "destinationSecurityGroupTags",
    "src_dynamic": "sourceDynamicObjects",
    "dst_dynamic": "destinationDynamicObjects",
    "time_ranges": "timeRangeObjects",
}
# Conditions an offline matcher can't evaluate (layer 7, identity, time).
OPAQUE_CONDITIONS = (
    "applications",
    "urls",
    "users",
    "vlanTags",
    "sourceSecurityGroupTags",
    "destinationSecurityGroupTags",
    "sourceDynamicObjects",
    "destinationDynamicObjects",
    "timeRangeObjects",
    "endPointDeviceTypes",
    "networkAccessDeviceIPs",
)


def url_labels(block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    out = block_labels(block)
    for c in block.get("urlCategoriesWithReputation") or []:
        cat = ref_label(c.get("category") or {})
        rep = c.get("reputation")
        out.append(f"category:{cat}" + (f" ({rep})" if rep else ""))
    return out


def has_value(v: Any) -> bool:
    if isinstance(v, dict):
        return any(has_value(x) for x in v.values())
    if isinstance(v, list):
        return bool(v)
    return v not in (None, "", False)


def flatten_access_rule(r: dict[str, Any], sgt_tags: dict[str, Any] | None = None) -> dict[str, Any]:
    """One compact row; `sgt_tags` (rule_conditions.sgt_tags) adds tag numbers to the SGT labels."""
    meta = r.get("metadata") or {}
    row: dict[str, Any] = {
        "index": meta.get("ruleIndex"),
        "section": meta.get("section"),
        "category": meta.get("category") if meta.get("category") not in (None, "--Undefined--") else None,
        "name": r.get("name"),
        "action": r.get("action"),
        "enabled": r.get("enabled"),
    }
    for key, field in ACCESS_CONDITIONS.items():
        labels = sgt_labels(r.get(field), sgt_tags) if field in SGT_FIELDS else block_labels(r.get(field))
        row[key] = labels or None
    row["applications"] = app_labels(r.get("applications")) or None
    row["urls"] = url_labels(r.get("urls")) or None
    row["intrusion_policy"] = ref_label(r["ipsPolicy"]) if r.get("ipsPolicy") else None
    row["file_policy"] = ref_label(r["filePolicy"]) if r.get("filePolicy") else None
    logging = [n for n, f in (("begin", "logBegin"), ("end", "logEnd"), ("files", "logFiles")) if r.get(f)]
    row["logging"] = logging or None
    comments = r.get("commentHistoryList") or []
    if comments:
        row["comments"] = len(comments)
    row["id"] = r.get("id")
    return {k: v for k, v in row.items() if v is not None}


def flatten_prefilter_rule(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row: dict[str, Any] = {
        "index": meta.get("ruleIndex"),
        "name": r.get("name"),
        "type": r.get("ruleType"),
        "action": r.get("action"),
        "enabled": r.get("enabled"),
        "bidirectional": r.get("bidirectional"),
        "src_interfaces": block_labels(r.get("sourceInterfaces")) or None,
        "dst_interfaces": block_labels(r.get("destinationInterfaces")) or None,
        "src_networks": block_labels(r.get("sourceNetworks")) or None,
        "dst_networks": block_labels(r.get("destinationNetworks")) or None,
        "src_ports": block_labels(r.get("sourcePorts")) or None,
        "dst_ports": block_labels(r.get("destinationPorts")) or None,
        "vlan_tags": block_labels(r.get("vlanTags")) or None,
        "encapsulation": block_labels(r.get("encapsulationPorts")) or None,
        "tunnel_zone": ref_label(r["tunnelZone"]) if r.get("tunnelZone") else None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def _lbl(v: Any) -> str | None:
    return ref_label(v) if v else None


def flatten_nat_rule(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    auto = r.get("type") == "FTDAutoNatRule"
    row: dict[str, Any] = {
        "section": meta.get("section") or r.get("section"),
        "index": meta.get("index"),
        "kind": "auto" if auto else "manual",
        "nat_type": r.get("natType"),
        "enabled": r.get("enabled", True),
        "src_interface": _lbl(r.get("sourceInterface")),
        "dst_interface": _lbl(r.get("destinationInterface")),
    }
    if auto:
        row.update(
            original_source=_lbl(r.get("originalNetwork")),
            translated_source="interface"
            if r.get("interfaceInTranslatedNetwork")
            else _lbl(r.get("translatedNetwork")),
            service=f"{r.get('serviceProtocol')}/{r.get('originalPort')}->{r.get('translatedPort')}"
            if r.get("serviceProtocol")
            else None,
        )
    else:
        row.update(
            original_source=_lbl(r.get("originalSource")),
            translated_source="interface"
            if r.get("interfaceInTranslatedSource")
            else _lbl(r.get("translatedSource")),
            original_destination="interface"
            if r.get("interfaceInOriginalDestination")
            else _lbl(r.get("originalDestination")),
            translated_destination=_lbl(r.get("translatedDestination")),
            original_source_port=_lbl(r.get("originalSourcePort")),
            translated_source_port=_lbl(r.get("translatedSourcePort")),
            original_destination_port=_lbl(r.get("originalDestinationPort")),
            translated_destination_port=_lbl(r.get("translatedDestinationPort")),
            unidirectional=r.get("unidirectional") or None,
        )
    opts = [o for o in ("dns", "noProxyArp", "routeLookup", "netToNet", "fallThrough") if r.get(o)]
    row["options"] = opts or None
    row["description"] = r.get("description")
    row["id"] = r.get("id")
    return {k: v for k, v in row.items() if v is not None}
