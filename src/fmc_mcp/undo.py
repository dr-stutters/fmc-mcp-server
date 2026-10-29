"""Back-out steps for write tools (core C81 `Plan.undo`): helpers the tools share.

A create backs out with the matching delete (the new id comes from the apply result, `FromResult`), an
update with the same update carrying the values read for the preview, and a delete either re-creates the
object from what was read (when one tool call can) or says it isn't reversible and gives the definition
to re-create it from."""

import json
from dataclasses import dataclass
from typing import Any

from fmc_mcp._core import FromResult
from fmc_mcp.tools.common import proto_name, ref_label

_DEFINITION_CHARS = 1500  # the old definition in a 'not reversible' text: enough for a MOP, not a dump


@dataclass(frozen=True)
class ResultId(FromResult):
    """A new object's id from the apply result: `path` (e.g. 'rule.id' for a flattened access rule), or
    the result's own `id` when the tool returned FMC's answer as it came."""

    def resolve(self, result: Any) -> Any:
        try:
            return super().resolve(result)
        except LookupError:
            if isinstance(result, dict) and result.get("id"):
                return result["id"]
            raise


def without_none(args: dict[str, Any]) -> dict[str, Any]:
    """Undo arguments without the ones left at their default (None = keep / not given)."""
    return {k: v for k, v in args.items() if v is not None}


def ref_ids(refs: Any) -> list[str]:
    """The ids of a list of FMC references (objects in a block, zones, interface objects)."""
    return [str(r["id"]) for r in refs or [] if isinstance(r, dict) and r.get("id")]


def literal_text(lit: dict[str, Any]) -> str:
    """A rule or group literal as the write tools take it back ('10.1.0.0/16', 'tcp/443', 'icmp/8',
    '100-110', a URL): the reverse of refs.network_literal / port_literal / vlan_literal / url_literal."""
    if "value" in lit:
        return str(lit["value"])
    if lit.get("url"):
        return str(lit["url"])
    if "startTag" in lit:
        lo, hi = lit.get("startTag"), lit.get("endTag", lit.get("startTag"))
        return str(lo) if lo == hi else f"{lo}-{hi}"
    if "protocol" in lit:
        proto = proto_name(lit.get("protocol")).lower()
        if lit.get("icmpType") is not None:
            return proto if str(lit["icmpType"]).lower() == "any" else f"{proto}/{lit['icmpType']}"
        return f"{proto}/{lit['port']}" if lit.get("port") else proto
    return ref_label(lit)


def block_refs(block: Any) -> list[str]:
    """A condition or group block {"objects", "literals"} as the write tools take it back: object ids,
    then the literals' values."""
    if not isinstance(block, dict):
        return ref_ids(block) if isinstance(block, list) else []
    return ref_ids(block.get("objects")) + [literal_text(x) for x in block.get("literals") or []]


def not_reversible(what: str, recreate_with: str, definition: Any) -> str:
    """'not reversible: ...' with the definition read before the change (trimmed), for the MOP."""
    text = json.dumps(definition, sort_keys=True, default=str)
    if len(text) > _DEFINITION_CHARS:
        text = text[: _DEFINITION_CHARS - 3] + "..."
    return (
        f"not reversible: FMC can't restore a deleted {what}; re-create it with {recreate_with} from: {text}"
    )
