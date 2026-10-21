"""Grouped fmc_policy_audit findings as one fmc_bulk_update_access_rules call each (F67)."""

from __future__ import annotations

from typing import Any

NAMES_CAP = 50  # rule names per suggested call (longer selections: repeat with the rest)
# check -> the bulk `set` that fixes it (the same change the per-rule fix proposes)
BULK_SETS: dict[str, dict[str, Any]] = {
    "no_logging": {"log": "end"},
    "no_intrusion": {"intrusion_policy": "Balanced Security and Connectivity"},
    "unused": {"enabled": False},
}


def bulk_fixes(policy: str, findings: list[dict[str, Any]], unused_days: int) -> list[dict[str, Any]]:
    """For each check with two or more findings, the bulk call that applies all their fixes in one preview.
    Unused rules are selected the way the audit found them (zero_hits_days), the others by name."""
    out: list[dict[str, Any]] = []
    for check, change in BULK_SETS.items():
        names = [str((f.get("rule") or {}).get("name")) for f in findings if f.get("check") == check]
        names = [n for n in dict.fromkeys(names) if n != "None"]
        if len(names) < 2:
            continue
        if check == "unused":
            select: dict[str, Any] = {"zero_hits_days": unused_days}
            change = {**change, "comment": f"no hits in {unused_days} days (fmc_policy_audit)"}
        else:
            select = {"names": names[:NAMES_CAP]}
        args = ", ".join(f"{k}={v!r}" for k, v in (("policy", policy), ("select", select), ("set", change)))
        row: dict[str, Any] = {
            "check": check,
            "rules": len(names),
            "fix": f"fmc_bulk_update_access_rules({args})",
        }
        if check != "unused" and len(names) > NAMES_CAP:
            row["note"] = (
                f"The call names the first {NAMES_CAP}; repeat it with the other {len(names) - NAMES_CAP}."
            )
        out.append(row)
    return out
