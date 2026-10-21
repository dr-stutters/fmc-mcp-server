"""Feature licences of FTDs: the names a device holds and the ones an access policy needs.

A leaf module (it imports nothing from fmc_mcp.tools), shared by fmc_threat_posture and fmc_license_status
so both answer 'does this device hold the licences its policy needs?' the same way."""

from typing import Any

# Older licence names FMC still reports for some devices.
LICENCE_ALIASES = {"THREAT": "IPS", "MALWARE": "MALWARE_DEFENSE", "URLFILTER": "URL"}


def licences(caps: list[Any] | None) -> set[str]:
    """FMC licence names, normalised: the older aliases, and an HA unit's IPS_HA / URL_HA /
    MALWARE_DEFENSE_HA (FMC 10.0.1 /license/devicelicenses; its device records say IPS / URL /
    MALWARE_DEFENSE) as the plain licence."""
    out = set()
    for c in caps or []:
        up = str(c).upper().removesuffix("_HA")
        out.add(LICENCE_ALIASES.get(up, up))
    return out


def licence_needs(acp: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, str]:
    """The feature licences an access policy (its full record, for the default action) needs, each with
    why: IPS for an intrusion policy on the default action or an enabled ALLOW rule, MALWARE_DEFENSE for
    a file policy on an enabled ALLOW rule, URL for URL categories/reputation on an enabled rule."""
    enabled = [r for r in rules if r.get("enabled", True)]
    allow = [r for r in enabled if str(r.get("action", "")).upper() == "ALLOW"]
    out: dict[str, str] = {}
    ips = next((r for r in allow if (r.get("ipsPolicy") or {}).get("id")), None)
    if ((acp.get("defaultAction") or {}).get("intrusionPolicy") or {}).get("id"):
        out["IPS"] = "intrusion policy on the default action"
    elif ips:
        out["IPS"] = f"intrusion policy on rule {ips.get('name')!r}"
    files = next((r for r in allow if r.get("filePolicy")), None)
    if files:
        out["MALWARE_DEFENSE"] = f"file policy on rule {files.get('name')!r}"
    urls = next((r for r in enabled if (r.get("urls") or {}).get("urlCategoriesWithReputation")), None)
    if urls:
        out["URL"] = f"URL categories on rule {urls.get('name')!r}"
    return out
