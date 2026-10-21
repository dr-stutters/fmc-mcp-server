"""Hardening baselines for fmc_hardening_check (F80): YAML checklists, one evaluator per check id.

The server ships `fmc_mcp/baselines/ftd-hardening.yaml` (name ftd-hardening-v1; the same file is
docs/baselines/ftd-hardening.yaml). An operator's edited copy lives in FMC_BUNDLE_DIR and is named by its
file name ('my-ftd.yaml', or 'my-ftd'). A bundled name always means the bundled file, so an edited copy
needs its own name. The file can change each check's severity, enabled flag and params; the check ids
select the evaluators built into the server (tools/hardening.py), so a check id the server doesn't know is
reported as not evaluated, never as passed. Every check names the source of its expectation.
"""

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from fmc_mcp._core import InvalidRequest

DEFAULT_BASELINE = "ftd-hardening-v1"
BUNDLED_FILES = ("ftd-hardening.yaml",)
SEVERITIES = ("high", "medium", "low", "info")
SCOPES = ("fmc", "platform_settings", "device")
MAX_BYTES = 256 * 1024
_FILE = re.compile(r"[\w.@+-]+\.ya?ml")
_STEM = re.compile(r"[\w.@+-]+")
_CHECK_KEYS = {"id", "scope", "title", "severity", "enabled", "params", "fix_tool", "source"}
_TOP_KEYS = {"name", "version", "description", "checks"}


@dataclass(frozen=True)
class Check:
    id: str
    scope: str
    title: str
    severity: str
    enabled: bool
    params: dict[str, Any]
    fix_tool: str | None
    source: tuple[str, ...]


@dataclass(frozen=True)
class Baseline:
    name: str
    version: str
    description: str
    origin: str  # 'bundled' or 'FMC_BUNDLE_DIR/<file>'
    checks: tuple[Check, ...] = field(default_factory=tuple)

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "from": self.origin,
            "checks": len(self.checks),
            "disabled": [c.id for c in self.checks if not c.enabled] or None,
        }


def parse_baseline(text: str, origin: str) -> Baseline:
    """A baseline from YAML text; InvalidRequest naming every problem (an edited file with a typo must not
    silently drop a check)."""
    if len(text.encode()) > MAX_BYTES:
        raise InvalidRequest(f"Baseline {origin} is larger than {MAX_BYTES // 1024} KB.")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise InvalidRequest(f"Baseline {origin} is not valid YAML: {e}") from None
    if not isinstance(data, dict):
        raise InvalidRequest(f"Baseline {origin}: expected a mapping with name, version and checks.")
    problems: list[str] = []
    unknown = set(data) - _TOP_KEYS
    if unknown:
        problems.append(f"unknown keys {sorted(unknown)}")
    name = str(data.get("name") or "").strip()
    if not name:
        problems.append("`name` is missing")
    raw = data.get("checks")
    if not isinstance(raw, list) or not raw:
        problems.append("`checks` must be a non-empty list")
        raw = []
    checks: list[Check] = []
    seen: set[str] = set()
    for n, c in enumerate(raw, 1):
        if not isinstance(c, dict):
            problems.append(f"check {n} is not a mapping")
            continue
        cid = str(c.get("id") or "").strip()
        where = f"check {cid or n}"
        bad = set(c) - _CHECK_KEYS
        if bad:
            problems.append(f"{where}: unknown keys {sorted(bad)}")
        if not cid:
            problems.append(f"check {n}: `id` is missing")
        elif cid in seen:
            problems.append(f"{where}: id appears twice")
        seen.add(cid)
        scope = str(c.get("scope") or "")
        if scope not in SCOPES:
            problems.append(f"{where}: scope must be one of {list(SCOPES)}")
        severity = str(c.get("severity") or "").lower()
        if severity not in SEVERITIES:
            problems.append(f"{where}: severity must be one of {list(SEVERITIES)}")
        enabled = c.get("enabled", True)
        if not isinstance(enabled, bool):
            problems.append(f"{where}: enabled must be true or false")
        params = c.get("params") or {}
        if not isinstance(params, dict):
            problems.append(f"{where}: params must be a mapping")
            params = {}
        source = c.get("source") or []
        if isinstance(source, str):
            source = [source]
        if not isinstance(source, list) or not source:
            problems.append(f"{where}: `source` must name where the check comes from")
            source = []
        fix_tool = c.get("fix_tool")
        if fix_tool is not None and not re.fullmatch(r"fmc_[a-z0-9_]+", str(fix_tool)):
            problems.append(f"{where}: fix_tool must be an fmc_* tool name or empty")
        checks.append(
            Check(
                id=cid,
                scope=scope,
                title=str(c.get("title") or cid),
                severity=severity,
                enabled=bool(enabled),
                params=dict(params),
                fix_tool=str(fix_tool) if fix_tool else None,
                source=tuple(str(s) for s in source),
            )
        )
    if problems:
        raise InvalidRequest(f"Baseline {origin} is not usable: " + "; ".join(problems) + ".")
    return Baseline(
        name=name,
        version=str(data.get("version") or ""),
        description=" ".join(str(data.get("description") or "").split()),
        origin=origin,
        checks=tuple(checks),
    )


def bundled_text(file: str) -> str:
    return (resources.files("fmc_mcp") / "baselines" / file).read_text(encoding="utf-8")


def bundled() -> dict[str, Baseline]:
    """The baselines that ship with the server, by name."""
    out = {}
    for f in BUNDLED_FILES:
        b = parse_baseline(bundled_text(f), "bundled")
        out[b.name] = b
    return out


def load_baseline(ref: str, bundle_dir: Path | None) -> Baseline:
    """A bundled baseline by name, or an edited copy in FMC_BUNDLE_DIR by file name (with or without
    .yaml). Paths are never taken from the caller: only a plain file name inside that directory."""
    ref = (ref or DEFAULT_BASELINE).strip()
    shipped = bundled()
    if ref in shipped:
        return shipped[ref]
    if not (_FILE.fullmatch(ref) or _STEM.fullmatch(ref)):
        raise InvalidRequest(
            f"Baseline {ref!r}: give a bundled name ({', '.join(shipped)}) or a file name in FMC_BUNDLE_DIR."
        )
    if bundle_dir is None:
        raise InvalidRequest(
            f"Baseline {ref!r} is not bundled ({', '.join(shipped)}), and FMC_BUNDLE_DIR is not set on "
            "the server, so edited baselines can't be read."
        )
    root = bundle_dir.resolve()
    names = [ref] if _FILE.fullmatch(ref) else [f"{ref}.yaml", f"{ref}.yml"]
    for name in names:
        path = (root / name).resolve()
        if path.parent == root and path.is_file():
            return parse_baseline(path.read_text(encoding="utf-8"), f"FMC_BUNDLE_DIR/{name}")
    raise InvalidRequest(
        f"No baseline {ref!r}: not bundled ({', '.join(shipped)}) and no {' or '.join(names)} in "
        "FMC_BUNDLE_DIR."
    )
