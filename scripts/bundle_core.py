#!/usr/bin/env python3
"""Bundle stutters-mcp-core into a server package (ADR-005).

A server pins a core tag and its commit in its pyproject.toml:

    [tool.bundle-core]
    tag = "v0.12.4"
    commit = "70a6bafab04a94df152944acc9f024562fbd7020"
    extras = ["tasks"]          # optional: core extras whose dependencies the server needs

and marks where core's runtime dependencies go in [project].dependencies:

    dependencies = [
        "defusedxml>=0.7.1",
        # >>> bundled stutters-mcp-core v0.12.4 (scripts/bundle_core.py; do not edit)
        # <<< bundled stutters-mcp-core
    ]

Commands (run from the server repo; stdlib only, Python 3.12+, needs git):

    python scripts/bundle_core.py vendor              # src/<pkg>/_core from the pinned tag + deps block
    python scripts/bundle_core.py check               # drift: pin vs bundled copy vs the tag itself
    python scripts/bundle_core.py check --offline     # the same without fetching the tag
    python scripts/bundle_core.py check --dist dist   # also the built wheel and sdist
    python scripts/bundle_core.py update --tag v0.13.0  # move the pin, then vendor

`--source PATH` (or BUNDLE_CORE_SOURCE) reads core from a local git clone instead of cloning the
repository. The vendored copy is generated, not committed: src/<pkg>/_core/ belongs in .gitignore.
The canonical copy of this script lives in stutters-mcp-core/scripts/; `check` fails when the
server's copy differs from the one in the pinned tag (once the tag has one).
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CORE_DIST = "stutters-mcp-core"
CORE_PKG = "stutters_mcp_core"
DEFAULT_REPO = "https://github.com/dr-stutters/stutters-mcp-core"
SCRIPT_PATH = "scripts/bundle_core.py"
META = "BUNDLE.json"
BEGIN = "# >>> bundled stutters-mcp-core"
END = "# <<< bundled stutters-mcp-core"

_IMPORT_RE = re.compile(rf"^(?P<lead>[ \t]*(?:from|import)[ \t]+){CORE_PKG}(?=[\s.])", re.MULTILINE)
_VERSION_IMPORT_RE = re.compile(
    r"^from importlib\.metadata import PackageNotFoundError, version\n", re.MULTILINE
)
_VERSION_BLOCK_RE = re.compile(
    r'^try:\n[ \t]+__version__ = version\("stutters-mcp-core"\)\n'
    r"except PackageNotFoundError:[^\n]*\n[ \t]+__version__ = \"[^\"]*\"\n",
    re.MULTILINE,
)
_BLOCK_RE = re.compile(
    rf"^(?P<indent>[ \t]*){re.escape(BEGIN)}[^\n]*\n(?:.*\n)*?[ \t]*{re.escape(END)}[^\n]*\n", re.MULTILINE
)


class BundleError(Exception):
    pass


@dataclass(frozen=True)
class Pin:
    root: Path
    package: str
    tag: str
    commit: str
    extras: tuple[str, ...]
    repository: str

    @property
    def dest(self) -> Path:
        return self.root / "src" / self.package / "_core"


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _req_name(req: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
    return _norm(m.group(1)) if m else ""


def _req_key(req: str) -> str:
    # wheel metadata writes markers with single quotes (python_version < '3.13'); pyproject may use double
    return re.sub(r"\s+", "", req).lower().replace('"', "'")


def load_pin(root: Path) -> Pin:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise BundleError(f"{pyproject}: not found (run from the server repo or pass --root)")
    data = tomllib.loads(pyproject.read_text())
    cfg = data.get("tool", {}).get("bundle-core")
    if not cfg:
        raise BundleError(f"{pyproject}: no [tool.bundle-core] table (tag, commit, extras)")
    package = cfg.get("package") or data.get("tool", {}).get("uv", {}).get("build-backend", {}).get(
        "module-name"
    )
    if not package:
        raise BundleError(
            f"{pyproject}: set [tool.bundle-core].package or [tool.uv.build-backend].module-name"
        )
    tag, commit = cfg.get("tag", ""), cfg.get("commit", "")
    if not re.fullmatch(r"v\d+\.\d+\.\d+\S*", tag):
        raise BundleError(
            f"{pyproject}: [tool.bundle-core].tag must be a release tag like v0.12.4, got {tag!r}"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise BundleError(f"{pyproject}: [tool.bundle-core].commit must be the tag's full 40-hex commit")
    return Pin(root, package, tag, commit, tuple(cfg.get("extras", [])), cfg.get("repository", DEFAULT_REPO))


# --- fetching core --------------------------------------------------------------------------------


def _git(*args: str, cwd: Path | None = None) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise BundleError("git is not installed") from e
    except subprocess.CalledProcessError as e:
        raise BundleError(f"git {' '.join(args)}: {e.stderr.strip() or e}") from e
    return out.stdout.strip()


def fetch_core(
    pin: Pin, workdir: Path, source: Path | None = None, tag: str | None = None
) -> tuple[Path, str]:
    """Check out core at `tag` (default: the pin) under workdir; return (tree, commit)."""
    tag = tag or pin.tag
    tree = workdir / "core"
    if source is not None:
        commit = _git("rev-parse", "--verify", f"{tag}^{{commit}}", cwd=source)
        archive = subprocess.run(
            ["git", "archive", "--format=tar", commit], cwd=source, check=True, capture_output=True
        ).stdout
        tree.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(tree, filter="data")
    else:
        _git(
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            tag,
            pin.repository,
            str(tree),
        )
        commit = _git("rev-parse", "HEAD", cwd=tree)
    return tree, commit


def _source_from(arg: str | None) -> Path | None:
    value = arg or os.environ.get("BUNDLE_CORE_SOURCE")
    return Path(value).expanduser().resolve() if value else None


# --- building the bundle --------------------------------------------------------------------------


def core_dependencies(tree: Path, extras: tuple[str, ...]) -> tuple[str, list[str]]:
    project = tomllib.loads((tree / "pyproject.toml").read_text())["project"]
    if project.get("name") != CORE_DIST:
        raise BundleError(f"{tree}: not a {CORE_DIST} checkout")
    optional = project.get("optional-dependencies", {})
    deps: list[str] = list(project.get("dependencies", []))
    for extra in extras:
        if extra not in optional:
            raise BundleError(
                f"core {project['version']} has no extra {extra!r} (has: {', '.join(optional)})"
            )
        deps += optional[extra]
    unique: dict[str, str] = {}
    for d in deps:
        unique.setdefault(_req_key(d), d)
    return project["version"], list(unique.values())


def rewrite_imports(text: str, target: str, path: str) -> str:
    out = _IMPORT_RE.sub(lambda m: m.group("lead") + target, text)
    for node in ast.walk(ast.parse(out, filename=path)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == CORE_PKG:
            raise BundleError(f"{path}:{node.lineno}: import of {CORE_PKG} left after the rewrite")
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == CORE_PKG:
                    raise BundleError(f"{path}:{node.lineno}: import of {CORE_PKG} left after the rewrite")
                if alias.name.startswith(target) and alias.asname is None:
                    raise BundleError(f"{path}:{node.lineno}: bare `import {alias.name}` can't be bundled")
        if isinstance(node, ast.Name) and node.id == CORE_PKG:
            raise BundleError(f"{path}:{node.lineno}: {CORE_PKG} used as a name")
    return out


def build_bundle(pin: Pin, tree: Path, commit: str) -> tuple[dict[str, bytes], dict[str, Any]]:
    """The files of src/<pkg>/_core (relative path -> bytes) and the BUNDLE.json metadata."""
    version, deps = core_dependencies(tree, pin.extras)
    if pin.tag != f"v{version}":
        raise BundleError(f"tag {pin.tag} holds core version {version}: tag and pyproject version must match")
    src = tree / "src" / CORE_PKG
    if not src.is_dir():
        raise BundleError(f"{tree}: no src/{CORE_PKG}")
    target = f"{pin.package}._core"
    files: dict[str, bytes] = {}
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src).as_posix()
        if path.is_dir() or "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
            continue
        data = path.read_bytes()
        if path.suffix == ".py":
            text = rewrite_imports(data.decode(), target, f"{CORE_PKG}/{rel}")
            if rel == "__init__.py":
                text, n = _VERSION_BLOCK_RE.subn(f'__version__ = "{version}"\n', text)
                if n != 1:
                    raise BundleError("core's __init__.py no longer sets __version__ the expected way")
                text = _VERSION_IMPORT_RE.sub("", text, count=1)
                text = (
                    f"# Bundled from {CORE_DIST} {pin.tag} ({commit[:12]}) by {SCRIPT_PATH}: generated,"
                    " do not edit.\n" + text
                )
            data = text.encode()
        files[rel] = data
    if (tree / "LICENSE").is_file():
        files["LICENSE"] = (tree / "LICENSE").read_bytes()
    meta: dict[str, Any] = {
        "distribution": CORE_DIST,
        "version": version,
        "tag": pin.tag,
        "commit": commit,
        "extras": list(pin.extras),
        "dependencies": deps,
        "sha256": digest(files),
    }
    return files, meta


def digest(files: dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for rel in sorted(files):
        if rel == META:
            continue
        h.update(rel.encode() + b"\0" + hashlib.sha256(files[rel]).digest())
    return h.hexdigest()


def read_tree(dest: Path) -> dict[str, bytes]:
    return {
        p.relative_to(dest).as_posix(): p.read_bytes()
        for p in sorted(dest.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".pyo")
    }


def write_bundle(dest: Path, files: dict[str, bytes], meta: dict[str, Any]) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    for rel, data in files.items():
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    (dest / META).write_text(json.dumps(meta, indent=2) + "\n")


# --- pyproject ------------------------------------------------------------------------------------


def render_block(indent: str, tag: str, deps: list[str]) -> str:
    lines = [f"{indent}{BEGIN} {tag} ({SCRIPT_PATH}; do not edit)"]
    lines += [f"{indent}{json.dumps(d)}," for d in deps]
    lines.append(f"{indent}{END}")
    return "\n".join(lines) + "\n"


def sync_dependencies(text: str, tag: str, deps: list[str]) -> str:
    m = _BLOCK_RE.search(text)
    if not m:
        raise BundleError(
            f"pyproject.toml: [project].dependencies needs the marker lines '{BEGIN}' and '{END}'"
        )
    return text[: m.start()] + render_block(m.group("indent"), tag, deps) + text[m.end() :]


def set_pin(text: str, tag: str, commit: str) -> str:
    m = re.search(r"^\[tool\.bundle-core\][^\n]*\n(?:(?!\[).*\n?)*", text, re.MULTILINE)
    if not m:
        raise BundleError("pyproject.toml: no [tool.bundle-core] table")
    section = re.sub(r'^tag\s*=\s*"[^"]*"', f'tag = "{tag}"', m.group(0), count=1, flags=re.MULTILINE)
    section = re.sub(r'^commit\s*=\s*"[^"]*"', f'commit = "{commit}"', section, count=1, flags=re.MULTILINE)
    return text[: m.start()] + section + text[m.end() :]


# --- commands -------------------------------------------------------------------------------------


def vendor(pin: Pin, source: Path | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        tree, commit = fetch_core(pin, Path(tmp), source)
        if commit != pin.commit:
            raise BundleError(f"tag {pin.tag} is commit {commit}, but the pin says {pin.commit} (tag moved?)")
        files, meta = build_bundle(pin, tree, commit)
        _script_drift(tree, pin, warn=True)
    write_bundle(pin.dest, files, meta)
    pyproject = pin.root / "pyproject.toml"
    old = pyproject.read_text()
    new = sync_dependencies(old, pin.tag, list(meta["dependencies"]))
    if new != old:
        pyproject.write_text(new)
        print("pyproject.toml: bundled core dependencies updated (run `uv lock`)")
    print(f"vendored {CORE_DIST} {meta['version']} ({pin.tag}, {pin.commit[:12]}) into {pin.package}._core")
    return meta


def _script_drift(tree: Path, pin: Pin, warn: bool) -> list[str]:
    theirs = tree / SCRIPT_PATH
    ours = pin.root / SCRIPT_PATH
    if not theirs.is_file() or not ours.is_file() or theirs.read_bytes() == ours.read_bytes():
        return []
    msg = f"{SCRIPT_PATH} differs from the copy in core {pin.tag}: copy it from there"
    if warn:
        print(f"warning: {msg}", file=sys.stderr)
    return [msg]


def _project_errors(pin: Pin, deps: list[str]) -> list[str]:
    errors = []
    text = (pin.root / "pyproject.toml").read_text()
    project = tomllib.loads(text).get("project", {})
    declared = project.get("dependencies", [])
    if any(_req_name(d) == CORE_DIST for d in declared):
        errors.append(f"pyproject.toml still depends on {CORE_DIST}; the bundle replaces it")
    if "stutters-mcp-core" in str(tomllib.loads(text).get("tool", {}).get("uv", {}).get("sources", {})):
        errors.append(f"pyproject.toml still has a [tool.uv.sources] entry for {CORE_DIST}")
    try:
        if sync_dependencies(text, pin.tag, deps) != text:
            errors.append(
                "pyproject.toml: the bundled core dependency block is stale (run vendor, then uv lock)"
            )
    except BundleError as e:
        errors.append(str(e))
    return errors


def _dist_errors(pin: Pin, dist: Path, meta: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    prefix = f"{pin.package}/_core/"
    artifacts = sorted(dist.glob("*.whl")) + sorted(dist.glob("*.tar.gz"))
    if not artifacts:
        return [f"{dist}: no wheel or sdist"]
    for art in artifacts:
        files: dict[str, bytes] = {}
        metadata = ""
        if art.suffix == ".whl":
            with zipfile.ZipFile(art) as zf:
                for name in zf.namelist():
                    if name.startswith(prefix) and not name.endswith("/"):
                        files[name[len(prefix) :]] = zf.read(name)
                    elif name.endswith(".dist-info/METADATA"):
                        metadata = zf.read(name).decode()
        else:
            with tarfile.open(art) as tar:
                for member in tar.getmembers():
                    parts = member.name.split("/", 1)
                    inner = parts[1] if len(parts) == 2 else ""
                    if member.isfile() and inner.startswith(f"src/{prefix}"):
                        f = tar.extractfile(member)
                        files[inner[len("src/") + len(prefix) :]] = f.read() if f else b""
                    elif member.isfile() and inner == "PKG-INFO":
                        f = tar.extractfile(member)
                        metadata = f.read().decode() if f else ""
        files = {
            k: v for k, v in files.items() if "__pycache__/" not in k and not k.endswith((".pyc", ".pyo"))
        }
        if META not in files:
            errors.append(f"{art.name}: no bundled core ({prefix}{META})")
            continue
        art_meta = json.loads(files[META])
        if (art_meta.get("tag"), art_meta.get("commit")) != (pin.tag, pin.commit):
            errors.append(f"{art.name}: bundles core {art_meta.get('tag')}, pinned {pin.tag}")
        if digest(files) != meta["sha256"]:
            errors.append(f"{art.name}: bundled core files differ from the pinned tag")
        requires = {
            _req_key(line.split(":", 1)[1])
            for line in metadata.splitlines()
            if line.startswith("Requires-Dist:")
        }
        missing = [d for d in meta["dependencies"] if _req_key(d) not in requires]
        if missing:
            errors.append(f"{art.name}: metadata lacks core dependencies {missing}")
        if any(_req_name(r) == CORE_DIST for r in requires):
            errors.append(f"{art.name}: metadata still requires {CORE_DIST}")
    return errors


def check(pin: Pin, source: Path | None, offline: bool, dists: list[Path]) -> list[str]:
    errors: list[str] = []
    meta_path = pin.dest / META
    if not meta_path.is_file():
        return [f"src/{pin.package}/_core is not vendored: run `python {SCRIPT_PATH} vendor`"]
    meta = json.loads(meta_path.read_text())
    if (meta.get("tag"), meta.get("commit")) != (pin.tag, pin.commit):
        errors.append(
            f"drift: pinned core {pin.tag} ({pin.commit[:12]}) but the bundled copy is "
            f"{meta.get('tag')} ({str(meta.get('commit'))[:12]}): run vendor"
        )
    if digest(read_tree(pin.dest)) != meta.get("sha256"):
        errors.append(f"src/{pin.package}/_core was edited by hand (digest mismatch): run vendor")
    expected = meta
    if not offline:
        with tempfile.TemporaryDirectory() as tmp:
            tree, commit = fetch_core(pin, Path(tmp), source)
            if commit != pin.commit:
                errors.append(f"tag {pin.tag} is now commit {commit}, pinned {pin.commit} (tag moved)")
            else:
                _, expected = build_bundle(pin, tree, commit)
                if expected["sha256"] != meta.get("sha256"):
                    errors.append(f"src/{pin.package}/_core differs from what {pin.tag} produces: run vendor")
            errors += _script_drift(tree, pin, warn=False)
    errors += _project_errors(pin, list(expected["dependencies"]))
    for dist in dists:
        errors += _dist_errors(pin, dist, expected)
    return errors


def update(pin: Pin, tag: str, source: Path | None) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        _, commit = fetch_core(pin, Path(tmp), source, tag=tag)
    pyproject = pin.root / "pyproject.toml"
    pyproject.write_text(set_pin(pyproject.read_text(), tag, commit))
    print(f"pinned {CORE_DIST} {tag} ({commit})")
    vendor(load_pin(pin.root), source)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=".", help="server repo (default: current directory)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("vendor", "check", "update"):
        p = sub.add_parser(name)
        p.add_argument("--source", help="local stutters-mcp-core git clone (default: clone the repository)")
        if name == "check":
            p.add_argument(
                "--offline", action="store_true", help="don't fetch the tag; check pin vs bundle only"
            )
            p.add_argument(
                "--dist", action="append", default=[], help="also check the wheel/sdist in this dir"
            )
        if name == "update":
            p.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        pin = load_pin(Path(args.root).resolve())
        source = _source_from(args.source)
        if args.cmd == "vendor":
            vendor(pin, source)
        elif args.cmd == "update":
            update(pin, args.tag, source)
        else:
            errors = check(pin, source, args.offline, [Path(d) for d in args.dist])
            for e in errors:
                print(f"error: {e}", file=sys.stderr)
            if errors:
                return 1
            print(f"bundled core {pin.tag} ({pin.commit[:12]}) matches the pin")
    except BundleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
