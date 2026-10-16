"""Inputs that depend on your own FMC and FTD (device name, addresses, realm, domain) come from FMC_LIVE_*
variables, in the environment or in ./.env (docs/live-tests.md lists them). A test whose variables are unset
is skipped and the skip reason names them."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


def live_env(name: str, default: str = "") -> str:
    """FMC_LIVE_* value from the environment, else from .env in the current directory, else `default`."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    env = Path.cwd() / ".env"
    if env.is_file():
        for line in env.read_text().splitlines():
            key, sep, raw = line.partition("=")
            if sep and key.strip() == name:
                raw = raw.split(" #", 1)[0].strip().strip("'\"")
                if raw:
                    return raw
    return default


def missing(*names: str) -> list[str]:
    return [n for n in names if not live_env(n)]


def needs(*names: str) -> pytest.MarkDecorator:
    """Skip the test unless every named FMC_LIVE_* variable is set."""
    gone = missing(*names)
    return pytest.mark.skipif(bool(gone), reason=f"{', '.join(gone)} not set (docs/live-tests.md)")


def need(name: str) -> str:
    """The variable's value, or skip the calling test naming it."""
    value = live_env(name)
    if not value:
        pytest.skip(f"{name} not set (docs/live-tests.md)")
    return value
