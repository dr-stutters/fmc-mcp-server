"""Helpers shared by the tool modules: parameter types, response shaping, name/id resolution."""

from typing import Annotated

from pydantic import Field

Domain = Annotated[
    str | None,
    Field(description="FMC domain name (e.g. 'Global') or UUID; default FMC_DOMAIN or the login's domain"),
]
