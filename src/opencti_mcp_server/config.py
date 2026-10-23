"""Settings, all from the environment (or a .env file)."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import dotenv_values
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from opencti_mcp_server.guards import normalize_tlp, parse_extra_tlp


class Settings(BaseSettings):
    """Every setting is read from its upper-case name only (see `__init__`)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # OpenCTI. Use a read-only service account; see README "OpenCTI service account".
    opencti_url: str = "http://localhost:8080"
    opencti_token: SecretStr = SecretStr("")
    opencti_verify_tls: bool = True
    opencti_ca_cert: str | None = None
    opencti_timeout: float = Field(default=30.0, gt=0, le=300)

    # Server-side guards (defence in depth on top of the service account's own allowed markings).
    opencti_max_tlp: str = Field(
        default="TLP:AMBER+STRICT",
        description="Highest TLP returned; anything marked above it is withheld and counted",
    )
    opencti_extra_tlp: str = Field(
        default="",
        description="Operator-defined TLP markings and their rank, e.g. 'TLP:EX:CHR:3'; any other "
        "non-standard TLP marking is withheld",
    )
    opencti_hide_withheld_counts: bool = Field(
        default=False, description="Omit `withheld` and report totals that exclude withheld items"
    )
    opencti_max_first: int = Field(default=50, ge=1, le=500)
    mcp_max_output_chars: int = Field(default=20_000, ge=1_000)

    # MCP transport.
    mcp_server_host: str = "127.0.0.1"
    mcp_server_port: int = 8000
    mcp_auth_token: SecretStr | None = None
    mcp_allowed_hosts: str = Field(
        default="", description="Comma-separated Host header values for DNS-rebinding protection; empty = off"
    )

    @field_validator("opencti_max_tlp")
    @classmethod
    def _known_tlp(cls, value: str) -> str:
        return normalize_tlp(value)

    @field_validator("opencti_extra_tlp")
    @classmethod
    def _extra_tlp(cls, value: str) -> str:
        parse_extra_tlp(value)
        return value

    @field_validator("opencti_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("OPENCTI_URL must start with http:// or https://")
        return value

    def __init__(self, **values: Any) -> None:
        # pydantic-settings matches names case-insensitively, so `opencti_max_tlp` in an env file
        # would beat a deployment's forced `OPENCTI_MAX_TLP` (Compose overrides identical keys only).
        env_file = values.get("_env_file", self.model_config.get("env_file"))
        names = list(os.environ)
        if env_file and Path(env_file).is_file():
            names += list(dotenv_values(env_file))
        bad = miscased_names(names)
        if bad:
            raise ValueError(f"settings must be upper case, refusing: {', '.join(bad)}")
        super().__init__(**values)

    @property
    def extra_tlp(self) -> dict[str, int]:
        return parse_extra_tlp(self.opencti_extra_tlp)

    def cleartext_warning(self) -> str | None:
        """A warning when the OpenCTI token would cross the network unencrypted."""
        url = urlparse(self.opencti_url)
        if url.scheme != "http":
            return None
        host = url.hostname or ""
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if loopback:
            return None
        return (
            "OPENCTI_URL uses http:// to a non-loopback host: the OpenCTI token is sent in cleartext. "
            "Use https:// unless the connection is on a private, trusted network."
        )

    @property
    def graphql_url(self) -> str:
        return self.opencti_url if self.opencti_url.endswith("/graphql") else f"{self.opencti_url}/graphql"


def miscased_names(names: Iterable[str]) -> list[str]:
    """Names that spell a setting in anything but upper case, e.g. `opencti_max_tlp`."""
    fields = {name.upper() for name in Settings.model_fields}
    return sorted({n for n in names if n.upper() in fields and n != n.upper()})


@lru_cache
def get_settings() -> Settings:
    return Settings()
