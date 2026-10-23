"""Settings, all from the environment (or a .env file)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from opencti_mcp_server.guards import normalize_tlp


class Settings(BaseSettings):
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

    @field_validator("opencti_url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("OPENCTI_URL must start with http:// or https://")
        return value

    @property
    def graphql_url(self) -> str:
        return self.opencti_url if self.opencti_url.endswith("/graphql") else f"{self.opencti_url}/graphql"


@lru_cache
def get_settings() -> Settings:
    return Settings()
