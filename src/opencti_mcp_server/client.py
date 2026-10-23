"""A minimal async GraphQL client for OpenCTI: plain httpx, fixed documents, fail-closed errors.

OpenCTI reports failures as HTTP 200 with an `errors` array, sometimes next to partial `data`. Any
`errors` entry fails the whole call: a partial answer could silently drop the very object an
analyst is asking about.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from opencti_mcp_server import __version__
from opencti_mcp_server.config import Settings
from opencti_mcp_server.output import clean

log = logging.getLogger(__name__)

_REFUSED = frozenset({"AUTH_REQUIRED", "FORBIDDEN_ACCESS", "UNAUTHENTICATED", "FORBIDDEN", "OTP_REQUIRED"})
_BAD_REQUEST = frozenset(
    {
        "GRAPHQL_VALIDATION_FAILED",
        "GRAPHQL_PARSE_FAILED",
        "BAD_USER_INPUT",
        "VALIDATION_ERROR",
        "FUNCTIONAL_ERROR",
        "UNSUPPORTED_ERROR",
    }
)
_NOT_FOUND = frozenset({"NOT_FOUND", "MISSING_REFERENCE_ERROR"})


class OpenCTIClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.url = settings.graphql_url
        self._token = settings.opencti_token.get_secret_value()
        verify: bool | ssl.SSLContext = settings.opencti_verify_tls
        if settings.opencti_verify_tls and settings.opencti_ca_cert:
            verify = ssl.create_default_context(cafile=settings.opencti_ca_cert)
        self._http = httpx.AsyncClient(
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/json",
                "User-Agent": f"opencti-mcp-server/{__version__}",
            },
            timeout=settings.opencti_timeout,
            verify=verify,
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def execute(self, document: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one of the fixed documents in `queries`. Returns `data`, or raises a ToolError."""
        try:
            resp = await self._http.post(self.url, json={"query": document, "variables": variables or {}})
        except httpx.TimeoutException:
            raise ToolError("opencti unavailable or timed out") from None
        except httpx.HTTPError as e:
            log.warning("opencti request failed: %s", type(e).__name__)
            raise ToolError("opencti unavailable or timed out") from None
        if resp.status_code in (502, 503, 504):
            raise ToolError(f"opencti unavailable or timed out (HTTP {resp.status_code})")
        try:
            body = resp.json()
        except ValueError:
            raise ToolError(f"opencti error: non-JSON response (HTTP {resp.status_code})") from None
        if not isinstance(body, dict):
            raise ToolError(f"opencti error: unexpected response (HTTP {resp.status_code})")
        errors = body.get("errors")
        if errors:
            raise self._graphql_error(errors)
        if resp.status_code != 200:
            raise ToolError(f"opencti error: HTTP {resp.status_code}")
        data = body.get("data")
        if not isinstance(data, dict):
            raise ToolError("opencti error: response has no data")
        return data

    def _graphql_error(self, errors: Any) -> ToolError:
        first = errors[0] if isinstance(errors, list) and errors and isinstance(errors[0], dict) else {}
        ext = first.get("extensions") if isinstance(first.get("extensions"), dict) else {}
        code = str(ext.get("code") or first.get("name") or "UNKNOWN")[:64]
        message = clean(first.get("message") or "no message", 300) or ""
        if self._token:
            message = message.replace(self._token, "[redacted]")
        more = len(errors) - 1 if isinstance(errors, list) else 0
        detail = f"{message} ({clean(code, 64)}{f', +{more} more' if more > 0 else ''})"
        log.warning("opencti returned an error: %s", code)
        if code in _REFUSED:
            return ToolError(f"opencti refused the request: {detail}")
        if code in _BAD_REQUEST:
            return ToolError(f"bad request: {detail}")
        if code in _NOT_FOUND:
            return ToolError(f"not found: {detail}")
        return ToolError(f"opencti error: {detail}")
