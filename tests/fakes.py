"""A fake OpenCTI GraphQL endpoint (httpx.MockTransport) and synthetic response builders.

All values are synthetic: documentation IP ranges (RFC 5737 / RFC 3849), example.* domains
(RFC 2606) and made-up ids. Nothing here comes from a real OpenCTI instance.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import httpx

from opencti_mcp_server.client import OpenCTIClient
from opencti_mcp_server.config import Settings

TOKEN = "octi-test-token-5f2b7c1e-do-not-leak"
MCP_TOKEN = "mcp-test-token-91c3"

MARKINGS = {
    "TLP:CLEAR": {"definition_type": "TLP", "definition": "TLP:CLEAR", "x_opencti_order": 1},
    "TLP:GREEN": {"definition_type": "TLP", "definition": "TLP:GREEN", "x_opencti_order": 2},
    "TLP:AMBER": {"definition_type": "TLP", "definition": "TLP:AMBER", "x_opencti_order": 3},
    "TLP:AMBER+STRICT": {"definition_type": "TLP", "definition": "TLP:AMBER+STRICT", "x_opencti_order": 4},
    "TLP:RED": {"definition_type": "TLP", "definition": "TLP:RED", "x_opencti_order": 5},
    # PAP shares order numbers with TLP; it must never be read as TLP.
    "PAP:CLEAR": {"definition_type": "PAP", "definition": "PAP:CLEAR", "x_opencti_order": 1},
    "PAP:RED": {"definition_type": "PAP", "definition": "PAP:RED", "x_opencti_order": 4},
    # A TLP marking this server has never heard of, ordered above AMBER+STRICT.
    "TLP:BLACK": {"definition_type": "TLP", "definition": "TLP:BLACK", "x_opencti_order": 6},
    "statement": {
        "definition_type": "statement",
        "definition": "Copyright Example Corp",
        "x_opencti_order": 0,
    },
}

_n = 0


def uid() -> str:
    global _n
    _n += 1
    return f"00000000-0000-4000-8000-{_n:012d}"


def settings(**kw: Any) -> Settings:
    base = {
        "opencti_url": "https://opencti.example.test",
        "opencti_token": TOKEN,
        "mcp_auth_token": MCP_TOKEN,
        "mcp_max_output_chars": 20_000,
    }
    return Settings(_env_file=None, **(base | kw))


def _meta(entity_type: str, markings: tuple[str, ...] = (), labels: tuple[str, ...] = ()) -> dict[str, Any]:
    i = uid()
    return {
        "id": i,
        "standard_id": f"{entity_type.lower()}--{i}",
        "entity_type": entity_type,
        "created_at": "2026-01-02T03:04:05.000Z",
        "updated_at": "2026-02-03T04:05:06.000Z",
        "createdBy": {"name": "Example Feed"},
        "objectLabel": [{"value": v} for v in labels],
        "objectMarking": [MARKINGS[m] for m in markings],
    }


def conn(
    nodes: list[dict[str, Any]], total: int | None = None, next_cursor: str | None = None
) -> dict[str, Any]:
    return {
        "pageInfo": {
            "globalCount": len(nodes) if total is None else total,
            "hasNextPage": next_cursor is not None,
            "endCursor": next_cursor or "",
        },
        "edges": [{"node": n} for n in nodes],
    }


def indicator(
    name: str = "malicious.example.com",
    markings: tuple[str, ...] = ("TLP:CLEAR",),
    labels: tuple[str, ...] = ("phishing",),
    **kw: Any,
) -> dict[str, Any]:
    node = _meta("Indicator", markings, labels) | {
        "name": name,
        "description": "Synthetic indicator for tests.",
        "pattern": f"[domain-name:value = '{name}']",
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "x_opencti_main_observable_type": "Domain-Name",
        "x_opencti_score": 80,
        "x_opencti_detection": True,
        "confidence": 75,
        "valid_from": "2026-01-01T00:00:00.000Z",
        "valid_until": "2026-12-31T00:00:00.000Z",
        "revoked": False,
        "killChainPhases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    }
    return node | kw


def observable(
    value: str = "malicious.example.com",
    entity_type: str = "Domain-Name",
    markings: tuple[str, ...] = ("TLP:CLEAR",),
    labels: tuple[str, ...] = ("phishing",),
    **kw: Any,
) -> dict[str, Any]:
    node = _meta(entity_type, markings, labels) | {
        "observable_value": value,
        "x_opencti_score": 70,
        "x_opencti_description": "Synthetic observable for tests.",
    }
    if entity_type == "StixFile":
        node |= {"name": "dropper.exe", "hashes": [{"algorithm": "MD5", "hash": value}]}
    return node | kw


def report(
    name: str = "Example campaign report", markings: tuple[str, ...] = ("TLP:CLEAR",)
) -> dict[str, Any]:
    return {
        "id": uid(),
        "name": name,
        "published": "2026-03-01T00:00:00.000Z",
        "objectMarking": [MARKINGS[m] for m in markings],
    }


Responder = dict[str, Any] | httpx.Response | Exception | Callable[[dict[str, Any]], Any]


class FakeOpenCTI:
    """Answers by GraphQL operation name and records every request."""

    def __init__(self, responses: dict[str, Responder] | None = None) -> None:
        self.responses = responses or {}
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append({"url": str(request.url), "headers": dict(request.headers), "body": body})
        op = re.match(r"\s*query\s+(\w+)", body["query"]).group(1)
        r = self.responses[op]
        if callable(r) and not isinstance(r, httpx.Response):
            r = r(body)
        if isinstance(r, Exception):
            raise r
        if isinstance(r, httpx.Response):
            return r
        return httpx.Response(200, json=r)

    def client(self, s: Settings | None = None) -> OpenCTIClient:
        return OpenCTIClient(s or settings(), transport=httpx.MockTransport(self))

    @property
    def variables(self) -> dict[str, Any]:
        return self.requests[-1]["body"]["variables"]
