"""Argument guards, filter builders and the TLP guard.

Every tool call passes its arguments through these before anything reaches OpenCTI. Caller values
only ever become GraphQL variables (FilterGroup values, ids, cursors); they are never spliced into a
document.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Literal

from mcp.server.mcpserver.exceptions import ToolError

# --- errors -------------------------------------------------------------------------------------


def bad_request(message: str) -> ToolError:
    return ToolError(f"bad request: {message}")


# --- ids, cursors, search text ------------------------------------------------------------------

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ID = re.compile(rf"^(?:[a-z][a-z0-9-]{{0,62}}--)?{_UUID}$", re.IGNORECASE)
_CURSOR = re.compile(r"^[A-Za-z0-9+/=_-]{1,512}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]")


def check_id(value: str) -> str:
    """An OpenCTI internal id (a UUID) or a STIX id (`<type>--<uuid>`)."""
    value = (value or "").strip()
    if not _ID.fullmatch(value):
        raise bad_request("id must be a UUID or a STIX id such as 'indicator--<uuid>'")
    return value.lower()


def check_cursor(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if not _CURSOR.fullmatch(value):
        raise bad_request("after must be the endCursor of a previous page")
    return value


def check_text(value: str | None, name: str, max_len: int) -> str | None:
    """Free text from the caller: no control or zero-width characters, bounded length."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if _CONTROL.search(value):
        raise bad_request(f"{name} contains control or zero-width characters")
    if len(value) > max_len:
        raise bad_request(f"{name} is longer than {max_len} characters")
    return value


def check_first(first: int, max_first: int) -> int:
    if first < 1 or first > max_first:
        raise bad_request(f"first must be between 1 and {max_first}")
    return first


# --- observable values --------------------------------------------------------------------------

ObservableKind = Literal[
    "md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "domain", "hostname", "url", "email"
]

# kind -> (OpenCTI observable types, filter key)
_KINDS: dict[str, tuple[list[str], str]] = {
    "md5": (["StixFile"], "hashes.MD5"),
    "sha1": (["StixFile"], "hashes.SHA-1"),
    "sha256": (["StixFile"], "hashes.SHA-256"),
    "sha512": (["StixFile"], "hashes.SHA-512"),
    "ipv4": (["IPv4-Addr"], "value"),
    "ipv6": (["IPv6-Addr"], "value"),
    "domain": (["Domain-Name"], "value"),
    "hostname": (["Hostname"], "value"),
    "url": (["Url"], "value"),
    "email": (["Email-Addr"], "value"),
}
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_LABEL = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
_DOMAIN = re.compile(rf"^(?:{_LABEL}\.)+[A-Za-z][A-Za-z0-9-]{{0,62}}$")
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{0,15}://\S+$")
MAX_VALUE_LEN = 2048


def detect_kind(value: str) -> str:
    if _HEX.fullmatch(value) and len(value) in _HASH_LENGTHS:
        return _HASH_LENGTHS[len(value)]
    try:
        return "ipv4" if ipaddress.ip_address(value).version == 4 else "ipv6"
    except ValueError:
        pass
    if _URL.fullmatch(value):
        return "url"
    if _EMAIL.fullmatch(value) and _DOMAIN.fullmatch(value.rsplit("@", 1)[1]):
        return "email"
    if _DOMAIN.fullmatch(value.rstrip(".")):
        return "domain"
    raise bad_request(
        "could not detect the observable type; pass type as one of " + ", ".join(sorted(_KINDS))
    )


def _valid_for(kind: str, value: str) -> bool:
    if kind in ("md5", "sha1", "sha256", "sha512"):
        return bool(_HEX.fullmatch(value)) and _HASH_LENGTHS.get(len(value)) == kind
    if kind in ("ipv4", "ipv6"):
        try:
            return ipaddress.ip_address(value).version == (4 if kind == "ipv4" else 6)
        except ValueError:
            return False
    if kind == "url":
        return bool(_URL.fullmatch(value))
    if kind == "email":
        return bool(_EMAIL.fullmatch(value))
    if kind == "domain":
        return bool(_DOMAIN.fullmatch(value.rstrip(".")))
    if kind == "hostname":
        return bool(_HOSTNAME.fullmatch(value.rstrip(".")))
    return False


def observable_lookup(value: str, kind: str | None) -> tuple[str, str, list[str], dict[str, Any]]:
    """Validate a value to look up and build its exact-match filter.

    Returns (kind, normalised value, observable types, FilterGroup). Domains also match Hostname
    observables when the type was auto-detected.
    """
    value = check_text(value, "value", MAX_VALUE_LEN)
    if value is None:
        raise bad_request("value is required")
    detected = kind is None
    if kind is None:
        kind = detect_kind(value)
    elif kind not in _KINDS:
        raise bad_request("type must be one of " + ", ".join(sorted(_KINDS)))
    if not _valid_for(kind, value):
        raise bad_request(f"value is not a valid {kind}")
    if kind in ("domain", "hostname"):
        value = value.rstrip(".").lower()
    elif kind in ("md5", "sha1", "sha256", "sha512"):
        value = value.lower()
    types, key = _KINDS[kind]
    if detected and kind == "domain":
        types = ["Domain-Name", "Hostname"]
    return kind, value, list(types), filter_group([eq(key, value)])


# --- FilterGroup builders (one key per filter, values only) -------------------------------------


def eq(key: str, value: str) -> dict[str, Any]:
    return {"key": [key], "values": [value], "operator": "eq", "mode": "or"}


def filter_group(
    filters: list[dict[str, Any]], groups: list[dict[str, Any]] | None = None, mode: str = "and"
) -> dict[str, Any]:
    return {"mode": mode, "filters": filters, "filterGroups": groups or []}


def _stix_pattern_literal(value: str) -> str:
    """The value as it appears quoted inside a STIX pattern (`'...'`, with \\ and ' escaped)."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


ObservableType = Literal[
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Hostname",
    "Url",
    "Email-Addr",
    "StixFile",
    "Mac-Addr",
    "Autonomous-System",
    "User-Agent",
    "Cryptocurrency-Wallet",
    "Windows-Registry-Key",
    "X509-Certificate",
    "Email-Message",
    "Mutex",
    "Process",
    "Text",
]

PatternType = Literal[
    "stix",
    "sigma",
    "yara",
    "snort",
    "suricata",
    "pcre",
    "eql",
    "spl",
    "kql",
    "shodan",
    "tanium-signal",
    "sentinel-rule",
]

OBSERVABLE_TYPES = frozenset(ObservableType.__args__)
PATTERN_TYPES = frozenset(PatternType.__args__)


def indicator_filters(
    *,
    value: str | None,
    min_score: int | None,
    observable_type: str | None,
    pattern_type: str | None,
    include_revoked: bool,
) -> dict[str, Any] | None:
    """FilterGroup for search_indicators.

    `value` is an exact, case-insensitive match: the indicator's name equals it, or its pattern
    holds it as a quoted literal (so 'evil.com' does not match 'notevil.com').
    """
    filters: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    if value is not None:
        groups.append(
            filter_group(
                [
                    eq("name", value),
                    {
                        "key": ["pattern"],
                        "values": [_stix_pattern_literal(value)],
                        "operator": "contains",
                        "mode": "or",
                    },
                ],
                mode="or",
            )
        )
    if min_score is not None:
        if not 0 <= min_score <= 100:
            raise bad_request("min_score must be between 0 and 100")
        filters.append(
            {"key": ["x_opencti_score"], "values": [str(min_score)], "operator": "gte", "mode": "or"}
        )
    if observable_type is not None:
        if observable_type not in OBSERVABLE_TYPES:
            raise bad_request("observable_type must be one of " + ", ".join(sorted(OBSERVABLE_TYPES)))
        filters.append(eq("x_opencti_main_observable_type", observable_type))
    if pattern_type is not None:
        if pattern_type not in PATTERN_TYPES:
            raise bad_request("pattern_type must be one of " + ", ".join(sorted(PATTERN_TYPES)))
        filters.append(eq("pattern_type", pattern_type))
    if not include_revoked:
        filters.append(eq("revoked", "false"))
    if not filters and not groups:
        return None
    return filter_group(filters, groups)


# --- TLP guard ----------------------------------------------------------------------------------

# Standard TLP 2.0 names (and TLP 1.0's WHITE) with the order OpenCTI gives them by default.
TLP_ORDER = {
    "TLP:CLEAR": 1,
    "TLP:WHITE": 1,
    "TLP:GREEN": 2,
    "TLP:AMBER": 3,
    "TLP:AMBER+STRICT": 4,
    "TLP:RED": 5,
}


def normalize_tlp(value: str) -> str:
    name = value.strip().upper()
    if not name.startswith("TLP:"):
        name = f"TLP:{name}"
    if name not in TLP_ORDER:
        raise ValueError(f"OPENCTI_MAX_TLP must be one of {', '.join(TLP_ORDER)}")
    return name


class TlpGuard:
    """Withholds objects marked above a TLP ceiling.

    Only markings whose `definition_type` is TLP count; PAP and statement markings share order
    numbers with TLP and are ignored. A TLP marking's rank is the higher of its `x_opencti_order`
    and its standard name's rank, so a renamed or reordered marking cannot slip under the ceiling.
    A TLP marking with neither a known name nor an order is treated as above the ceiling (fail
    closed). Unmarked objects are visible.
    """

    def __init__(self, ceiling: str) -> None:
        self.ceiling_name = normalize_tlp(ceiling)
        self.ceiling = TLP_ORDER[self.ceiling_name]

    def allows(self, node: Any) -> bool:
        if not isinstance(node, dict):
            return True
        for marking in node.get("objectMarking") or []:
            if not isinstance(marking, dict):
                return False
            if str(marking.get("definition_type") or "").strip().upper() != "TLP":
                continue
            ranks = []
            by_name = TLP_ORDER.get(str(marking.get("definition") or "").strip().upper())
            if by_name is not None:
                ranks.append(by_name)
            order = marking.get("x_opencti_order")
            if isinstance(order, int) and not isinstance(order, bool):
                ranks.append(order)
            if not ranks or max(ranks) > self.ceiling:
                return False
        return True


class Withheld:
    """Counts nodes the TLP guard drops in one tool call."""

    def __init__(self, guard: TlpGuard) -> None:
        self.guard = guard
        self.count = 0

    def allows(self, node: Any) -> bool:
        if self.guard.allows(node):
            return True
        self.count += 1
        return False

    def keep(self, nodes: list[Any]) -> list[Any]:
        return [n for n in nodes if self.allows(n)]
