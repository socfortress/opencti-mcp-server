"""Argument guards, filter builders and the TLP guard.

Every tool call passes its arguments through these before anything reaches OpenCTI. Caller values
only ever become GraphQL variables (FilterGroup values, ids, cursors); they are never spliced into a
document.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal

from mcp.server.mcpserver.exceptions import ToolError

from opencti_mcp_server.output import invisible

# --- errors -------------------------------------------------------------------------------------


def bad_request(message: str) -> ToolError:
    return ToolError(f"bad request: {message}")


# --- loose argument types -----------------------------------------------------------------------
# Tool arguments are declared loosely (the JSON schema still says string / integer / boolean), so a
# wrong type reaches these checks and comes back as `bad request:` rather than a schema error.


def as_str(value: Any, name: str) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise bad_request(f"{name} must be a string")


def as_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*-?\d{1,9}\s*", value):
        return int(value)
    raise bad_request(f"{name} must be an integer")


def as_bool(value: Any, name: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise bad_request(f"{name} must be true or false")


# --- ids, cursors, search text ------------------------------------------------------------------

_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_ID = re.compile(rf"^(?:[a-z][a-z0-9-]{{0,62}}--)?{_UUID}$", re.IGNORECASE)
_CURSOR = re.compile(r"^[A-Za-z0-9+/=_-]{1,512}$")

# OpenCTI's keyword sub-fields have `ignore_above: 512`: a longer value is not indexed for exact
# matching, so `eq` / `contains` on it silently match nothing.
EXACT_MATCH_MAX = 512
FUZZY_LABEL = "fuzzy (value longer than OpenCTI's 512-character exact-match limit)"


def check_id(value: Any) -> str:
    """An OpenCTI internal id (a UUID) or a STIX id (`<type>--<uuid>`)."""
    value = (as_str(value, "id") or "").strip()
    if not _ID.fullmatch(value):
        raise bad_request("id must be a UUID or a STIX id such as 'indicator--<uuid>'")
    return value.lower()


def check_cursor(value: Any) -> str | None:
    value = as_str(value, "after")
    if value is None or value == "":
        return None
    if not _CURSOR.fullmatch(value):
        raise bad_request("after must be the endCursor of a previous page")
    return value


def check_text(value: Any, name: str, max_len: int) -> str | None:
    """Free text from the caller: no control, format, private-use, unassigned or invisible
    characters (the set `output.clean` strips, plus newlines and tabs), bounded length."""
    value = as_str(value, name)
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if any(ch in "\n\t\u2028\u2029" or invisible(ch) for ch in value):
        raise bad_request(f"{name} contains control or zero-width characters")
    if len(value) > max_len:
        raise bad_request(f"{name} is longer than {max_len} characters")
    return value


def check_search(value: Any, max_len: int) -> str | None:
    """OpenCTI keyword search. `~` (fuzzy) and a leading `*` are refused: they turn a lookup into an
    expensive, loosely matching query."""
    value = check_text(value, "search", max_len)
    if value is None:
        return None
    if "~" in value:
        raise bad_request("search must not contain '~' (fuzzy matching is not allowed)")
    if value.startswith("*"):
        raise bad_request("search must not start with '*'")
    return value


def check_value(value: Any, name: str = "value") -> str | None:
    value = check_text(value, name, MAX_VALUE_LEN)
    if value is not None and value[0] in "*~":
        raise bad_request(f"{name} must not start with '*' or '~'")
    return value


def fuzzy_text(value: str) -> str:
    """A long value as plain search text: OpenCTI's search syntax characters become spaces."""
    return re.sub(r"\s+", " ", re.sub(r'[~*?"\\]', " ", value)).strip()


def check_first(first: Any, max_first: int, name: str = "first") -> int:
    first = as_int(first, name)
    if first is None or first < 1 or first > max_first:
        raise bad_request(f"{name} must be between 1 and {max_first}")
    return first


# --- observable values --------------------------------------------------------------------------

ObservableKind = Literal[
    "md5", "sha1", "sha256", "sha512", "ipv4", "ipv6", "domain", "hostname", "url", "email"
]

_HASHED = ["StixFile", "Artifact", "X509-Certificate"]
# kind -> (OpenCTI observable types, filter key)
_KINDS: dict[str, tuple[list[str], str]] = {
    "md5": (_HASHED, "hashes.MD5"),
    "sha1": (_HASHED, "hashes.SHA-1"),
    "sha256": (_HASHED, "hashes.SHA-256"),
    "sha512": (_HASHED, "hashes.SHA-512"),
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


@dataclass(frozen=True)
class Lookup:
    kind: str
    value: str
    types: list[str]
    filters: dict[str, Any] | None  # exact match
    search: str | None  # fuzzy fallback for values over EXACT_MATCH_MAX

    @property
    def fuzzy(self) -> bool:
        return self.search is not None


def canonical_ip(value: str) -> str:
    """An IP address in one form whatever the Python version: compressed IPv6, and an IPv4-mapped
    IPv6 address as `::ffff:a.b.c.d` (Python 3.13 changed how `compressed` writes those)."""
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return f"::ffff:{ip.ipv4_mapped}"
    return ip.compressed


def observable_lookup(value: Any, kind: Any) -> Lookup:
    """Validate a value to look up and build its exact-match filter.

    Domains also match Hostname observables when the type was auto-detected; hashes match files,
    artifacts and X.509 certificates. IP addresses are canonicalised (IPv6 compressed). A value
    longer than OpenCTI's exact-match limit falls back to a fuzzy search.
    """
    value = check_value(value)
    kind = as_str(kind, "type")
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
    elif kind in ("ipv4", "ipv6"):
        value = canonical_ip(value)
    types, key = _KINDS[kind]
    if detected and kind == "domain":
        types = ["Domain-Name", "Hostname"]
    if len(value) > EXACT_MATCH_MAX:
        return Lookup(kind, value, list(types), None, fuzzy_text(value))
    return Lookup(kind, value, list(types), filter_group([eq(key, value)]), None)


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
    min_score: Any,
    observable_type: Any,
    pattern_type: Any,
    include_revoked: bool,
) -> dict[str, Any] | None:
    """FilterGroup for search_indicators.

    `value` is an exact, case-insensitive match: the indicator's name equals it, or its pattern
    holds it as a quoted literal (so 'evil.com' does not match 'notevil.com').
    """
    min_score = as_int(min_score, "min_score")
    observable_type = as_str(observable_type, "observable_type")
    pattern_type = as_str(pattern_type, "pattern_type")
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

# Standard TLP 2.0 names (and TLP 1.0's WHITE) and their rank, the order OpenCTI gives them.
TLP_ORDER = {
    "TLP:CLEAR": 1,
    "TLP:WHITE": 1,
    "TLP:GREEN": 2,
    "TLP:AMBER": 3,
    "TLP:AMBER+STRICT": 4,
    "TLP:RED": 5,
}


def _squash(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).upper()


def tlp_name(value: Any) -> str:
    """Normalise a TLP name: whitespace removed, upper-cased, `TLP:` added if missing."""
    name = _squash(value)
    return name if name.startswith("TLP:") else f"TLP:{name}"


def normalize_tlp(value: str) -> str:
    name = tlp_name(value)
    if name not in TLP_ORDER:
        raise ValueError(f"OPENCTI_MAX_TLP must be one of {', '.join(TLP_ORDER)}")
    return name


def parse_extra_tlp(value: str) -> dict[str, int]:
    """`OPENCTI_EXTRA_TLP`: comma-separated `NAME:rank`, e.g. `TLP:EX:CHR:3,TLP:AMBER-NL:3`."""
    extra: dict[str, int] = {}
    for item in (value or "").split(","):
        if not item.strip():
            continue
        name, sep, rank = item.strip().rpartition(":")
        if not sep or not name or not rank.strip().isdigit():
            raise ValueError(f"OPENCTI_EXTRA_TLP entry {item.strip()!r} is not NAME:rank")
        norm = tlp_name(name)
        if norm in TLP_ORDER:
            raise ValueError(f"OPENCTI_EXTRA_TLP cannot redefine the standard marking {norm}")
        if not 0 <= int(rank) <= 100:
            raise ValueError("OPENCTI_EXTRA_TLP ranks must be between 0 and 100")
        extra[norm] = int(rank)
    return extra


def is_tlp(marking: dict[str, Any]) -> bool:
    """A marking is TLP if its definition_type says so (any case or spelling: `TLP`, `tlp`,
    `TLPv2`, `TLP 2.0`) or its definition starts with `TLP:`. A definition starting with `PAP:` is
    PAP, never TLP; PAP orders overlap TLP's."""
    definition = _squash(marking.get("definition"))
    if definition.startswith("PAP:"):
        return False
    kind = re.sub(r"[^A-Z0-9]", "", _squash(marking.get("definition_type")))
    return kind.startswith("TLP") or definition.startswith("TLP:")


class TlpGuard:
    """Withholds objects marked above a TLP ceiling.

    A TLP marking is ranked by its normalised name only: the standard names, plus any the operator
    adds with OPENCTI_EXTRA_TLP. A TLP marking with any other name is withheld whatever its
    `x_opencti_order` (OpenCTI gives imported custom markings order 0). PAP and statement markings
    are ignored. Every document requests `objectMarking`, so a node without the key, a non-object
    node or a non-object marking is withheld (fail closed). Unmarked objects are visible.
    """

    def __init__(self, ceiling: str, extra: dict[str, int] | None = None) -> None:
        self.ceiling_name = normalize_tlp(ceiling)
        self.ceiling = TLP_ORDER[self.ceiling_name]
        self.ranks = {**(extra or {}), **TLP_ORDER}

    def allows(self, node: Any) -> bool:
        if not isinstance(node, dict) or "objectMarking" not in node:
            return False
        markings = node["objectMarking"]
        if markings is None:
            return True
        if not isinstance(markings, list):
            return False
        for marking in markings:
            if not isinstance(marking, dict):
                return False
            if not is_tlp(marking):
                continue
            rank = self.ranks.get(tlp_name(marking.get("definition")))
            if rank is None or rank > self.ceiling:
                return False
        return True


class Withheld:
    """Counts the nodes the TLP guard drops in one tool call."""

    def __init__(self, guard: TlpGuard, hide_counts: bool = False) -> None:
        self.guard = guard
        self.hide_counts = hide_counts
        self.count = 0

    def allows(self, node: Any) -> bool:
        if self.guard.allows(node):
            return True
        self.count += 1
        return False

    def keep(self, nodes: list[Any]) -> list[Any]:
        return [n for n in nodes if self.allows(n)]

    def total(self, platform_total: int | None, fetched: int, kept: int) -> int | None:
        """The total to report. With hidden counts it must exclude withheld items, which is only
        computable when the page holds every item; otherwise it is omitted."""
        if not self.hide_counts:
            return platform_total
        if platform_total is not None and fetched >= platform_total:
            return kept
        return None

    def fields(self) -> dict[str, Any]:
        if self.hide_counts:
            return {}
        out: dict[str, Any] = {"withheld": self.count}
        if self.count:
            out["withheld_reason"] = f"marked above {self.guard.ceiling_name}"
        return out
