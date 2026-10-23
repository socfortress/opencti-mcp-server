"""Compact JSON output: third-party text cleaned and capped, with an explicit truncation marker.

OpenCTI content comes from third-party feeds, so every string is stripped of invisible characters
and every free-text field and list is capped before it reaches the model.
"""

from __future__ import annotations

import json
import unicodedata
from typing import Any

DESCRIPTION_MAX = 500
PATTERN_MAX = 1000
TEXT_MAX = 300
LABELS_MAX = 20
LIST_MAX = 20  # other short lists: kill chain phases, indicator types, observable values
ELLIPSIS = chr(0x2026)

# Categories stripped: Cc control (newline and tab are kept by `clean`), Cf format (zero-width,
# bidi overrides, soft hyphen, tag characters), Co private use, Cn unassigned.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn"})
# Invisible characters outside those categories: variation selectors, the tag block (also covered
# by Cf/Cn), soft hyphen, Mongolian vowel separator, combining grapheme joiner.
_STRIP_RANGES = (
    (0xFE00, 0xFE0F),
    (0xE0100, 0xE01EF),
    (0xE0000, 0xE007F),
    (0x00AD, 0x00AD),
    (0x180E, 0x180E),
    (0x034F, 0x034F),
)
_LINE_SEPARATORS = {0x2028: "\n", 0x2029: "\n"}


def invisible(ch: str) -> bool:
    """True for a character `clean` strips (newline and tab count: callers that keep them say so)."""
    if unicodedata.category(ch) in _STRIP_CATEGORIES:
        return True
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _STRIP_RANGES)


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def clean(value: Any, max_len: int = TEXT_MAX) -> str | None:
    """Third-party text: drop invisible characters (keeping newline and tab), then cap the length."""
    if value is None:
        return None
    text = str(value).translate(_LINE_SEPARATORS)
    text = "".join(ch for ch in text if ch in "\n\t" or not invisible(ch))
    if len(text) > max_len:
        return text[: max_len - 1] + ELLIPSIS
    return text


def capped(items: list[Any], limit: int = LIST_MAX) -> tuple[list[Any], int | None]:
    """The first `limit` items, and the full count when anything was cut (else None)."""
    return items[:limit], (len(items) if len(items) > limit else None)


def fit(result: dict[str, Any], list_path: str | tuple[str, ...], max_chars: int) -> str:
    """Serialise `result`, dropping items from the list at `list_path` until it fits in `max_chars`.

    `list_path` is a key, or a tuple of keys for a nested list (e.g. ("indicator", "observables")).
    When anything is dropped, the result says so with the original item count and size, so the
    caller never mistakes a partial answer for a complete one. If the result is still too large
    with the list empty, only its top-level scalars are returned, with the same marker.
    """
    text = dumps(result)
    if len(text) <= max_chars:
        return text
    path = (list_path,) if isinstance(list_path, str) else tuple(list_path)
    parent: Any = result
    for key in path[:-1]:
        parent = parent.get(key) if isinstance(parent, dict) else None
    items = parent.get(path[-1]) if isinstance(parent, dict) else None
    original_items = len(items) if isinstance(items, list) else 0
    original_chars = len(text)

    def marker(returned: int, hint: str) -> dict[str, Any]:
        return {
            "list": ".".join(path),
            "returned_items": returned,
            "original_items": original_items,
            "original_chars": original_chars,
            "hint": hint,
        }

    hint = "ask for fewer items with `first`, or narrow the query"
    if isinstance(items, list):
        kept = list(items)
        while kept:
            kept = kept[: max(len(kept) * 3 // 4, len(kept) - 1)] if len(kept) > 1 else []
            parent[path[-1]] = kept
            text = dumps({**result, "truncated": marker(len(kept), hint)})
            if len(text) <= max_chars:
                return text
    scalars = {k: v for k, v in result.items() if not isinstance(v, (dict, list))}
    too_big = marker(0, "the result exceeds MCP_MAX_OUTPUT_CHARS even without items; raise the limit")
    return dumps({**scalars, "truncated": too_big})
