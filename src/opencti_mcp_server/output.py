"""Compact JSON output: third-party text cleaned and capped, with an explicit truncation marker.

OpenCTI content comes from third-party feeds, so every string is stripped of control and
zero-width characters and every free-text field is capped before it reaches the model.
"""

from __future__ import annotations

import json
import re
from typing import Any

DESCRIPTION_MAX = 500
PATTERN_MAX = 1000
TEXT_MAX = 300
LABELS_MAX = 20

# Control characters (except newline and tab), zero-width and bidi-override characters.
_STRIP = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)
_LINE_SEPARATORS = re.compile(r"[\u2028\u2029]")


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str)


def clean(value: Any, max_len: int = TEXT_MAX) -> str | None:
    """Third-party text: drop control and zero-width characters, then cap the length."""
    if value is None:
        return None
    text = _LINE_SEPARATORS.sub("\n", _STRIP.sub("", str(value)))
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text


def fit(result: dict[str, Any], list_path: str | tuple[str, ...], max_chars: int) -> str:
    """Serialise `result`, dropping items from the list at `list_path` until it fits in `max_chars`.

    `list_path` is a key, or a tuple of keys for a nested list (e.g. ("indicator", "observables")).
    When anything is dropped, the result says so with the original item count and size, so the
    caller never mistakes a partial answer for a complete one.
    """
    text = dumps(result)
    path = (list_path,) if isinstance(list_path, str) else tuple(list_path)
    parent = result
    for key in path[:-1]:
        parent = parent.get(key) if isinstance(parent, dict) else None
    items = parent.get(path[-1]) if isinstance(parent, dict) else None
    if len(text) <= max_chars or not isinstance(items, list):
        return text
    original_items, original_chars = len(items), len(text)
    kept = list(items)
    while kept:
        kept = kept[: max(len(kept) * 3 // 4, len(kept) - 1)] if len(kept) > 1 else []
        parent[path[-1]] = kept
        candidate = {
            **result,
            "truncated": {
                "list": ".".join(path),
                "returned_items": len(kept),
                "original_items": original_items,
                "original_chars": original_chars,
                "hint": "ask for fewer items with `first`, or narrow the query",
            },
        }
        text = dumps(candidate)
        if len(text) <= max_chars:
            return text
    return text
