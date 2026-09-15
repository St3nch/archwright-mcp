"""Recursive redaction for requests, results and error details."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_KEY = re.compile(
    r"(^|[_-])(authorization|cookie|credential|password|passphrase|private[_-]?key|psk|secret|token)([_-]|$)",
    re.IGNORECASE,
)


def is_secret_key(key: str) -> bool:
    """Return whether a structured field name carries secret material."""

    return bool(_SECRET_KEY.search(key))


def redact(value: Any, *, extra_secret_keys: frozenset[str] = frozenset()) -> Any:
    """Return a recursively redacted, JSON-compatible copy of ``value``."""

    normalized_extra = {key.casefold() for key in extra_secret_keys}

    def visit(item: Any) -> Any:
        if isinstance(item, Mapping):
            redacted: dict[str, Any] = {}
            for raw_key, nested in item.items():
                key = str(raw_key)
                if key.casefold() in normalized_extra or is_secret_key(key):
                    redacted[key] = REDACTED
                else:
                    redacted[key] = visit(nested)
            return redacted
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            return [visit(nested) for nested in item]
        if isinstance(item, bytes):
            return f"[BYTES:{len(item)}]"
        if item is None or isinstance(item, (str, int, float, bool)):
            return item
        return str(item)

    return visit(value)
