# SPDX-FileCopyrightText: 2026 Jake Wehmeier (BTSpaniel) <https://github.com/BTSpaniel>
#
# SPDX-License-Identifier: LicenseRef-ParticleRealms-Alpha

"""Strict, resource-bounded JSON decoding for untrusted network input."""

from __future__ import annotations

import json
from typing import Any


class StrictJsonError(ValueError):
    """Raised when JSON is invalid, ambiguous, or exceeds structural limits."""


def loads_strict(
    value: str | bytes | bytearray,
    *,
    max_bytes: int,
    max_depth: int = 16,
    max_nodes: int = 512,
    max_string_bytes: int = 65_536,
) -> Any:
    if isinstance(value, str):
        raw = value.encode("utf-8")
        text = value
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJsonError("JSON must be UTF-8") from exc
    else:
        raise StrictJsonError("JSON input must be text or bytes")
    if len(raw) > max_bytes:
        raise StrictJsonError("JSON exceeds the byte limit")
    _check_nesting(text, max_depth)

    def reject_constant(token: str):
        raise StrictJsonError(f"non-finite JSON number is forbidden: {token}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise StrictJsonError(f"duplicate JSON property is forbidden: {key}")
            result[key] = child
        return result

    try:
        decoded = json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise StrictJsonError("invalid JSON") from exc
    _check_tree(decoded, max_nodes=max_nodes, max_string_bytes=max_string_bytes)
    return decoded


def _check_nesting(text: str, maximum: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise StrictJsonError("JSON nesting exceeds the limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise StrictJsonError("invalid JSON nesting")
    if in_string or depth != 0:
        raise StrictJsonError("invalid JSON nesting")


def _check_tree(value: Any, *, max_nodes: int, max_string_bytes: int) -> None:
    nodes = 0
    pending = [value]
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > max_nodes:
            raise StrictJsonError("JSON node count exceeds the limit")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > max_string_bytes:
                raise StrictJsonError("JSON string exceeds the byte limit")
        elif isinstance(current, dict):
            for key, child in current.items():
                if len(key.encode("utf-8")) > max_string_bytes:
                    raise StrictJsonError("JSON property name exceeds the byte limit")
                pending.append(child)
        elif isinstance(current, list):
            pending.extend(current)
