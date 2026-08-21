"""Host-independent canonical relative path handling."""

from __future__ import annotations

import re


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def canonical_relative_path(value: str) -> str:
    """Return a slash-separated relative path without changing its casing.

    Absolute paths, drive-qualified paths, traversal, NULs, and empty paths are
    rejected so external deployment locations cannot leak into portable records.
    """
    if not isinstance(value, str):
        raise TypeError("path must be a string")
    if not value or "\x00" in value:
        raise ValueError("path must be a non-empty string without NUL bytes")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_PREFIX.match(normalized):
        raise ValueError("path must be relative and drive-free")

    parts: list[str] = []
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("path traversal is not allowed")
        parts.append(part)
    if not parts:
        raise ValueError("path must identify a relative entry")
    return "/".join(parts)


def canonical_path_key(value: str) -> str:
    """Return the deterministic case-insensitive comparison key for a path."""
    return canonical_relative_path(value).casefold()
