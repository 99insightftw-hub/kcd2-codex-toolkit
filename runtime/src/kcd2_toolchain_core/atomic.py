"""Same-directory atomic file replacement helpers."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from .hashing import canonical_json_bytes


def atomic_write_bytes(path: str | Path, data: bytes) -> None:
    """Flush bytes to a same-directory temporary file and atomically replace path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, target)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def atomic_write_text(path: str | Path, text: str) -> None:
    """Atomically write UTF-8 text without platform newline translation."""
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: str | Path, value: Any) -> None:
    """Atomically write canonical JSON followed by one newline."""
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"value is not canonical-JSON serializable: {error}") from error
    atomic_write_bytes(path, encoded + b"\n")
