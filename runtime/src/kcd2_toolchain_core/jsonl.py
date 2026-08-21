"""Bounded, deterministic JSON Lines ingestion."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class BoundedJsonlLimits:
    schema_version: str = "kcd2.bounded-jsonl-limits.v1"
    max_records: int = 10_000
    max_line_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.bounded-jsonl-limits.v1":
            raise ValueError("unsupported bounded JSONL limits schema_version")
        for name in ("max_records", "max_line_bytes", "max_total_bytes"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "max_records": self.max_records,
            "max_line_bytes": self.max_line_bytes,
            "max_total_bytes": self.max_total_bytes,
        }


TruncationReason = Literal["max_records", "max_total_bytes"]


@dataclass(frozen=True, slots=True)
class BoundedJsonlResult:
    records: tuple[Any, ...]
    bytes_read: int
    lines_read: int
    truncated: bool = False
    reason: TruncationReason | None = None
    schema_version: str = "kcd2.bounded-jsonl-result.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "records": list(self.records),
            "bytes_read": self.bytes_read,
            "lines_read": self.lines_read,
            "truncated": self.truncated,
            "reason": self.reason,
        }


def read_bounded_jsonl(
    path: str | Path,
    *,
    limits: BoundedJsonlLimits | None = None,
) -> BoundedJsonlResult:
    """Read complete JSONL records while enforcing byte, line, and record ceilings."""
    bounds = limits or BoundedJsonlLimits()
    records: list[Any] = []
    bytes_read = 0
    lines_read = 0
    truncated = False
    reason: TruncationReason | None = None

    with Path(path).open("rb") as stream:
        while True:
            line = stream.readline(bounds.max_line_bytes + 1)
            if not line:
                break
            lines_read += 1
            bytes_read += len(line)
            if len(line) > bounds.max_line_bytes:
                raise ValueError(f"line {lines_read} exceeds max_line_bytes")
            if bytes_read > bounds.max_total_bytes:
                truncated = True
                reason = "max_total_bytes"
                break
            if len(records) >= bounds.max_records:
                truncated = True
                reason = "max_records"
                break
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"line {lines_read} is not valid UTF-8") from error
            if not text.strip():
                raise ValueError(f"line {lines_read} is empty")
            try:
                records.append(json.loads(text))
            except json.JSONDecodeError as error:
                raise ValueError(f"line {lines_read} is not valid JSON: {error.msg}") from error

    return BoundedJsonlResult(
        records=tuple(records),
        bytes_read=bytes_read,
        lines_read=lines_read,
        truncated=truncated,
        reason=reason,
    )
