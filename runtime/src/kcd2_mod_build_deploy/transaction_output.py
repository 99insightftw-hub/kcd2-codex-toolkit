"""Bounded compact projections for guarded transaction results."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Mapping


_SHA256 = re.compile(r"[a-f0-9]{64}")
_TYPED_SHA256 = re.compile(r"(?P<kind>[a-z][a-z0-9_-]{0,63}):sha256:(?P<sha>[a-f0-9]{64})")
MAX_FULL_BYTES = 8 * 1024 * 1024


class TransactionOutputError(ValueError):
    """A transaction result cannot be projected safely and deterministically."""


@dataclass(frozen=True, slots=True)
class CompactTransactionOutput:
    status: str
    exit_status: int
    receipt_path: str | None
    rollback_unit: str | None
    principal_hashes: tuple[tuple[str, str], ...]
    details_sha256: str
    details: Any | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "kcd2.compact-transaction-output.v1",
            "status": self.status,
            "exit_status": self.exit_status,
            "receipt_path": self.receipt_path,
            "rollback_unit": self.rollback_unit,
            "principal_hashes": dict(self.principal_hashes),
            "details_included": self.details is not None,
            "details_sha256": self.details_sha256,
        }
        if self.details is not None:
            payload["details"] = self.details
        return payload


def compact_transaction_output(
    result: object,
    *,
    status: str | None = None,
    exit_status: int = 0,
    receipt_path: Path | str | None = None,
    rollback_unit: Path | str | None = None,
    include_full: bool = False,
    max_full_bytes: int = MAX_FULL_BYTES,
) -> CompactTransactionOutput:
    """Return a stable summary; include the complete result only by explicit opt-in."""
    if not isinstance(exit_status, int) or isinstance(exit_status, bool):
        raise TransactionOutputError("exit_status must be an integer")
    if not isinstance(max_full_bytes, int) or not 1 <= max_full_bytes <= MAX_FULL_BYTES:
        raise TransactionOutputError("max_full_bytes is outside its hard bound")
    details = _json_safe(result)
    encoded = _canonical_bytes(details)
    if len(encoded) > max_full_bytes:
        raise TransactionOutputError("transaction details exceed the configured byte bound")
    mapping = details if isinstance(details, Mapping) else {}
    resolved_status = status if status is not None else _infer_status(result, mapping, exit_status)
    if not isinstance(resolved_status, str) or not 1 <= len(resolved_status) <= 64:
        raise TransactionOutputError("status must contain 1 to 64 characters")
    resolved_receipt = _path_value(
        receipt_path if receipt_path is not None else _field(result, mapping, "receipt_path")
    )
    if resolved_receipt is None:
        resolved_receipt = _path_value(_field(result, mapping, "last_receipt_path"))
    resolved_rollback = _path_value(
        rollback_unit if rollback_unit is not None else _field(result, mapping, "rollback_unit")
    )
    hashes = _principal_hashes(details)
    if resolved_receipt is not None:
        path = Path(resolved_receipt)
        if path.exists():
            if not path.is_file():
                raise TransactionOutputError("receipt_path exists but is not a file")
            hashes["receipt_sha256"] = _hash_file(path)
    return CompactTransactionOutput(
        status=resolved_status,
        exit_status=exit_status,
        receipt_path=resolved_receipt,
        rollback_unit=resolved_rollback,
        principal_hashes=tuple(sorted(hashes.items())),
        details_sha256=hashlib.sha256(encoded).hexdigest(),
        details=details if include_full else None,
    )


def _infer_status(result: object, mapping: Mapping[str, Any], exit_status: int) -> str:
    value = _field(result, mapping, "status")
    if isinstance(value, str):
        return value
    phase = _field(result, mapping, "phase")
    if hasattr(phase, "name") and isinstance(phase.name, str):
        return phase.name
    if isinstance(phase, str):
        return phase
    return "PASS" if exit_status == 0 else "ERROR"


def _field(result: object, mapping: Mapping[str, Any], name: str) -> object:
    if name in mapping:
        return mapping[name]
    return getattr(result, name, None)


def _path_value(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, Path)):
        raise TransactionOutputError("transaction path fields must be paths or null")
    text = str(value)
    if not 1 <= len(text) <= 4096:
        raise TransactionOutputError("transaction path exceeds its character bound")
    return text


def _json_safe(value: object) -> Any:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _json_safe(value.to_dict())
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(child) for child in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "name") and isinstance(value.name, str):
        return value.name
    raise TransactionOutputError(f"unsupported transaction detail type: {type(value).__name__}")


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TransactionOutputError("transaction details are not canonical JSON") from exc


def _principal_hashes(value: Any) -> dict[str, str]:
    hashes: dict[str, str] = {}

    def visit(node: Any, path: tuple[str, ...]) -> None:
        if isinstance(node, Mapping):
            for key in sorted(node):
                visit(node[key], path + (str(key),))
        elif isinstance(node, list):
            for child in node:
                visit(child, path)
        elif isinstance(node, str) and path:
            key = path[-1]
            lowered = node.lower()
            typed = _TYPED_SHA256.fullmatch(lowered)
            if typed is not None:
                hashes.setdefault(key, typed.group("sha"))
            elif key.endswith("sha256") and _SHA256.fullmatch(lowered):
                hashes.setdefault(key, lowered)

    visit(value, ())
    return hashes


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "CompactTransactionOutput",
    "MAX_FULL_BYTES",
    "TransactionOutputError",
    "compact_transaction_output",
]
