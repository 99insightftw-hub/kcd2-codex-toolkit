"""In-memory exact-artifact overlay that never writes a production Index."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


MAX_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 200_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}")
_ACCEPTED_RECEIPT_PREFIXES = (
    "kcd2.candidate-build-receipt.",
    "kcd2.double-build-receipt.",
    "kcd2.install-receipt.",
)


class TransactionOverlayError(ValueError):
    """The exact receipt/artifact overlay cannot be trusted or bounded."""


@dataclass(frozen=True, slots=True)
class OverlayMember:
    canonical_path: str
    sha256: str
    bytes: int
    compression_method: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_path": self.canonical_path,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "compression_method": self.compression_method,
        }


@dataclass(frozen=True, slots=True)
class TransactionLocalOverlay:
    receipt_path: Path
    receipt_sha256: str
    receipt_schema_version: str
    artifact_path: Path
    artifact_sha256: str
    members: tuple[OverlayMember, ...]
    source_mode: str = "transaction_local_exact_artifact"
    production_index_writes: bool = False

    def query(self, internal_path: str) -> dict[str, Any]:
        canonical = _internal_path(internal_path)
        matches = [item for item in self.members if item.canonical_path.casefold() == canonical.casefold()]
        if len(matches) > 1:
            raise TransactionOverlayError("overlay contains ambiguous case-colliding members")
        member = matches[0] if matches else None
        return {
            "schema_version": "kcd2.transaction-local-overlay-query.v1",
            "source_mode": self.source_mode,
            "receipt_sha256": self.receipt_sha256,
            "artifact_sha256": self.artifact_sha256,
            "query_path": canonical,
            "status": "FOUND" if member is not None else "NOT_FOUND_EXACT_ARTIFACT",
            "member": None if member is None else member.to_dict(),
            "production_index_consulted": False,
            "production_index_writes": False,
        }


def open_transaction_local_overlay(
    receipt_path: Path | str,
    artifact_path: Path | str,
) -> TransactionLocalOverlay:
    receipt_source = _plain_file(receipt_path, max_bytes=MAX_RECEIPT_BYTES, label="receipt")
    artifact_source = _plain_file(artifact_path, max_bytes=MAX_TOTAL_BYTES, label="artifact")
    receipt_bytes = receipt_source.read_bytes()
    try:
        receipt = json.loads(receipt_bytes, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransactionOverlayError("receipt is not valid JSON") from exc
    if not isinstance(receipt, Mapping):
        raise TransactionOverlayError("receipt root must be an object")
    schema = receipt.get("schema_version")
    if not isinstance(schema, str) or not schema.startswith(_ACCEPTED_RECEIPT_PREFIXES):
        raise TransactionOverlayError("receipt schema is not an accepted build/install authority")
    artifact_sha256 = _hash_file(artifact_source)
    declared = _declared_hashes(receipt)
    if artifact_sha256 not in declared:
        raise TransactionOverlayError("artifact SHA-256 is not declared by the exact receipt")
    members = _inspect_zip(artifact_source)
    return TransactionLocalOverlay(
        receipt_path=receipt_source,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        receipt_schema_version=schema,
        artifact_path=artifact_source,
        artifact_sha256=artifact_sha256,
        members=members,
    )


def _inspect_zip(path: Path) -> tuple[OverlayMember, ...]:
    members: list[OverlayMember] = []
    names: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise TransactionOverlayError("archive member count exceeds its bound")
            for info in infos:
                canonical = _internal_path(info.filename)
                if canonical.casefold() in names:
                    raise TransactionOverlayError("archive contains duplicate or case-colliding members")
                names.add(canonical.casefold())
                if info.is_dir() or info.file_size > MAX_MEMBER_BYTES:
                    raise TransactionOverlayError("archive member is a directory or exceeds its byte bound")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise TransactionOverlayError("archive expanded size exceeds its bound")
                digest = hashlib.sha256()
                observed = 0
                with archive.open(info) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        observed += len(chunk)
                        if observed > info.file_size or observed > MAX_MEMBER_BYTES:
                            raise TransactionOverlayError("archive member expanded beyond its declaration")
                        digest.update(chunk)
                if observed != info.file_size:
                    raise TransactionOverlayError("archive member size changed during inspection")
                members.append(
                    OverlayMember(canonical, digest.hexdigest(), observed, info.compress_type)
                )
    except (OSError, zipfile.BadZipFile) as exc:
        raise TransactionOverlayError("artifact is not a readable ZIP/PAK") from exc
    return tuple(sorted(members, key=lambda item: item.canonical_path.casefold()))


def _declared_hashes(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            if isinstance(child, str) and str(key).endswith("sha256") and _SHA256.fullmatch(child.lower()):
                result.add(child.lower())
            else:
                result.update(_declared_hashes(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_declared_hashes(child))
    return result


def _plain_file(value: Path | str, *, max_bytes: int, label: str) -> Path:
    path = Path(value).resolve(strict=True)
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or path.stat().st_size > max_bytes:
        raise TransactionOverlayError(f"{label} is not a bounded plain file")
    return path


def _internal_path(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or "\\" in value:
        raise TransactionOverlayError("internal path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise TransactionOverlayError("internal path is not canonical and relative")
    return path.as_posix()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransactionOverlayError("receipt contains duplicate JSON keys")
        result[key] = value
    return result


__all__ = [
    "OverlayMember",
    "TransactionLocalOverlay",
    "TransactionOverlayError",
    "open_transaction_local_overlay",
]
