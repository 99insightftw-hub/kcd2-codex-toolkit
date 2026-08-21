"""Immutable, hash-linked attempt receipts for resumable local transactions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable, Mapping


_ATTEMPT = re.compile(r"attempt-(?P<number>[0-9]{3})")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_RECEIPT = re.compile(r"(?P<ordinal>[0-9]{3})-(?P<phase>[a-z_]+)\.json")
MAX_ATTEMPTS = 999
DEFAULT_MAX_FILES = 16_384
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024


class TransactionAttemptError(ValueError):
    """The attempt history or scratch boundary cannot be trusted."""


class AttemptPhase(IntEnum):
    CREATED = 0
    SOURCE_PREPARED = 10
    BUILT = 20
    VALIDATED = 30
    INSTALL_PLANNED = 40
    APPROVED = 50
    INSTALLED = 60
    VERIFIED = 70
    FAILED = 999


@dataclass(frozen=True, slots=True)
class AttemptArtifact:
    path: Path
    sha256: str
    bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"bytes": self.bytes, "path": str(self.path), "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class TransactionAttempt:
    transaction_root: Path
    attempt_path: Path
    attempt_id: str
    input_sha256: str
    phase: AttemptPhase
    last_receipt_path: Path
    last_receipt_sha256: str
    resumed: bool


def canonical_input_sha256(value: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping):
        raise TransactionAttemptError("transaction input must be a mapping")
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TransactionAttemptError("transaction input must be canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def open_transaction_attempt(
    transaction_root: Path | str,
    *,
    input_sha256: str,
    max_attempts: int = MAX_ATTEMPTS,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TransactionAttempt:
    """Resume one verified attempt or allocate the next immutable attempt directory."""
    digest = _digest(input_sha256, "input_sha256")
    root = _checked_root(transaction_root)
    _validate_limits(max_attempts=max_attempts, max_files=max_files, max_bytes=max_bytes)
    attempts = _attempt_directories(root, max_attempts=max_attempts)
    if attempts:
        latest_number, latest_path = attempts[-1]
        latest = _load_attempt(latest_path, root=root, max_files=max_files, max_bytes=max_bytes)
        if latest.input_sha256 == digest and latest.phase not in {AttemptPhase.FAILED}:
            _verify_recorded_artifacts(latest_path, max_files=max_files, max_bytes=max_bytes)
            return TransactionAttempt(
                transaction_root=latest.transaction_root,
                attempt_path=latest.attempt_path,
                attempt_id=latest.attempt_id,
                input_sha256=latest.input_sha256,
                phase=latest.phase,
                last_receipt_path=latest.last_receipt_path,
                last_receipt_sha256=latest.last_receipt_sha256,
                resumed=True,
            )
        if latest.phase != AttemptPhase.FAILED and latest.input_sha256 != digest:
            raise TransactionAttemptError(
                "active attempt is bound to different immutable inputs"
            )
        next_number = latest_number + 1
    else:
        next_number = 1
    if next_number > max_attempts:
        raise TransactionAttemptError("transaction attempt limit is exhausted")
    attempt_id = f"attempt-{next_number:03d}"
    attempt_path = root / attempt_id
    attempt_path.mkdir()
    receipt_path, receipt_sha256 = _write_phase_receipt(
        attempt_path,
        attempt_id=attempt_id,
        input_sha256=digest,
        phase=AttemptPhase.CREATED,
        previous_receipt_sha256=None,
        artifacts=(),
        reason=None,
    )
    return TransactionAttempt(
        transaction_root=root,
        attempt_path=attempt_path,
        attempt_id=attempt_id,
        input_sha256=digest,
        phase=AttemptPhase.CREATED,
        last_receipt_path=receipt_path,
        last_receipt_sha256=receipt_sha256,
        resumed=False,
    )


def record_attempt_phase(
    attempt: TransactionAttempt,
    phase: AttemptPhase,
    *,
    artifacts: Iterable[Path | str] = (),
    reason: str | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TransactionAttempt:
    """Append one phase receipt; prior receipts and attempts are never overwritten."""
    current = _load_attempt(
        attempt.attempt_path,
        root=attempt.transaction_root,
        max_files=max_files,
        max_bytes=max_bytes,
    )
    _verify_recorded_artifacts(
        current.attempt_path, max_files=max_files, max_bytes=max_bytes
    )
    if current.last_receipt_sha256 != attempt.last_receipt_sha256:
        raise TransactionAttemptError("attempt advanced outside the current owner")
    if current.phase in {AttemptPhase.FAILED, AttemptPhase.VERIFIED}:
        raise TransactionAttemptError("terminal attempt cannot advance")
    if phase == AttemptPhase.FAILED:
        if not isinstance(reason, str) or not 1 <= len(reason) <= 2048:
            raise TransactionAttemptError("failed phase requires a bounded reason")
    elif phase <= current.phase or phase == AttemptPhase.CREATED:
        raise TransactionAttemptError("attempt phases must advance monotonically")
    elif reason is not None:
        raise TransactionAttemptError("reason is reserved for failed attempts")
    ledger = _artifact_ledger(
        artifacts,
        attempt_root=current.attempt_path,
        max_files=max_files,
        max_bytes=max_bytes,
    )
    receipt_path, receipt_sha256 = _write_phase_receipt(
        current.attempt_path,
        attempt_id=current.attempt_id,
        input_sha256=current.input_sha256,
        phase=phase,
        previous_receipt_sha256=current.last_receipt_sha256,
        artifacts=ledger,
        reason=reason,
    )
    return TransactionAttempt(
        transaction_root=current.transaction_root,
        attempt_path=current.attempt_path,
        attempt_id=current.attempt_id,
        input_sha256=current.input_sha256,
        phase=phase,
        last_receipt_path=receipt_path,
        last_receipt_sha256=receipt_sha256,
        resumed=False,
    )


def fail_transaction_attempt(
    attempt: TransactionAttempt,
    reason: str,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> TransactionAttempt:
    return record_attempt_phase(
        attempt,
        AttemptPhase.FAILED,
        reason=reason,
        max_files=max_files,
        max_bytes=max_bytes,
    )


def _checked_root(value: Path | str) -> Path:
    root = Path(value)
    if not root.exists() or not root.is_dir():
        raise TransactionAttemptError("transaction root must already exist")
    if _is_reparse(root):
        raise TransactionAttemptError("transaction root must not be a reparse point")
    return root.resolve(strict=True)


def _attempt_directories(root: Path, *, max_attempts: int) -> list[tuple[int, Path]]:
    entries: list[tuple[int, Path]] = []
    for child in root.iterdir():
        match = _ATTEMPT.fullmatch(child.name)
        if match is None:
            raise TransactionAttemptError("transaction root contains undeclared content")
        if not child.is_dir() or _is_reparse(child):
            raise TransactionAttemptError("attempt entry is not a plain directory")
        number = int(match.group("number"))
        if number < 1 or number > max_attempts:
            raise TransactionAttemptError("attempt identifier exceeds the configured bound")
        entries.append((number, child.resolve(strict=True)))
    entries.sort()
    if [number for number, _ in entries] != list(range(1, len(entries) + 1)):
        raise TransactionAttemptError("attempt identifiers are not contiguous")
    return entries


def _load_attempt(
    attempt_path: Path,
    *,
    root: Path,
    max_files: int,
    max_bytes: int,
) -> TransactionAttempt:
    resolved = attempt_path.resolve(strict=True)
    if resolved.parent != root or _is_reparse(resolved):
        raise TransactionAttemptError("attempt escaped its transaction root")
    receipts = sorted(resolved.glob("[0-9][0-9][0-9]-*.json"))
    if not receipts:
        raise TransactionAttemptError("attempt has no phase receipts")
    if len(receipts) > len(AttemptPhase):
        raise TransactionAttemptError("attempt has too many phase receipts")
    previous: str | None = None
    input_sha256: str | None = None
    phase: AttemptPhase | None = None
    for index, path in enumerate(receipts):
        document, digest = _read_receipt(path)
        parsed = _RECEIPT.fullmatch(path.name)
        if parsed is None:
            raise TransactionAttemptError("phase receipt filename is invalid")
        try:
            receipt_phase = AttemptPhase(int(parsed.group("ordinal")))
        except ValueError as exc:
            raise TransactionAttemptError("phase receipt ordinal is unsupported") from exc
        if parsed.group("phase") != receipt_phase.name.lower():
            raise TransactionAttemptError("phase receipt filename is inconsistent")
        if document.get("phase") != receipt_phase.name:
            raise TransactionAttemptError("phase receipt body is inconsistent")
        if document.get("attempt_id") != resolved.name:
            raise TransactionAttemptError("phase receipt attempt identity differs")
        current_input = _digest(document.get("input_sha256"), "phase input_sha256")
        if input_sha256 is None:
            input_sha256 = current_input
        elif current_input != input_sha256:
            raise TransactionAttemptError("attempt input identity changed between phases")
        if document.get("previous_receipt_sha256") != previous:
            raise TransactionAttemptError("attempt receipt chain is invalid")
        if index == 0 and receipt_phase != AttemptPhase.CREATED:
            raise TransactionAttemptError("attempt does not begin at CREATED")
        if phase is not None:
            if phase in {AttemptPhase.FAILED, AttemptPhase.VERIFIED}:
                raise TransactionAttemptError("attempt continued after a terminal phase")
            if receipt_phase != AttemptPhase.FAILED and receipt_phase <= phase:
                raise TransactionAttemptError("attempt phase order is invalid")
        reason = document.get("reason")
        if receipt_phase == AttemptPhase.FAILED:
            if not isinstance(reason, str) or not 1 <= len(reason) <= 2048:
                raise TransactionAttemptError("failed attempt receipt reason is invalid")
        elif reason is not None:
            raise TransactionAttemptError("non-failed attempt receipt has a reason")
        previous = digest
        phase = receipt_phase
    assert input_sha256 is not None and phase is not None and previous is not None
    _enforce_tree_bounds(resolved, max_files=max_files, max_bytes=max_bytes)
    return TransactionAttempt(
        transaction_root=root,
        attempt_path=resolved,
        attempt_id=resolved.name,
        input_sha256=input_sha256,
        phase=phase,
        last_receipt_path=receipts[-1],
        last_receipt_sha256=previous,
        resumed=False,
    )


def _write_phase_receipt(
    attempt_path: Path,
    *,
    attempt_id: str,
    input_sha256: str,
    phase: AttemptPhase,
    previous_receipt_sha256: str | None,
    artifacts: Iterable[AttemptArtifact],
    reason: str | None,
) -> tuple[Path, str]:
    path = attempt_path / f"{int(phase):03d}-{phase.name.lower()}.json"
    if path.exists():
        raise TransactionAttemptError("phase receipt already exists")
    document = {
        "schema_version": "kcd2.transaction-attempt-phase.v1",
        "attempt_id": attempt_id,
        "input_sha256": input_sha256,
        "phase": phase.name,
        "previous_receipt_sha256": previous_receipt_sha256,
        "artifacts": [item.to_dict() for item in artifacts],
        "reason": reason,
    }
    payload = (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    temporary = path.with_suffix(".json.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path, hashlib.sha256(payload).hexdigest()


def _read_receipt(path: Path) -> tuple[dict[str, Any], str]:
    if _is_reparse(path) or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise TransactionAttemptError("phase receipt is invalid or oversized")
    payload = path.read_bytes()
    try:
        document = json.loads(payload, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransactionAttemptError("phase receipt is not valid JSON") from exc
    expected = {
        "schema_version",
        "attempt_id",
        "input_sha256",
        "phase",
        "previous_receipt_sha256",
        "artifacts",
        "reason",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise TransactionAttemptError("phase receipt fields are invalid")
    if document["schema_version"] != "kcd2.transaction-attempt-phase.v1":
        raise TransactionAttemptError("phase receipt schema is unsupported")
    return document, hashlib.sha256(payload).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransactionAttemptError("phase receipt contains duplicate JSON keys")
        result[key] = value
    return result


def _artifact_ledger(
    paths: Iterable[Path | str],
    *,
    attempt_root: Path,
    max_files: int,
    max_bytes: int,
) -> tuple[AttemptArtifact, ...]:
    resolved_paths = sorted({Path(value).resolve(strict=True) for value in paths})
    if len(resolved_paths) > max_files:
        raise TransactionAttemptError("artifact file-count limit exceeded")
    total = 0
    ledger: list[AttemptArtifact] = []
    for path in resolved_paths:
        if path.parent != attempt_root and attempt_root not in path.parents:
            raise TransactionAttemptError("attempt artifact escaped its private root")
        if _is_reparse(path) or not path.is_file():
            raise TransactionAttemptError("attempt artifact is not a plain file")
        size = path.stat().st_size
        total += size
        if total > max_bytes:
            raise TransactionAttemptError("artifact byte limit exceeded")
        ledger.append(AttemptArtifact(path, _hash_file(path), size))
    return tuple(ledger)


def _verify_recorded_artifacts(
    attempt_path: Path, *, max_files: int, max_bytes: int
) -> None:
    seen = 0
    total = 0
    for receipt in sorted(attempt_path.glob("[0-9][0-9][0-9]-*.json")):
        document, _ = _read_receipt(receipt)
        artifacts = document["artifacts"]
        if not isinstance(artifacts, list):
            raise TransactionAttemptError("phase artifact ledger is invalid")
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {"bytes", "path", "sha256"}:
                raise TransactionAttemptError("phase artifact identity is invalid")
            path = Path(item["path"])
            try:
                resolved = path.resolve(strict=True)
            except OSError as exc:
                raise TransactionAttemptError("recorded attempt artifact is missing") from exc
            if attempt_path not in resolved.parents or _is_reparse(resolved):
                raise TransactionAttemptError("recorded attempt artifact escaped its root")
            size = resolved.stat().st_size
            seen += 1
            total += size
            if seen > max_files or total > max_bytes:
                raise TransactionAttemptError("recorded attempt artifact bounds exceeded")
            if item["bytes"] != size or _digest(item["sha256"], "artifact sha256") != _hash_file(resolved):
                raise TransactionAttemptError("recorded attempt artifact drifted")


def _enforce_tree_bounds(root: Path, *, max_files: int, max_bytes: int) -> None:
    count = 0
    total = 0
    for path in root.rglob("*"):
        if _is_reparse(path):
            raise TransactionAttemptError("attempt tree contains a reparse point")
        if path.is_file():
            count += 1
            total += path.stat().st_size
            if count > max_files or total > max_bytes:
                raise TransactionAttemptError("attempt tree exceeds its resource bounds")


def _validate_limits(*, max_attempts: int, max_files: int, max_bytes: int) -> None:
    if not isinstance(max_attempts, int) or not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise TransactionAttemptError("max_attempts is invalid")
    if not isinstance(max_files, int) or not 1 <= max_files <= DEFAULT_MAX_FILES:
        raise TransactionAttemptError("max_files is invalid")
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= DEFAULT_MAX_BYTES:
        raise TransactionAttemptError("max_bytes is invalid")


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value.lower()) is None:
        raise TransactionAttemptError(f"{field} must be SHA-256")
    return value.lower()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        return path.is_symlink() or bool(path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):
        return path.is_symlink()
