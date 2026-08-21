"""Compact exact-mod responses with deterministic, hash-bound detail pagination."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal


DetailLevel = Literal["compact", "normal", "full"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CURSOR = re.compile(r"^cursor:([0-9a-f]{64}):([0-9]+)$")
_MIN_RESPONSE_BYTES = 512
_DEFAULT_MAX_RECORDS = 100_000
_DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_DEFAULT_MAX_RECORD_BYTES = 1024 * 1024
_COMPACT_FIELDS = (
    "target_mod_id",
    "provider_state",
    "manifest",
    "paks",
    "package_profile",
    "mod_order",
    "active_state",
    "effective_winners",
    "scope_receipt_id",
    "diagnostics",
    "recommended_next_operation",
    "coverage_validity",
    "conflict_summary",
)

_COMPLETE_COVERAGE = frozenset({"COMPLETE", "COMPLETE_FOR_REQUESTED_SCOPE"})


class ResponseNormalizationError(RuntimeError):
    """An exact-mod result cannot be represented by the bounded response contract."""


class ResponseLimitError(ResponseNormalizationError):
    """The irreducible response or one page record exceeds its declared byte limit."""


class ArtifactIntegrityError(ResponseNormalizationError):
    """A detail reference, cursor, or stored artifact failed its hash binding."""


def _plain_positive(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ResponseNormalizationError("detail contains non-canonical JSON data") from exc


def _canonical_copy(value: object) -> Any:
    try:
        return json.loads(_canonical_bytes(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - canonical encoder is authoritative
        raise ResponseNormalizationError("canonical JSON round trip failed") from exc


def _digest_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _relative_directory(value: Path) -> Path:
    if value.is_absolute() or not value.parts or ".." in value.parts:
        raise ValueError("artifact_directory must be a non-traversing relative path")
    if value.parts[0].casefold() != "artifacts":
        raise ValueError("artifact_directory must remain under the repository artifacts root")
    return value


@dataclass(frozen=True, slots=True)
class DetailArtifact:
    path: str
    sha256: str
    cursor: str | None
    record_count: int
    byte_count: int

    def to_reference(self) -> dict[str, str | None]:
        return {"path": self.path, "sha256": self.sha256, "cursor": self.cursor}


@dataclass(frozen=True, slots=True)
class DetailPage:
    artifact_sha256: str
    records: tuple[Any, ...]
    next_cursor: str | None
    complete: bool
    schema_version: str = "kcd2.detail-artifact-page.v1"

    def to_dict(self) -> dict[str, Any]:
        return _canonical_copy(
            {
                "schema_version": self.schema_version,
                "artifact_sha256": self.artifact_sha256,
                "records": self.records,
                "next_cursor": self.next_cursor,
                "complete": self.complete,
            }
        )

    def to_json(self) -> str:
        return _canonical_bytes(self.to_dict()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class NormalizedExactModResponse:
    summary: Mapping[str, Any]
    detail_artifact: DetailArtifact | None

    @property
    def detail_record_count(self) -> int:
        return self.detail_artifact.record_count if self.detail_artifact is not None else 0

    def to_dict(self) -> dict[str, Any]:
        return _canonical_copy(self.summary)

    def to_json(self) -> str:
        return _canonical_bytes(self.to_dict()).decode("utf-8")


class DetailArtifactStore:
    """Write and retrieve canonical JSONL only under a repository artifact directory."""

    def __init__(
        self,
        repository_root: Path,
        *,
        artifact_directory: Path = Path("artifacts/details"),
        max_records: int = _DEFAULT_MAX_RECORDS,
        max_artifact_bytes: int = _DEFAULT_MAX_ARTIFACT_BYTES,
        max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
    ) -> None:
        if not isinstance(repository_root, Path):
            raise TypeError("repository_root must be a pathlib.Path")
        if not isinstance(artifact_directory, Path):
            raise TypeError("artifact_directory must be a pathlib.Path")
        self.repository_root = repository_root.resolve(strict=True)
        self.artifact_directory = _relative_directory(artifact_directory)
        self.max_records = _plain_positive(max_records, name="max_records")
        self.max_artifact_bytes = _plain_positive(
            max_artifact_bytes, name="max_artifact_bytes"
        )
        self.max_record_bytes = _plain_positive(max_record_bytes, name="max_record_bytes")

    @property
    def directory(self) -> Path:
        directory = (self.repository_root / self.artifact_directory).resolve(strict=False)
        try:
            directory.relative_to(self.repository_root)
        except ValueError as exc:
            raise ArtifactIntegrityError(
                "artifact directory resolves outside the repository root"
            ) from exc
        return directory

    def _cursor(self, digest: str, offset: int) -> str:
        return f"cursor:{digest}:{offset}"

    def _artifact_path(self, digest: str) -> Path:
        if _SHA256.fullmatch(digest) is None:
            raise ArtifactIntegrityError("artifact SHA-256 must be lowercase hexadecimal")
        return self.directory / f"{digest}.jsonl"

    def write_records(self, records: Iterable[object]) -> DetailArtifact:
        """Stream bounded canonical records to a content-addressed artifact atomically."""
        if isinstance(records, (str, bytes, Mapping)) or not isinstance(records, Iterable):
            raise TypeError("records must be an iterable of JSON values")
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary_name: str | None = None
        digest = hashlib.sha256()
        record_count = 0
        byte_count = 0
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=".idx007-",
                suffix=".tmp",
                dir=self.directory,
                delete=False,
            ) as stream:
                temporary_name = stream.name
                for record in records:
                    if record_count >= self.max_records:
                        raise ResponseLimitError(
                            f"detail record limit of {self.max_records} would be exceeded"
                        )
                    encoded = _canonical_bytes(record) + b"\n"
                    if len(encoded) > self.max_record_bytes:
                        raise ResponseLimitError(
                            f"one detail record exceeds {self.max_record_bytes} bytes"
                        )
                    if byte_count + len(encoded) > self.max_artifact_bytes:
                        raise ResponseLimitError(
                            f"detail artifact exceeds {self.max_artifact_bytes} bytes"
                        )
                    stream.write(encoded)
                    digest.update(encoded)
                    record_count += 1
                    byte_count += len(encoded)
                stream.flush()
                os.fsync(stream.fileno())

            artifact_sha256 = digest.hexdigest()
            final_path = self._artifact_path(artifact_sha256)
            temporary_path = Path(temporary_name)
            if final_path.exists():
                with final_path.open("rb") as existing:
                    existing_digest, existing_size = _digest_stream(existing)
                if existing_digest != artifact_sha256 or existing_size != byte_count:
                    raise ArtifactIntegrityError(
                        "existing content-addressed artifact does not match its SHA-256 name"
                    )
                temporary_path.unlink()
                temporary_name = None
            else:
                os.replace(temporary_path, final_path)
                temporary_name = None

            relative_path = final_path.relative_to(self.repository_root).as_posix()
            return DetailArtifact(
                path=relative_path,
                sha256=artifact_sha256,
                cursor=self._cursor(artifact_sha256, 0) if byte_count else None,
                record_count=record_count,
                byte_count=byte_count,
            )
        finally:
            if temporary_name is not None:
                temporary_path = Path(temporary_name)
                if temporary_path.exists():
                    temporary_path.unlink()

    def _validated_reference(
        self, reference: Mapping[str, object]
    ) -> tuple[Path, str, str | None]:
        if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256", "cursor"}:
            raise ArtifactIntegrityError("detail artifact reference fields do not match v1")
        path = reference["path"]
        digest = reference["sha256"]
        cursor = reference["cursor"]
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ArtifactIntegrityError("detail artifact path and SHA-256 must be strings")
        if cursor is not None and not isinstance(cursor, str):
            raise ArtifactIntegrityError("detail artifact cursor must be a string or null")
        expected_path = self._artifact_path(digest)
        if path != expected_path.relative_to(self.repository_root).as_posix():
            raise ArtifactIntegrityError("detail artifact path is not bound to its SHA-256")
        return expected_path, digest, cursor

    def _verify_open(self, path: Path, digest: str) -> tuple[BinaryIO, int]:
        try:
            stream = path.open("rb")
        except OSError as exc:
            raise ArtifactIntegrityError(f"detail artifact cannot be opened: {exc}") from exc
        try:
            observed, size = _digest_stream(stream)
            if observed != digest:
                raise ArtifactIntegrityError("detail artifact SHA-256 verification failed")
            stream.seek(0)
            return stream, size
        except Exception:
            stream.close()
            raise

    def _parse_cursor(self, cursor: str | None, digest: str) -> int:
        if cursor is None:
            return 0
        match = _CURSOR.fullmatch(cursor)
        if match is None or match.group(1) != digest:
            raise ArtifactIntegrityError("detail cursor is not bound to the artifact SHA-256")
        return int(match.group(2))

    def read_page(
        self,
        reference: Mapping[str, object],
        *,
        cursor: str | None = None,
        max_response_bytes: int,
    ) -> DetailPage:
        """Return one deterministic page whose serialized envelope fits the caller limit."""
        limit = _plain_positive(max_response_bytes, name="max_response_bytes")
        if limit < _MIN_RESPONSE_BYTES:
            raise ValueError(f"max_response_bytes must be at least {_MIN_RESPONSE_BYTES}")
        path, digest, initial_cursor = self._validated_reference(reference)
        offset = self._parse_cursor(cursor if cursor is not None else initial_cursor, digest)
        stream, size = self._verify_open(path, digest)
        try:
            if offset > size:
                raise ArtifactIntegrityError("detail cursor points beyond the artifact")
            if offset:
                stream.seek(offset - 1)
                if stream.read(1) != b"\n":
                    raise ArtifactIntegrityError(
                        "detail cursor does not point to a record boundary"
                    )
            stream.seek(offset)
            records: list[Any] = []
            next_offset = offset
            while next_offset < size:
                line = stream.readline(self.max_record_bytes + 1)
                if not line.endswith(b"\n"):
                    raise ArtifactIntegrityError(
                        "detail artifact contains an invalid bounded record"
                    )
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ArtifactIntegrityError(
                        "detail artifact contains invalid canonical JSONL"
                    ) from exc
                if line != _canonical_bytes(record) + b"\n":
                    raise ArtifactIntegrityError("detail artifact record is not canonical JSONL")
                after = stream.tell()
                complete = after == size
                candidate = DetailPage(
                    artifact_sha256=digest,
                    records=tuple([*records, record]),
                    next_cursor=None if complete else self._cursor(digest, after),
                    complete=complete,
                )
                if len(candidate.to_json().encode("utf-8")) > limit:
                    if not records:
                        raise ResponseLimitError(
                            "one detail record cannot fit the declared page response limit"
                        )
                    break
                records.append(record)
                next_offset = after

            complete = next_offset == size
            page = DetailPage(
                artifact_sha256=digest,
                records=tuple(records),
                next_cursor=None if complete else self._cursor(digest, next_offset),
                complete=complete,
            )
            if len(page.to_json().encode("utf-8")) > limit:
                raise ResponseLimitError("detail page envelope exceeds max_response_bytes")
            return page
        finally:
            stream.close()

    def iter_verified_records(self, reference: Mapping[str, object]) -> Iterator[Any]:
        """Verify the complete artifact before yielding its full record stream."""
        path, digest, _ = self._validated_reference(reference)
        stream, _ = self._verify_open(path, digest)
        try:
            record_count = 0
            for line in stream:
                record_count += 1
                if record_count > self.max_records or len(line) > self.max_record_bytes:
                    raise ArtifactIntegrityError("detail artifact exceeds retrieval bounds")
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ArtifactIntegrityError(
                        "detail artifact contains invalid canonical JSONL"
                    ) from exc
                if line != _canonical_bytes(record) + b"\n":
                    raise ArtifactIntegrityError("detail artifact record is not canonical JSONL")
                yield record
        finally:
            stream.close()


class ExactModResponseNormalizer:
    """Select the reviewed compact summary fields and spill optional detail by default."""

    def __init__(self, artifact_store: DetailArtifactStore) -> None:
        if not isinstance(artifact_store, DetailArtifactStore):
            raise TypeError("artifact_store must be a DetailArtifactStore")
        self.artifact_store = artifact_store

    def normalize(
        self,
        response: Mapping[str, object],
        *,
        full_detail_records: Iterable[object] | None = None,
        detail_level: DetailLevel = "compact",
        max_response_bytes: int,
    ) -> NormalizedExactModResponse:
        if not isinstance(response, Mapping):
            raise TypeError("response must be a mapping")
        if detail_level not in {"compact", "normal", "full"}:
            raise ValueError("detail_level must be compact, normal, or full")
        limit = _plain_positive(max_response_bytes, name="max_response_bytes")
        if limit < _MIN_RESPONSE_BYTES:
            raise ValueError(f"max_response_bytes must be at least {_MIN_RESPONSE_BYTES}")
        missing = [field for field in _COMPACT_FIELDS if field not in response]
        if missing:
            raise ResponseNormalizationError(
                f"exact-mod response is missing compact fields: {', '.join(missing)}"
            )
        if not isinstance(response["paks"], Sequence) or isinstance(
            response["paks"], (str, bytes)
        ):
            raise ResponseNormalizationError("paks must be an array")
        if not isinstance(response["diagnostics"], Sequence) or isinstance(
            response["diagnostics"], (str, bytes)
        ):
            raise ResponseNormalizationError("diagnostics must be an array")

        coverage = response["coverage_validity"]
        conflicts = response["conflict_summary"]
        if not isinstance(coverage, Mapping) or not isinstance(conflicts, Mapping):
            raise ResponseNormalizationError(
                "coverage_validity and conflict_summary must be objects"
            )
        overall_status = coverage.get("overall_status")
        absence_allowed = coverage.get("absence_claim_allowed")
        observed_count = conflicts.get("observed_count")
        conclusion = conflicts.get("conclusion")
        absence_valid = conflicts.get("absence_claim_valid")
        if (
            isinstance(observed_count, bool)
            or not isinstance(observed_count, int)
            or observed_count < 0
        ):
            raise ResponseNormalizationError(
                "conflict_summary.observed_count must be a non-negative integer"
            )
        if observed_count > 0 and conclusion != "CONFLICTS_OBSERVED":
            raise ResponseNormalizationError(
                "a positive observed conflict count requires CONFLICTS_OBSERVED"
            )
        if observed_count == 0 and conclusion == "CONFLICTS_OBSERVED":
            raise ResponseNormalizationError(
                "CONFLICTS_OBSERVED requires a positive observed conflict count"
            )
        confirmed_none_allowed = bool(
            overall_status in _COMPLETE_COVERAGE and absence_allowed is True
        )
        if conclusion == "CONFIRMED_NONE" and (
            not confirmed_none_allowed or absence_valid is not True
        ):
            raise ResponseNormalizationError(
                "CONFIRMED_NONE requires complete fresh unsaturated coverage and a valid "
                "absence claim"
            )
        if absence_valid is True and conclusion != "CONFIRMED_NONE":
            raise ResponseNormalizationError(
                "absence_claim_valid=true is permitted only for CONFIRMED_NONE"
            )

        detail = (
            self.artifact_store.write_records(full_detail_records)
            if full_detail_records is not None
            else None
        )
        summary: dict[str, Any] = {
            "schema_version": "kcd2.mod-inspection-summary.v2",
            **{field: _canonical_copy(response[field]) for field in _COMPACT_FIELDS},
            "detail_level": detail_level,
            "detail_artifact": detail.to_reference() if detail is not None else None,
        }

        trimmed = False
        while len(_canonical_bytes(summary)) > limit and summary["diagnostics"]:
            summary["diagnostics"].pop()
            trimmed = True
        while len(_canonical_bytes(summary)) > limit and summary["paks"]:
            summary["paks"].pop()
            trimmed = True
        if trimmed:
            if detail is None:
                raise ResponseLimitError(
                    "compact fields require truncation but no detail artifact was supplied"
                )
            marker = "COMPACT_RESPONSE_TRUNCATED; retrieve detail_artifact"
            summary["diagnostics"].append(marker)
            while len(_canonical_bytes(summary)) > limit and summary["paks"]:
                summary["paks"].pop()
            if len(_canonical_bytes(summary)) > limit:
                summary["diagnostics"].clear()
        if len(_canonical_bytes(summary)) > limit:
            raise ResponseLimitError("irreducible compact response exceeds max_response_bytes")
        return NormalizedExactModResponse(summary=summary, detail_artifact=detail)
