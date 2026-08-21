"""Bounded, profile-driven confirmation of PAK opens in the latest complete boot."""

from __future__ import annotations

import codecs
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Pattern


_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TEXT = 1024
_MAX_PATTERN = 4096
_DEFAULT_MAX_LOG_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_LOG_LINES = 500_000
_MAX_HASH_BYTES = 16 * 1024 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_REQUIRED_EVENT_GROUPS = frozenset({"mod", "pak", "internal_path", "subsystem"})


class LatestBootError(ValueError):
    """An input cannot support bounded, exact latest-boot parsing."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise LatestBootError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _identity(value: str) -> str:
    normalized = value.replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.casefold()


def _compile(pattern: str, name: str) -> Pattern[str]:
    if not isinstance(pattern, str) or not pattern or len(pattern) > _MAX_PATTERN:
        raise LatestBootError(
            f"{name} must be a non-empty regex of at most {_MAX_PATTERN} characters"
        )
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise LatestBootError(f"{name} is not a valid regex: {exc}") from exc


@dataclass(frozen=True, slots=True)
class BootLogProfile:
    """Reviewed syntax for one log source; KCD2 formats stay outside reusable code."""

    boot_start_pattern: str
    boot_complete_pattern: str
    pak_open_pattern: str
    encoding: str = "utf-8"
    _start: Pattern[str] = field(init=False, repr=False, compare=False)
    _complete: Pattern[str] = field(init=False, repr=False, compare=False)
    _opened: Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        start = _compile(self.boot_start_pattern, "boot_start_pattern")
        complete = _compile(self.boot_complete_pattern, "boot_complete_pattern")
        opened = _compile(self.pak_open_pattern, "pak_open_pattern")
        missing = sorted(_REQUIRED_EVENT_GROUPS - opened.groupindex.keys())
        if missing:
            raise LatestBootError(
                "pak_open_pattern is missing named groups: " + ", ".join(missing)
            )
        try:
            codecs.lookup(_text(self.encoding, "encoding"))
        except LookupError as exc:
            raise LatestBootError(f"encoding is not recognized: {self.encoding}") from exc
        object.__setattr__(self, "_start", start)
        object.__setattr__(self, "_complete", complete)
        object.__setattr__(self, "_opened", opened)


@dataclass(frozen=True, slots=True)
class BootOpenSelector:
    """All four identities must match one event before a PAK may be implicated."""

    mod_id: str
    pak_name: str
    internal_path: str
    subsystem: str

    def __post_init__(self) -> None:
        _text(self.mod_id, "mod_id")
        _text(self.pak_name, "pak_name")
        _text(self.internal_path, "internal_path")
        _text(self.subsystem, "subsystem")

    def matches(self, event: Mapping[str, str]) -> bool:
        return all(
            _identity(event[key]) == _identity(expected)
            for key, expected in (
                ("mod", self.mod_id),
                ("pak", self.pak_name),
                ("internal_path", self.internal_path),
                ("subsystem", self.subsystem),
            )
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "internal_path": self.internal_path,
            "mod_id": self.mod_id,
            "pak_name": self.pak_name,
            "subsystem": self.subsystem,
        }


@dataclass(frozen=True, slots=True)
class InstalledHashRequest:
    """Expected install-receipt hash and the exact artifact to re-hash."""

    path: Path
    expected_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise LatestBootError("installed hash path must be a pathlib.Path")
        if (
            not isinstance(self.expected_sha256, str)
            or _SHA256.fullmatch(self.expected_sha256) is None
        ):
            raise LatestBootError("expected_sha256 must be a SHA-256 digest")
        object.__setattr__(self, "expected_sha256", self.expected_sha256.lower())


@dataclass(frozen=True, slots=True)
class BootReceipt:
    """Deterministic receipt that does not collapse log and byte-hash evidence."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class _Boot:
    start_line: int
    end_line: int
    events: tuple[tuple[int, Mapping[str, str]], ...]
    invalid_event_lines: tuple[int, ...]


def _file_sha256(path: Path, *, maximum_bytes: int) -> str:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise LatestBootError(f"file exceeds the {maximum_bytes}-byte hard bound")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_hash_evidence(request: InstalledHashRequest | None) -> dict[str, Any]:
    if request is None:
        return {
            "actual_sha256": None,
            "expected_sha256": None,
            "source_name": None,
            "status": "not_requested",
        }
    base = {
        "actual_sha256": None,
        "expected_sha256": request.expected_sha256,
        "source_name": request.path.name,
        "status": "unavailable",
    }
    if not request.path.is_file():
        base["reason_code"] = "INSTALLED_ARTIFACT_MISSING"
        return base
    try:
        actual = _file_sha256(request.path, maximum_bytes=_MAX_HASH_BYTES)
    except (OSError, LatestBootError):
        base["reason_code"] = "INSTALLED_ARTIFACT_UNREADABLE_OR_OVERSIZE"
        return base
    base["actual_sha256"] = actual
    base["status"] = "verified" if actual == request.expected_sha256 else "mismatch"
    return base


def _incomplete_receipt(
    *,
    receipt_id: str,
    log_path: Path,
    selector: BootOpenSelector,
    installed_hash: InstalledHashRequest | None,
    reason_code: str,
    log_sha256: str | None = None,
) -> BootReceipt:
    return BootReceipt(
        {
            "schema_version": "kcd2.boot-receipt.v1",
            "receipt_id": receipt_id,
            "scope": {
                "complete_boot": False,
                "end_line": 0,
                "latest_complete_boot": True,
                "log_name": log_path.name,
                "log_sha256": log_sha256,
                "start_line": 0,
            },
            "selector": selector.to_dict(),
            "path_open_evidence": {
                "conclusion": "incomplete",
                "implicated_packages": [],
                "matching_events": [],
            },
            "installed_hash_evidence": _installed_hash_evidence(installed_hash),
            "reason_codes": [reason_code],
        }
    )


def _parse_boots(lines: list[str], profile: BootLogProfile) -> list[_Boot]:
    complete_boots: list[_Boot] = []
    start_line: int | None = None
    events: list[tuple[int, Mapping[str, str]]] = []
    invalid: list[int] = []
    for line_number, line in enumerate(lines, start=1):
        if profile._start.search(line) is not None:
            start_line = line_number
            events = []
            invalid = []
            continue
        if start_line is None:
            continue
        opened = profile._opened.search(line)
        if opened is not None:
            captures = {name: opened.group(name) for name in _REQUIRED_EVENT_GROUPS}
            if any(value is None or value == "" for value in captures.values()):
                invalid.append(line_number)
            else:
                events.append((line_number, captures))  # type: ignore[arg-type]
        if profile._complete.search(line) is not None:
            complete_boots.append(
                _Boot(start_line, line_number, tuple(events), tuple(invalid))
            )
            start_line = None
            events = []
            invalid = []
    return complete_boots


def parse_latest_boot(
    *,
    receipt_id: str,
    log_path: Path,
    profile: BootLogProfile,
    selector: BootOpenSelector,
    installed_hash: InstalledHashRequest | None = None,
    max_log_bytes: int = _DEFAULT_MAX_LOG_BYTES,
    max_log_lines: int = _DEFAULT_MAX_LOG_LINES,
) -> BootReceipt:
    """Confirm an exact open only in the last complete boot in an explicit log.

    The caller supplies reviewed boundary and event regexes. The parser never infers a
    KCD2 format, relaxes any selector field, or treats an installed hash as log proof.
    """

    receipt_id = _text(receipt_id, "receipt_id")
    if not isinstance(log_path, Path):
        raise LatestBootError("log_path must be a pathlib.Path")
    if not isinstance(profile, BootLogProfile):
        raise LatestBootError("profile must be a BootLogProfile")
    if not isinstance(selector, BootOpenSelector):
        raise LatestBootError("selector must be a BootOpenSelector")
    if installed_hash is not None and not isinstance(installed_hash, InstalledHashRequest):
        raise LatestBootError("installed_hash must be an InstalledHashRequest")
    if not isinstance(max_log_bytes, int) or not 1 <= max_log_bytes <= _DEFAULT_MAX_LOG_BYTES:
        raise LatestBootError(
            f"max_log_bytes must be between 1 and {_DEFAULT_MAX_LOG_BYTES}"
        )
    if not isinstance(max_log_lines, int) or not 1 <= max_log_lines <= _DEFAULT_MAX_LOG_LINES:
        raise LatestBootError(
            f"max_log_lines must be between 1 and {_DEFAULT_MAX_LOG_LINES}"
        )
    if not log_path.is_file():
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="BOOT_LOG_MISSING",
        )
    try:
        if log_path.stat().st_size > max_log_bytes:
            return _incomplete_receipt(
                receipt_id=receipt_id,
                log_path=log_path,
                selector=selector,
                installed_hash=installed_hash,
                reason_code="BOOT_LOG_SIZE_LIMIT_EXCEEDED",
            )
        with log_path.open("rb") as stream:
            raw = stream.read(max_log_bytes + 1)
    except OSError:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="BOOT_LOG_UNREADABLE",
        )
    if len(raw) > max_log_bytes:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="BOOT_LOG_SIZE_LIMIT_EXCEEDED",
        )
    log_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode(profile.encoding, errors="strict")
    except UnicodeDecodeError:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="BOOT_LOG_DECODING_FAILED",
            log_sha256=log_sha256,
        )
    lines = text.splitlines()
    if len(lines) > max_log_lines:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="BOOT_LOG_LINE_LIMIT_EXCEEDED",
            log_sha256=log_sha256,
        )
    boots = _parse_boots(lines, profile)
    if not boots:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="NO_COMPLETE_BOOT",
            log_sha256=log_sha256,
        )
    latest = boots[-1]
    if latest.invalid_event_lines:
        return _incomplete_receipt(
            receipt_id=receipt_id,
            log_path=log_path,
            selector=selector,
            installed_hash=installed_hash,
            reason_code="PAK_OPEN_CAPTURE_INVALID",
            log_sha256=log_sha256,
        )
    matches = [
        {
            "internal_path": selector.internal_path,
            "line_number": line_number,
            "mod_id": selector.mod_id,
            "pak_name": selector.pak_name,
            "subsystem": selector.subsystem,
        }
        for line_number, event in latest.events
        if selector.matches(event)
    ]
    confirmed = bool(matches)
    return BootReceipt(
        {
            "schema_version": "kcd2.boot-receipt.v1",
            "receipt_id": receipt_id,
            "scope": {
                "complete_boot": True,
                "end_line": latest.end_line,
                "latest_complete_boot": True,
                "log_name": log_path.name,
                "log_sha256": log_sha256,
                "start_line": latest.start_line,
            },
            "selector": selector.to_dict(),
            "path_open_evidence": {
                "conclusion": "confirmed" if confirmed else "not_observed",
                "implicated_packages": [selector.pak_name] if confirmed else [],
                "matching_events": matches,
            },
            "installed_hash_evidence": _installed_hash_evidence(installed_hash),
            "reason_codes": [] if confirmed else ["EXACT_PAK_OPEN_NOT_OBSERVED"],
        }
    )
