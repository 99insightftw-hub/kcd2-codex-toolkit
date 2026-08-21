"""Applicability-aware, bounded container classification and legacy migration."""

from __future__ import annotations

import json
import os
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from .hashing import canonical_json_bytes


ContainerType = Literal["zip_pak", "pe_image", "seven_zip", "directory", "unknown"]
PeValidationStatus = Literal["valid", "invalid", "not_applicable", "not_checked"]

_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_SEVEN_ZIP_MAGIC = b"7z\xbc\xaf'\x1c"
_PE_SUFFIXES = frozenset({".cpl", ".dll", ".efi", ".exe", ".ocx", ".sys"})


@dataclass(frozen=True, slots=True)
class ContainerValidationLimits:
    """Resource ceilings used before archive member payloads are inspected."""

    max_file_bytes: int = 4 * 1024 * 1024 * 1024
    max_archive_members: int = 100_000
    max_total_uncompressed_bytes: int = 512 * 1024 * 1024

    def __post_init__(self) -> None:
        ceilings = {
            "max_file_bytes": 16 * 1024 * 1024 * 1024,
            "max_archive_members": 1_000_000,
            "max_total_uncompressed_bytes": 8 * 1024 * 1024 * 1024,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
            if value > ceiling:
                raise ValueError(f"{name} exceeds the hard ceiling of {ceiling}")


@dataclass(frozen=True, slots=True)
class PeValidation:
    applicable: bool
    status: PeValidationStatus
    details: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in ("valid", "invalid", "not_applicable", "not_checked"):
            raise ValueError("unsupported PE validation status")
        if self.applicable and self.status not in ("valid", "invalid", "not_checked"):
            raise ValueError("applicable PE validation cannot be not_applicable")
        if not self.applicable and self.status != "not_applicable":
            raise ValueError("inapplicable PE validation must be not_applicable")
        if any(not isinstance(item, str) for item in self.details):
            raise ValueError("PE validation details must be strings")

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable": self.applicable,
            "status": self.status,
            "details": list(self.details),
        }


@dataclass(frozen=True, slots=True)
class ContainerValidation:
    path: str
    container_type: ContainerType
    container_valid: bool
    pe_validation: PeValidation
    diagnostics: tuple[str, ...] = ()
    schema_version: str = "kcd2.container-validation.v1"

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("container path must not be empty")
        if self.container_type not in (
            "zip_pak",
            "pe_image",
            "seven_zip",
            "directory",
            "unknown",
        ):
            raise ValueError("unsupported container type")
        if self.schema_version != "kcd2.container-validation.v1":
            raise ValueError("unsupported container validation schema_version")
        if self.container_type == "pe_image":
            if not self.pe_validation.applicable:
                raise ValueError("PE images require applicable PE validation")
            if self.pe_validation.status not in ("valid", "invalid"):
                raise ValueError("PE image validation must be valid or invalid")
        elif self.pe_validation.applicable or self.pe_validation.status != "not_applicable":
            raise ValueError("non-PE containers require not_applicable PE validation")
        if any(not isinstance(item, str) for item in self.diagnostics):
            raise ValueError("container diagnostics must be strings")

    def to_dict(self) -> dict[str, Any]:
        """Return the v1 response shape; the deprecated ``pe_valid`` key is never emitted."""
        return {
            "schema_version": self.schema_version,
            "path": self.path,
            "container_type": self.container_type,
            "container_valid": self.container_valid,
            "pe_validation": self.pe_validation.to_dict(),
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True, slots=True)
class LegacyPeValidMigration:
    """Receipt that retains historical evidence beside, not inside, a current response."""

    legacy_evidence_json: bytes
    current_validation: ContainerValidation
    diagnostics: tuple[str, ...] = (
        "pe_valid is deprecated; its original value is retained only as legacy evidence and "
        "was not used to derive current container or PE validity.",
    )
    schema_version: str = "kcd2.legacy-pe-valid-migration.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.legacy-pe-valid-migration.v1":
            raise ValueError("unsupported legacy PE migration schema_version")

    @property
    def legacy_evidence(self) -> dict[str, Any]:
        """Return a fresh copy so callers cannot mutate the retained evidence bytes."""
        decoded = json.loads(self.legacy_evidence_json)
        if not isinstance(decoded, dict):  # pragma: no cover - constructed by the adapter
            raise ValueError("legacy evidence must be an object")
        return decoded

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "legacy_evidence": self.legacy_evidence,
            "current_validation": self.current_validation.to_dict(),
            "deprecated_fields": ["pe_valid"],
            "diagnostics": list(self.diagnostics),
        }


def _not_applicable() -> PeValidation:
    return PeValidation(applicable=False, status="not_applicable")


def _result(
    path: Path,
    container_type: ContainerType,
    container_valid: bool,
    diagnostics: tuple[str, ...] = (),
    *,
    pe_validation: PeValidation | None = None,
) -> ContainerValidation:
    return ContainerValidation(
        path=str(path),
        container_type=container_type,
        container_valid=container_valid,
        pe_validation=pe_validation or _not_applicable(),
        diagnostics=diagnostics,
    )


def _validate_zip_pak(path: Path, limits: ContainerValidationLimits) -> ContainerValidation:
    file_size = path.stat().st_size
    if file_size > limits.max_file_bytes:
        return _result(
            path,
            "zip_pak",
            False,
            (f"file size {file_size} exceeds max_file_bytes {limits.max_file_bytes}",),
        )
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > limits.max_archive_members:
                return _result(
                    path,
                    "zip_pak",
                    False,
                    (
                        f"archive member count {len(members)} exceeds max_archive_members "
                        f"{limits.max_archive_members}",
                    ),
                )
            total_uncompressed = sum(member.file_size for member in members)
            if total_uncompressed > limits.max_total_uncompressed_bytes:
                return _result(
                    path,
                    "zip_pak",
                    False,
                    (
                        f"archive uncompressed bytes {total_uncompressed} exceed "
                        "max_total_uncompressed_bytes "
                        f"{limits.max_total_uncompressed_bytes}",
                    ),
                )
            bad_member = archive.testzip()
            if bad_member is not None:
                return _result(
                    path,
                    "zip_pak",
                    False,
                    (f"archive CRC check failed for member {bad_member!r}",),
                )
    except (
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        return _result(path, "zip_pak", False, (f"ZIP validation failed: {exc}",))
    return _result(path, "zip_pak", True)


def _validate_pe(path: Path, file_size: int) -> ContainerValidation:
    diagnostics: tuple[str, ...]
    try:
        with path.open("rb") as stream:
            dos_header = stream.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                diagnostics = ("missing or truncated DOS MZ header",)
            else:
                pe_offset = int.from_bytes(dos_header[0x3C:0x40], "little")
                if pe_offset < 64 or pe_offset > file_size - 24:
                    diagnostics = ("PE header offset is outside the file",)
                else:
                    stream.seek(pe_offset)
                    pe_header = stream.read(24)
                    if len(pe_header) != 24 or pe_header[:4] != b"PE\0\0":
                        diagnostics = ("missing or truncated PE signature and COFF header",)
                    elif int.from_bytes(pe_header[4:6], "little") == 0:
                        diagnostics = ("PE COFF machine field is zero",)
                    else:
                        section_count = int.from_bytes(pe_header[6:8], "little")
                        optional_header_size = int.from_bytes(pe_header[20:22], "little")
                        headers_end = pe_offset + 24 + optional_header_size + section_count * 40
                        optional_magic = stream.read(2)
                        if section_count == 0:
                            diagnostics = ("PE COFF section count is zero",)
                        elif optional_header_size < 2 or headers_end > file_size:
                            diagnostics = ("PE optional header or section table is truncated",)
                        elif optional_magic not in (b"\x0b\x01", b"\x0b\x02"):
                            diagnostics = ("PE optional header magic is unsupported",)
                        else:
                            diagnostics = ()
    except OSError as exc:
        diagnostics = (f"PE validation failed: {exc}",)

    valid = not diagnostics
    return _result(
        path,
        "pe_image",
        valid,
        diagnostics,
        pe_validation=PeValidation(
            applicable=True,
            status="valid" if valid else "invalid",
            details=diagnostics,
        ),
    )


def _validate_seven_zip(path: Path, prefix: bytes) -> ContainerValidation:
    if len(prefix) < 32:
        return _result(path, "seven_zip", False, ("truncated 7z signature header",))
    expected_crc = int.from_bytes(prefix[8:12], "little")
    actual_crc = zlib.crc32(prefix[12:32]) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        return _result(path, "seven_zip", False, ("7z start-header CRC mismatch",))
    return _result(path, "seven_zip", True)


def classify_container(
    path: str | os.PathLike[str],
    *,
    limits: ContainerValidationLimits | None = None,
) -> ContainerValidation:
    """Classify and structurally validate a container without live side effects."""
    selected_limits = limits or ContainerValidationLimits()
    candidate = Path(path)
    if candidate.is_dir():
        return _result(candidate, "directory", True)
    if not candidate.exists():
        return _result(candidate, "unknown", False, ("path does not exist",))
    if not candidate.is_file():
        return _result(candidate, "unknown", False, ("path is not a regular file",))

    try:
        file_size = candidate.stat().st_size
        with candidate.open("rb") as stream:
            prefix = stream.read(64)
    except OSError as exc:
        return _result(candidate, "unknown", False, (f"container read failed: {exc}",))

    suffix = candidate.suffix.casefold()
    has_zip_magic = prefix.startswith(_ZIP_MAGICS)
    if suffix == ".pak" and (has_zip_magic or zipfile.is_zipfile(candidate)):
        return _validate_zip_pak(candidate, selected_limits)
    if prefix.startswith(b"MZ") or suffix in _PE_SUFFIXES:
        return _validate_pe(candidate, file_size)
    if prefix.startswith(_SEVEN_ZIP_MAGIC):
        return _validate_seven_zip(candidate, prefix)
    if suffix == ".pak":
        return _result(
            candidate,
            "unknown",
            False,
            (".pak file is not a recognized ZIP container",),
        )
    if has_zip_magic:
        return _result(
            candidate,
            "unknown",
            False,
            ("ZIP container is not identified as a .pak",),
        )
    return _result(candidate, "unknown", False, ("unrecognized container format",))


def adapt_legacy_pe_valid(
    legacy_record: Mapping[str, Any],
    current_validation: ContainerValidation | None = None,
) -> LegacyPeValidMigration:
    """Preserve legacy ``pe_valid`` evidence and attach an independent current validation.

    The deprecated boolean is deliberately not translated into either ``container_valid`` or
    ``pe_validation``. When a current validation is not supplied, the legacy path is inspected.
    """
    if not isinstance(legacy_record, Mapping):
        raise TypeError("legacy record must be a mapping")
    if type(legacy_record.get("pe_valid")) is not bool:
        raise ValueError("legacy record must contain a boolean pe_valid")
    legacy_path = legacy_record.get("path")
    if not isinstance(legacy_path, str) or not legacy_path:
        raise ValueError("legacy record must contain a non-empty path")

    evidence_bytes = canonical_json_bytes(dict(legacy_record))
    validation = current_validation or classify_container(legacy_path)
    if not isinstance(validation, ContainerValidation):
        raise TypeError("current_validation must be a ContainerValidation")
    if Path(legacy_path).resolve(strict=False) != Path(validation.path).resolve(strict=False):
        raise ValueError("legacy record path does not match current validation path")
    return LegacyPeValidMigration(
        legacy_evidence_json=evidence_bytes,
        current_validation=validation,
    )


# Explicit migration wording for callers that discover the adapter by task terminology.
migrate_legacy_pe_valid = adapt_legacy_pe_valid
