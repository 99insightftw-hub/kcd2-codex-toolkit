"""Bounded packaging-profile detection and per-member ZIP/PAK ledgers."""

from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping

from kcd2_toolchain_core.containers import classify_container


MAX_PARENT_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_MEMBER_PATH_CHARS = 4096
_METHODS = {zipfile.ZIP_STORED: "stored", zipfile.ZIP_DEFLATED: "deflate"}
StructuralIntegrity = Literal["VALID", "CORRUPT", "UNREADABLE"]


@dataclass(frozen=True, slots=True)
class PackagingDiagnostic:
    code: str
    severity: Literal["error", "warning"]
    message: str
    occurrences: int
    member_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "occurrences": self.occurrences,
        }
        if self.member_paths:
            result["member_paths"] = list(self.member_paths)
        return result


@dataclass(frozen=True, slots=True)
class MemberPackagingLedgerEntry:
    logical_path: str
    method: Literal["stored", "deflate"]
    compressed_bytes: int
    uncompressed_bytes: int
    crc32: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_path": self.logical_path,
            "method": self.method,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "crc32": self.crc32,
        }


@dataclass(frozen=True, slots=True)
class PackagingProfileDetectionReport:
    valid: bool
    source: Literal["explicit_profile", "parent_artifact", "missing", "ambiguous"]
    profile_id: str | None
    parent_pak_sha256: str | None
    allowed_methods: tuple[Literal["stored", "deflate"], ...]
    compression_policy: Literal["stored", "deflated", "mixed"] | None
    member_ledger: tuple[MemberPackagingLedgerEntry, ...]
    diagnostics: tuple[PackagingDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.packaging-profile-detection-report.v1",
            "status": "PASS" if self.valid else "FAIL",
            "source": self.source,
            "profile_id": self.profile_id,
            "parent_pak_sha256": self.parent_pak_sha256,
            "allowed_methods": list(self.allowed_methods),
            "compression_policy": self.compression_policy,
            "member_ledger": [item.to_dict() for item in self.member_ledger],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class PackagingProfileSelectionReport:
    """A policy verdict kept separate from archive structural integrity."""

    verdict: Literal["PASS", "FAIL", "PROFILE_MISMATCH", "UNKNOWN"]
    requested_mode: Literal["retail_strict", "lineage_inherited"]
    selected_profile: Literal["retail_stored", "lineage_inherited"] | None
    recommended_profile: Literal["retail_stored", "lineage_inherited"] | None
    structural_integrity: StructuralIntegrity
    allowed_methods: tuple[Literal["stored", "deflate"], ...]
    compression_policy: Literal["stored", "deflated", "mixed"] | None
    member_ledger: tuple[MemberPackagingLedgerEntry, ...]
    diagnostics: tuple[PackagingDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.packaging-profile-selection-report.v1",
            "verdict": self.verdict,
            "requested_mode": self.requested_mode,
            "selected_profile": self.selected_profile,
            "recommended_profile": self.recommended_profile,
            "structural_integrity": self.structural_integrity,
            "allowed_methods": list(self.allowed_methods),
            "compression_policy": self.compression_policy,
            "member_ledger": [item.to_dict() for item in self.member_ledger],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


def select_packaging_profile(
    *,
    requested_mode: Literal["retail_strict", "lineage_inherited"],
    parent_pak: Path | str | None = None,
    candidate_pak: Path | str | None = None,
    declared_method_changes: tuple[str, ...] = (),
    max_parent_bytes: int = MAX_PARENT_BYTES,
    max_members: int = MAX_MEMBERS,
) -> PackagingProfileSelectionReport:
    """Select new-build stored policy or verify an inherited method ledger.

    Structural validation runs before policy comparison so a damaged archive is never
    mislabeled as ``PROFILE_MISMATCH``. A new build with no parent deterministically selects
    the project ``retail_stored`` policy.
    """
    if requested_mode not in {"retail_strict", "lineage_inherited"}:
        raise ValueError("requested_mode must be retail_strict or lineage_inherited")
    _validate_bound("max_parent_bytes", max_parent_bytes, MAX_PARENT_BYTES)
    _validate_bound("max_members", max_members, MAX_MEMBERS)
    if not isinstance(declared_method_changes, tuple) or any(
        not isinstance(item, str) or not _canonical_member_path(item)
        for item in declared_method_changes
    ):
        raise ValueError("declared_method_changes must be canonical member paths in a tuple")
    if len(set(declared_method_changes)) != len(declared_method_changes):
        raise ValueError("declared_method_changes must not contain duplicates")

    parent_report, structural_failure = _validated_archive_report(
        parent_pak, "parent", max_parent_bytes, max_members
    )
    if structural_failure is not None:
        return _selection_failure(requested_mode, structural_failure)
    candidate_report, structural_failure = _validated_archive_report(
        candidate_pak, "candidate", max_parent_bytes, max_members
    )
    if structural_failure is not None:
        return _selection_failure(requested_mode, structural_failure)

    if requested_mode == "retail_strict":
        if parent_report is not None and parent_report.compression_policy != "stored":
            diagnostic = PackagingDiagnostic(
                "PROFILE_MISMATCH",
                "error",
                "retail_strict cannot replace a known non-stored lineage; use lineage_inherited",
                1,
                (),
            )
            return PackagingProfileSelectionReport(
                "PROFILE_MISMATCH",
                requested_mode,
                None,
                "lineage_inherited",
                "VALID",
                parent_report.allowed_methods,
                parent_report.compression_policy,
                parent_report.member_ledger,
                (diagnostic,),
            )
        if candidate_report is not None and candidate_report.compression_policy != "stored":
            diagnostic = PackagingDiagnostic(
                "RETAIL_STORED_METHOD_MISMATCH",
                "error",
                "retail_strict requires every candidate member to use stored compression",
                1,
                (),
            )
            return PackagingProfileSelectionReport(
                "FAIL",
                requested_mode,
                "retail_stored",
                None,
                "VALID",
                ("stored",),
                "stored",
                candidate_report.member_ledger,
                (diagnostic,),
            )
        ledger = candidate_report.member_ledger if candidate_report is not None else ()
        return PackagingProfileSelectionReport(
            "PASS",
            requested_mode,
            "retail_stored",
            None,
            "VALID",
            ("stored",),
            "stored",
            ledger,
            (),
        )

    if parent_report is None or candidate_report is None:
        missing = "parent and candidate PAKs are required for lineage_inherited"
        diagnostic = PackagingDiagnostic("LINEAGE_ARCHIVE_MISSING", "error", missing, 1, ())
        return PackagingProfileSelectionReport(
            "FAIL", requested_mode, None, None, "UNREADABLE", (), None, (), (diagnostic,)
        )

    parent_methods = {item.logical_path: item.method for item in parent_report.member_ledger}
    child_methods = {item.logical_path: item.method for item in candidate_report.member_ledger}
    declared = set(declared_method_changes)
    drift = tuple(
        sorted(
            path
            for path in parent_methods.keys() | child_methods.keys()
            if parent_methods.get(path) != child_methods.get(path) and path not in declared
        )
    )
    if drift:
        diagnostic = PackagingDiagnostic(
            "UNDECLARED_MEMBER_METHOD_DRIFT",
            "error",
            "candidate member compression differs from the inherited ledger without declaration",
            len(drift),
            drift,
        )
        return PackagingProfileSelectionReport(
            "FAIL",
            requested_mode,
            "lineage_inherited",
            None,
            "VALID",
            parent_report.allowed_methods,
            parent_report.compression_policy,
            candidate_report.member_ledger,
            (diagnostic,),
        )
    return PackagingProfileSelectionReport(
        "PASS",
        requested_mode,
        "lineage_inherited",
        None,
        "VALID",
        parent_report.allowed_methods,
        parent_report.compression_policy,
        candidate_report.member_ledger,
        (),
    )


def _validated_archive_report(
    archive_path: Path | str | None,
    role: str,
    max_parent_bytes: int,
    max_members: int,
) -> tuple[
    PackagingProfileDetectionReport | None,
    tuple[StructuralIntegrity, str, str] | None,
]:
    if archive_path is None:
        return None, None
    path = Path(archive_path)
    validation = classify_container(path)
    if not validation.container_valid or validation.container_type != "zip_pak":
        integrity = "CORRUPT" if path.exists() and path.is_file() else "UNREADABLE"
        detail = validation.diagnostics[0] if validation.diagnostics else "invalid ZIP PAK"
        return None, (integrity, f"{role.upper()}_PAK_CORRUPT", detail)
    report = detect_packaging_profile(
        parent_pak=path,
        max_parent_bytes=max_parent_bytes,
        max_members=max_members,
    )
    if not report.valid:
        detail = ", ".join(item.code for item in report.diagnostics)
        return None, ("CORRUPT", f"{role.upper()}_PAK_INSPECTION_FAILED", detail)
    return report, None


def _selection_failure(
    requested_mode: Literal["retail_strict", "lineage_inherited"],
    failure: tuple[StructuralIntegrity, str, str],
) -> PackagingProfileSelectionReport:
    integrity, code, detail = failure
    diagnostic = PackagingDiagnostic(code, "error", detail, 1, ())
    return PackagingProfileSelectionReport(
        "UNKNOWN",
        requested_mode,
        None,
        None,
        integrity,
        (),
        None,
        (),
        (diagnostic,),
    )


class _Diagnostics:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str, str], tuple[int, list[str]]] = {}

    def add(
        self,
        code: str,
        message: str,
        *,
        severity: Literal["error", "warning"] = "error",
        member_path: str | None = None,
    ) -> None:
        key = (code, severity, message)
        occurrences, paths = self._items.setdefault(key, (0, []))
        if member_path is not None:
            paths.append(member_path)
        self._items[key] = (occurrences + 1, paths)

    def finish(self) -> tuple[PackagingDiagnostic, ...]:
        return tuple(
            PackagingDiagnostic(code, severity, message, occurrences, tuple(sorted(paths)))
            for (code, severity, message), (occurrences, paths) in sorted(self._items.items())
        )


def detect_packaging_profile(
    *,
    explicit_profile: Mapping[str, Any] | None = None,
    parent_pak: Path | str | None = None,
    max_parent_bytes: int = MAX_PARENT_BYTES,
    max_members: int = MAX_MEMBERS,
) -> PackagingProfileDetectionReport:
    """Inspect exactly one declared profile source without mutating the source artifact."""
    _validate_bound("max_parent_bytes", max_parent_bytes, MAX_PARENT_BYTES)
    _validate_bound("max_members", max_members, MAX_MEMBERS)
    if explicit_profile is None and parent_pak is None:
        diagnostic = PackagingDiagnostic(
            "PROFILE_SOURCE_MISSING",
            "error",
            "an explicit profile or parent PAK is required",
            1,
            (),
        )
        return PackagingProfileDetectionReport(
            False, "missing", None, None, (), None, (), (diagnostic,)
        )
    if explicit_profile is not None and parent_pak is not None:
        diagnostic = PackagingDiagnostic(
            "PROFILE_SOURCE_AMBIGUOUS",
            "error",
            "declare either an explicit profile or a parent PAK, not both",
            1,
            (),
        )
        return PackagingProfileDetectionReport(
            False, "ambiguous", None, None, (), None, (), (diagnostic,)
        )
    if explicit_profile is not None:
        return _inspect_explicit_profile(explicit_profile)
    assert parent_pak is not None
    return _inspect_parent(Path(parent_pak), max_parent_bytes, max_members)


def _inspect_explicit_profile(profile: Mapping[str, Any]) -> PackagingProfileDetectionReport:
    diagnostics = _Diagnostics()
    required = {
        "schema_version",
        "profile_id",
        "profile_kind",
        "profile_source",
        "allowed_methods",
        "member_ledger_required",
    }
    for field in sorted(required - set(profile)):
        diagnostics.add("PROFILE_FIELD_MISSING", f"required profile field is missing: {field}")
    if profile.get("schema_version") != "kcd2.packaging-profile.v1":
        diagnostics.add(
            "PROFILE_SCHEMA_UNSUPPORTED", "unsupported packaging profile schema_version"
        )
    allowed_fields = required | {
        "parent_pak_sha256",
        "parent_profile_sha256",
        "undeclared_method_change_fails",
        "notes",
    }
    for field in sorted(str(item) for item in set(profile) - allowed_fields):
        diagnostics.add("PROFILE_FIELD_UNKNOWN", f"profile field is not allowed: {field}")
    profile_id = profile.get("profile_id")
    if (
        not isinstance(profile_id, str)
        or re.fullmatch(r"profile:[A-Za-z0-9._:-]+", profile_id) is None
    ):
        diagnostics.add("PROFILE_ID_INVALID", "profile_id does not match the v1 profile contract")
        profile_id = None
    raw_methods = profile.get("allowed_methods")
    methods: tuple[Literal["stored", "deflate"], ...] = ()
    if isinstance(raw_methods, list) and raw_methods:
        for value in raw_methods:
            if value not in {"stored", "deflate"}:
                diagnostics.add(
                    "PROFILE_METHOD_UNSUPPORTED",
                    f"unsupported declared compression method: {value!r}",
                )
        methods = tuple(item for item in ("stored", "deflate") if item in raw_methods)
        if len(set(raw_methods)) != len(raw_methods):
            diagnostics.add("PROFILE_METHOD_DUPLICATE", "allowed_methods contains duplicates")
    else:
        diagnostics.add("PROFILE_METHODS_INVALID", "allowed_methods must be a non-empty array")
    if profile.get("member_ledger_required") is not True:
        diagnostics.add("MEMBER_LEDGER_NOT_REQUIRED", "build profiles must require a member ledger")
    profile_kind = profile.get("profile_kind")
    if profile_kind not in {
        "retail_stored",
        "lineage_inherited",
        "inspect_only",
        "custom_declared",
    }:
        diagnostics.add("PROFILE_KIND_INVALID", "profile_kind is not supported by schema v1")
    if profile.get("profile_source") not in {
        "project_policy",
        "parent_artifact",
        "operator_declaration",
        "inspection_only",
    }:
        diagnostics.add("PROFILE_SOURCE_INVALID", "profile_source is not supported by schema v1")
    if profile_kind == "retail_stored" and raw_methods != ["stored"]:
        diagnostics.add("RETAIL_STORED_METHOD_MISMATCH", "retail_stored permits only stored")
    if profile_kind == "lineage_inherited":
        for field in ("parent_pak_sha256", "parent_profile_sha256"):
            value = profile.get(field)
            if not isinstance(value, str) or re.fullmatch(r"[A-Fa-f0-9]{64}", value) is None:
                diagnostics.add(
                    "LINEAGE_IDENTITY_INVALID",
                    f"lineage_inherited requires a valid {field}",
                )
    finished = diagnostics.finish()
    return PackagingProfileDetectionReport(
        not any(item.severity == "error" for item in finished),
        "explicit_profile",
        profile_id,
        None,
        methods,
        _policy(methods),
        (),
        finished,
    )


def _inspect_parent(
    path: Path, max_parent_bytes: int, max_members: int
) -> PackagingProfileDetectionReport:
    diagnostics = _Diagnostics()
    digest: str | None = None
    ledger: list[MemberPackagingLedgerEntry] = []
    methods: set[Literal["stored", "deflate"]] = set()
    try:
        size = path.stat().st_size
        if not path.is_file() or size > max_parent_bytes:
            raise OSError(f"parent must be a file no larger than {max_parent_bytes} bytes")
        digest = _hash_file(path)
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                if item.is_dir():
                    diagnostics.add(
                        "DIRECTORY_ENTRY_IGNORED",
                        "ZIP directory entries are not package members",
                        severity="warning",
                        member_path=item.filename,
                    )
            members = [item for item in archive.infolist() if not item.is_dir()]
            if not members:
                diagnostics.add("PARENT_PAK_EMPTY", "parent PAK has no file members")
            if len(members) > max_members:
                diagnostics.add(
                    "PARENT_MEMBER_LIMIT",
                    f"parent contains more than the allowed {max_members} members",
                )
                members = members[:max_members]
            seen: set[str] = set()
            for item in members:
                logical = item.filename
                if not _canonical_member_path(logical):
                    diagnostics.add(
                        "PARENT_MEMBER_PATH_INVALID",
                        "parent contains a noncanonical or unsafe member path",
                        member_path=logical,
                    )
                    continue
                folded = logical.casefold()
                if folded in seen:
                    diagnostics.add(
                        "PARENT_MEMBER_COLLISION",
                        "parent contains duplicate or case-colliding member paths",
                        member_path=logical,
                    )
                    continue
                seen.add(folded)
                method = _METHODS.get(item.compress_type)
                if method is None:
                    diagnostics.add(
                        "UNSUPPORTED_COMPRESSION_METHOD",
                        f"parent uses unsupported ZIP compression method {item.compress_type}",
                        member_path=logical,
                    )
                    continue
                if item.flag_bits & 0x1:
                    diagnostics.add(
                        "ENCRYPTED_MEMBER_UNSUPPORTED",
                        "parent contains encrypted members that cannot be inherited",
                        member_path=logical,
                    )
                    continue
                methods.add(method)
                ledger.append(
                    MemberPackagingLedgerEntry(
                        logical,
                        method,
                        item.compress_size,
                        item.file_size,
                        f"{item.CRC:08x}",
                    )
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        diagnostics.add("PARENT_PAK_READ_FAILED", f"could not inspect parent PAK: {exc}")
    ledger.sort(key=lambda item: item.logical_path.encode("utf-8"))
    ordered_methods = tuple(item for item in ("stored", "deflate") if item in methods)
    finished = diagnostics.finish()
    valid = digest is not None and bool(ledger) and not any(
        item.severity == "error" for item in finished
    )
    profile_id = f"profile:parent:{digest[:16]}" if digest is not None else None
    return PackagingProfileDetectionReport(
        valid,
        "parent_artifact",
        profile_id,
        digest,
        ordered_methods,
        _policy(ordered_methods),
        tuple(ledger),
        finished,
    )


def _policy(
    methods: tuple[Literal["stored", "deflate"], ...]
) -> Literal["stored", "deflated", "mixed"] | None:
    if methods == ("stored",):
        return "stored"
    if methods == ("deflate",):
        return "deflated"
    if methods == ("stored", "deflate"):
        return "mixed"
    return None


def _canonical_member_path(value: str) -> bool:
    if not value or len(value) > MAX_MEMBER_PATH_CHARS or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and not any(part in {"", ".", ".."} for part in path.parts)
        and re.match(r"^[A-Za-z]:", value) is None
    )


def _validate_bound(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
