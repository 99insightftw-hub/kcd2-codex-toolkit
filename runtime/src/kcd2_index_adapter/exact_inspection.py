"""Bounded read-only fallback for genuinely exact KCD2 mod-provider inspection."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from .path_contributions import PathContributionError, classify_path_semantics
from .scope_guard import ScopeAccess, ScopeGuard, ScopeLimits


ProviderKind = Literal["local", "workshop", "explicit_path"]

_HARD_MAX_FILES = 4096
_HARD_MAX_ARCHIVE_ENTRIES = 100_000
_HARD_MAX_PHYSICAL_BYTES = 512 * 1024 * 1024
_HARD_MAX_RESPONSE_BYTES = 1024 * 1024
_MIN_RESPONSE_BYTES = 8192
_CAPTURE_BYTES = 1024 * 1024
_EOCD_MAX_BYTES = 65_535 + 22
_EOCD_SIGNATURE = b"PK\x05\x06"


class _ReadLimitReached(RuntimeError):
    pass


class _ArchiveEntryLimitReached(RuntimeError):
    pass


class _ArchiveIncomplete(RuntimeError):
    pass


class _ScopeBoundaryChanged(RuntimeError):
    def __init__(self, path: Path, message: str) -> None:
        super().__init__(message)
        self.path = path


def _plain_positive(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _portable(path: Path) -> str:
    return path.as_posix()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class ExactModInspectionRequest:
    """Caller-declared exact mod directory or standard child PAK and resource ceilings."""

    target_mod_id: str
    provider_kind: ProviderKind
    provider_root: Path
    receipt_id: str
    limits: ScopeLimits
    mod_order_path: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.target_mod_id, str) or not self.target_mod_id.strip():
            raise ValueError("target_mod_id must be a non-empty string")
        if len(self.target_mod_id) > 256:
            raise ValueError("target_mod_id exceeds the 256-character bound")
        if self.provider_kind not in {"local", "workshop", "explicit_path"}:
            raise ValueError("provider_kind must identify one exact provider")
        if not isinstance(self.provider_root, Path):
            raise TypeError("provider_root must be a pathlib.Path")
        if not isinstance(self.receipt_id, str) or not self.receipt_id:
            raise ValueError("receipt_id must be a non-empty string")
        if len(self.receipt_id) > 256:
            raise ValueError("receipt_id exceeds the 256-character bound")
        if not isinstance(self.limits, ScopeLimits):
            raise TypeError("limits must be ScopeLimits")
        ceilings = {
            "max_files": _HARD_MAX_FILES,
            "max_archive_entries": _HARD_MAX_ARCHIVE_ENTRIES,
            "max_physical_bytes": _HARD_MAX_PHYSICAL_BYTES,
            "max_response_bytes": _HARD_MAX_RESPONSE_BYTES,
        }
        for name, ceiling in ceilings.items():
            value = _plain_positive(getattr(self.limits, name), name=name)
            if value > ceiling:
                raise ValueError(f"{name} exceeds the adapter hard ceiling of {ceiling}")
        if self.limits.max_response_bytes < _MIN_RESPONSE_BYTES:
            raise ValueError(
                f"max_response_bytes must be at least {_MIN_RESPONSE_BYTES} for the receipt"
            )
        if self.mod_order_path is not None:
            if not isinstance(self.mod_order_path, Path):
                raise TypeError("mod_order_path must be a pathlib.Path or None")
            if self.mod_order_path.name.casefold() != "mod_order.txt":
                raise ValueError("the only permitted external metadata file is mod_order.txt")


@dataclass(frozen=True, slots=True)
class ExactModInspectionResult:
    """Compact deterministic adapter result with its self-measured scope receipt."""

    payload: Mapping[str, Any]
    scope_receipt: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(
            json.dumps(
                {**dict(self.payload), "scope_receipt": dict(self.scope_receipt)},
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    def to_json(self) -> str:
        return _canonical_bytes(self.to_dict()).decode("utf-8")


@dataclass(frozen=True, slots=True)
class _FileRecord:
    path: Path
    relative_path: str
    size: int
    device: int
    inode: int
    mtime_ns: int


def _same_identity(record: _FileRecord, info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_size == record.size
        and info.st_dev == record.device
        and info.st_ino == record.inode
        and info.st_mtime_ns == record.mtime_ns
    )


class _ReadBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.bytes_read = 0
        self.opened: set[Path] = set()

    @property
    def remaining(self) -> int:
        return self.maximum - self.bytes_read

    def mark_open(self, path: Path) -> None:
        self.opened.add(path)

    def consume(self, amount: int) -> None:
        if amount < 0 or amount > self.remaining:
            raise _ReadLimitReached("physical byte limit would be exceeded")
        self.bytes_read += amount


class _BudgetedReader:
    def __init__(self, stream: BinaryIO, path: Path, budget: _ReadBudget) -> None:
        self._stream = stream
        self._budget = budget
        budget.mark_open(path)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._budget.remaining
        if size > self._budget.remaining:
            raise _ReadLimitReached("physical byte limit would be exceeded")
        data = self._stream.read(size)
        self._budget.consume(len(data))
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        self._stream.close()

    @property
    def closed(self) -> bool:
        return self._stream.closed

    def __enter__(self) -> "_BudgetedReader":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _enumerate_provider(
    root: Path,
    *,
    max_files: int,
) -> tuple[list[_FileRecord], list[str], set[str], bool]:
    records: list[_FileRecord] = []
    diagnostics: list[str] = []
    out_of_scope: set[str] = set()
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            directory_info = directory.lstat()
            directory_resolved = directory.resolve(strict=False)
            if (
                _is_reparse(directory_info)
                or not stat.S_ISDIR(directory_info.st_mode)
                or not _is_within(directory_resolved, root)
            ):
                out_of_scope.add(_portable(directory_resolved))
                diagnostics.append(
                    f"provider directory crossed the exact root: {_portable(directory)}"
                )
                return records, diagnostics, out_of_scope, False
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda item: (item.name.casefold(), item.name))
        except OSError as exc:
            diagnostics.append(f"provider enumeration failed at {_portable(directory)}: {exc}")
            return records, diagnostics, out_of_scope, False
        child_directories: list[Path] = []
        for entry in ordered:
            path = Path(entry.path)
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                diagnostics.append(f"provider entry metadata failed at {_portable(path)}: {exc}")
                return records, diagnostics, out_of_scope, False
            if _is_reparse(info):
                resolved = path.resolve(strict=False)
                out_of_scope.add(_portable(resolved))
                diagnostics.append(
                    f"reparse or symbolic-link entry was refused: {_portable(path)}"
                )
                return records, diagnostics, out_of_scope, False
            resolved = path.resolve(strict=False)
            if not _is_within(resolved, root):
                out_of_scope.add(_portable(resolved))
                diagnostics.append(f"provider entry escaped the exact root: {_portable(path)}")
                return records, diagnostics, out_of_scope, False
            if stat.S_ISDIR(info.st_mode):
                child_directories.append(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                diagnostics.append(f"non-regular provider entry was refused: {_portable(path)}")
                out_of_scope.add(_portable(path))
                return records, diagnostics, out_of_scope, False
            try:
                identity_info = path.lstat()
            except OSError as exc:
                diagnostics.append(f"provider identity failed at {_portable(path)}: {exc}")
                return records, diagnostics, out_of_scope, False
            if _is_reparse(identity_info) or not stat.S_ISREG(identity_info.st_mode):
                out_of_scope.add(_portable(path.resolve(strict=False)))
                diagnostics.append(
                    f"provider entry changed before identity capture: {_portable(path)}"
                )
                return records, diagnostics, out_of_scope, False
            records.append(
                _FileRecord(
                    path=path,
                    relative_path=path.relative_to(root).as_posix(),
                    size=identity_info.st_size,
                    device=identity_info.st_dev,
                    inode=identity_info.st_ino,
                    mtime_ns=identity_info.st_mtime_ns,
                )
            )
            if len(records) > max_files:
                diagnostics.append(f"provider file count exceeds max_files {max_files}")
                return records, diagnostics, out_of_scope, False
        stack.extend(reversed(child_directories))
    records.sort(key=lambda item: (item.relative_path.casefold(), item.relative_path))
    return records, diagnostics, out_of_scope, True


def _hash_file(
    record: _FileRecord,
    budget: _ReadBudget,
    *,
    capture: bool,
    allowed_root: Path,
) -> tuple[str, bytes | None]:
    current = record.path.lstat()
    resolved = record.path.resolve(strict=False)
    if _is_reparse(current) or not _same_identity(record, current) or not _is_within(
        resolved, allowed_root
    ):
        raise _ScopeBoundaryChanged(
            resolved,
            f"provider entry changed identity before open: {record.relative_path}",
        )
    if record.size > budget.remaining:
        raise _ReadLimitReached("physical byte limit would be exceeded")
    digest = hashlib.sha256()
    captured = bytearray() if capture and record.size <= _CAPTURE_BYTES else None
    with record.path.open("rb") as raw:
        budget.mark_open(resolved)
        if not _same_identity(record, os.fstat(raw.fileno())):
            raise _ScopeBoundaryChanged(
                record.path.resolve(strict=False),
                f"provider entry changed identity during open: {record.relative_path}",
            )
        reader = _BudgetedReader(raw, record.path.resolve(strict=False), budget)
        remaining_file = record.size
        while remaining_file:
            chunk = reader.read(min(1024 * 1024, remaining_file))
            if not chunk:
                raise _ScopeBoundaryChanged(
                    record.path.resolve(strict=False),
                    f"provider entry was truncated during read: {record.relative_path}",
                )
            digest.update(chunk)
            remaining_file -= len(chunk)
            if captured is not None:
                captured.extend(chunk)
        if not _same_identity(record, os.fstat(raw.fileno())):
            raise _ScopeBoundaryChanged(
                record.path.resolve(strict=False),
                f"provider entry changed identity during read: {record.relative_path}",
            )
    return digest.hexdigest(), bytes(captured) if captured is not None else None


def _read_fixed_metadata(path: Path, budget: _ReadBudget) -> tuple[str, bytes]:
    info = path.lstat()
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise ValueError("mod_order.txt must be one non-reparse regular file")
    if info.st_size > _CAPTURE_BYTES:
        raise ValueError(f"mod_order.txt exceeds the fixed metadata bound of {_CAPTURE_BYTES}")
    record = _FileRecord(
        path=path,
        relative_path=path.name,
        size=info.st_size,
        device=info.st_dev,
        inode=info.st_ino,
        mtime_ns=info.st_mtime_ns,
    )
    digest, data = _hash_file(record, budget, capture=True, allowed_root=path.parent)
    assert data is not None
    return digest, data


def _manifest_details(data: bytes | None, requested_mod_id: str) -> tuple[str | None, bool | None]:
    if data is None:
        return None, None
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return None, None
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].casefold()
        if local_name in {"modid", "mod_id"} and element.text:
            declared = element.text.strip()
            return declared, declared.casefold() == requested_mod_id.casefold()
    return None, None


def _declared_native_paths(data: bytes | None) -> list[str]:
    """Return bounded relative native paths explicitly named by the sibling manifest."""
    if data is None:
        return []
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return []
    candidates: set[str] = set()
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].casefold().replace("-", "_")
        if local_name not in {"component", "native", "native_component", "nativecomponent"}:
            continue
        values = list(element.attrib.values())
        if element.text and element.text.strip():
            values.append(element.text.strip())
        for value in values:
            normalized = value.strip().replace("\\", "/")
            if normalized.casefold().endswith((".dll", ".exe")) and not normalized.startswith("/"):
                parts = normalized.split("/")
                if all(part not in {"", ".", ".."} for part in parts):
                    candidates.add("/".join(parts))
    return sorted(candidates, key=lambda item: (item.casefold(), item))


def _open_budgeted(path: Path, budget: _ReadBudget) -> _BudgetedReader:
    return _BudgetedReader(path.open("rb"), path.resolve(strict=False), budget)


def _is_standard_package(record: _FileRecord) -> bool:
    parts = record.relative_path.replace("\\", "/").split("/")
    return (
        len(parts) == 2
        and parts[0].casefold() in {"data", "localization"}
        and parts[1].casefold().endswith(".pak")
    )


def _zip_eocd_entry_count(path: Path, size: int, budget: _ReadBudget) -> int:
    tail_size = min(size, _EOCD_MAX_BYTES)
    with _open_budgeted(path, budget) as stream:
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
    offset = tail.rfind(_EOCD_SIGNATURE)
    if offset < 0 or len(tail) - offset < 22:
        raise _ArchiveIncomplete("ZIP end-of-central-directory record was not found")
    record = tail[offset : offset + 22]
    comment_length = int.from_bytes(record[20:22], "little")
    if offset + 22 + comment_length != len(tail):
        raise _ArchiveIncomplete("ZIP end-of-central-directory record is malformed")
    disk_number = int.from_bytes(record[4:6], "little")
    central_disk = int.from_bytes(record[6:8], "little")
    disk_entries = int.from_bytes(record[8:10], "little")
    total_entries = int.from_bytes(record[10:12], "little")
    if disk_number or central_disk or disk_entries != total_entries:
        raise _ArchiveIncomplete("multi-disk ZIP containers are unsupported")
    if total_entries == 0xFFFF:
        raise _ArchiveIncomplete("ZIP64 entry counts require an upstream bounded parser")
    return total_entries


def _inspect_pak(
    record: _FileRecord,
    digest: str,
    budget: _ReadBudget,
    *,
    remaining_entries: int,
) -> tuple[dict[str, Any], int]:
    pak: dict[str, Any] = {
        "path": record.relative_path,
        "size": record.size,
        "sha256": digest,
        "archive_entry_count": None,
        "structure_valid": False,
        "compression_methods": [],
        "container_payload_override": False,
        "members": [],
        "diagnostics": [],
    }
    try:
        entry_count = _zip_eocd_entry_count(record.path, record.size, budget)
        pak["archive_entry_count"] = entry_count
        if entry_count > remaining_entries:
            raise _ArchiveEntryLimitReached(
                f"archive entry count {entry_count} exceeds remaining bound {remaining_entries}"
            )
        with _open_budgeted(record.path, budget) as stream, zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
        if len(members) != entry_count:
            raise _ArchiveIncomplete("central-directory entry count does not match the EOCD")
        pak["compression_methods"] = sorted({member.compress_type for member in members})
        member_records: list[dict[str, Any]] = []
        for member in members:
            raw_path = member.filename.replace("\\", "/")
            if member.is_dir():
                member_records.append(
                    {
                        "path": raw_path,
                        "size": member.file_size,
                        "path_family": "directory",
                        "contribution_kind": "none",
                        "resolution_semantics": "no_runtime_override",
                        "payload_override_risk": False,
                    }
                )
                continue
            try:
                rule = classify_path_semantics(raw_path)
                path_family = rule.family
                contribution_kind = rule.contribution_kind
                semantics = rule.resolution_semantics
                override_risk = semantics == "override_last_wins"
            except (PathContributionError, TypeError, ValueError):
                path_family = "invalid"
                contribution_kind = "invalid_member_path"
                semantics = "unknown"
                override_risk = False
            member_records.append(
                {
                    "path": raw_path,
                    "size": member.file_size,
                    "path_family": path_family,
                    "contribution_kind": contribution_kind,
                    "resolution_semantics": semantics,
                    "payload_override_risk": override_risk,
                }
            )
        member_records.sort(key=lambda item: (item["path"].casefold(), item["path"]))
        pak["members"] = member_records
        pak["structure_valid"] = True
        return pak, entry_count
    except _ArchiveEntryLimitReached:
        raise
    except _ReadLimitReached:
        raise
    except (
        _ArchiveIncomplete,
        OSError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        pak["diagnostics"] = [f"bounded PAK structure inspection failed: {exc}"]
        return pak, 0


def _scope_guard(request: ExactModInspectionRequest, root: Path, allowed: list[str]) -> ScopeGuard:
    return ScopeGuard(
        receipt_id=request.receipt_id,
        operation="inspect_mod_exact",
        requested_target={
            "mod_id": request.target_mod_id,
            "provider_kind": request.provider_kind,
            "provider_path": _portable(root),
            "manifest_sha256": None,
            "pak_sha256s": [],
        },
        allowed_roots=allowed,
        limits=request.limits,
    )


def _emit_measured_receipt(
    payload: Mapping[str, Any],
    guard: ScopeGuard,
    access: ScopeAccess,
) -> tuple[dict[str, Any], dict[str, Any]]:
    response_bytes = 0
    receipt: dict[str, Any] = {}
    for _ in range(8):
        measured = ScopeAccess(
            roots_touched=access.roots_touched,
            files_opened=access.files_opened,
            archive_entries_examined=access.archive_entries_examined,
            physical_bytes_read=access.physical_bytes_read,
            provider_records_touched=access.provider_records_touched,
            other_provider_records_touched=access.other_provider_records_touched,
            out_of_scope_paths=access.out_of_scope_paths,
            response_bytes=response_bytes,
            scan_complete=access.scan_complete,
            limits_reached=access.limits_reached,
        )
        receipt = guard.emit(measured)
        candidate = {**dict(payload), "scope_receipt": receipt}
        updated = len(_canonical_bytes(candidate))
        if updated == response_bytes:
            return candidate, receipt
        response_bytes = updated
    measured = ScopeAccess(
        roots_touched=access.roots_touched,
        files_opened=access.files_opened,
        archive_entries_examined=access.archive_entries_examined,
        physical_bytes_read=access.physical_bytes_read,
        provider_records_touched=access.provider_records_touched,
        other_provider_records_touched=access.other_provider_records_touched,
        out_of_scope_paths=access.out_of_scope_paths,
        response_bytes=response_bytes,
        scan_complete=access.scan_complete,
        limits_reached=access.limits_reached,
    )
    receipt = guard.emit(measured)
    return {**dict(payload), "scope_receipt": receipt}, receipt


def _fit_response(
    payload: dict[str, Any],
    guard: ScopeGuard,
    access: ScopeAccess,
) -> tuple[dict[str, Any], dict[str, Any]]:
    while True:
        response, receipt = _emit_measured_receipt(payload, guard, access)
        if len(_canonical_bytes(response)) <= guard.limits.max_response_bytes:
            return response, receipt
        paks = payload["paks"]
        if paks:
            paks.pop()
            payload["pak_records_truncated"] = True
            message = (
                "PAK records were truncated from the response; the inventory digest is complete"
            )
            if message not in payload["diagnostics"]:
                payload["diagnostics"].append(message)
            continue
        override_paths = payload.get("payload_override_paths", [])
        if override_paths:
            override_paths.pop()
            payload["payload_override_paths_truncated"] = True
            continue
        fact_paks = payload.get("package_facts", {}).get("paks", [])
        if fact_paks:
            fact_paks.pop()
            payload["package_facts"]["pak_records_truncated"] = True
            continue
        native_components = payload.get("native_components", [])
        if native_components:
            native_components.pop()
            payload["native_component_records_truncated"] = True
            continue
        raise RuntimeError("the exact inspection base response exceeds max_response_bytes")


def _resolve_topology_root(source: Path) -> tuple[Path, Path]:
    """Resolve an exact mod directory or one standard child PAK to the same topology root."""
    resolved = source.resolve(strict=True)
    info = source.lstat()
    if _is_reparse(info):
        raise ValueError("provider_root must not be a reparse point")
    if stat.S_ISDIR(info.st_mode):
        return resolved, resolved
    if not stat.S_ISREG(info.st_mode) or resolved.suffix.casefold() != ".pak":
        raise ValueError("provider_root must be one mod directory or standard child PAK")
    package_directory = resolved.parent
    if package_directory.name.casefold() not in {"data", "localization"}:
        raise ValueError("direct PAK must be an immediate child of Data or Localization")
    topology_root = package_directory.parent.resolve(strict=True)
    topology_info = topology_root.lstat()
    if _is_reparse(topology_info) or not stat.S_ISDIR(topology_info.st_mode):
        raise ValueError("direct PAK sibling topology root must be a non-reparse directory")
    return topology_root, resolved


def inspect_mod_exact(request: ExactModInspectionRequest) -> ExactModInspectionResult:
    """Inspect exactly one caller-resolved mod topology without scanning mod siblings.

    A direct standard child PAK resolves to its sibling manifest and root config, producing the
    same package facts as the mod-directory view. The fallback never calls the opaque Index
    runtime, refuses links/reparse points, and optionally reads only one explicitly named
    ``mod_order.txt`` as fixed external metadata.
    """
    if not isinstance(request, ExactModInspectionRequest):
        raise TypeError("request must be ExactModInspectionRequest")

    root, requested_source = _resolve_topology_root(request.provider_root)
    if len(_portable(root)) > 1024:
        raise ValueError("provider_root exceeds the 1024-character response bound")

    mod_order: Path | None = None
    if request.mod_order_path is not None:
        mod_order_info = request.mod_order_path.lstat()
        if _is_reparse(mod_order_info) or not stat.S_ISREG(mod_order_info.st_mode):
            raise ValueError("mod_order.txt must be one non-reparse regular file")
        if mod_order_info.st_size > _CAPTURE_BYTES:
            raise ValueError(
                f"mod_order.txt exceeds the fixed metadata bound of {_CAPTURE_BYTES}"
            )
        mod_order = request.mod_order_path.resolve(strict=True)
        if mod_order.name.casefold() != "mod_order.txt":
            raise ValueError("the only permitted external metadata file is mod_order.txt")
        if len(_portable(mod_order)) > 1024:
            raise ValueError("mod_order_path exceeds the 1024-character response bound")

    allowed = [_portable(root)]
    roots_touched = [_portable(root)]
    if mod_order is not None:
        allowed.append(_portable(mod_order))
    guard = _scope_guard(request, root, allowed)

    records, diagnostics, out_of_scope, enumeration_complete = _enumerate_provider(
        root,
        max_files=request.limits.max_files,
    )
    limits_reached: set[str] = set()
    if len(records) > request.limits.max_files:
        limits_reached.add("files")
    scan_complete = enumeration_complete and not out_of_scope and not limits_reached
    budget = _ReadBudget(request.limits.max_physical_bytes)
    hashes: dict[str, str] = {}
    captured: dict[str, bytes | None] = {}
    pak_records: list[dict[str, Any]] = []
    pak_files = [record for record in records if _is_standard_package(record)]
    archive_entries_examined = 0

    if scan_complete:
        try:
            for record in records:
                capture = record.relative_path.casefold() in {"mod.manifest", "mod.cfg"}
                digest, data = _hash_file(
                    record,
                    budget,
                    capture=capture,
                    allowed_root=root,
                )
                hashes[record.relative_path] = digest
                captured[record.relative_path.casefold()] = data
        except _ScopeBoundaryChanged as exc:
            diagnostics.append(str(exc))
            out_of_scope.add(_portable(exc.path))
            scan_complete = False
        except (OSError, _ReadLimitReached) as exc:
            diagnostics.append(f"provider content scan did not complete: {exc}")
            limits_reached.add("physical_bytes")
            scan_complete = False

    if scan_complete:
        for record in pak_files:
            try:
                pak, examined = _inspect_pak(
                    record,
                    hashes[record.relative_path],
                    budget,
                    remaining_entries=(
                        request.limits.max_archive_entries - archive_entries_examined
                    ),
                )
                pak_records.append(pak)
                archive_entries_examined += examined
                diagnostics.extend(pak["diagnostics"])
            except _ArchiveEntryLimitReached as exc:
                diagnostics.append(str(exc))
                limits_reached.add("archive_entries")
                scan_complete = False
                break
            except _ReadLimitReached as exc:
                diagnostics.append(str(exc))
                limits_reached.add("physical_bytes")
                scan_complete = False
                break

    mod_order_result: dict[str, Any] = {
        "path": None,
        "sha256": None,
        "entry_count": 0,
        "state": "NOT_CHECKED",
    }
    if scan_complete and mod_order is not None:
        try:
            mod_order_digest, mod_order_bytes = _read_fixed_metadata(mod_order, budget)
            entries = [
                line.strip()
                for line in mod_order_bytes.decode("utf-8-sig", errors="strict").splitlines()
                if line.strip()
            ]
            matches = sum(
                entry.casefold() == request.target_mod_id.casefold() for entry in entries
            )
            state = "ABSENT" if matches == 0 else "EXACTLY_ONE" if matches == 1 else "DUPLICATE"
            mod_order_result = {
                "path": _portable(mod_order),
                "sha256": mod_order_digest,
                "entry_count": matches,
                "state": state,
            }
        except UnicodeDecodeError as exc:
            diagnostics.append(f"mod_order.txt is not valid UTF-8: {exc}")
            scan_complete = False
        except _ReadLimitReached as exc:
            diagnostics.append(str(exc))
            limits_reached.add("physical_bytes")
            scan_complete = False

    inventory_hasher = hashlib.sha256()
    for record in records:
        digest = hashes.get(record.relative_path)
        if digest is None:
            continue
        inventory_hasher.update(record.relative_path.encode("utf-8"))
        inventory_hasher.update(b"\0")
        inventory_hasher.update(str(record.size).encode("ascii"))
        inventory_hasher.update(b"\0")
        inventory_hasher.update(digest.encode("ascii"))
        inventory_hasher.update(b"\n")

    manifest_record = next(
        (record for record in records if record.relative_path.casefold() == "mod.manifest"),
        None,
    )
    manifest: dict[str, Any] | None = None
    if manifest_record is not None and manifest_record.relative_path in hashes:
        declared_mod_id, matches = _manifest_details(
            captured.get("mod.manifest"), request.target_mod_id
        )
        manifest = {
            "path": manifest_record.relative_path,
            "size": manifest_record.size,
            "sha256": hashes[manifest_record.relative_path],
            "declared_mod_id": declared_mod_id,
            "mod_id_matches_request": matches,
        }
        if matches is None:
            diagnostics.append("manifest mod ID could not be established from bounded XML")

    cfg_record = next(
        (record for record in records if record.relative_path.casefold() == "mod.cfg"),
        None,
    )
    cfg: dict[str, Any] | None = None
    if cfg_record is not None and cfg_record.relative_path in hashes:
        cfg = {
            "path": cfg_record.relative_path,
            "size": cfg_record.size,
            "sha256": hashes[cfg_record.relative_path],
        }

    declared_native = _declared_native_paths(captured.get("mod.manifest"))
    records_by_key = {record.relative_path.casefold(): record for record in records}
    native_components: list[dict[str, Any]] = []
    for declared_path in declared_native:
        component = records_by_key.get(declared_path.casefold())
        native_components.append(
            {
                "declared_path": declared_path,
                "present": component is not None and component.relative_path in hashes,
                "sha256": (
                    hashes[component.relative_path]
                    if component is not None and component.relative_path in hashes
                    else None
                ),
            }
        )

    payload_override_paths = sorted(
        {
            member["path"]
            for pak in pak_records
            for member in pak["members"]
            if member["payload_override_risk"]
        },
        key=lambda item: (item.casefold(), item),
    )
    package_facts = {
        "manifest_sha256": manifest["sha256"] if manifest is not None else None,
        "mod_cfg_sha256": cfg["sha256"] if cfg is not None else None,
        "pak_count": len(pak_files),
        "paks": [
            {
                "path": pak["path"],
                "sha256": pak["sha256"],
                "archive_entry_count": pak["archive_entry_count"],
                "structure_valid": pak["structure_valid"],
            }
            for pak in pak_records
        ],
        "localization_package_count": sum(
            record.relative_path.casefold().startswith("localization/") for record in pak_files
        ),
        "declared_native_component_count": len(native_components),
        "pak_records_truncated": False,
    }
    topology = {
        "manifest": manifest["path"] if manifest is not None else None,
        "root_config": cfg["path"] if cfg is not None else None,
        "data_pak_count": sum(
            record.relative_path.casefold().startswith("data/") for record in pak_files
        ),
        "localization_package_count": sum(
            record.relative_path.casefold().startswith("localization/") for record in pak_files
        ),
        "declared_native_component_count": len(native_components),
    }

    payload: dict[str, Any] = {
        "schema_version": "kcd2.index-adapter-inspect-mod-exact.v1",
        "operation": "inspect_mod_exact",
        "source_mode": "bounded_read_only_adapter",
        "upstream_source_state": "PATCH_STAGED_NOT_DEPLOYED",
        "target": {
            "mod_id": request.target_mod_id,
            "provider_kind": request.provider_kind,
            "provider_root": _portable(root),
            "requested_source": _portable(requested_source),
        },
        "selected_mod_count": 1,
        "inventory": {
            "file_count": len(records),
            "total_file_bytes": sum(record.size for record in records),
            "sha256": inventory_hasher.hexdigest(),
        },
        "manifest": manifest,
        "mod_cfg": cfg,
        "pak_count": len(pak_files),
        "paks": pak_records,
        "pak_records_truncated": False,
        "package_facts": package_facts,
        "payload_override_paths": payload_override_paths,
        "payload_override_paths_truncated": False,
        "native_components": native_components,
        "native_component_records_truncated": False,
        "topology": topology,
        "mod_order": mod_order_result,
        "diagnostics": diagnostics,
        "server_side_scope_repaired": False,
    }
    access = ScopeAccess(
        roots_touched=(
            roots_touched
            + (
                [_portable(mod_order)]
                if mod_order is not None and mod_order in budget.opened
                else []
            )
        ),
        files_opened=len(budget.opened),
        archive_entries_examined=archive_entries_examined,
        physical_bytes_read=budget.bytes_read,
        provider_records_touched=0,
        other_provider_records_touched=0,
        out_of_scope_paths=tuple(out_of_scope),
        response_bytes=0,
        scan_complete=scan_complete,
        limits_reached=tuple(limits_reached),
    )
    response, receipt = _fit_response(payload, guard, access)
    response_payload = dict(response)
    response_payload.pop("scope_receipt")
    return ExactModInspectionResult(payload=response_payload, scope_receipt=receipt)
