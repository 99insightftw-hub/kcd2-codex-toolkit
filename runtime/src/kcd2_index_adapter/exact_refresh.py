"""Staged-only transaction model for an exact KCD2 Index provider refresh.

The authoritative Index runtime source is unavailable.  This module therefore does not
patch or write its databases.  It provides a deterministic dry-run plan and exercises the
required transaction, journal, and rollback mechanics only against an explicitly identified
adapter-owned staged test database.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from kcd2_toolchain_core.approvals import ApprovalTarget, ApprovalVerifier

from .scope_guard import ScopeAccess, ScopeGuard, ScopeLimits


_SHA256 = "0123456789abcdef"
_TABLE = "staged_provider_records"
ProviderKind = Literal["local", "workshop", "explicit_path"]


class ExactRefreshError(RuntimeError):
    """The staged exact-refresh contract could not be satisfied."""


class HashDriftError(ExactRefreshError):
    """Provider content changed after the reviewed dry run."""


class PlanDriftError(ExactRefreshError):
    """The staged target-provider rows changed after the reviewed dry run."""


class PersistentRefreshUnavailableError(ExactRefreshError):
    """Persistent Index refresh is unavailable without authoritative runtime source."""


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
        raise ExactRefreshError("refresh data must be bounded JSON-compatible data") from exc


def _canonical_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256 for character in value.casefold())
    ):
        raise ExactRefreshError(f"{name} must be a SHA-256 digest")
    return value.casefold()


def _portable(path: Path) -> str:
    return path.resolve(strict=False).as_posix()


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse) or stat.S_ISLNK(info.st_mode)


def _relative_path(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ExactRefreshError(f"{name} must be a canonical relative provider path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ExactRefreshError(f"{name} must not escape the exact provider root")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class RefreshRecord:
    record_key: str
    content_sha256: str
    payload: object

    def __post_init__(self) -> None:
        if not isinstance(self.record_key, str) or not self.record_key or "\x00" in self.record_key:
            raise ExactRefreshError("record_key must be a non-empty string without NUL bytes")
        _validate_sha256(self.content_sha256, "content_sha256")
        _canonical_bytes(self.payload)

    def to_dict(self, provider_id: str) -> dict[str, Any]:
        return {
            "provider_id": provider_id,
            "record_key": self.record_key,
            "content_sha256": self.content_sha256.casefold(),
            "payload": _canonical_copy(self.payload),
        }


@dataclass(frozen=True, slots=True)
class ExactRefreshPlan:
    payload: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExactRefreshPlan":
        if not isinstance(value, Mapping):
            raise ExactRefreshError("plan must be an exact-refresh plan object")
        copied = _canonical_copy(value)
        if copied.get("schema_version") != "kcd2.index-adapter-refresh-plan.v1":
            raise ExactRefreshError("unsupported exact-refresh plan version")
        plan_id = copied.get("plan_id")
        unsigned = dict(copied)
        unsigned.pop("plan_id", None)
        if plan_id != f"refresh-plan:{_digest(unsigned)}":
            raise ExactRefreshError("exact-refresh plan digest does not match its content")
        return cls(copied)

    def to_dict(self) -> dict[str, Any]:
        return _canonical_copy(self.payload)


@dataclass(frozen=True, slots=True)
class ExactRefreshRequest:
    database_path: Path
    target_mod_id: str
    provider_id: str
    provider_kind: ProviderKind
    provider_root: Path
    desired_records: Sequence[RefreshRecord]
    manifest_path: str = "mod.manifest"
    pak_paths: Sequence[str] = ()
    dry_run: bool = True
    plan: ExactRefreshPlan | None = None
    staged_test_database: bool = False
    allow_staged_write: bool = False
    limits: ScopeLimits = ScopeLimits(1024, 65536, 268_435_456, 262_144)
    receipt_id: str = "scope:refresh-mod-exact:adapter"

    def __post_init__(self) -> None:
        for name in ("target_mod_id", "provider_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ExactRefreshError(f"{name} must be a non-empty string without NUL bytes")
        if self.provider_kind not in ("local", "workshop", "explicit_path"):
            raise ExactRefreshError("provider_kind is not supported for an exact refresh")
        if not isinstance(self.database_path, Path) or not isinstance(self.provider_root, Path):
            raise ExactRefreshError("database_path and provider_root must be Path objects")
        if isinstance(self.desired_records, (str, bytes)) or not isinstance(
            self.desired_records, Sequence
        ):
            raise ExactRefreshError("desired_records must be an array")
        if not all(isinstance(record, RefreshRecord) for record in self.desired_records):
            raise ExactRefreshError("desired_records must contain RefreshRecord values")
        keys = [record.record_key for record in self.desired_records]
        if len(set(keys)) != len(keys):
            raise ExactRefreshError("desired record keys must be unique")
        if len(keys) > self.limits.max_files:
            raise ExactRefreshError("desired record count exceeds max_files")
        _relative_path(self.manifest_path, "manifest_path")
        if isinstance(self.pak_paths, (str, bytes)) or not isinstance(self.pak_paths, Sequence):
            raise ExactRefreshError("pak_paths must be an array")
        normalized_paks = [_relative_path(value, "pak_paths item") for value in self.pak_paths]
        if len(set(normalized_paks)) != len(normalized_paks):
            raise ExactRefreshError("pak_paths must be unique")
        if not isinstance(self.dry_run, bool):
            raise ExactRefreshError("dry_run must be a boolean")
        if not self.dry_run and self.plan is None:
            raise ExactRefreshError("commit requires the exact reviewed dry-run plan")
        if not isinstance(self.staged_test_database, bool) or not isinstance(
            self.allow_staged_write, bool
        ):
            raise ExactRefreshError("staged write gates must be booleans")


@dataclass(frozen=True, slots=True)
class ExactRefreshResult:
    payload: Mapping[str, Any]
    plan: ExactRefreshPlan
    scope_receipt: Mapping[str, Any]

    @property
    def status(self) -> str:
        return str(self.payload["status"])

    @property
    def rollback_journal(self) -> Mapping[str, Any]:
        return self.payload["rollback_journal"]

    def to_dict(self) -> dict[str, Any]:
        return _canonical_copy({**dict(self.payload), "scope_receipt": self.scope_receipt})

    def to_json(self) -> str:
        return _canonical_bytes(self.to_dict()).decode("utf-8")


def _provider_files(request: ExactRefreshRequest) -> tuple[Path, list[tuple[str, Path]]]:
    root_info = request.provider_root.lstat()
    root = request.provider_root.resolve(strict=True)
    if _is_reparse(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise ExactRefreshError("provider_root must be one non-reparse directory")
    relative_paths = [request.manifest_path, *request.pak_paths]
    if len(relative_paths) > request.limits.max_files:
        raise ExactRefreshError("provider hash file count exceeds max_files")
    files: list[tuple[str, Path]] = []
    for relative in relative_paths:
        normalized = _relative_path(relative, "provider hash path")
        path = root.joinpath(*PurePosixPath(normalized).parts)
        info = path.lstat()
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ExactRefreshError("provider hash path escaped the exact provider root") from exc
        if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
            raise ExactRefreshError("provider hash path must be one non-reparse regular file")
        files.append((normalized, path))
    return root, files


def _hash_provider(
    request: ExactRefreshRequest,
) -> tuple[Path, dict[str, str], int, int]:
    root, files = _provider_files(request)
    total = 0
    hashes: dict[str, str] = {}
    for relative, path in files:
        before = path.lstat()
        if before.st_size > request.limits.max_physical_bytes - total:
            raise ExactRefreshError("provider hashes exceed max_physical_bytes")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            if os.fstat(stream.fileno()) != before:
                raise HashDriftError(f"provider hash drift while opening {relative}")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                digest.update(chunk)
            after = os.fstat(stream.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise HashDriftError(f"provider hash drift while reading {relative}")
        hashes[relative] = digest.hexdigest()
    return root, hashes, len(files), total


def _decode_database_row(row: tuple[object, ...], provider_id: str) -> dict[str, Any]:
    if len(row) != 3:
        raise ExactRefreshError("staged provider record query returned an invalid row")
    record_key, content_sha256, payload_json = row
    if not isinstance(record_key, str) or not record_key:
        raise ExactRefreshError("staged record_key is invalid")
    digest = _validate_sha256(content_sha256, "staged content_sha256")
    if not isinstance(payload_json, str):
        raise ExactRefreshError("staged payload_json is invalid")
    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        raise ExactRefreshError("staged payload_json is not valid JSON") from exc
    return {
        "provider_id": provider_id,
        "record_key": record_key,
        "content_sha256": digest,
        "payload": _canonical_copy(payload),
    }


def _read_target_rows(
    connection: sqlite3.Connection, provider_id: str
) -> list[dict[str, Any]]:
    try:
        rows = connection.execute(
            f"SELECT record_key, content_sha256, payload_json FROM {_TABLE} "
            "WHERE provider_id = ? ORDER BY record_key",
            (provider_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise ExactRefreshError(
            "database is not an adapter-owned staged exact-refresh fixture"
        ) from exc
    return [_decode_database_row(row, provider_id) for row in rows]


def _require_staged_database_marker(connection: sqlite3.Connection) -> None:
    try:
        row = connection.execute(
            "SELECT value FROM staged_refresh_metadata WHERE key = 'database_role'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise PersistentRefreshUnavailableError(
            "database lacks the required staged-test marker table"
        ) from exc
    if row != ("staged_test_only",):
        raise PersistentRefreshUnavailableError(
            "database lacks the exact staged-test marker; persistent refresh is refused"
        )


def _desired_rows(request: ExactRefreshRequest) -> list[dict[str, Any]]:
    return sorted(
        (record.to_dict(request.provider_id) for record in request.desired_records),
        key=lambda item: item["record_key"],
    )


def _operations(
    before_rows: Sequence[Mapping[str, Any]], after_rows: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    before = {str(row["record_key"]): dict(row) for row in before_rows}
    after = {str(row["record_key"]): dict(row) for row in after_rows}
    operations: list[dict[str, Any]] = []
    for key in sorted(before.keys() | after.keys()):
        old = before.get(key)
        new = after.get(key)
        if old is None:
            operations.append({"action": "add", "record_key": key, "before": None, "after": new})
        elif new is None:
            operations.append(
                {"action": "remove", "record_key": key, "before": old, "after": None}
            )
        elif old != new:
            operations.append(
                {"action": "update", "record_key": key, "before": old, "after": new}
            )
    return operations


def _make_plan(
    request: ExactRefreshRequest,
    root: Path,
    hashes: Mapping[str, str],
    before_rows: Sequence[Mapping[str, Any]],
) -> ExactRefreshPlan:
    desired = _desired_rows(request)
    operations = _operations(before_rows, desired)
    counts = {
        action: sum(operation["action"] == action for operation in operations)
        for action in ("add", "remove", "update")
    }
    unsigned = {
        "schema_version": "kcd2.index-adapter-refresh-plan.v1",
        "target": {
            "mod_id": request.target_mod_id,
            "provider_id": request.provider_id,
            "provider_kind": request.provider_kind,
            "provider_root": _portable(root),
        },
        "provider_hashes": dict(sorted(hashes.items())),
        "baseline_target_rows_sha256": _digest(before_rows),
        "desired_target_rows_sha256": _digest(desired),
        "counts": counts,
        "operations": operations,
        "other_provider_records_touched": 0,
    }
    return ExactRefreshPlan.from_mapping(
        {**unsigned, "plan_id": f"refresh-plan:{_digest(unsigned)}"}
    )


def _validate_plan_request(
    request: ExactRefreshRequest, plan: ExactRefreshPlan, root: Path
) -> None:
    target = plan.payload.get("target")
    if not isinstance(target, Mapping):
        raise ExactRefreshError("plan target is invalid")
    expected = {
        "mod_id": request.target_mod_id,
        "provider_id": request.provider_id,
        "provider_kind": request.provider_kind,
        "provider_root": _portable(root),
    }
    if dict(target) != expected:
        raise ExactRefreshError("commit request does not match the reviewed dry-run target")
    desired = _desired_rows(request)
    if plan.payload.get("desired_target_rows_sha256") != _digest(desired):
        raise ExactRefreshError("commit desired records do not match the reviewed dry run")
    for operation in plan.payload.get("operations", []):
        if not isinstance(operation, Mapping):
            raise ExactRefreshError("plan operation is invalid")
        for side in ("before", "after"):
            row = operation.get(side)
            if row is not None and (
                not isinstance(row, Mapping) or row.get("provider_id") != request.provider_id
            ):
                raise ExactRefreshError("plan contains a record owned by another provider")
    if plan.payload.get("other_provider_records_touched") != 0:
        raise ExactRefreshError("plan is not provider-isolated")


def _payload_json(row: Mapping[str, Any]) -> str:
    return _canonical_bytes(row["payload"]).decode("utf-8")


def _apply_operation(
    connection: sqlite3.Connection,
    provider_id: str,
    operation: Mapping[str, Any],
) -> None:
    action = operation["action"]
    key = operation["record_key"]
    if action == "add":
        row = operation["after"]
        connection.execute(
            f"INSERT INTO {_TABLE} "
            "(provider_id, record_key, content_sha256, payload_json) VALUES (?, ?, ?, ?)",
            (provider_id, key, row["content_sha256"], _payload_json(row)),
        )
        return
    if action == "remove":
        cursor = connection.execute(
            f"DELETE FROM {_TABLE} WHERE provider_id = ? AND record_key = ?",
            (provider_id, key),
        )
    elif action == "update":
        row = operation["after"]
        cursor = connection.execute(
            f"UPDATE {_TABLE} SET content_sha256 = ?, payload_json = ? "
            "WHERE provider_id = ? AND record_key = ?",
            (row["content_sha256"], _payload_json(row), provider_id, key),
        )
    else:
        raise ExactRefreshError("plan contains an unsupported action")
    if cursor.rowcount != 1:
        raise PlanDriftError(f"target row changed before {action}: {key}")


def _inverse_operations(operations: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    inverse: list[dict[str, Any]] = []
    for operation in reversed(operations):
        action = operation["action"]
        inverted = {"add": "remove", "remove": "add", "update": "update"}[action]
        inverse.append(
            {
                "action": inverted,
                "record_key": operation["record_key"],
                "before": _canonical_copy(operation["after"]),
                "after": _canonical_copy(operation["before"]),
            }
        )
    return inverse


def _scope_guard(request: ExactRefreshRequest, root: Path, database: Path) -> ScopeGuard:
    return ScopeGuard(
        receipt_id=request.receipt_id,
        operation="refresh_mod_exact",
        requested_target={
            "mod_id": request.target_mod_id,
            "provider_kind": request.provider_kind,
            "provider_path": _portable(root),
            "manifest_sha256": None,
            "pak_sha256s": [],
        },
        allowed_roots=(_portable(root), _portable(database)),
        limits=request.limits,
    )


def _result(
    *,
    request: ExactRefreshRequest,
    root: Path,
    plan: ExactRefreshPlan,
    status: str,
    journal: Mapping[str, Any],
    files_opened: int,
    physical_bytes_read: int,
    provider_records_touched: int,
) -> ExactRefreshResult:
    database = request.database_path.resolve(strict=True)
    guard = _scope_guard(request, root, database)
    ledger: list[dict[str, Any]] = []
    for operation in plan.payload["operations"]:
        ledger.append(
            {
                "provider_id": request.provider_id,
                "record_key": operation["record_key"],
                "action": operation["action"],
            }
        )
    payload = {
        "schema_version": "kcd2.index-adapter-refresh-mod-exact.v1",
        "operation": "refresh_mod_exact",
        "status": status,
        "source_mode": "bounded_source_unavailable_adapter",
        "upstream_source_state": "SOURCE_BLOCKED",
        "persistent_targeted_refresh_claim": False,
        "server_side_scope_repaired": False,
        "persistence_scope": "staged_test_database_only",
        "plan": plan.to_dict(),
        "provider_ownership_ledger": ledger,
        "rollback_journal": _canonical_copy(journal),
    }
    response_bytes = 0
    receipt: Mapping[str, Any] = {}
    for _ in range(8):
        access = ScopeAccess(
            roots_touched=(_portable(root), _portable(database)),
            files_opened=files_opened,
            archive_entries_examined=0,
            physical_bytes_read=physical_bytes_read,
            provider_records_touched=provider_records_touched,
            other_provider_records_touched=0,
            out_of_scope_paths=(),
            response_bytes=response_bytes,
            scan_complete=True,
        )
        receipt = guard.emit(access)
        updated = len(_canonical_bytes({**payload, "scope_receipt": receipt}))
        if updated == response_bytes:
            break
        response_bytes = updated
    if response_bytes > request.limits.max_response_bytes:
        raise ExactRefreshError("exact-refresh response exceeds max_response_bytes")
    return ExactRefreshResult(payload, plan, receipt)


def _refresh_mod_exact_impl(request: ExactRefreshRequest) -> ExactRefreshResult:
    """Plan an exact refresh or execute it against an explicit staged test database only."""
    if not isinstance(request, ExactRefreshRequest):
        raise TypeError("request must be ExactRefreshRequest")
    database = request.database_path.resolve(strict=True)
    database_info = request.database_path.lstat()
    if _is_reparse(database_info) or not stat.S_ISREG(database_info.st_mode):
        raise ExactRefreshError("database_path must be one non-reparse regular staged file")
    root, hashes, files_opened, physical_bytes_read = _hash_provider(request)

    if request.dry_run:
        with closing(sqlite3.connect(database)) as connection:
            before_rows = _read_target_rows(connection, request.provider_id)
        plan = _make_plan(request, root, hashes, before_rows)
        journal = {
            "schema_version": "kcd2.index-adapter-refresh-journal.v1",
            "status": "PLANNED_NOT_EXECUTED",
            "plan_id": plan.payload["plan_id"],
            "provider_id": request.provider_id,
            "rollback_unit_exists": True,
            "inverse_operations": _inverse_operations(plan.payload["operations"]),
            "pre_state_sha256": plan.payload["baseline_target_rows_sha256"],
            "post_state_sha256": plan.payload["desired_target_rows_sha256"],
        }
        return _result(
            request=request,
            root=root,
            plan=plan,
            status="DRY_RUN",
            journal=journal,
            files_opened=files_opened + 1,
            physical_bytes_read=physical_bytes_read,
            provider_records_touched=len(before_rows),
        )

    if not request.staged_test_database:
        raise PersistentRefreshUnavailableError(
            "authoritative Index runtime source is unavailable; persistent targeted refresh "
            "cannot be claimed or executed"
        )
    if not request.allow_staged_write:
        raise PersistentRefreshUnavailableError("staged commit requires allow_staged_write")
    assert request.plan is not None
    plan = ExactRefreshPlan.from_mapping(request.plan.payload)
    _validate_plan_request(request, plan, root)
    if dict(plan.payload["provider_hashes"]) != hashes:
        raise HashDriftError("provider hash drift cancels exact-refresh commit")

    operations = plan.payload["operations"]
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_staged_database_marker(connection)
        current = _read_target_rows(connection, request.provider_id)
        if _digest(current) != plan.payload["baseline_target_rows_sha256"]:
            raise PlanDriftError("target provider rows changed after the dry run")
        _, locked_hashes, extra_files, extra_bytes = _hash_provider(request)
        files_opened += extra_files
        physical_bytes_read += extra_bytes
        if locked_hashes != hashes:
            raise HashDriftError("provider hash drift cancels exact-refresh commit")
        for operation in operations:
            _apply_operation(connection, request.provider_id, operation)
        after = _read_target_rows(connection, request.provider_id)
        if _digest(after) != plan.payload["desired_target_rows_sha256"]:
            raise PlanDriftError("staged target rows do not match the reviewed desired state")
        _, final_hashes, extra_files, extra_bytes = _hash_provider(request)
        files_opened += extra_files
        physical_bytes_read += extra_bytes
        if final_hashes != hashes:
            raise HashDriftError("provider hash drift cancels exact-refresh commit")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()

    journal_unsigned = {
        "schema_version": "kcd2.index-adapter-refresh-journal.v1",
        "status": "COMMITTED_STAGED_ONLY",
        "plan_id": plan.payload["plan_id"],
        "provider_id": request.provider_id,
        "database_path": _portable(database),
        "rollback_unit_exists": True,
        "inverse_operations": _inverse_operations(operations),
        "pre_state_sha256": plan.payload["baseline_target_rows_sha256"],
        "post_state_sha256": plan.payload["desired_target_rows_sha256"],
        "other_provider_records_touched": 0,
    }
    journal = {
        **journal_unsigned,
        "journal_sha256": _digest(journal_unsigned),
    }
    return _result(
        request=request,
        root=root,
        plan=plan,
        status="COMMITTED_STAGED_ONLY",
        journal=journal,
        files_opened=files_opened + 1,
        physical_bytes_read=physical_bytes_read,
        provider_records_touched=len(operations),
    )


def _rollback_mod_exact_impl(
    *,
    database_path: Path,
    journal: Mapping[str, Any],
    staged_test_database: bool,
) -> dict[str, Any]:
    """Apply one verified rollback unit to its exact staged target-provider rows."""
    if not staged_test_database:
        raise PersistentRefreshUnavailableError(
            "authoritative Index runtime source is unavailable; persistent rollback is refused"
        )
    if not isinstance(journal, Mapping):
        raise ExactRefreshError("rollback journal must be an object")
    copied = _canonical_copy(journal)
    digest = copied.pop("journal_sha256", None)
    if digest != _digest(copied):
        raise ExactRefreshError("rollback journal digest does not match its content")
    if copied.get("status") != "COMMITTED_STAGED_ONLY":
        raise ExactRefreshError("rollback requires a committed staged-only journal")
    database = database_path.resolve(strict=True)
    if copied.get("database_path") != _portable(database):
        raise ExactRefreshError("rollback journal is bound to a different staged database")
    provider_id = copied.get("provider_id")
    if not isinstance(provider_id, str) or not provider_id:
        raise ExactRefreshError("rollback journal provider_id is invalid")
    inverse = copied.get("inverse_operations")
    if not isinstance(inverse, list):
        raise ExactRefreshError("rollback journal inverse_operations is invalid")
    for operation in inverse:
        if not isinstance(operation, Mapping):
            raise ExactRefreshError("rollback operation is invalid")
        for side in ("before", "after"):
            row = operation.get(side)
            if row is not None and (
                not isinstance(row, Mapping) or row.get("provider_id") != provider_id
            ):
                raise ExactRefreshError("rollback journal crosses provider ownership")

    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_staged_database_marker(connection)
        current = _read_target_rows(connection, provider_id)
        if _digest(current) != copied.get("post_state_sha256"):
            raise PlanDriftError("staged target rows changed after commit; rollback cancelled")
        for operation in inverse:
            _apply_operation(connection, provider_id, operation)
        restored = _read_target_rows(connection, provider_id)
        if _digest(restored) != copied.get("pre_state_sha256"):
            raise PlanDriftError("rollback did not restore the exact pre-refresh target state")
        connection.execute("COMMIT")
    except Exception:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()
    return {
        "schema_version": "kcd2.index-adapter-refresh-rollback.v1",
        "status": "ROLLED_BACK_STAGED_ONLY",
        "plan_id": copied["plan_id"],
        "provider_id": provider_id,
        "provider_records_touched": len(inverse),
        "other_provider_records_touched": 0,
        "restored_state_sha256": copied["pre_state_sha256"],
        "persistent_targeted_refresh_claim": False,
        "upstream_source_state": "SOURCE_BLOCKED",
    }


def refresh_mod_exact_approval_targets(
    request: ExactRefreshRequest,
) -> tuple[ApprovalTarget, ...]:
    if request.dry_run or request.plan is None:
        raise ExactRefreshError("dry-run refresh does not require mutation approval targets")
    current = ApprovalTarget.from_paths(
        role="staged_index_database", path=request.database_path
    )
    database = ApprovalTarget(
        role=current.role,
        path=current.path,
        expected_current_sha256=current.expected_current_sha256,
        proposed_sha256=str(request.plan.payload["desired_target_rows_sha256"]),
    )
    provider = ApprovalTarget.from_paths(
        role="provider_inputs", path=request.provider_root, proposed_path=request.provider_root
    )
    return database, provider


def refresh_mod_exact(
    request: ExactRefreshRequest,
    *,
    approval: Mapping[str, object] | None = None,
    approval_verifier: ApprovalVerifier | None = None,
) -> ExactRefreshResult:
    """Dry runs are approval-free; staged writes use the shared one-time gate."""
    if request.dry_run:
        return _refresh_mod_exact_impl(request)
    if approval is None or approval_verifier is None:
        raise ExactRefreshError("staged Index mutation requires transaction approval")
    targets = refresh_mod_exact_approval_targets(request)
    return approval_verifier.execute(
        approval,
        operation="persistent_index_write",
        targets=targets,
        mutation=lambda: _refresh_mod_exact_impl(request),
    )


def rollback_mod_exact_approval_targets(
    *, database_path: Path, journal: Mapping[str, Any]
) -> tuple[ApprovalTarget, ...]:
    current = ApprovalTarget.from_paths(role="staged_index_database", path=database_path)
    return (
        ApprovalTarget(
            role=current.role,
            path=current.path,
            expected_current_sha256=current.expected_current_sha256,
            proposed_sha256=str(journal.get("pre_state_sha256")),
        ),
    )


def rollback_mod_exact(
    *,
    database_path: Path,
    journal: Mapping[str, Any],
    staged_test_database: bool,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
) -> dict[str, Any]:
    targets = rollback_mod_exact_approval_targets(
        database_path=database_path, journal=journal
    )
    return approval_verifier.execute(
        approval,
        operation="persistent_index_write",
        targets=targets,
        mutation=lambda: _rollback_mod_exact_impl(
            database_path=database_path,
            journal=journal,
            staged_test_database=staged_test_database,
        ),
    )
