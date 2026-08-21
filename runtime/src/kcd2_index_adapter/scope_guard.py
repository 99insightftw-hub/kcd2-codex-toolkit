"""Fail-closed receipts for KCD2 Index operations advertised as exact or targeted."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal


ScopeStatus = Literal[
    "TARGET_SCOPE_OK",
    "TARGET_SCOPE_BREACH",
    "TARGET_SCOPE_LIMIT_REACHED",
    "INCONCLUSIVE",
]

EXACT_OPERATIONS = frozenset(
    {"inspect_mod_exact", "refresh_mod_exact", "resolve_mod_provider_exact"}
)
_LIMIT_NAMES = (
    "files",
    "archive_entries",
    "physical_bytes",
    "response_bytes",
)
_RECEIPT_ID = re.compile(r"^scope:[A-Za-z0-9._:-]+$")
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")


class TargetScopeReceiptError(RuntimeError):
    """An exact call did not return a complete, self-consistent scope receipt."""

    code = "TARGET_SCOPE_RECEIPT_INVALID"


class TargetScopeBreachError(TargetScopeReceiptError):
    """The receipt proves that an exact call crossed its declared scope."""

    code = "TARGET_SCOPE_BREACH"


class TargetScopeLimitError(TargetScopeReceiptError):
    """The receipt proves that an exact call exceeded or saturated a declared limit."""

    code = "TARGET_SCOPE_LIMIT_REACHED"


class TargetScopeInconclusiveError(TargetScopeReceiptError):
    """The receipt is bounded but does not establish complete exact coverage."""

    code = "INCONCLUSIVE"


def _require_plain_int(value: object, *, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TargetScopeReceiptError(f"{name} must be an integer of at least {minimum}")
    return value


def _canonical_path(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise TargetScopeReceiptError(f"{name} must be a non-empty path without NUL bytes")
    normalized = value.replace("\\", "/")
    prefix = "/" if normalized.startswith("/") else ""
    parts: list[str] = []
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise TargetScopeReceiptError(f"{name} must not contain path traversal")
        parts.append(part)
    if not parts:
        raise TargetScopeReceiptError(f"{name} must identify a path")
    return prefix + "/".join(parts)


def _path_is_within(path: str, root: str) -> bool:
    path_key = path.rstrip("/").casefold()
    root_key = root.rstrip("/").casefold()
    return path_key == root_key or path_key.startswith(root_key + "/")


def _canonical_json_copy(value: object, *, name: str) -> Any:
    try:
        return json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (TypeError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        raise TargetScopeReceiptError(f"{name} must be JSON-compatible") from exc


@dataclass(frozen=True, slots=True)
class ScopeLimits:
    max_files: int
    max_archive_entries: int
    max_physical_bytes: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_archive_entries",
            "max_physical_bytes",
            "max_response_bytes",
        ):
            _require_plain_int(getattr(self, name), name=name, minimum=1)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ScopeLimits":
        expected = {
            "max_files",
            "max_archive_entries",
            "max_physical_bytes",
            "max_response_bytes",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise TargetScopeReceiptError("declared_limits fields do not match v1")
        return cls(**{name: value[name] for name in expected})  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_archive_entries": self.max_archive_entries,
            "max_physical_bytes": self.max_physical_bytes,
            "max_response_bytes": self.max_response_bytes,
        }


@dataclass(frozen=True, slots=True)
class ScopeAccess:
    roots_touched: Sequence[str]
    files_opened: int
    archive_entries_examined: int
    physical_bytes_read: int
    provider_records_touched: int
    other_provider_records_touched: int
    out_of_scope_paths: Sequence[str]
    response_bytes: int
    scan_complete: bool
    limits_reached: Sequence[str] = ()
    detail_artifact: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        for name in (
            "files_opened",
            "archive_entries_examined",
            "physical_bytes_read",
            "provider_records_touched",
            "other_provider_records_touched",
            "response_bytes",
        ):
            _require_plain_int(getattr(self, name), name=name, minimum=0)
        if not isinstance(self.scan_complete, bool):
            raise TargetScopeReceiptError("scan_complete must be a boolean")
        for name in ("roots_touched", "out_of_scope_paths", "limits_reached"):
            candidate = getattr(self, name)
            if isinstance(candidate, (str, bytes)) or not isinstance(candidate, Sequence):
                raise TargetScopeReceiptError(f"{name} must be an array")
        roots = tuple(
            _canonical_path(item, name="roots_touched item") for item in self.roots_touched
        )
        out_of_scope = tuple(
            _canonical_path(item, name="out_of_scope_paths item")
            for item in self.out_of_scope_paths
        )
        limits = tuple(self.limits_reached)
        if len({item.casefold() for item in roots}) != len(roots) or len(
            {item.casefold() for item in out_of_scope}
        ) != len(out_of_scope):
            raise TargetScopeReceiptError("scope access paths must be unique")
        if len(set(limits)) != len(limits) or not set(limits).issubset(_LIMIT_NAMES):
            raise TargetScopeReceiptError("limits_reached contains an invalid or duplicate limit")
        if self.other_provider_records_touched > self.provider_records_touched:
            raise TargetScopeReceiptError(
                "other_provider_records_touched cannot exceed provider_records_touched"
            )
        if self.detail_artifact is not None:
            if set(self.detail_artifact) != {"path", "sha256"}:
                raise TargetScopeReceiptError("detail_artifact fields do not match v1")
            _canonical_path(self.detail_artifact["path"], name="detail_artifact.path")
            if _SHA256.fullmatch(self.detail_artifact["sha256"]) is None:
                raise TargetScopeReceiptError("detail_artifact.sha256 must be a SHA-256 digest")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ScopeAccess":
        required = {
            "roots_touched",
            "files_opened",
            "archive_entries_examined",
            "physical_bytes_read",
            "provider_records_touched",
            "other_provider_records_touched",
            "out_of_scope_paths",
            "response_bytes",
            "scan_complete",
            "limits_reached",
        }
        allowed = required | {"detail_artifact"}
        if (
            not isinstance(value, Mapping)
            or not required.issubset(value)
            or not set(value).issubset(allowed)
        ):
            raise TargetScopeReceiptError("actual_access fields do not match v1")
        for name in ("roots_touched", "out_of_scope_paths", "limits_reached"):
            candidate = value[name]
            if isinstance(candidate, (str, bytes)) or not isinstance(candidate, Sequence):
                raise TargetScopeReceiptError(f"actual_access.{name} must be an array")
        detail = value.get("detail_artifact")
        if detail is not None and not isinstance(detail, Mapping):
            raise TargetScopeReceiptError(
                "actual_access.detail_artifact must be an object or null"
            )
        return cls(
            roots_touched=value["roots_touched"],  # type: ignore[arg-type]
            files_opened=value["files_opened"],  # type: ignore[arg-type]
            archive_entries_examined=value["archive_entries_examined"],  # type: ignore[arg-type]
            physical_bytes_read=value["physical_bytes_read"],  # type: ignore[arg-type]
            provider_records_touched=value["provider_records_touched"],  # type: ignore[arg-type]
            other_provider_records_touched=value[
                "other_provider_records_touched"
            ],  # type: ignore[arg-type]
            out_of_scope_paths=value["out_of_scope_paths"],  # type: ignore[arg-type]
            response_bytes=value["response_bytes"],  # type: ignore[arg-type]
            detail_artifact=detail,  # type: ignore[arg-type]
            scan_complete=value["scan_complete"],  # type: ignore[arg-type]
            limits_reached=value["limits_reached"],  # type: ignore[arg-type]
        )

    def to_dict(
        self,
        *,
        roots_touched: Sequence[str] | None = None,
        out_of_scope_paths: Sequence[str] | None = None,
        limits_reached: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        roots = self.roots_touched if roots_touched is None else roots_touched
        out_of_scope = (
            self.out_of_scope_paths if out_of_scope_paths is None else out_of_scope_paths
        )
        reached = self.limits_reached if limits_reached is None else limits_reached
        detail = None
        if self.detail_artifact is not None:
            detail = {
                "path": _canonical_path(
                    self.detail_artifact["path"], name="detail_artifact.path"
                ),
                "sha256": self.detail_artifact["sha256"].lower(),
            }
        return {
            "roots_touched": sorted(
                {_canonical_path(item, name="roots_touched item") for item in roots},
                key=str.casefold,
            ),
            "files_opened": self.files_opened,
            "archive_entries_examined": self.archive_entries_examined,
            "physical_bytes_read": self.physical_bytes_read,
            "provider_records_touched": self.provider_records_touched,
            "other_provider_records_touched": self.other_provider_records_touched,
            "out_of_scope_paths": sorted(
                {_canonical_path(item, name="out_of_scope_paths item") for item in out_of_scope},
                key=str.casefold,
            ),
            "response_bytes": self.response_bytes,
            "detail_artifact": detail,
            "scan_complete": self.scan_complete,
            "limits_reached": sorted(set(reached)),
        }


@dataclass(frozen=True, slots=True)
class ExactToolResponse:
    response: Any
    scope_receipt: Mapping[str, Any]
    schema_version: str = "kcd2.index-adapter-exact-response.v1"

    def to_dict(self) -> dict[str, Any]:
        return _canonical_json_copy(
            {
                "schema_version": self.schema_version,
                "response": self.response.to_dict(),
                "scope_receipt": dict(self.scope_receipt),
            },
            name="exact tool response",
        )

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True, slots=True)
class ScopeGuard:
    receipt_id: str
    operation: str
    requested_target: Mapping[str, Any]
    allowed_roots: Sequence[str]
    limits: ScopeLimits

    def __post_init__(self) -> None:
        if not isinstance(self.receipt_id, str) or _RECEIPT_ID.fullmatch(self.receipt_id) is None:
            raise TargetScopeReceiptError("receipt_id does not match target-scope-receipt-v1")
        if self.operation not in EXACT_OPERATIONS:
            raise TargetScopeReceiptError("operation is not a canonical exact operation")
        self._canonical_target()
        if isinstance(self.allowed_roots, (str, bytes)) or not isinstance(
            self.allowed_roots, Sequence
        ):
            raise TargetScopeReceiptError("allowed_roots must be an array")
        roots = tuple(
            _canonical_path(item, name="allowed_roots item") for item in self.allowed_roots
        )
        if len({root.casefold() for root in roots}) != len(roots):
            raise TargetScopeReceiptError("allowed_roots must be unique")
        provider_path = self._canonical_target()["provider_path"]
        if provider_path is not None:
            if provider_path.casefold() not in {root.casefold() for root in roots}:
                raise TargetScopeReceiptError(
                    "allowed_roots must contain the exact requested provider_path"
                )
            if any(
                root.casefold() != provider_path.casefold()
                and _path_is_within(provider_path, root)
                for root in roots
            ):
                raise TargetScopeReceiptError(
                    "allowed_roots must not widen the requested provider_path"
                )
        if not isinstance(self.limits, ScopeLimits):
            raise TargetScopeReceiptError("limits must be ScopeLimits")

    @classmethod
    def from_contract(cls, value: Mapping[str, object]) -> "ScopeGuard":
        expected = {
            "receipt_id",
            "operation",
            "requested_target",
            "declared_limits",
            "allowed_roots",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise TargetScopeReceiptError("scope contract fields do not match v1")
        target = value["requested_target"]
        limits = value["declared_limits"]
        roots = value["allowed_roots"]
        if not isinstance(target, Mapping) or not isinstance(limits, Mapping):
            raise TargetScopeReceiptError("scope contract target and limits must be objects")
        if isinstance(roots, (str, bytes)) or not isinstance(roots, Sequence):
            raise TargetScopeReceiptError("allowed_roots must be an array")
        return cls(
            receipt_id=value["receipt_id"],  # type: ignore[arg-type]
            operation=value["operation"],  # type: ignore[arg-type]
            requested_target=target,
            allowed_roots=roots,  # type: ignore[arg-type]
            limits=ScopeLimits.from_mapping(limits),
        )

    def _canonical_target(self) -> dict[str, Any]:
        allowed = {
            "mod_id",
            "provider_kind",
            "provider_path",
            "manifest_sha256",
            "pak_sha256s",
        }
        required = {"mod_id", "provider_kind"}
        if not isinstance(self.requested_target, Mapping):
            raise TargetScopeReceiptError("requested_target must be an object")
        if not required.issubset(self.requested_target) or not set(
            self.requested_target
        ).issubset(allowed):
            raise TargetScopeReceiptError("requested_target fields do not match v1")
        mod_id = self.requested_target["mod_id"]
        provider_kind = self.requested_target["provider_kind"]
        if not isinstance(mod_id, str) or not mod_id:
            raise TargetScopeReceiptError("requested_target.mod_id must not be empty")
        if provider_kind not in {"local", "workshop", "explicit_path", "unresolved"}:
            raise TargetScopeReceiptError("requested_target.provider_kind is invalid")
        provider_path = self.requested_target.get("provider_path")
        if provider_path is not None:
            provider_path = _canonical_path(provider_path, name="requested_target.provider_path")
        manifest = self.requested_target.get("manifest_sha256")
        if manifest is not None and (
            not isinstance(manifest, str) or _SHA256.fullmatch(manifest) is None
        ):
            raise TargetScopeReceiptError("requested_target.manifest_sha256 is invalid")
        paks = self.requested_target.get("pak_sha256s", [])
        if isinstance(paks, (str, bytes)) or not isinstance(paks, Sequence):
            raise TargetScopeReceiptError("requested_target.pak_sha256s must be an array")
        if any(not isinstance(item, str) or _SHA256.fullmatch(item) is None for item in paks):
            raise TargetScopeReceiptError("requested_target.pak_sha256s contains an invalid digest")
        lowered_paks = sorted({item.lower() for item in paks})
        if len(lowered_paks) != len(paks):
            raise TargetScopeReceiptError("requested_target.pak_sha256s must be unique")
        return {
            "mod_id": mod_id,
            "provider_kind": provider_kind,
            "provider_path": provider_path,
            "manifest_sha256": manifest.lower() if manifest is not None else None,
            "pak_sha256s": lowered_paks,
        }

    def _canonical_allowed_roots(self) -> list[str]:
        return sorted(
            {_canonical_path(item, name="allowed_roots item") for item in self.allowed_roots},
            key=str.casefold,
        )

    def emit(self, access: ScopeAccess) -> dict[str, Any]:
        """Evaluate observed access and emit a complete deterministic v1 receipt."""
        if not isinstance(access, ScopeAccess):
            raise TargetScopeReceiptError("access must be ScopeAccess")
        allowed_roots = self._canonical_allowed_roots()
        roots_touched = [
            _canonical_path(item, name="roots_touched item") for item in access.roots_touched
        ]
        leaked_roots = {
            root
            for root in roots_touched
            if not any(_path_is_within(root, allowed) for allowed in allowed_roots)
        }
        out_of_scope = {
            _canonical_path(item, name="out_of_scope_paths item")
            for item in access.out_of_scope_paths
        } | leaked_roots

        observed = {
            "files": (access.files_opened, self.limits.max_files),
            "archive_entries": (
                access.archive_entries_examined,
                self.limits.max_archive_entries,
            ),
            "physical_bytes": (access.physical_bytes_read, self.limits.max_physical_bytes),
            "response_bytes": (access.response_bytes, self.limits.max_response_bytes),
        }
        limits_reached = set(access.limits_reached)
        limits_reached.update(
            name for name, (actual, maximum) in observed.items() if actual > maximum
        )

        diagnostics: list[str] = []
        if leaked_roots:
            diagnostics.append("one or more touched roots are outside allowed_roots")
        if access.other_provider_records_touched:
            diagnostics.append("one or more records belong to another provider")
        if out_of_scope and not leaked_roots:
            diagnostics.append("one or more out-of-scope paths were reported")
        if limits_reached:
            diagnostics.append("one or more declared limits were reached")
        if not access.scan_complete:
            diagnostics.append("the exact scan did not complete")

        if out_of_scope or access.other_provider_records_touched:
            status: ScopeStatus = "TARGET_SCOPE_BREACH"
        elif limits_reached:
            status = "TARGET_SCOPE_LIMIT_REACHED"
        elif not access.scan_complete:
            status = "INCONCLUSIVE"
        else:
            status = "TARGET_SCOPE_OK"

        return {
            "schema_version": "kcd2.target-scope-receipt.v1",
            "receipt_id": self.receipt_id,
            "operation": self.operation,
            "requested_target": self._canonical_target(),
            "declared_limits": self.limits.to_dict(),
            "allowed_roots": allowed_roots,
            "actual_access": access.to_dict(
                roots_touched=roots_touched,
                out_of_scope_paths=tuple(out_of_scope),
                limits_reached=tuple(limits_reached),
            ),
            "status": status,
            "diagnostics": diagnostics,
        }

    def validate_receipt(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        expected = {
            "schema_version",
            "receipt_id",
            "operation",
            "requested_target",
            "declared_limits",
            "allowed_roots",
            "actual_access",
            "status",
            "diagnostics",
        }
        if not isinstance(receipt, Mapping) or set(receipt) != expected:
            raise TargetScopeReceiptError("scope_receipt fields do not match v1")
        if receipt["schema_version"] != "kcd2.target-scope-receipt.v1":
            raise TargetScopeReceiptError("scope_receipt schema_version is unsupported")
        declaration = {
            "receipt_id": receipt["receipt_id"],
            "operation": receipt["operation"],
            "requested_target": receipt["requested_target"],
            "declared_limits": receipt["declared_limits"],
            "allowed_roots": receipt["allowed_roots"],
        }
        returned_guard = ScopeGuard.from_contract(declaration)
        if (
            returned_guard.receipt_id != self.receipt_id
            or returned_guard.operation != self.operation
            or returned_guard._canonical_target() != self._canonical_target()
            or returned_guard.limits != self.limits
            or returned_guard._canonical_allowed_roots() != self._canonical_allowed_roots()
        ):
            raise TargetScopeReceiptError("scope_receipt declaration differs from the call guard")
        actual = receipt["actual_access"]
        if not isinstance(actual, Mapping):
            raise TargetScopeReceiptError("scope_receipt.actual_access must be an object")
        recomputed = self.emit(ScopeAccess.from_mapping(actual))
        if receipt["status"] != recomputed["status"]:
            raise TargetScopeReceiptError("scope_receipt status does not match observed access")
        diagnostics = receipt["diagnostics"]
        if isinstance(diagnostics, (str, bytes)) or not isinstance(diagnostics, Sequence):
            raise TargetScopeReceiptError("scope_receipt diagnostics must be an array")
        if any(not isinstance(item, str) for item in diagnostics):
            raise TargetScopeReceiptError("scope_receipt diagnostics must contain strings")
        return _canonical_json_copy(receipt, name="scope_receipt")

    def require_ok(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Validate a receipt and reject every status that cannot support an exact claim."""
        validated = self.validate_receipt(receipt)
        status = validated["status"]
        if status == "TARGET_SCOPE_BREACH":
            raise TargetScopeBreachError("exact operation crossed its declared target scope")
        if status == "TARGET_SCOPE_LIMIT_REACHED":
            raise TargetScopeLimitError("exact operation reached a declared limit")
        if status == "INCONCLUSIVE":
            raise TargetScopeInconclusiveError("exact operation did not complete")
        return validated
