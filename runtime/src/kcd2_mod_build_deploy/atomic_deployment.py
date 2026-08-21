"""Fail-closed candidate installation and receipt-driven rollback transactions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from kcd2_toolchain_core.approvals import ApprovalTarget, ApprovalVerifier

from .candidate_registry import (
    CandidateRecord,
    CandidateRegistry,
    InstalledArtifact,
)
from .deployment_registry import (
    DeploymentNode,
    DeploymentOperation,
    DeploymentRegistry,
    SnapshotGateDecision,
)
from .identity_types import (
    TypedIdentityError,
    artifact_id,
    canonical_build_output_id,
    installed_tree_id,
    typed_identity,
    validate_typed_identity,
)
from .package_validation import PackageValidationReport


MAX_TRANSACTION_FILES = 4096
MAX_TRANSACTION_BYTES = 16 * 1024 * 1024 * 1024
MAX_MOD_ORDER_BYTES = 4 * 1024 * 1024
MAX_BUILD_ATTESTATION_BYTES = 16 * 1024 * 1024
_TRANSACTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CANDIDATE_ID = re.compile(r"cand:sha256:[a-f0-9]{64}")
_DEPLOYMENT_ID = re.compile(r"deploy:sha256:[a-f0-9]{64}")
_SHA256 = re.compile(r"[a-f0-9]{64}")
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
_CONFLICT_KEYS = frozenset(
    {
        "schema_version",
        "coverage_id",
        "observed_conflict_count",
        "ignored_provider_metadata_count",
        "items",
        "conclusion",
        "absence_claim_valid",
        "reason_codes",
    }
)


class AtomicDeploymentError(RuntimeError):
    """A deployment gate or transactional restoration failed closed."""


class InstallBoundary(StrEnum):
    AFTER_BACKUP = "after_backup"
    AFTER_INCOMING_COPY = "after_incoming_copy"
    AFTER_TARGET_DISPLACEMENT = "after_target_displacement"
    AFTER_TARGET_SWAP = "after_target_swap"
    AFTER_MOD_ORDER_SWAP = "after_mod_order_swap"
    BEFORE_RECEIPT = "before_receipt"


@dataclass(frozen=True, slots=True)
class BuildAttestationReference:
    """One immutable, hash-bound receipt consumed by installation."""

    path: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class AcceptedBuildAttestations:
    """The accepted build evidence that installation must preserve exactly."""

    artifact_sha256: str
    build_receipt: BuildAttestationReference
    parent_diff_receipt: BuildAttestationReference
    package_validation_receipt: BuildAttestationReference
    xml_tbl_receipt: BuildAttestationReference
    packaging_profile_receipt: BuildAttestationReference


@dataclass(frozen=True, slots=True)
class InstallReceipt:
    transaction_id: str
    candidate_id: str
    deployment_id: str
    target_folder_name: str
    mods_root: Path
    receipt_path: Path
    backup_target_path: Path
    backup_mod_order_path: Path
    target_existed: bool
    original_target_tree_sha256: str | None
    installed_tree_sha256: str
    mod_order_before_sha256: str
    mod_order_after_sha256: str
    conflict_report_sha256: str
    original_target_files: tuple[Mapping[str, Any], ...]
    installed_target_files: tuple[Mapping[str, Any], ...]
    mod_order_before_bytes: int
    mod_order_after_bytes: int
    candidate_parent_id: str | None
    candidate_parent_artifact_sha256: str | None
    candidate_artifacts: tuple[Mapping[str, Any], ...]
    manifest_sha256: str
    semantic_validation: Mapping[str, Any]
    conflict_validation: Mapping[str, Any]
    completed_at: datetime
    accepted_build_attestations: Mapping[str, Any] | None = None
    status: str = "installed"

    def to_dict(self) -> dict[str, Any]:
        attested = self.accepted_build_attestations is not None
        typed_attested = bool(
            attested
            and isinstance(self.accepted_build_attestations, Mapping)
            and isinstance(
                self.accepted_build_attestations.get("verified_claims"), Mapping
            )
            and "build_output_id"
            in self.accepted_build_attestations["verified_claims"]
        )
        payload = {
            "schema_version": (
                "kcd2.install-receipt.v3"
                if typed_attested
                else (
                    "kcd2.install-receipt.v2"
                    if attested
                    else "kcd2.install-receipt.v1"
                )
            ),
            "status": self.status,
            "transaction_id": self.transaction_id,
            (
                "registry_candidate_id" if typed_attested else "candidate_id"
            ): self.candidate_id,
            "deployment_id": self.deployment_id,
            "target_folder_name": self.target_folder_name,
            "mods_root": str(self.mods_root),
            "receipt_path": str(self.receipt_path),
            "backup_target_path": str(self.backup_target_path),
            "backup_mod_order_path": str(self.backup_mod_order_path),
            "target_existed": self.target_existed,
            "original_target_tree_sha256": self.original_target_tree_sha256,
            "installed_tree_sha256": self.installed_tree_sha256,
            "mod_order_before_sha256": self.mod_order_before_sha256,
            "mod_order_after_sha256": self.mod_order_after_sha256,
            "conflict_report_sha256": self.conflict_report_sha256,
            "mod_order_path": "mods/mod_order.txt",
            "byte_state": {
                "before": {
                    "mod_order": {
                        "bytes": self.mod_order_before_bytes,
                        "path": "mods/mod_order.txt",
                        "sha256": self.mod_order_before_sha256,
                    },
                    "target": list(self.original_target_files),
                    "target_file_ledger_sha256": _byte_ledger_sha256(
                        self.original_target_files
                    ),
                    "target_tree_sha256": self.original_target_tree_sha256,
                },
                "after": {
                    "mod_order": {
                        "bytes": self.mod_order_after_bytes,
                        "path": "mods/mod_order.txt",
                        "sha256": self.mod_order_after_sha256,
                    },
                    "target": list(self.installed_target_files),
                    "target_file_ledger_sha256": _byte_ledger_sha256(
                        self.installed_target_files
                    ),
                    "target_tree_sha256": self.installed_tree_sha256,
                },
            },
            "parent": {
                "artifact_sha256": self.candidate_parent_artifact_sha256,
                (
                    "registry_candidate_id" if typed_attested else "candidate_id"
                ): self.candidate_parent_id,
            },
            "candidate_artifacts": list(self.candidate_artifacts),
            "manifest_sha256": self.manifest_sha256,
            "manifest_artifacts": [
                dict(item)
                for item in self.candidate_artifacts
                if item["role"] == "manifest"
            ],
            "localization_artifacts": [
                dict(item)
                for item in self.candidate_artifacts
                if item["role"] == "localization_pak"
                or PurePosixPath(item["logical_path"]).parts[0].casefold()
                == "localization"
            ],
            "semantic_validation": dict(self.semantic_validation),
            "conflict_validation": dict(self.conflict_validation),
            "completed_at": self.completed_at.isoformat().replace("+00:00", "Z"),
        }
        if attested:
            attestations = dict(self.accepted_build_attestations)
            payload["accepted_build_attestations"] = attestations
            payload["build_attestation_bundle_sha256"] = _json_sha256(attestations)
        if typed_attested:
            payload["identities"] = {
                "build_output_id": attestations["verified_claims"]["build_output_id"],
                "artifact_id": artifact_id(attestations["artifact_sha256"]),
                "registry_candidate_id": self.candidate_id,
                "deployment_id": self.deployment_id,
                "installed_tree_id": installed_tree_id(self.installed_tree_sha256),
            }
        return payload

    @property
    def registry_candidate_id(self) -> str:
        """Explicit name for the registry identity retained by the legacy API."""
        return self.candidate_id


@dataclass(frozen=True, slots=True)
class RollbackReceipt:
    transaction_id: str
    candidate_id: str
    deployment_id: str
    receipt_path: Path
    restored_target_tree_sha256: str | None
    restored_mod_order_sha256: str
    restored_byte_state: Mapping[str, Any]
    rollback_from_byte_state: Mapping[str, Any]
    completed_at: datetime
    source_identities: Mapping[str, str] | None = None
    status: str = "rolled_back"

    def to_dict(self) -> dict[str, Any]:
        typed = self.source_identities is not None
        payload = {
            "schema_version": (
                "kcd2.rollback-receipt.v2" if typed else "kcd2.rollback-receipt.v1"
            ),
            "status": self.status,
            "transaction_id": self.transaction_id,
            (
                "registry_candidate_id" if typed else "candidate_id"
            ): self.candidate_id,
            "deployment_id": self.deployment_id,
            "receipt_path": str(self.receipt_path),
            "restored_target_tree_sha256": self.restored_target_tree_sha256,
            "restored_mod_order_sha256": self.restored_mod_order_sha256,
            "mod_order_path": "mods/mod_order.txt",
            "exact_bytes_restored": True,
            "rollback_from_byte_state": dict(self.rollback_from_byte_state),
            "restored_byte_state": dict(self.restored_byte_state),
            "completed_at": self.completed_at.isoformat().replace("+00:00", "Z"),
        }
        if typed:
            payload["identities"] = dict(self.source_identities)
        return payload

    @property
    def registry_candidate_id(self) -> str:
        """Explicit name for the registry identity retained by the legacy API."""
        return self.candidate_id


def _install_receipt_identities(receipt: InstallReceipt) -> dict[str, str] | None:
    attestations = receipt.accepted_build_attestations
    if not isinstance(attestations, Mapping):
        return None
    claims = attestations.get("verified_claims")
    if not isinstance(claims, Mapping) or "build_output_id" not in claims:
        return None
    return {
        "build_output_id": validate_typed_identity(
            claims["build_output_id"], "build-output"
        ),
        "artifact_id": artifact_id(attestations["artifact_sha256"]),
        "registry_candidate_id": receipt.registry_candidate_id,
        "deployment_id": receipt.deployment_id,
        "installed_tree_id": installed_tree_id(receipt.installed_tree_sha256),
    }


@dataclass(frozen=True, slots=True)
class _InstallContext:
    candidate: CandidateRecord
    candidate_registry: CandidateRegistry
    source: Path
    mods_root: Path
    backup_root: Path
    target: Path
    mod_order: Path
    transaction: Path
    conflict_report_sha256: str
    conflict_validation: Mapping[str, Any]
    semantic_validation: Mapping[str, Any]
    accepted_build_attestations: Mapping[str, Any]
    evaluated_at: datetime


def _install_candidate_impl(
    *,
    candidate_id: str,
    candidate_source: Path | str,
    mods_root: Path | str,
    backup_root: Path | str,
    candidate_registry: CandidateRegistry,
    deployment_registry: DeploymentRegistry,
    deployment_id: str,
    snapshot_decision: SnapshotGateDecision,
    package_report: PackageValidationReport,
    conflict_report: Mapping[str, Any],
    evaluated_at: datetime,
    transaction_id: str,
    build_attestations: AcceptedBuildAttestations,
    failure_inject_at: InstallBoundary | str | None = None,
) -> InstallReceipt:
    """Install one registered candidate or restore exact original bytes on any failure."""

    boundary = _coerce_install_boundary(failure_inject_at)
    context = _preflight_install(
        candidate_id=candidate_id,
        candidate_source=candidate_source,
        mods_root=mods_root,
        backup_root=backup_root,
        candidate_registry=candidate_registry,
        deployment_registry=deployment_registry,
        deployment_id=deployment_id,
        snapshot_decision=snapshot_decision,
        package_report=package_report,
        conflict_report=conflict_report,
        evaluated_at=evaluated_at,
        transaction_id=transaction_id,
        build_attestations=build_attestations,
    )
    node = deployment_registry.get(deployment_id)
    assert node is not None

    original_order = context.mod_order.read_bytes()
    order_before_sha256 = _sha256_bytes(original_order)
    if (
        len(original_order) != node.identity.mod_order.bytes
        or order_before_sha256 != node.identity.mod_order.sha256
    ):
        raise AtomicDeploymentError("mod_order identity drifted after install preflight")
    updated_order = _ensure_exactly_one_order_entry(
        original_order, context.candidate.identity.mod_id
    )
    if len(updated_order) > MAX_MOD_ORDER_BYTES:
        raise AtomicDeploymentError("updated mod_order exceeds the fixed byte bound")
    order_after_sha256 = _sha256_bytes(updated_order)
    target_existed = context.target.exists()
    original_tree_sha256 = _tree_sha256(context.target) if target_existed else None
    original_target_files = (
        tuple(_tree_byte_state(context.target)) if target_existed else ()
    )
    backup_dir = context.transaction / "backup"
    backup_target = backup_dir / "target"
    backup_order = backup_dir / "mod_order.txt"
    staged_target = context.transaction / "incoming" / context.target.name
    receipt_path = context.transaction / "install-receipt.json"
    backup_verified = False
    target_mutated = False
    order_mutated = False

    try:
        context.transaction.mkdir()
    except OSError as exc:
        raise AtomicDeploymentError("backup transaction could not be created exclusively") from exc
    try:
        backup_dir.mkdir()
        _atomic_json_write(
            context.transaction / "accepted-build-attestations.json",
            context.accepted_build_attestations,
        )
        _write_new_file(backup_order, original_order)
        if target_existed:
            _copy_verified_tree(context.target, backup_target)
            if _tree_sha256(backup_target) != original_tree_sha256:
                raise AtomicDeploymentError("target-folder backup verification failed")
        if _sha256_file(backup_order) != order_before_sha256:
            raise AtomicDeploymentError("mod_order backup verification failed")
        backup_verified = True
        _inject(boundary, InstallBoundary.AFTER_BACKUP)

        staged_target.parent.mkdir()
        _copy_verified_tree(context.source, staged_target)
        installed_tree_sha256 = _tree_sha256(staged_target)
        installed_target_files = tuple(_tree_byte_state(staged_target))
        _verify_candidate_source(
            context.candidate_registry, context.candidate, staged_target, node
        )
        _inject(boundary, InstallBoundary.AFTER_INCOMING_COPY)

        target_mutated = True
        if context.target.exists():
            _remove_tree(context.target, context.mods_root)
        _inject(boundary, InstallBoundary.AFTER_TARGET_DISPLACEMENT)

        os.replace(staged_target, context.target)
        _inject(boundary, InstallBoundary.AFTER_TARGET_SWAP)

        order_mutated = True
        _atomic_write_bytes(context.mod_order, updated_order, transaction_id)
        _inject(boundary, InstallBoundary.AFTER_MOD_ORDER_SWAP)

        if _tree_sha256(context.target) != installed_tree_sha256:
            raise AtomicDeploymentError("installed target tree differs from staged candidate")
        _verify_exactly_one_order_entry(
            context.mod_order.read_bytes(), context.candidate.identity.mod_id
        )
        _inject(boundary, InstallBoundary.BEFORE_RECEIPT)

        receipt = InstallReceipt(
            transaction_id=transaction_id,
            candidate_id=candidate_id,
            deployment_id=deployment_id,
            target_folder_name=context.target.name,
            mods_root=context.mods_root,
            receipt_path=receipt_path,
            backup_target_path=backup_target,
            backup_mod_order_path=backup_order,
            target_existed=target_existed,
            original_target_tree_sha256=original_tree_sha256,
            installed_tree_sha256=installed_tree_sha256,
            mod_order_before_sha256=order_before_sha256,
            mod_order_after_sha256=order_after_sha256,
            conflict_report_sha256=context.conflict_report_sha256,
            original_target_files=original_target_files,
            installed_target_files=installed_target_files,
            mod_order_before_bytes=len(original_order),
            mod_order_after_bytes=len(updated_order),
            candidate_parent_id=context.candidate.identity.parent_candidate_id,
            candidate_parent_artifact_sha256=(
                context.candidate.identity.parent_artifact_sha256
            ),
            candidate_artifacts=tuple(
                artifact.identity_payload()
                for artifact in sorted(
                    context.candidate.identity.artifacts,
                    key=lambda item: item.logical_path.encode("utf-8"),
                )
            ),
            manifest_sha256=context.candidate.identity.manifest_sha256,
            semantic_validation=context.semantic_validation,
            conflict_validation=context.conflict_validation,
            completed_at=context.evaluated_at,
            accepted_build_attestations=context.accepted_build_attestations,
        )
        _atomic_json_write(receipt_path, receipt.to_dict())
        return receipt
    except Exception as exc:
        try:
            _restore_install_original(
                context=context,
                target_existed=target_existed,
                backup_target=backup_target,
                original_tree_sha256=original_tree_sha256,
                original_order=original_order,
                order_before_sha256=order_before_sha256,
                transaction_id=transaction_id,
                backup_verified=backup_verified,
                target_mutated=target_mutated,
                order_mutated=order_mutated,
            )
            failure = {
                "schema_version": "kcd2.install-failure-receipt.v1",
                "status": "rolled_back_after_install_failure",
                "transaction_id": transaction_id,
                "candidate_id": candidate_id,
                "deployment_id": deployment_id,
                "failure_boundary": boundary.value if boundary is not None else None,
                "restored_target_tree_sha256": original_tree_sha256,
                "restored_mod_order_sha256": order_before_sha256,
            }
            _atomic_json_write(context.transaction / "failure-receipt.json", failure)
        except Exception as restore_exc:
            raise AtomicDeploymentError(
                "install failed and exact automatic restoration also failed"
            ) from restore_exc
        if isinstance(exc, AtomicDeploymentError):
            raise
        raise AtomicDeploymentError(f"install transaction failed: {exc}") from exc


def _rollback_install_impl(
    install_receipt_path: Path | str,
    *,
    mods_root: Path | str,
    backup_root: Path | str,
    evaluated_at: datetime,
) -> RollbackReceipt:
    """Restore exact pre-install folder and load-order bytes from one persisted receipt."""

    checked_at = _timestamp(evaluated_at, "evaluated_at")
    checked_mods = _existing_plain_directory(mods_root, "mods_root")
    checked_backups = _existing_plain_directory(backup_root, "backup_root")
    if (
        checked_backups == checked_mods
        or _is_within(checked_backups, checked_mods)
        or _is_within(checked_mods, checked_backups)
    ):
        raise AtomicDeploymentError("backup_root must be outside mods_root")
    receipt_path = Path(install_receipt_path).resolve(strict=True)
    document = _read_receipt_document(receipt_path)
    receipt = _receipt_from_document(document)
    if receipt.receipt_path != receipt_path:
        raise AtomicDeploymentError("install receipt self-path binding is invalid")
    transaction = checked_backups / receipt.transaction_id
    if receipt_path != transaction / "install-receipt.json":
        raise AtomicDeploymentError("install receipt is not at its bound backup transaction path")
    if receipt.mods_root != checked_mods:
        raise AtomicDeploymentError("install receipt is bound to a different mods_root")
    target = _target_child(checked_mods, receipt.target_folder_name)
    mod_order = checked_mods / "mod_order.txt"
    if receipt.backup_target_path != transaction / "backup" / "target":
        raise AtomicDeploymentError("receipt target backup path is not transaction-bound")
    if receipt.backup_mod_order_path != transaction / "backup" / "mod_order.txt":
        raise AtomicDeploymentError("receipt mod_order backup path is not transaction-bound")
    if not target.is_dir() or _tree_sha256(target) != receipt.installed_tree_sha256:
        raise AtomicDeploymentError("installed target drift blocks receipt rollback")
    _require_plain_file(mod_order, "mod_order.txt", MAX_MOD_ORDER_BYTES)
    if _sha256_file(mod_order) != receipt.mod_order_after_sha256:
        raise AtomicDeploymentError("mod_order drift blocks receipt rollback")
    _require_plain_file(receipt.backup_mod_order_path, "backup mod_order", MAX_MOD_ORDER_BYTES)
    original_order = receipt.backup_mod_order_path.read_bytes()
    if _sha256_bytes(original_order) != receipt.mod_order_before_sha256:
        raise AtomicDeploymentError("receipt mod_order backup hash is invalid")
    if receipt.target_existed:
        if (
            not receipt.backup_target_path.is_dir()
            or _tree_sha256(receipt.backup_target_path)
            != receipt.original_target_tree_sha256
        ):
            raise AtomicDeploymentError("receipt target backup identity is invalid")
    elif receipt.backup_target_path.exists():
        raise AtomicDeploymentError("receipt claims absent target but contains a target backup")

    rollback_work = transaction / "rollback-current"
    rollback_receipt_path = transaction / "rollback-receipt.json"
    if rollback_work.exists() or rollback_receipt_path.exists():
        raise AtomicDeploymentError("this install receipt already has rollback state")
    current_target = rollback_work / "target"
    current_order = rollback_work / "mod_order.txt"
    current_order_bytes = mod_order.read_bytes()
    try:
        rollback_work.mkdir()
        _copy_verified_tree(target, current_target)
        _write_new_file(current_order, current_order_bytes)
        if (
            _tree_sha256(current_target) != receipt.installed_tree_sha256
            or _sha256_file(current_order) != receipt.mod_order_after_sha256
        ):
            raise AtomicDeploymentError("rollback recovery backup verification failed")
    except Exception as exc:
        if rollback_work.exists():
            _remove_tree(rollback_work, transaction)
        if isinstance(exc, AtomicDeploymentError):
            raise
        raise AtomicDeploymentError("rollback recovery backup could not be prepared") from exc

    try:
        _remove_tree(target, checked_mods)
        if receipt.target_existed:
            _copy_verified_tree(receipt.backup_target_path, target)
        _atomic_write_bytes(mod_order, original_order, receipt.transaction_id + "-rollback")
        restored_tree = _tree_sha256(target) if receipt.target_existed else None
        if restored_tree != receipt.original_target_tree_sha256:
            raise AtomicDeploymentError("rollback target verification failed")
        if _sha256_file(mod_order) != receipt.mod_order_before_sha256:
            raise AtomicDeploymentError("rollback mod_order verification failed")
        restored_byte_state = _receipt_byte_state(receipt, "before")
        observed_target_files = (
            _tree_byte_state(target) if receipt.target_existed else []
        )
        observed_restored = {
            "mod_order": {
                "bytes": mod_order.stat().st_size,
                "path": "mods/mod_order.txt",
                "sha256": _sha256_file(mod_order),
            },
            "target": observed_target_files,
            "target_file_ledger_sha256": _byte_ledger_sha256(observed_target_files),
            "target_tree_sha256": restored_tree,
        }
        if observed_restored != restored_byte_state:
            raise AtomicDeploymentError("rollback byte-level state verification failed")
        rollback = RollbackReceipt(
            transaction_id=receipt.transaction_id,
            candidate_id=receipt.candidate_id,
            deployment_id=receipt.deployment_id,
            receipt_path=rollback_receipt_path,
            restored_target_tree_sha256=restored_tree,
            restored_mod_order_sha256=receipt.mod_order_before_sha256,
            restored_byte_state=restored_byte_state,
            rollback_from_byte_state=_receipt_byte_state(receipt, "after"),
            completed_at=checked_at,
            source_identities=_install_receipt_identities(receipt),
        )
        _atomic_json_write(rollback_receipt_path, rollback.to_dict())
        return rollback
    except Exception as exc:
        try:
            if target.exists():
                _remove_tree(target, checked_mods)
            _copy_verified_tree(current_target, target)
            _atomic_write_bytes(
                mod_order,
                current_order_bytes,
                receipt.transaction_id + "-rollback-recovery",
            )
        except Exception as restore_exc:
            raise AtomicDeploymentError(
                "rollback failed and the installed state could not be restored"
            ) from restore_exc
        if isinstance(exc, AtomicDeploymentError):
            raise
        raise AtomicDeploymentError(f"rollback transaction failed: {exc}") from exc


def _install_candidate_approval_targets(context: _InstallContext) -> tuple[ApprovalTarget, ...]:
    """Bind source, destination, load order, and exclusive backup transaction."""
    original_order = context.mod_order.read_bytes()
    updated_order = _ensure_exactly_one_order_entry(
        original_order, context.candidate.identity.mod_id
    )
    targets = (
        ApprovalTarget.from_paths(
            role="candidate_source", path=context.source, proposed_path=context.source
        ),
        ApprovalTarget.from_paths(
            role="installed_mod_folder", path=context.target, proposed_path=context.source
        ),
        ApprovalTarget.from_bytes(
            role="mod_order", path=context.mod_order, proposed_bytes=updated_order
        ),
        ApprovalTarget.from_payload(
            role="backup_transaction",
            path=context.transaction,
            proposed_payload={"transaction_id": context.transaction.name},
        ),
    )
    targets += (
        ApprovalTarget.from_payload(
            role="accepted_build_attestations",
            path=context.transaction / "accepted-build-attestations.json",
            proposed_payload=context.accepted_build_attestations,
        ),
    )
    return targets


def plan_install_candidate_approval_targets(
    *,
    candidate_id: str,
    candidate_source: Path | str,
    mods_root: Path | str,
    backup_root: Path | str,
    candidate_registry: CandidateRegistry,
    deployment_registry: DeploymentRegistry,
    deployment_id: str,
    snapshot_decision: SnapshotGateDecision,
    package_report: PackageValidationReport,
    conflict_report: Mapping[str, Any],
    evaluated_at: datetime,
    transaction_id: str,
    build_attestations: AcceptedBuildAttestations,
) -> tuple[ApprovalTarget, ...]:
    """Perform read-only preflight and return the exact install approval bindings."""
    context = _preflight_install(
        candidate_id=candidate_id,
        candidate_source=candidate_source,
        mods_root=mods_root,
        backup_root=backup_root,
        candidate_registry=candidate_registry,
        deployment_registry=deployment_registry,
        deployment_id=deployment_id,
        snapshot_decision=snapshot_decision,
        package_report=package_report,
        conflict_report=conflict_report,
        evaluated_at=evaluated_at,
        transaction_id=transaction_id,
        build_attestations=build_attestations,
    )
    return _install_candidate_approval_targets(context)


def install_candidate_atomic(
    *,
    candidate_id: str,
    candidate_source: Path | str,
    mods_root: Path | str,
    backup_root: Path | str,
    candidate_registry: CandidateRegistry,
    deployment_registry: DeploymentRegistry,
    deployment_id: str,
    snapshot_decision: SnapshotGateDecision,
    package_report: PackageValidationReport,
    conflict_report: Mapping[str, Any],
    evaluated_at: datetime,
    transaction_id: str,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
    build_attestations: AcceptedBuildAttestations,
    failure_inject_at: InstallBoundary | str | None = None,
) -> InstallReceipt:
    context = _preflight_install(
        candidate_id=candidate_id,
        candidate_source=candidate_source,
        mods_root=mods_root,
        backup_root=backup_root,
        candidate_registry=candidate_registry,
        deployment_registry=deployment_registry,
        deployment_id=deployment_id,
        snapshot_decision=snapshot_decision,
        package_report=package_report,
        conflict_report=conflict_report,
        evaluated_at=evaluated_at,
        transaction_id=transaction_id,
        build_attestations=build_attestations,
    )
    targets = _install_candidate_approval_targets(context)
    return approval_verifier.execute(
        approval,
        operation="install_candidate",
        targets=targets,
        mutation=lambda: _install_candidate_impl(
            candidate_id=candidate_id,
            candidate_source=candidate_source,
            mods_root=mods_root,
            backup_root=backup_root,
            candidate_registry=candidate_registry,
            deployment_registry=deployment_registry,
            deployment_id=deployment_id,
            snapshot_decision=snapshot_decision,
            package_report=package_report,
            conflict_report=conflict_report,
            evaluated_at=evaluated_at,
            transaction_id=transaction_id,
            build_attestations=build_attestations,
            failure_inject_at=failure_inject_at,
        ),
    )


def rollback_install_approval_targets(
    install_receipt_path: Path | str,
    *,
    mods_root: Path | str,
) -> tuple[ApprovalTarget, ...]:
    receipt_path = Path(install_receipt_path).resolve(strict=True)
    receipt = _receipt_from_document(_read_receipt_document(receipt_path))
    checked_mods = Path(mods_root).resolve(strict=True)
    target = _target_child(checked_mods, receipt.target_folder_name)
    proposed_target = receipt.backup_target_path if receipt.target_existed else None
    return (
        ApprovalTarget.from_paths(
            role="install_receipt", path=receipt_path, proposed_path=receipt_path
        ),
        ApprovalTarget.from_paths(
            role="installed_mod_folder", path=target, proposed_path=proposed_target
        ),
        ApprovalTarget.from_paths(
            role="mod_order",
            path=checked_mods / "mod_order.txt",
            proposed_path=receipt.backup_mod_order_path,
        ),
        ApprovalTarget.from_payload(
            role="rollback_receipt",
            path=receipt_path.parent / "rollback-receipt.json",
            proposed_payload={"transaction_id": receipt.transaction_id},
        ),
    )


def rollback_install_atomic(
    install_receipt_path: Path | str,
    *,
    mods_root: Path | str,
    backup_root: Path | str,
    evaluated_at: datetime,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
) -> RollbackReceipt:
    targets = rollback_install_approval_targets(
        install_receipt_path, mods_root=mods_root
    )
    return approval_verifier.execute(
        approval,
        operation="rollback",
        targets=targets,
        mutation=lambda: _rollback_install_impl(
            install_receipt_path,
            mods_root=mods_root,
            backup_root=backup_root,
            evaluated_at=evaluated_at,
        ),
    )


def _preflight_install(
    *,
    candidate_id: str,
    candidate_source: Path | str,
    mods_root: Path | str,
    backup_root: Path | str,
    candidate_registry: CandidateRegistry,
    deployment_registry: DeploymentRegistry,
    deployment_id: str,
    snapshot_decision: SnapshotGateDecision,
    package_report: PackageValidationReport,
    conflict_report: Mapping[str, Any],
    evaluated_at: datetime,
    transaction_id: str,
    build_attestations: AcceptedBuildAttestations,
) -> _InstallContext:
    if not isinstance(transaction_id, str) or _TRANSACTION_ID.fullmatch(transaction_id) is None:
        raise AtomicDeploymentError("transaction_id must be one bounded path component")
    if not isinstance(candidate_registry, CandidateRegistry):
        raise AtomicDeploymentError("candidate_registry is invalid")
    if not isinstance(deployment_registry, DeploymentRegistry):
        raise AtomicDeploymentError("deployment_registry is invalid")
    if deployment_registry.candidates != candidate_registry:
        raise AtomicDeploymentError("deployment and install candidate registries differ")
    if not isinstance(candidate_id, str) or _CANDIDATE_ID.fullmatch(candidate_id) is None:
        raise AtomicDeploymentError("candidate_id is invalid")
    candidate = next(
        (item for item in candidate_registry.records if item.candidate_id == candidate_id), None
    )
    if candidate is None:
        raise AtomicDeploymentError("candidate is not a known lineage node")
    if not isinstance(deployment_id, str) or _DEPLOYMENT_ID.fullmatch(deployment_id) is None:
        raise AtomicDeploymentError("deployment_id is invalid")
    node = deployment_registry.get(deployment_id)
    if node is None or node.candidate_id != candidate_id:
        raise AtomicDeploymentError("deployment does not bind the selected lineage node")
    if not isinstance(snapshot_decision, SnapshotGateDecision):
        raise AtomicDeploymentError("snapshot_decision is invalid")
    if (
        not snapshot_decision.authorizes(DeploymentOperation.INSTALL_VALIDATION)
        or snapshot_decision.deployment_id != deployment_id
        or snapshot_decision.snapshot_id != node.snapshot_id
        or snapshot_decision.snapshot_sha256 != node.snapshot_sha256
    ):
        raise AtomicDeploymentError(
            "fresh exact deployment/snapshot gate did not authorize install"
        )
    if not isinstance(package_report, PackageValidationReport):
        raise AtomicDeploymentError("package_report is invalid")
    if (
        not package_report.overall_static_readiness
        or package_report.structural_integrity != "VALID"
        or package_report.package_promotion == "BLOCKED"
        or package_report.artifact_sha256 != node.identity.target_pak.sha256
    ):
        raise AtomicDeploymentError("package gate did not authorize install")
    accepted_build_attestations = _authorize_build_attestations(
        build_attestations,
        package_report=package_report,
    )
    checked_at = _timestamp(evaluated_at, "evaluated_at")
    conflict_hash, conflict_validation = _authorize_conflict_report(conflict_report)

    source = _existing_plain_directory(candidate_source, "candidate_source")
    checked_mods = _existing_plain_directory(mods_root, "mods_root")
    checked_backups = _existing_plain_directory(backup_root, "backup_root")
    if (
        checked_backups == checked_mods
        or _is_within(checked_backups, checked_mods)
        or _is_within(checked_mods, checked_backups)
    ):
        raise AtomicDeploymentError("backup_root must be outside mods_root")
    target = _target_child(checked_mods, candidate.identity.folder_name_exact)
    if source == target:
        raise AtomicDeploymentError("candidate_source must not be the active target folder")
    if _is_within(source, checked_mods):
        raise AtomicDeploymentError("candidate_source must be outside mods_root")
    if source.name != candidate.identity.folder_name_exact:
        raise AtomicDeploymentError("candidate_source folder case differs from candidate identity")
    transaction = checked_backups / transaction_id
    if transaction.exists() or transaction.is_symlink():
        raise AtomicDeploymentError("backup transaction path already exists")
    mod_order = checked_mods / "mod_order.txt"
    _require_plain_file(mod_order, "mod_order.txt", MAX_MOD_ORDER_BYTES)
    if (
        mod_order.stat().st_size != node.identity.mod_order.bytes
        or _sha256_file(mod_order) != node.identity.mod_order.sha256
    ):
        raise AtomicDeploymentError(
            "mods/mod_order.txt identity drifted after the exact snapshot"
        )
    if node.identity.mod_order.path != "mods/mod_order.txt":
        raise AtomicDeploymentError(
            "deployment load-order path must be exactly mods/mod_order.txt"
        )
    _verify_candidate_source(candidate_registry, candidate, source, node)
    if target.exists():
        if not target.is_dir() or _is_reparse(target):
            raise AtomicDeploymentError("target mod folder is not a plain directory")
        _tree_sha256(target)
    return _InstallContext(
        candidate=candidate,
        candidate_registry=candidate_registry,
        source=source,
        mods_root=checked_mods,
        backup_root=checked_backups,
        target=target,
        mod_order=mod_order,
        transaction=transaction,
        conflict_report_sha256=conflict_hash,
        conflict_validation=conflict_validation,
        semantic_validation=package_report.to_dict(),
        accepted_build_attestations=accepted_build_attestations,
        evaluated_at=checked_at,
    )


def _authorize_conflict_report(
    report: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    if not isinstance(report, Mapping):
        raise AtomicDeploymentError("conflict_report is invalid")
    try:
        detached = json.loads(
            json.dumps(report, allow_nan=False, ensure_ascii=False, sort_keys=True)
        )
    except (TypeError, ValueError) as exc:
        raise AtomicDeploymentError("conflict_report is not detached JSON data") from exc
    if set(detached) != _CONFLICT_KEYS:
        raise AtomicDeploymentError("conflict_report fields differ from the reviewed draft")
    if detached["schema_version"] != "kcd2.conflict-classification.v1":
        raise AtomicDeploymentError("unsupported conflict_report schema_version")
    if not isinstance(detached["coverage_id"], str) or not 1 <= len(
        detached["coverage_id"]
    ) <= 512:
        raise AtomicDeploymentError("conflict_report coverage_id is invalid")
    if (
        not isinstance(detached["observed_conflict_count"], int)
        or isinstance(detached["observed_conflict_count"], bool)
        or detached["observed_conflict_count"] != 0
        or not isinstance(detached["ignored_provider_metadata_count"], int)
        or isinstance(detached["ignored_provider_metadata_count"], bool)
        or detached["ignored_provider_metadata_count"] < 0
        or detached["ignored_provider_metadata_count"] > 4096
        or detached["conclusion"] != "CONFIRMED_NONE"
        or detached["absence_claim_valid"] is not True
        or detached["reason_codes"] != []
    ):
        raise AtomicDeploymentError("conflict gate did not prove complete conflict absence")
    items = detached["items"]
    if not isinstance(items, list) or len(items) > 4096:
        raise AtomicDeploymentError("conflict_report items are invalid")
    for item in items:
        required = {"path", "classification", "providers"}
        if not isinstance(item, dict) or set(item) != required:
            raise AtomicDeploymentError("conflict_report item fields are invalid")
        if item["classification"] != "PROVIDER_METADATA_NO_CONFLICT":
            raise AtomicDeploymentError("conflict_report contains a non-benign item")
        if not isinstance(item["path"], str) or not 1 <= len(item["path"]) <= 2048:
            raise AtomicDeploymentError("conflict_report item path is invalid")
        providers = item["providers"]
        if not isinstance(providers, list) or len(providers) > 256 or any(
            not isinstance(value, str) or not 1 <= len(value) <= 512 for value in providers
        ):
            raise AtomicDeploymentError("conflict_report providers are invalid")
    encoded = json.dumps(
        detached, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return _sha256_bytes(encoded), detached


def _authorize_build_attestations(
    bundle: AcceptedBuildAttestations,
    *,
    package_report: PackageValidationReport,
) -> dict[str, Any]:
    """Verify accepted build receipts and preserve their strongest package claim."""
    if not isinstance(bundle, AcceptedBuildAttestations):
        raise AtomicDeploymentError("accepted build attestations are required")
    artifact_sha256 = _digest(bundle.artifact_sha256, "build attestation artifact")
    if artifact_sha256 != package_report.artifact_sha256:
        raise AtomicDeploymentError(
            "build attestation artifact differs from package validation"
        )

    references = {
        "build_receipt": bundle.build_receipt,
        "parent_diff_receipt": bundle.parent_diff_receipt,
        "package_validation_receipt": bundle.package_validation_receipt,
        "xml_tbl_receipt": bundle.xml_tbl_receipt,
        "packaging_profile_receipt": bundle.packaging_profile_receipt,
    }
    documents: dict[str, dict[str, Any]] = {}
    normalized: dict[str, dict[str, Any]] = {}
    for role, reference in references.items():
        if not isinstance(reference, BuildAttestationReference):
            raise AtomicDeploymentError(f"{role} reference is invalid")
        expected_sha256 = _digest(reference.sha256, f"{role} SHA-256")
        path = _require_attestation_file(reference.path, role)
        document, observed_sha256 = _read_bounded_json(path, role)
        if observed_sha256 != expected_sha256:
            raise AtomicDeploymentError(f"{role} hash differs from accepted evidence")
        schema_version = document.get("schema_version")
        if not isinstance(schema_version, str) or not schema_version:
            raise AtomicDeploymentError(f"{role} schema_version is invalid")
        documents[role] = document
        normalized[role] = {
            "path": str(path),
            "sha256": observed_sha256,
            "schema_version": schema_version,
        }

    build = documents["build_receipt"]
    build_schema = build.get("schema_version")
    if build_schema not in {
        "kcd2.candidate-build-receipt.v1",
        "kcd2.candidate-build-receipt.v2",
        "kcd2.double-build-receipt.v1",
        "kcd2.double-build-receipt.v2",
    } or build.get("status") != "PASS":
        raise AtomicDeploymentError("build receipt is not an accepted guarded build")
    if str(build.get("pak_sha256", "")).lower() != artifact_sha256:
        raise AtomicDeploymentError("build receipt is bound to a different artifact")
    if build_schema in {
        "kcd2.candidate-build-receipt.v2",
        "kcd2.double-build-receipt.v2",
    }:
        try:
            build_output_id = validate_typed_identity(
                build.get("build_output_id"), "build-output"
            )
            declared_artifact_id = validate_typed_identity(
                build.get("artifact_id"), "artifact"
            )
        except TypedIdentityError as exc:
            raise AtomicDeploymentError("build receipt typed identities are invalid") from exc
        if declared_artifact_id != artifact_id(artifact_sha256):
            raise AtomicDeploymentError("build receipt artifact_id differs from its PAK")
        identity_document = build
        if build_schema == "kcd2.double-build-receipt.v2":
            builds = build.get("builds")
            if (
                not isinstance(builds, list)
                or len(builds) != 2
                or any(not isinstance(item, dict) for item in builds)
                or any(
                    item.get("schema_version")
                    != "kcd2.candidate-build-receipt.v2"
                    or item.get("status") != "PASS"
                    or item.get("build_output_id") != build_output_id
                    or item.get("artifact_id") != declared_artifact_id
                    or str(item.get("pak_sha256", "")).lower() != artifact_sha256
                    for item in builds
                )
            ):
                raise AtomicDeploymentError(
                    "double-build receipt identity members are invalid"
                )
            identity_document = builds[0]
        parent = identity_document.get("parent")
        packaging = identity_document.get("packaging_profile")
        variant = identity_document.get("variant_selection")
        candidate = identity_document.get("candidate")
        if not all(isinstance(item, dict) for item in (parent, packaging, variant, candidate)):
            raise AtomicDeploymentError("build receipt identity material is incomplete")
        expected_build_output_id = canonical_build_output_id(
            {
                "schema_version": "kcd2.selected-variant-candidate-identity.v1",
                "spec_id": identity_document.get("spec_id"),
                "variant_selection_id": variant.get("selection_id"),
                "parent_candidate_id": parent.get("registry_candidate_id"),
                "parent_artifact_sha256": parent.get("artifact_sha256"),
                "profile_id": packaging.get("profile_id"),
                "profile_sha256": packaging.get("profile_sha256"),
                "pak_sha256": artifact_sha256,
                "manifest_sha256": candidate.get("manifest_sha256"),
            }
        )
        if build_output_id != expected_build_output_id:
            raise AtomicDeploymentError(
                "build receipt build_output_id differs from its identity material"
            )
        identity_derivation = "declared_build_receipt_v2"
    else:
        build_output_id = typed_identity(
            "build-output", normalized["build_receipt"]["sha256"]
        )
        identity_derivation = "historical_receipt_sha256"

    parent_diff = documents["parent_diff_receipt"]
    if (
        parent_diff.get("schema_version")
        != "kcd2.candidate-parent-diff-ledger.v1"
        or parent_diff.get("status") != "PASS"
        or str(parent_diff.get("candidate_sha256", "")).lower()
        != artifact_sha256
        or parent_diff.get("parent_contamination_detected") is not False
    ):
        raise AtomicDeploymentError("parent-diff receipt is not accepted for this artifact")
    if build.get("spec_id") != parent_diff.get("spec_id"):
        raise AtomicDeploymentError("build and parent-diff spec identities differ")

    package = documents["package_validation_receipt"]
    if package != package_report.to_dict():
        raise AtomicDeploymentError(
            "package_report is weaker than or differs from accepted build validation"
        )

    xml_tbl = documents["xml_tbl_receipt"]
    if xml_tbl.get("schema_version") != "kcd2.xml-tbl-contract-report.v1":
        raise AtomicDeploymentError("XML/TBL receipt schema is unsupported")
    changed_paths = xml_tbl.get("changed_paths")
    if (
        not isinstance(changed_paths, list)
        or any(not isinstance(path, str) or not path for path in changed_paths)
        or changed_paths
        != sorted(set(changed_paths), key=lambda path: path.encode("utf-8"))
    ):
        raise AtomicDeploymentError("XML/TBL changed-path evidence is invalid")
    xml_tbl_gate = xml_tbl.get("xml_tbl_gate")
    if xml_tbl_gate != package_report.xml_tbl_gate:
        raise AtomicDeploymentError(
            "install package report lost the accepted XML/TBL gate result"
        )
    if changed_paths and xml_tbl_gate != "CLEAR":
        raise AtomicDeploymentError(
            "changed XML/TBL evidence must remain CLEAR at installation"
        )

    profile = documents["packaging_profile_receipt"]
    if profile.get("schema_version") != "kcd2.packaging-profile.v1":
        raise AtomicDeploymentError("packaging profile receipt schema is unsupported")
    if build.get("profile_id") != profile.get("profile_id"):
        raise AtomicDeploymentError("build and packaging-profile identities differ")

    return {
        "schema_version": "kcd2.accepted-build-attestations.v1",
        "artifact_sha256": artifact_sha256,
        "receipts": normalized,
        "verified_claims": {
            "build_output_id": build_output_id,
            "build_output_id_derivation": identity_derivation,
            "spec_id": build.get("spec_id"),
            "profile_id": build.get("profile_id"),
            "xml_tbl_gate": xml_tbl_gate,
            "changed_xml_paths": changed_paths,
            "package_static_readiness": package_report.overall_static_readiness,
        },
    }


def _verify_candidate_source(
    registry: CandidateRegistry,
    candidate: CandidateRecord,
    source: Path,
    node: DeploymentNode,
) -> None:
    expected = tuple(
        artifact for artifact in candidate.identity.artifacts if artifact.role != "native_component"
    )
    expected_paths: dict[str, Any] = {}
    installed: list[InstalledArtifact] = []
    for artifact in expected:
        relative = _safe_relative_artifact_path(artifact.logical_path)
        canonical = relative.as_posix()
        if canonical in expected_paths:
            raise AtomicDeploymentError("candidate artifact paths normalize to a duplicate")
        expected_paths[canonical] = artifact
        path = source.joinpath(*relative.parts)
        _require_plain_file(path, f"candidate artifact {canonical}", MAX_TRANSACTION_BYTES)
        if path.stat().st_size != artifact.bytes or _sha256_file(path) != artifact.sha256:
            raise AtomicDeploymentError(f"candidate artifact identity mismatch: {canonical}")
        installed.append(
            InstalledArtifact(
                candidate.candidate_id,
                artifact.logical_path,
                artifact.sha256,
                artifact.bytes,
            )
        )
    registry.validate_installed_artifacts(installed)
    manifest = [artifact for artifact in expected if artifact.role == "manifest"]
    paks = [
        artifact
        for artifact in expected
        if artifact.role in {"data_pak", "localization_pak"}
        and artifact.sha256 == node.identity.target_pak.sha256
        and artifact.bytes == node.identity.target_pak.bytes
    ]
    if len(manifest) != 1 or len(paks) != 1:
        raise AtomicDeploymentError("candidate must bind exactly one target manifest and PAK")
    if manifest[0].sha256 != candidate.identity.manifest_sha256:
        raise AtomicDeploymentError("candidate manifest identity is internally inconsistent")
    target_prefix = f"mods/{candidate.identity.folder_name_exact}/"
    if node.identity.target_pak.path != target_prefix + paks[0].logical_path:
        raise AtomicDeploymentError("deployment target PAK path differs from candidate lineage")
    if node.identity.target_manifest.path != target_prefix + manifest[0].logical_path:
        raise AtomicDeploymentError("deployment manifest path differs from candidate lineage")
    manifest_entries = _tree_manifest(
        source, MAX_TRANSACTION_FILES, MAX_TRANSACTION_BYTES
    )
    observed = {item["path"] for item in manifest_entries if item["kind"] == "file"}
    if observed != set(expected_paths):
        raise AtomicDeploymentError("candidate folder contains missing or unregistered artifacts")


def _restore_install_original(
    *,
    context: _InstallContext,
    target_existed: bool,
    backup_target: Path,
    original_tree_sha256: str | None,
    original_order: bytes,
    order_before_sha256: str,
    transaction_id: str,
    backup_verified: bool,
    target_mutated: bool,
    order_mutated: bool,
) -> None:
    if target_mutated:
        if not backup_verified:
            raise AtomicDeploymentError("target mutation occurred before a verified backup")
        if context.target.exists():
            _remove_tree(context.target, context.mods_root)
        if target_existed:
            _copy_verified_tree(backup_target, context.target)
            if _tree_sha256(context.target) != original_tree_sha256:
                raise AtomicDeploymentError("restored target tree differs from its backup")
    elif target_existed:
        if not context.target.is_dir() or _tree_sha256(context.target) != original_tree_sha256:
            raise AtomicDeploymentError("unmutated target changed during failed backup")
    elif context.target.exists():
        raise AtomicDeploymentError("target appeared during failed backup")
    if order_mutated:
        if not backup_verified:
            raise AtomicDeploymentError("mod_order mutation occurred before a verified backup")
        _atomic_write_bytes(
            context.mod_order, original_order, transaction_id + "-install-recovery"
        )
    if _sha256_file(context.mod_order) != order_before_sha256:
        raise AtomicDeploymentError("restored mod_order differs from its backup")


def _ensure_exactly_one_order_entry(original: bytes, mod_id: str) -> bytes:
    bom = b"\xef\xbb\xbf" if original.startswith(b"\xef\xbb\xbf") else b""
    payload = original[len(bom) :]
    try:
        chunks = payload.splitlines(keepends=True)
        decoded = [chunk.decode("utf-8", errors="strict") for chunk in chunks]
    except UnicodeDecodeError as exc:
        raise AtomicDeploymentError("mod_order.txt must be valid UTF-8") from exc
    kept: list[bytes] = []
    found = False
    newline = b"\r\n"
    for chunk, text in zip(chunks, decoded, strict=True):
        if chunk.endswith(b"\r\n"):
            newline = b"\r\n"
        elif chunk.endswith(b"\n"):
            newline = b"\n"
        elif chunk.endswith(b"\r"):
            newline = b"\r"
        if text.strip().casefold() == mod_id.casefold():
            if not found:
                kept.append(chunk)
                found = True
            continue
        kept.append(chunk)
    if not found:
        if kept and not kept[-1].endswith((b"\r", b"\n")):
            kept.append(newline)
        kept.append(mod_id.encode("utf-8") + newline)
    result = bom + b"".join(kept)
    _verify_exactly_one_order_entry(result, mod_id)
    return result


def _verify_exactly_one_order_entry(content: bytes, mod_id: str) -> None:
    try:
        entries = [
            line.strip()
            for line in content.decode("utf-8-sig", errors="strict").splitlines()
            if line.strip()
        ]
    except UnicodeDecodeError as exc:
        raise AtomicDeploymentError("mod_order.txt must be valid UTF-8") from exc
    matches = sum(entry.casefold() == mod_id.casefold() for entry in entries)
    if matches != 1:
        raise AtomicDeploymentError("mod_order.txt does not contain exactly one target entry")


def _receipt_from_document(document: Mapping[str, Any]) -> InstallReceipt:
    schema_version = document.get("schema_version")
    expected = {
        "schema_version",
        "status",
        "transaction_id",
        "candidate_id",
        "deployment_id",
        "target_folder_name",
        "mods_root",
        "receipt_path",
        "backup_target_path",
        "backup_mod_order_path",
        "target_existed",
        "original_target_tree_sha256",
        "installed_tree_sha256",
        "mod_order_before_sha256",
        "mod_order_after_sha256",
        "conflict_report_sha256",
        "mod_order_path",
        "byte_state",
        "parent",
        "candidate_artifacts",
        "manifest_sha256",
        "manifest_artifacts",
        "localization_artifacts",
        "semantic_validation",
        "conflict_validation",
        "completed_at",
    }
    if schema_version in {"kcd2.install-receipt.v2", "kcd2.install-receipt.v3"}:
        expected |= {
            "accepted_build_attestations",
            "build_attestation_bundle_sha256",
        }
    if schema_version == "kcd2.install-receipt.v3":
        expected.remove("candidate_id")
        expected |= {"registry_candidate_id", "identities"}
    if set(document) != expected:
        raise AtomicDeploymentError("install receipt fields are invalid")
    if schema_version not in {
        "kcd2.install-receipt.v1",
        "kcd2.install-receipt.v2",
        "kcd2.install-receipt.v3",
    }:
        raise AtomicDeploymentError("install receipt schema_version is unsupported")
    if document["status"] != "installed":
        raise AtomicDeploymentError("install receipt does not represent a completed install")
    transaction_id = document["transaction_id"]
    candidate_id = (
        document["registry_candidate_id"]
        if schema_version == "kcd2.install-receipt.v3"
        else document["candidate_id"]
    )
    deployment_id = document["deployment_id"]
    if not isinstance(transaction_id, str) or _TRANSACTION_ID.fullmatch(transaction_id) is None:
        raise AtomicDeploymentError("install receipt transaction_id is invalid")
    if not isinstance(candidate_id, str) or _CANDIDATE_ID.fullmatch(candidate_id) is None:
        raise AtomicDeploymentError("install receipt candidate_id is invalid")
    if not isinstance(deployment_id, str) or _DEPLOYMENT_ID.fullmatch(deployment_id) is None:
        raise AtomicDeploymentError("install receipt deployment_id is invalid")
    if schema_version == "kcd2.install-receipt.v3":
        identities = document["identities"]
        if not isinstance(identities, dict) or set(identities) != {
            "build_output_id",
            "artifact_id",
            "registry_candidate_id",
            "deployment_id",
            "installed_tree_id",
        }:
            raise AtomicDeploymentError("install receipt identity types are invalid")
        try:
            validate_typed_identity(identities["build_output_id"], "build-output")
            validate_typed_identity(identities["artifact_id"], "artifact")
            validate_typed_identity(identities["installed_tree_id"], "installed-tree")
        except TypedIdentityError as exc:
            raise AtomicDeploymentError("install receipt identity types are invalid") from exc
        if (
            identities["registry_candidate_id"] != candidate_id
            or identities["deployment_id"] != deployment_id
        ):
            raise AtomicDeploymentError("install receipt identity values disagree")
    target_name = document["target_folder_name"]
    _safe_windows_component(target_name, "install receipt target folder")
    path_fields = (
        "mods_root",
        "receipt_path",
        "backup_target_path",
        "backup_mod_order_path",
    )
    if any(
        not isinstance(document[field], str)
        or not 1 <= len(document[field]) <= 32767
        or "\x00" in document[field]
        or not Path(document[field]).is_absolute()
        for field in path_fields
    ):
        raise AtomicDeploymentError("install receipt contains an invalid path")
    digests = (
        "installed_tree_sha256",
        "mod_order_before_sha256",
        "mod_order_after_sha256",
        "conflict_report_sha256",
    )
    if any(
        not isinstance(document[field], str) or _SHA256.fullmatch(document[field]) is None
        for field in digests
    ):
        raise AtomicDeploymentError("install receipt contains an invalid digest")
    if (
        schema_version == "kcd2.install-receipt.v3"
        and document["identities"]["installed_tree_id"]
        != installed_tree_id(document["installed_tree_sha256"])
    ):
        raise AtomicDeploymentError("install receipt identity values disagree")
    original = document["original_target_tree_sha256"]
    target_existed = document["target_existed"]
    if not isinstance(target_existed, bool) or (
        target_existed != (isinstance(original, str) and _SHA256.fullmatch(original) is not None)
    ):
        raise AtomicDeploymentError("install receipt prior-target identity is inconsistent")
    if document["mod_order_path"] != "mods/mod_order.txt":
        raise AtomicDeploymentError(
            "install receipt load-order path must be exactly mods/mod_order.txt"
        )
    byte_state = _validate_receipt_byte_state(
        document["byte_state"],
        target_existed=target_existed,
        original_tree_sha256=original,
        installed_tree_sha256=document["installed_tree_sha256"],
        mod_order_before_sha256=document["mod_order_before_sha256"],
        mod_order_after_sha256=document["mod_order_after_sha256"],
    )
    parent = document["parent"]
    parent_id_field = (
        "registry_candidate_id"
        if schema_version == "kcd2.install-receipt.v3"
        else "candidate_id"
    )
    if not isinstance(parent, dict) or set(parent) != {
        "artifact_sha256",
        parent_id_field,
    }:
        raise AtomicDeploymentError("install receipt parent identity is invalid")
    parent_candidate_id = parent[parent_id_field]
    parent_artifact_sha256 = parent["artifact_sha256"]
    if (parent_candidate_id is None) != (parent_artifact_sha256 is None):
        raise AtomicDeploymentError("install receipt parent identity is incomplete")
    if parent_candidate_id is not None and (
        not isinstance(parent_candidate_id, str)
        or _CANDIDATE_ID.fullmatch(parent_candidate_id) is None
        or not isinstance(parent_artifact_sha256, str)
        or _SHA256.fullmatch(parent_artifact_sha256) is None
    ):
        raise AtomicDeploymentError("install receipt parent identity is invalid")
    candidate_artifacts = _validate_receipt_artifacts(document["candidate_artifacts"])
    manifest_sha256 = document["manifest_sha256"]
    if not isinstance(manifest_sha256, str) or _SHA256.fullmatch(manifest_sha256) is None:
        raise AtomicDeploymentError("install receipt manifest identity is invalid")
    expected_manifest_artifacts = [
        item for item in candidate_artifacts if item["role"] == "manifest"
    ]
    if (
        len(expected_manifest_artifacts) != 1
        or expected_manifest_artifacts[0]["sha256"] != manifest_sha256
    ):
        raise AtomicDeploymentError("install receipt manifest identity is not artifact-bound")
    expected_localization_artifacts = [
        item
        for item in candidate_artifacts
        if item["role"] == "localization_pak"
        or PurePosixPath(item["logical_path"]).parts[0].casefold() == "localization"
    ]
    if document["manifest_artifacts"] != expected_manifest_artifacts:
        raise AtomicDeploymentError("install receipt manifest artifact ledger is invalid")
    if document["localization_artifacts"] != expected_localization_artifacts:
        raise AtomicDeploymentError("install receipt localization artifact ledger is invalid")
    semantic_validation = document["semantic_validation"]
    if (
        not isinstance(semantic_validation, dict)
        or semantic_validation.get("schema_version")
        != "kcd2.package-validation-report.v1"
    ):
        raise AtomicDeploymentError("install receipt semantic validation is invalid")
    semantic_artifact_sha256 = _digest(
        semantic_validation.get("artifact_sha256"),
        "install receipt semantic-validation artifact",
    )
    accepted_build_attestations = None
    if schema_version in {"kcd2.install-receipt.v2", "kcd2.install-receipt.v3"}:
        accepted_build_attestations = _validate_persisted_build_attestations(
            document["accepted_build_attestations"],
            semantic_validation=semantic_validation,
            require_typed_identities=(schema_version == "kcd2.install-receipt.v3"),
        )
        attestation_digest = document["build_attestation_bundle_sha256"]
        if (
            not isinstance(attestation_digest, str)
            or _SHA256.fullmatch(attestation_digest) is None
            or attestation_digest != _json_sha256(accepted_build_attestations)
        ):
            raise AtomicDeploymentError(
                "install receipt build-attestation digest is invalid"
            )
    if schema_version == "kcd2.install-receipt.v3":
        assert accepted_build_attestations is not None
        expected_identities = {
            "build_output_id": accepted_build_attestations["verified_claims"][
                "build_output_id"
            ],
            "artifact_id": artifact_id(semantic_artifact_sha256),
            "registry_candidate_id": candidate_id,
            "deployment_id": deployment_id,
            "installed_tree_id": installed_tree_id(document["installed_tree_sha256"]),
        }
        if document["identities"] != expected_identities:
            raise AtomicDeploymentError("install receipt identity values disagree")
    conflict_validation = document["conflict_validation"]
    conflict_digest, detached_conflict = _authorize_conflict_report(conflict_validation)
    if conflict_digest != document["conflict_report_sha256"]:
        raise AtomicDeploymentError("install receipt conflict validation digest is invalid")
    return InstallReceipt(
        transaction_id=transaction_id,
        candidate_id=candidate_id,
        deployment_id=deployment_id,
        target_folder_name=target_name,
        mods_root=Path(document["mods_root"]).resolve(strict=False),
        receipt_path=Path(document["receipt_path"]).resolve(strict=False),
        backup_target_path=Path(document["backup_target_path"]).resolve(strict=False),
        backup_mod_order_path=Path(document["backup_mod_order_path"]).resolve(strict=False),
        target_existed=target_existed,
        original_target_tree_sha256=original,
        installed_tree_sha256=document["installed_tree_sha256"],
        mod_order_before_sha256=document["mod_order_before_sha256"],
        mod_order_after_sha256=document["mod_order_after_sha256"],
        conflict_report_sha256=document["conflict_report_sha256"],
        original_target_files=tuple(byte_state["before"]["target"]),
        installed_target_files=tuple(byte_state["after"]["target"]),
        mod_order_before_bytes=byte_state["before"]["mod_order"]["bytes"],
        mod_order_after_bytes=byte_state["after"]["mod_order"]["bytes"],
        candidate_parent_id=parent_candidate_id,
        candidate_parent_artifact_sha256=parent_artifact_sha256,
        candidate_artifacts=tuple(candidate_artifacts),
        manifest_sha256=manifest_sha256,
        semantic_validation=semantic_validation,
        conflict_validation=detached_conflict,
        completed_at=_parse_timestamp(document["completed_at"], "completed_at"),
        accepted_build_attestations=accepted_build_attestations,
    )


def _validate_persisted_build_attestations(
    value: Any,
    *,
    semantic_validation: Mapping[str, Any],
    require_typed_identities: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "artifact_sha256",
        "receipts",
        "verified_claims",
    }:
        raise AtomicDeploymentError("install receipt build attestations are invalid")
    if value["schema_version"] != "kcd2.accepted-build-attestations.v1":
        raise AtomicDeploymentError("install receipt build-attestation schema is unsupported")
    artifact_sha256 = _digest(
        value["artifact_sha256"], "install receipt build-attestation artifact"
    )
    if artifact_sha256 != semantic_validation.get("artifact_sha256"):
        raise AtomicDeploymentError(
            "install receipt build attestations are bound to a different artifact"
        )

    receipts = value["receipts"]
    expected_roles = {
        "build_receipt",
        "parent_diff_receipt",
        "package_validation_receipt",
        "xml_tbl_receipt",
        "packaging_profile_receipt",
    }
    if not isinstance(receipts, dict) or set(receipts) != expected_roles:
        raise AtomicDeploymentError("install receipt build-attestation ledger is invalid")
    normalized_receipts: dict[str, dict[str, Any]] = {}
    for role in sorted(expected_roles):
        reference = receipts[role]
        if not isinstance(reference, dict) or set(reference) != {
            "path",
            "sha256",
            "schema_version",
        }:
            raise AtomicDeploymentError(
                "install receipt build-attestation reference is invalid"
            )
        path = reference["path"]
        schema = reference["schema_version"]
        if (
            not isinstance(path, str)
            or not 1 <= len(path) <= 32767
            or "\x00" in path
            or not Path(path).is_absolute()
            or not isinstance(schema, str)
            or not schema
        ):
            raise AtomicDeploymentError(
                "install receipt build-attestation reference is invalid"
            )
        normalized_receipts[role] = {
            "path": path,
            "sha256": _digest(
                reference["sha256"],
                "install receipt build-attestation reference",
            ),
            "schema_version": schema,
        }

    claims = value["verified_claims"]
    base_claim_fields = {
        "spec_id",
        "profile_id",
        "xml_tbl_gate",
        "changed_xml_paths",
        "package_static_readiness",
    }
    typed_claim_fields = {
        "build_output_id",
        "build_output_id_derivation",
    }
    if (
        not isinstance(claims, dict)
        or frozenset(claims)
        not in {
            frozenset(base_claim_fields),
            frozenset(base_claim_fields | typed_claim_fields),
        }
        or (require_typed_identities and not typed_claim_fields.issubset(claims))
    ):
        raise AtomicDeploymentError("install receipt build-attestation claims are invalid")
    changed_paths = claims["changed_xml_paths"]
    if (
        not isinstance(changed_paths, list)
        or any(not isinstance(path, str) or not path for path in changed_paths)
        or changed_paths != sorted(set(changed_paths), key=lambda path: path.encode("utf-8"))
        or not isinstance(claims["package_static_readiness"], bool)
        or claims["xml_tbl_gate"] != semantic_validation.get("xml_tbl_gate")
        or claims["package_static_readiness"]
        != semantic_validation.get("overall_static_readiness")
        or (changed_paths and claims["xml_tbl_gate"] != "CLEAR")
    ):
        raise AtomicDeploymentError("install receipt build-attestation claims are invalid")
    normalized_claims = {
        "spec_id": claims["spec_id"],
        "profile_id": claims["profile_id"],
        "xml_tbl_gate": claims["xml_tbl_gate"],
        "changed_xml_paths": list(changed_paths),
        "package_static_readiness": claims["package_static_readiness"],
    }
    if typed_claim_fields.issubset(claims):
        try:
            normalized_claims["build_output_id"] = validate_typed_identity(
                claims["build_output_id"], "build-output"
            )
        except TypedIdentityError as exc:
            raise AtomicDeploymentError(
                "install receipt build-attestation claims are invalid"
            ) from exc
        if claims["build_output_id_derivation"] not in {
            "declared_build_receipt_v2",
            "historical_receipt_sha256",
        }:
            raise AtomicDeploymentError(
                "install receipt build-attestation claims are invalid"
            )
        normalized_claims["build_output_id_derivation"] = claims[
            "build_output_id_derivation"
        ]
    return {
        "schema_version": "kcd2.accepted-build-attestations.v1",
        "artifact_sha256": artifact_sha256,
        "receipts": normalized_receipts,
        "verified_claims": normalized_claims,
    }


def _validate_receipt_byte_state(
    value: Any,
    *,
    target_existed: bool,
    original_tree_sha256: str | None,
    installed_tree_sha256: str,
    mod_order_before_sha256: str,
    mod_order_after_sha256: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"before", "after"}:
        raise AtomicDeploymentError("install receipt byte_state is invalid")
    expected = (
        ("before", original_tree_sha256, mod_order_before_sha256),
        ("after", installed_tree_sha256, mod_order_after_sha256),
    )
    for phase, tree_digest, order_digest in expected:
        state = value[phase]
        if not isinstance(state, dict) or set(state) != {
            "mod_order",
            "target",
            "target_file_ledger_sha256",
            "target_tree_sha256",
        }:
            raise AtomicDeploymentError("install receipt byte_state phase is invalid")
        order = state["mod_order"]
        if (
            not isinstance(order, dict)
            or set(order) != {"bytes", "path", "sha256"}
            or order["path"] != "mods/mod_order.txt"
            or order["sha256"] != order_digest
            or not isinstance(order["bytes"], int)
            or isinstance(order["bytes"], bool)
            or not 0 <= order["bytes"] <= MAX_MOD_ORDER_BYTES
        ):
            raise AtomicDeploymentError("install receipt mods/mod_order.txt byte state is invalid")
        if state["target_tree_sha256"] != tree_digest:
            raise AtomicDeploymentError("install receipt target tree byte state is invalid")
        state["target"] = _validate_tree_byte_state(state["target"])
        if state["target_file_ledger_sha256"] != _byte_ledger_sha256(state["target"]):
            raise AtomicDeploymentError("install receipt target byte ledger digest is invalid")
    if target_existed != bool(value["before"]["target"] or original_tree_sha256):
        raise AtomicDeploymentError("install receipt prior target byte state is inconsistent")
    if not value["after"]["target"]:
        raise AtomicDeploymentError("install receipt installed target byte state is empty")
    return value


def _validate_tree_byte_state(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_TRANSACTION_FILES:
        raise AtomicDeploymentError("install receipt target byte ledger is invalid")
    checked: list[dict[str, Any]] = []
    total = 0
    for item in value:
        if not isinstance(item, dict) or set(item) != {"bytes", "logical_path", "sha256"}:
            raise AtomicDeploymentError("install receipt target byte ledger entry is invalid")
        logical = _safe_relative_artifact_path(item["logical_path"]).as_posix()
        digest = item["sha256"]
        size = item["bytes"]
        if (
            not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise AtomicDeploymentError("install receipt target byte identity is invalid")
        total += size
        if total > MAX_TRANSACTION_BYTES:
            raise AtomicDeploymentError("install receipt target byte ledger exceeds bounds")
        checked.append({"bytes": size, "logical_path": logical, "sha256": digest})
    ordered = sorted(checked, key=lambda item: item["logical_path"].encode("utf-8"))
    paths = [item["logical_path"] for item in ordered]
    if checked != ordered or len(paths) != len(set(paths)):
        raise AtomicDeploymentError("install receipt target byte ledger is not canonical")
    return checked


def _validate_receipt_artifacts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise AtomicDeploymentError("install receipt candidate artifact ledger is invalid")
    roles = {"data_pak", "localization_pak", "manifest", "config", "native_component", "other"}
    checked: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "bytes",
            "logical_path",
            "required_at_runtime",
            "role",
            "sha256",
        }:
            raise AtomicDeploymentError("install receipt candidate artifact entry is invalid")
        logical = _safe_relative_artifact_path(item["logical_path"]).as_posix()
        if (
            item["role"] not in roles
            or not isinstance(item["sha256"], str)
            or _SHA256.fullmatch(item["sha256"]) is None
            or not isinstance(item["bytes"], int)
            or isinstance(item["bytes"], bool)
            or not 0 <= item["bytes"] <= MAX_TRANSACTION_BYTES
            or not isinstance(item["required_at_runtime"], bool)
        ):
            raise AtomicDeploymentError("install receipt candidate artifact identity is invalid")
        checked.append({**item, "logical_path": logical})
    ordered = sorted(checked, key=lambda item: item["logical_path"].encode("utf-8"))
    paths = [item["logical_path"] for item in ordered]
    if checked != ordered or len(paths) != len(set(paths)):
        raise AtomicDeploymentError("install receipt candidate artifact ledger is not canonical")
    return checked


def _receipt_byte_state(receipt: InstallReceipt, phase: str) -> dict[str, Any]:
    if phase == "before":
        return {
            "mod_order": {
                "bytes": receipt.mod_order_before_bytes,
                "path": "mods/mod_order.txt",
                "sha256": receipt.mod_order_before_sha256,
            },
            "target": list(receipt.original_target_files),
            "target_file_ledger_sha256": _byte_ledger_sha256(
                receipt.original_target_files
            ),
            "target_tree_sha256": receipt.original_target_tree_sha256,
        }
    if phase == "after":
        return {
            "mod_order": {
                "bytes": receipt.mod_order_after_bytes,
                "path": "mods/mod_order.txt",
                "sha256": receipt.mod_order_after_sha256,
            },
            "target": list(receipt.installed_target_files),
            "target_file_ledger_sha256": _byte_ledger_sha256(
                receipt.installed_target_files
            ),
            "target_tree_sha256": receipt.installed_tree_sha256,
        }
    raise AtomicDeploymentError("install receipt byte-state phase is invalid")


def _read_receipt_document(path: Path) -> dict[str, Any]:
    _require_plain_file(path, "install receipt", 1024 * 1024)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AtomicDeploymentError("install receipt is unreadable") from exc
    if not isinstance(value, dict):
        raise AtomicDeploymentError("install receipt must be a JSON object")
    return value


def _target_child(mods_root: Path, folder_name: str) -> Path:
    _safe_windows_component(folder_name, "target mod folder")
    matches = []
    for index, child in enumerate(mods_root.iterdir(), start=1):
        if index > MAX_TRANSACTION_FILES:
            raise AtomicDeploymentError("mods_root direct-child bound exceeded")
        if child.name.casefold() == folder_name.casefold():
            matches.append(child)
    if len(matches) > 1:
        raise AtomicDeploymentError("multiple case-insensitive target mod folders exist")
    if matches and matches[0].name != folder_name:
        raise AtomicDeploymentError("existing target folder case differs from candidate identity")
    return mods_root / folder_name


def _safe_relative_artifact_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value or "\x00" in value or ":" in value:
        raise AtomicDeploymentError("candidate artifact logical path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or path.as_posix() != value:
        raise AtomicDeploymentError("candidate artifact logical path is unsafe")
    for part in path.parts:
        _safe_windows_component(part, "candidate artifact path component")
    return path


def _safe_windows_component(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 260
        or value in {".", ".."}
        or any(character in '<>:"/\\|?*\x00' for character in value)
        or value.endswith((" ", "."))
        or value.split(".", 1)[0].upper() in _WINDOWS_RESERVED
    ):
        raise AtomicDeploymentError(f"{field} is not a safe single path component")
    return value


def _tree_manifest(root: Path, max_files: int, max_bytes: int) -> list[dict[str, Any]]:
    if not root.is_dir() or _is_reparse(root):
        raise AtomicDeploymentError("tree root must be a plain directory")
    entries: list[dict[str, Any]] = []
    total = 0
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            directory = current_path / name
            if _is_reparse(directory):
                raise AtomicDeploymentError("transaction trees must not contain reparse points")
            if len(entries) >= max_files:
                raise AtomicDeploymentError("transaction tree exceeds the fixed entry bound")
            entries.append(
                {
                    "path": directory.relative_to(root).as_posix(),
                    "kind": "directory",
                }
            )
        for name in file_names:
            path = current_path / name
            info = path.lstat()
            if _is_reparse(path) or not stat.S_ISREG(info.st_mode):
                raise AtomicDeploymentError("transaction trees accept regular files only")
            total += info.st_size
            if len(entries) >= max_files or total > max_bytes:
                raise AtomicDeploymentError("transaction tree exceeds fixed file or byte bounds")
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": "file",
                    "sha256": _sha256_file(path),
                    "bytes": info.st_size,
                }
            )
    return sorted(entries, key=lambda item: item["path"])


def _tree_byte_state(root: Path) -> list[dict[str, Any]]:
    """Return the canonical per-file byte identity ledger for a verified tree."""
    return [
        {
            "bytes": item["bytes"],
            "logical_path": item["path"],
            "sha256": item["sha256"],
        }
        for item in _tree_manifest(root, MAX_TRANSACTION_FILES, MAX_TRANSACTION_BYTES)
        if item["kind"] == "file"
    ]


def _byte_ledger_sha256(entries: Any) -> str:
    encoded = json.dumps(
        list(entries),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _tree_sha256(root: Path) -> str:
    encoded = json.dumps(
        _tree_manifest(root, MAX_TRANSACTION_FILES, MAX_TRANSACTION_BYTES),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _copy_verified_tree(source: Path, target: Path) -> None:
    source_digest = _tree_sha256(source)
    if target.exists() or target.is_symlink():
        raise AtomicDeploymentError("transaction copy target already exists")
    shutil.copytree(source, target, symlinks=False)
    if _tree_sha256(target) != source_digest:
        raise AtomicDeploymentError("transaction tree copy verification failed")


def _remove_tree(path: Path, parent: Path) -> None:
    resolved_parent = parent.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path == resolved_parent or not _is_within(resolved_path, resolved_parent):
        raise AtomicDeploymentError("refusing to remove a tree outside its transaction parent")
    _tree_sha256(resolved_path)
    shutil.rmtree(resolved_path)


def _existing_plain_directory(value: Path | str, field: str) -> Path:
    path = Path(value)
    if not path.exists() or not path.is_dir() or _is_reparse(path):
        raise AtomicDeploymentError(f"{field} must be an existing plain directory")
    return path.resolve(strict=True)


def _require_plain_file(path: Path, field: str, maximum: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AtomicDeploymentError(f"{field} is missing or unreadable") from exc
    if _is_reparse(path) or not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise AtomicDeploymentError(f"{field} must be a bounded plain file")


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return path.is_symlink()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _write_new_file(path: Path, content: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _atomic_write_bytes(path: Path, content: bytes, transaction_id: str) -> None:
    temporary = path.parent / f".{path.name}.{transaction_id}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise AtomicDeploymentError("atomic-write temporary path already exists")
    try:
        _write_new_file(temporary, content)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json_write(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise AtomicDeploymentError("receipt temporary path already exists")
    try:
        _write_new_file(temporary, encoded)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value.lower()) is None:
        raise AtomicDeploymentError(f"{field} is invalid")
    return value.lower()


def _require_attestation_file(value: Any, role: str) -> Path:
    if not isinstance(value, Path):
        raise AtomicDeploymentError(f"{role} path is invalid")
    try:
        path = value.resolve(strict=True)
    except OSError as exc:
        raise AtomicDeploymentError(f"{role} path is unavailable") from exc
    _require_plain_file(path, role, MAX_BUILD_ATTESTATION_BYTES)
    return path


def _read_bounded_json(path: Path, role: str) -> tuple[dict[str, Any], str]:
    try:
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BUILD_ATTESTATION_BYTES:
                raise AtomicDeploymentError(f"{role} must be a bounded plain file")
            payload = handle.read(MAX_BUILD_ATTESTATION_BYTES + 1)
        if len(payload) != info.st_size:
            raise AtomicDeploymentError(f"{role} changed while it was read")
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AtomicDeploymentError(f"{role} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise AtomicDeploymentError(f"{role} must contain one JSON object")
    return document, _sha256_bytes(payload)


def _timestamp(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AtomicDeploymentError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise AtomicDeploymentError(f"{field} is invalid")
    try:
        return _timestamp(datetime.fromisoformat(value.replace("Z", "+00:00")), field)
    except ValueError as exc:
        raise AtomicDeploymentError(f"{field} is invalid") from exc


def _coerce_install_boundary(value: InstallBoundary | str | None) -> InstallBoundary | None:
    if value is None:
        return None
    try:
        return InstallBoundary(value)
    except (TypeError, ValueError) as exc:
        raise AtomicDeploymentError("failure injection boundary is invalid") from exc


def _inject(selected: InstallBoundary | None, current: InstallBoundary) -> None:
    if selected is current:
        raise AtomicDeploymentError(f"injected failure at {current.value}")
