"""Guarded, non-live candidate construction in deterministic clean staging."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
import zipfile
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from kcd2_toolchain_core.approvals import ApprovalTarget, ApprovalVerifier

from .build_spec import parse_build_spec
from .candidate_manifest import generate_candidate_manifest, validate_candidate_manifest
from .identity_types import artifact_id, canonical_build_output_id
from .packaging_profiles import (
    MemberPackagingLedgerEntry,
    detect_packaging_profile,
)


_TRANSACTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_INCLUSION_SCAN_FILES = 16_384
MAX_INCLUSION_SCAN_BYTES = 2 * 1024 * 1024 * 1024


class BuildGuardError(ValueError):
    """A build was refused before it could cross a declared safety boundary."""


class AccidentalInclusionCategory(StrEnum):
    """Classes of review/staging debris that must never enter a candidate."""

    REFERENCE = "reference"
    TEMPORARY = "temporary"
    OLD = "old"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class AccidentalInclusionFinding:
    logical_path: str
    category: AccidentalInclusionCategory
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category.value,
            "logical_path": self.logical_path,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AccidentalInclusionReport:
    scanned_file_count: int
    scanned_bytes: int
    findings: tuple[AccidentalInclusionFinding, ...]

    @property
    def status(self) -> str:
        return "FAIL" if self.findings else "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.accidental-inclusion-report.v1",
            "status": self.status,
            "scanned_file_count": self.scanned_file_count,
            "scanned_bytes": self.scanned_bytes,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class BuildMemberIdentity:
    logical_path: str
    role: str
    sha256: str
    bytes: int
    compression: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bytes": self.bytes,
            "compression": self.compression,
            "logical_path": self.logical_path,
            "role": self.role,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class GeneratedManifestIdentity:
    logical_path: str
    sha256: str
    bytes: int
    candidate_number: int
    version: str
    mod_id: str
    folder_name_exact: str
    load_order_identity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_path": self.logical_path,
            "role": "manifest",
            "sha256": self.sha256,
            "bytes": self.bytes,
            "candidate_number": self.candidate_number,
            "version": self.version,
            "mod_id": self.mod_id,
            "folder_name_exact": self.folder_name_exact,
            "load_order_identity": self.load_order_identity,
        }


@dataclass(frozen=True, slots=True)
class CandidateBuildReceipt:
    build_output_id: str
    artifact_id: str
    spec_id: str
    profile_id: str
    profile_sha256: str
    profile_source: str
    staging_path: Path
    pak_path: Path
    pak_sha256: str
    pak_bytes: int
    member_sha256: tuple[tuple[str, str], ...]
    compression_method: str
    member_ledger: tuple[MemberPackagingLedgerEntry, ...]
    mod_id: str
    folder_name_exact: str
    parent_mode: str
    parent_candidate_id: str | None
    parent_artifact_sha256: str | None
    parent_evidence_refs: tuple[str, ...]
    member_identities: tuple[BuildMemberIdentity, ...]
    generated_manifest: GeneratedManifestIdentity
    lifecycle_intent: str
    accidental_inclusion_scan: AccidentalInclusionReport
    variant_selection_id: str | None
    selected_variant_member_ids: tuple[str, ...]
    excluded_variant_member_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.candidate-build-receipt.v2",
            "status": "PASS",
            "build_output_id": self.build_output_id,
            "artifact_id": self.artifact_id,
            "spec_id": self.spec_id,
            "profile_id": self.profile_id,
            "transaction_name": self.staging_path.name,
            "candidate_folder": self.folder_name_exact,
            "pak_relative_path": self.pak_path.relative_to(self.staging_path).as_posix(),
            "pak_sha256": self.pak_sha256,
            "pak_bytes": self.pak_bytes,
            "compression_method": self.compression_method,
            "parent": {
                "artifact_sha256": self.parent_artifact_sha256,
                "registry_candidate_id": self.parent_candidate_id,
                "evidence_refs": list(self.parent_evidence_refs),
                "mode": self.parent_mode,
            },
            "candidate": {
                "folder_name_exact": self.folder_name_exact,
                "mod_id": self.mod_id,
                "pak_bytes": self.pak_bytes,
                "pak_relative_path": self.pak_path.relative_to(self.staging_path).as_posix(),
                "pak_sha256": self.pak_sha256,
                "candidate_number": self.generated_manifest.candidate_number,
                "version": self.generated_manifest.version,
                "manifest_sha256": self.generated_manifest.sha256,
            },
            "packaging_profile": {
                "profile_id": self.profile_id,
                "profile_sha256": self.profile_sha256,
                "profile_source": self.profile_source,
                "preserved": True,
            },
            "variant_selection": {
                "selection_id": self.variant_selection_id,
                "selected_member_ids": list(self.selected_variant_member_ids),
                "excluded_member_ids": list(self.excluded_variant_member_ids),
            },
            "members": [item.to_dict() for item in self.member_identities],
            "member_ledger": [item.to_dict() for item in self.member_ledger],
            "compression_ledger": {
                "complete": sorted(
                    (item.logical_path, item.compression, item.bytes)
                    for item in self.member_identities
                )
                == sorted(
                    (item.logical_path, item.method, item.uncompressed_bytes)
                    for item in self.member_ledger
                ),
                "member_count": len(self.member_identities),
                "policy": self.compression_method,
                "entries": [item.to_dict() for item in self.member_ledger],
            },
            "semantic_validation": {
                "scope": "build_only",
                "status": (
                    "pending_package_validation"
                    if self.lifecycle_intent == "package_validation_requested"
                    else "not_requested"
                ),
            },
            "manifest_artifacts": [self.generated_manifest.to_dict()],
            "localization_artifacts": [
                item.to_dict()
                for item in self.member_identities
                if PurePosixPath(item.logical_path).parts[0].casefold() == "localization"
            ],
            "conflict_validation": {
                "scope": "build_only",
                "status": "not_evaluated_at_build",
            },
            "reproducibility": {"build_count": 1, "status": "not_checked"},
            "accidental_inclusion_scan": self.accidental_inclusion_scan.to_dict(),
        }

    @property
    def candidate_id(self) -> str:
        """Deprecated source compatibility; serialized receipts use build_output_id."""
        return self.build_output_id


@dataclass(frozen=True, slots=True)
class DoubleBuildReceipt:
    first: CandidateBuildReceipt
    second: CandidateBuildReceipt
    receipt_path: Path
    performance_path: Path | None = None
    performance: Mapping[str, Any] | None = None
    status: str = "PASS"

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "kcd2.double-build-receipt.v2",
            "status": self.status,
            "spec_id": self.first.spec_id,
            "profile_id": self.first.profile_id,
            "build_output_id": self.first.build_output_id,
            "artifact_id": self.first.artifact_id,
            "pak_sha256": self.first.pak_sha256,
            "pak_bytes": self.first.pak_bytes,
            "builds": [self.first.to_dict(), self.second.to_dict()],
            "packaging_profile": self.first.to_dict()["packaging_profile"],
            "variant_selection": self.first.to_dict()["variant_selection"],
            "reproducibility": {
                "build_count": 2,
                "byte_identical": True,
                "first_pak_sha256": self.first.pak_sha256,
                "second_pak_sha256": self.second.pak_sha256,
                "status": "verified",
            },
        }
        return payload

    def performance_to_dict(self) -> dict[str, Any] | None:
        if self.performance is None:
            return None
        return dict(self.performance)


@dataclass(frozen=True, slots=True)
class _FrozenBuildMember:
    logical_path: str
    data: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _FrozenBuildInputs:
    members: tuple[_FrozenBuildMember, ...]
    inclusion_scan: AccidentalInclusionReport
    ledger_sha256: str
    total_bytes: int


def _prepare_empty_staging(build_root: Path | str, staging_path: Path | str) -> Path:
    """Create one empty staging directory strictly below a non-reparse build root."""
    root = Path(build_root)
    target = Path(staging_path)
    if not root.exists() or not root.is_dir():
        raise BuildGuardError("build root must already exist as a directory")
    if _is_reparse(root):
        raise BuildGuardError("build root must not be a symlink or reparse point")

    resolved_root = root.resolve(strict=True)
    resolved_target = target.resolve(strict=False)
    if resolved_target.parent != resolved_root or resolved_target == resolved_root:
        raise BuildGuardError("staging path must be one direct child of the build root")
    if target.exists() or target.is_symlink():
        _reject_reparse_tree(target)
        if not target.is_dir():
            raise BuildGuardError("existing staging path is not a directory")
        shutil.rmtree(target)
    target.mkdir()
    return target


def _build_candidate_impl(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None = None,
    member_compression: Mapping[str, str] | None = None,
    transaction_name: str = "candidate",
    frozen_inputs: _FrozenBuildInputs | None = None,
) -> CandidateBuildReceipt:
    """Implementation reached only through the public transaction approval gate."""
    if not isinstance(transaction_name, str) or _TRANSACTION_RE.fullmatch(transaction_name) is None:
        raise BuildGuardError("transaction_name must be a bounded single path component")
    if not isinstance(build_spec, Mapping):
        raise BuildGuardError("build_spec must be an immutable declarative mapping")
    if not isinstance(packaging_profile, Mapping):
        raise BuildGuardError("packaging_profile must be an immutable declarative mapping")

    build_spec = _detached_json_object(build_spec, "build_spec")
    packaging_profile = _detached_json_object(packaging_profile, "packaging_profile")

    report = parse_build_spec(build_spec)
    if not report.valid or report.spec is None:
        codes = ", ".join(item.code for item in report.diagnostics)
        raise BuildGuardError(f"build specification is invalid: {codes}")
    if report.spec.schema_version != "kcd2.build-spec.v2" or report.spec.manifest_metadata is None:
        raise BuildGuardError(
            "candidate construction requires kcd2.build-spec.v2 manifest metadata"
        )
    if report.spec.parent.mode != "new_candidate":
        raise BuildGuardError("derived-candidate construction requires the parent-diff build gate")
    if report.spec.external_components:
        raise BuildGuardError("external components are outside deterministic PAK construction")

    profile_id, policy, allowed_methods = _validate_packaging(build_spec, packaging_profile)
    root = Path(build_root).resolve(strict=True)
    staging = _prepare_empty_staging(root, root / transaction_name)
    candidate_root = staging / report.spec.folder_name_exact
    pak_path = candidate_root / "Data" / f"{report.spec.mod_id}.pak"
    try:
        frozen = frozen_inputs or _freeze_build_inputs(build_spec, Path(input_root))
        members = frozen.members
        methods = _resolve_member_methods(
            members, policy, allowed_methods, member_compression
        )
        inclusion_scan = frozen.inclusion_scan
        if inclusion_scan.findings:
            categories = ", ".join(
                sorted({finding.category.value for finding in inclusion_scan.findings})
            )
            raise BuildGuardError(
                f"accidental candidate inclusions detected: {categories}"
            )
        pak_path.parent.mkdir(parents=True)
        manifest_path = candidate_root / "mod.manifest"
        manifest_bytes = generate_candidate_manifest(report.spec.manifest_metadata)
        manifest_report = validate_candidate_manifest(
            manifest_bytes, report.spec.manifest_metadata
        )
        if not manifest_report.valid:
            raise BuildGuardError(
                "generated manifest failed its own semantic validation: "
                + ", ".join(manifest_report.diagnostics)
            )
        manifest_path.write_bytes(manifest_bytes)
        manifest_identity = GeneratedManifestIdentity(
            logical_path="mod.manifest",
            sha256=_sha256(manifest_bytes),
            bytes=len(manifest_bytes),
            candidate_number=report.spec.manifest_metadata.candidate_number,
            version=report.spec.manifest_metadata.version,
            mod_id=report.spec.mod_id,
            folder_name_exact=report.spec.folder_name_exact,
            load_order_identity=report.spec.manifest_metadata.load_order_identity,
        )
        _write_deterministic_pak(pak_path, members, methods)
        pak_bytes = pak_path.stat().st_size
        maximum = build_spec["limits"]["max_output_bytes"]
        if pak_bytes > maximum:
            raise BuildGuardError(
                f"candidate PAK is {pak_bytes} bytes and exceeds max_output_bytes ({maximum})"
            )
        digest = _hash_file(pak_path)
        inspection = detect_packaging_profile(parent_pak=pak_path)
        if not inspection.valid:
            codes = ", ".join(item.code for item in inspection.diagnostics)
            raise BuildGuardError(f"constructed PAK packaging inspection failed: {codes}")
        inputs = {item["logical_path"]: item for item in build_spec["inputs"]}
        member_identities = tuple(
            BuildMemberIdentity(
                logical_path=item.logical_path,
                role=inputs[item.logical_path]["role"],
                sha256=item.sha256,
                bytes=len(item.data),
                compression=methods[item.logical_path],
            )
            for item in members
        )
        candidate_material = {
            "schema_version": "kcd2.selected-variant-candidate-identity.v1",
            "spec_id": report.spec.spec_id,
            "variant_selection_id": report.spec.variant_selection_id,
            "parent_candidate_id": report.spec.parent.candidate_id,
            "parent_artifact_sha256": report.spec.parent.artifact_sha256,
            "profile_id": profile_id,
            "profile_sha256": build_spec["packaging"]["profile_sha256"].lower(),
            "pak_sha256": digest,
            "manifest_sha256": manifest_identity.sha256,
        }
        build_output_id = canonical_build_output_id(candidate_material)
        return CandidateBuildReceipt(
            build_output_id=build_output_id,
            artifact_id=artifact_id(digest),
            spec_id=report.spec.spec_id,
            profile_id=profile_id,
            profile_sha256=build_spec["packaging"]["profile_sha256"].lower(),
            profile_source=build_spec["packaging"]["profile_source"],
            staging_path=staging,
            pak_path=pak_path,
            pak_sha256=digest,
            pak_bytes=pak_bytes,
            member_sha256=tuple((item.logical_path, item.sha256) for item in members),
            compression_method=policy,
            member_ledger=inspection.member_ledger,
            mod_id=report.spec.mod_id,
            folder_name_exact=report.spec.folder_name_exact,
            parent_mode=report.spec.parent.mode,
            parent_candidate_id=report.spec.parent.candidate_id,
            parent_artifact_sha256=report.spec.parent.artifact_sha256,
            parent_evidence_refs=report.spec.parent.evidence_refs,
            member_identities=member_identities,
            generated_manifest=manifest_identity,
            lifecycle_intent=report.spec.lifecycle_intent,
            accidental_inclusion_scan=inclusion_scan,
            variant_selection_id=report.spec.variant_selection_id,
            selected_variant_member_ids=report.spec.selected_variant_member_ids,
            excluded_variant_member_ids=report.spec.excluded_variant_member_ids,
        )
    except Exception:
        if staging.exists():
            _prepare_empty_staging(root, staging)
        raise


def _build_candidate_twice_impl(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None = None,
    member_compression: Mapping[str, str] | None = None,
) -> DoubleBuildReceipt:
    """Build twice in separate clean transactions and persist a reproducibility receipt."""
    root = Path(build_root).resolve(strict=True)
    freeze_started = time.perf_counter_ns()
    frozen = _freeze_build_inputs(build_spec, Path(input_root))
    freeze_ns = time.perf_counter_ns() - freeze_started
    build_started = time.perf_counter_ns()
    arguments = {
        "input_root": input_root,
        "build_root": root,
        "packaging_profile": packaging_profile,
        "member_compression": member_compression,
        "frozen_inputs": frozen,
    }
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="kcd2-repro-build") as executor:
        first_future = executor.submit(
            _build_candidate_impl,
            build_spec,
            transaction_name="repro-build-a",
            **arguments,
        )
        second_future = executor.submit(
            _build_candidate_impl,
            build_spec,
            transaction_name="repro-build-b",
            **arguments,
        )
        first = first_future.result()
        second = second_future.result()
    parallel_build_ns = time.perf_counter_ns() - build_started
    comparison_started = time.perf_counter_ns()
    if (
        first.pak_sha256 != second.pak_sha256
        or first.pak_bytes != second.pak_bytes
        or first.generated_manifest.sha256 != second.generated_manifest.sha256
        or first.generated_manifest.bytes != second.generated_manifest.bytes
    ):
        raise BuildGuardError("double-build reproducibility check failed")
    comparison_ns = time.perf_counter_ns() - comparison_started
    receipt_path = root / "double-build-receipt.json"
    performance_path = root / "build-performance-receipt.json"
    performance = {
        "schema_version": "kcd2.build-performance.v1",
        "strategy": "parallel_isolated_double_build",
        "max_parallel_builds": 2,
        "isolated_transactions": ["repro-build-a", "repro-build-b"],
        "immutable_input_ledger": {
            "member_count": len(frozen.members),
            "total_bytes": frozen.total_bytes,
            "sha256": frozen.ledger_sha256,
            "source_hash_passes": 1,
        },
        "phases_ns": {
            "input_freeze": freeze_ns,
            "parallel_build_wall": parallel_build_ns,
            "reproducibility_check": comparison_ns,
        },
        "compression": {
            "policy": first.compression_method,
            "decision": "UNCHANGED_PENDING_MEASURED_BOTTLENECK",
            "artifact_byte_identity_affected": False,
        },
    }
    receipt = DoubleBuildReceipt(
        first=first,
        second=second,
        receipt_path=receipt_path,
        performance_path=performance_path,
        performance=performance,
    )
    _atomic_json_write(receipt_path, receipt.to_dict())
    _atomic_json_write(performance_path, performance)
    return receipt


def build_candidate_approval_targets(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None,
    member_compression: Mapping[str, str] | None = None,
    transaction_name: str = "candidate",
) -> tuple[ApprovalTarget, ...]:
    """Rehash the exact build inputs and bind the intended transaction destination."""
    root = Path(build_root).resolve(strict=True)
    payload = {
        "build_spec": _detached_json_object(build_spec, "build_spec"),
        "packaging_profile": _detached_json_object(packaging_profile, "packaging_profile"),
        "member_compression": None if member_compression is None else dict(member_compression),
        "transaction_name": transaction_name,
    }
    return (
        ApprovalTarget.from_paths(
            role="build_inputs", path=input_root, proposed_path=input_root
        ),
        ApprovalTarget.from_payload(
            role="build_destination",
            path=root / transaction_name,
            proposed_payload=payload,
        ),
    )


def build_candidate_guarded(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None = None,
    member_compression: Mapping[str, str] | None = None,
    transaction_name: str = "candidate",
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
) -> CandidateBuildReceipt:
    """Build only after exact input/path approval and a direct process-state probe."""
    targets = build_candidate_approval_targets(
        build_spec,
        input_root=input_root,
        build_root=build_root,
        packaging_profile=packaging_profile,
        member_compression=member_compression,
        transaction_name=transaction_name,
    )
    return approval_verifier.execute(
        approval,
        operation="build_candidate",
        targets=targets,
        mutation=lambda: _build_candidate_impl(
            build_spec,
            input_root=input_root,
            build_root=build_root,
            packaging_profile=packaging_profile,
            member_compression=member_compression,
            transaction_name=transaction_name,
        ),
    )


def build_candidate_twice_approval_targets(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None,
    member_compression: Mapping[str, str] | None = None,
) -> tuple[ApprovalTarget, ...]:
    first = build_candidate_approval_targets(
        build_spec,
        input_root=input_root,
        build_root=build_root,
        packaging_profile=packaging_profile,
        member_compression=member_compression,
        transaction_name="repro-build-a",
    )
    second = build_candidate_approval_targets(
        build_spec,
        input_root=input_root,
        build_root=build_root,
        packaging_profile=packaging_profile,
        member_compression=member_compression,
        transaction_name="repro-build-b",
    )
    receipt = ApprovalTarget.from_payload(
        role="build_receipt",
        path=Path(build_root).resolve(strict=True) / "double-build-receipt.json",
        proposed_payload={"transactions": ["repro-build-a", "repro-build-b"]},
    )
    performance_receipt = ApprovalTarget.from_payload(
        role="build_performance_receipt",
        path=Path(build_root).resolve(strict=True) / "build-performance-receipt.json",
        proposed_payload={
            "schema_version": "kcd2.build-performance.v1",
            "transactions": ["repro-build-a", "repro-build-b"],
        },
    )
    return first + (second[1], receipt, performance_receipt)


def build_candidate_twice_guarded(
    build_spec: Mapping[str, Any],
    *,
    input_root: Path | str,
    build_root: Path | str,
    packaging_profile: Mapping[str, Any] | None = None,
    member_compression: Mapping[str, str] | None = None,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
) -> DoubleBuildReceipt:
    targets = build_candidate_twice_approval_targets(
        build_spec,
        input_root=input_root,
        build_root=build_root,
        packaging_profile=packaging_profile,
        member_compression=member_compression,
    )
    return approval_verifier.execute(
        approval,
        operation="build_candidate",
        targets=targets,
        mutation=lambda: _build_candidate_twice_impl(
            build_spec,
            input_root=input_root,
            build_root=build_root,
            packaging_profile=packaging_profile,
            member_compression=member_compression,
        ),
    )


def _validate_packaging(
    build_spec: Mapping[str, Any], profile: Mapping[str, Any]
) -> tuple[str, str, tuple[str, ...]]:
    detection = detect_packaging_profile(explicit_profile=profile)
    if not detection.valid:
        codes = ", ".join(item.code for item in detection.diagnostics)
        raise BuildGuardError(f"packaging profile is invalid: {codes}")
    required = {
        "schema_version",
        "profile_id",
        "profile_kind",
        "profile_source",
        "allowed_methods",
        "member_ledger_required",
    }
    if not required.issubset(profile):
        raise BuildGuardError("packaging profile is missing required fields")
    if profile["schema_version"] != "kcd2.packaging-profile.v1":
        raise BuildGuardError("unsupported packaging profile schema_version")
    packaging = build_spec["packaging"]
    profile_id = profile["profile_id"]
    if not isinstance(profile_id, str) or packaging["profile_id"] != profile_id:
        raise BuildGuardError("packaging profile identity does not match the build specification")
    canonical = json.dumps(
        profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if _sha256(canonical).lower() != packaging["profile_sha256"].lower():
        raise BuildGuardError("packaging profile SHA-256 does not match the build specification")
    if (
        packaging["profile_source"] == "parent_inherited"
        and profile.get("profile_kind") != "lineage_inherited"
    ):
        raise BuildGuardError("parent_inherited packaging requires a lineage_inherited profile")
    if profile.get("profile_kind") == "inspect_only":
        raise BuildGuardError("inspect_only packaging profiles cannot authorize a build")
    policy = packaging["compression_policy"]
    if policy == "stored":
        required_methods = ("stored",)
    elif policy == "deflated":
        required_methods = ("deflate",)
    elif policy in {"mixed", "inherit_exact"}:
        required_methods = ()
    else:  # The build-spec parser should make this unreachable.
        raise BuildGuardError("unsupported compression policy")
    allowed = profile["allowed_methods"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(item not in {"stored", "deflate"} for item in allowed)
        or any(item not in allowed for item in required_methods)
    ):
        raise BuildGuardError("compression method is not allowed by the packaging profile")
    if profile.get("profile_kind") == "retail_stored" and allowed != ["stored"]:
        raise BuildGuardError("retail_stored profiles permit only stored compression")
    if profile.get("member_ledger_required") is not True:
        raise BuildGuardError("deterministic construction requires a member ledger")
    return profile_id, policy, tuple(allowed)


def _resolve_member_methods(
    members: Iterable[_FrozenBuildMember],
    policy: str,
    allowed_methods: tuple[str, ...],
    member_compression: Mapping[str, str] | None,
) -> dict[str, str]:
    member_names = {item.logical_path for item in members}
    if policy in {"stored", "deflated"}:
        method = "stored" if policy == "stored" else "deflate"
        if member_compression is not None:
            supplied = dict(member_compression)
            if set(supplied) != member_names or any(value != method for value in supplied.values()):
                raise BuildGuardError(
                    "per-member compression ledger conflicts with the archive-wide policy"
                )
        return {name: method for name in member_names}
    if not isinstance(member_compression, Mapping):
        raise BuildGuardError(
            "mixed and inherit_exact compression require a declared per-member ledger"
        )
    supplied = dict(member_compression)
    if set(supplied) != member_names:
        raise BuildGuardError("per-member compression ledger must exactly cover package members")
    if any(value not in allowed_methods for value in supplied.values()):
        raise BuildGuardError("member compression method is not allowed by the packaging profile")
    if policy == "mixed" and len(set(supplied.values())) < 2:
        raise BuildGuardError("mixed compression policy requires both stored and deflate members")
    return supplied


def _freeze_build_inputs(
    build_spec: Mapping[str, Any], input_root: Path
) -> _FrozenBuildInputs:
    if not input_root.exists() or not input_root.is_dir() or _is_reparse(input_root):
        raise BuildGuardError("input root must be an existing non-reparse directory")
    resolved_root = input_root.resolve(strict=True)
    selection = build_spec.get("variant_selection")
    selected_member_ids: set[str] = set()
    if isinstance(selection, Mapping):
        selected_member_ids = {
            member_id
            for group in selection.get("groups", [])
            for member_id in group.get("selected_member_ids", [])
        }
    declarations: dict[str, Mapping[str, Any]] = {}
    active_declarations: dict[str, Mapping[str, Any]] = {}
    folded: set[str] = set()
    total = 0
    verified: dict[str, _FrozenBuildMember] = {}
    for item in build_spec["inputs"]:
        logical = _safe_logical_path(item["logical_path"])
        key = logical.casefold()
        if key in folded:
            raise BuildGuardError("input paths contain a case-insensitive collision")
        folded.add(key)
        declarations[logical] = item
        member_id = item.get("variant_member_id")
        if member_id is not None and member_id not in selected_member_ids:
            continue
        active_declarations[logical] = item
        source = resolved_root.joinpath(*PurePosixPath(logical).parts)
        resolved_source = source.resolve(strict=True)
        if resolved_source.parent != resolved_root and resolved_root not in resolved_source.parents:
            raise BuildGuardError("input path escapes the declared input root")
        if not resolved_source.is_file() or _is_reparse(source):
            raise BuildGuardError(f"input is not a regular non-reparse file: {logical}")
        try:
            data = resolved_source.read_bytes()
        except OSError as exc:
            raise BuildGuardError(f"could not freeze input: {logical}") from exc
        size = len(data)
        digest = _sha256(data)
        if size != item["bytes"] or digest.lower() != item["sha256"].lower():
            raise BuildGuardError(f"input identity mismatch: {logical}")
        verified[logical] = _FrozenBuildMember(logical, data, digest)
        total += size
    if total > build_spec["limits"]["max_input_bytes"]:
        raise BuildGuardError("verified input bytes exceed max_input_bytes")

    members: list[_FrozenBuildMember] = []
    for change in build_spec["allowed_changes"]:
        if change["change_kind"] != "add_member":
            raise BuildGuardError("new-candidate builder accepts add_member changes only")
        logical = _safe_logical_path(change["logical_path"])
        declaration = active_declarations.get(logical)
        if declaration is None and logical in declarations:
            continue
        if declaration is None or declaration["role"] not in {
            "source",
            "manifest",
            "configuration",
        }:
            raise BuildGuardError(f"add_member has no packageable declared input: {logical}")
        members.append(verified[logical])
    members.sort(key=lambda item: item.logical_path.encode("utf-8"))
    inclusion_scan = scan_accidental_inclusions(
        input_root, included_paths=(item.logical_path for item in members)
    )
    ledger = [
        {"logical_path": item.logical_path, "sha256": item.sha256, "bytes": len(item.data)}
        for item in members
    ]
    ledger_sha256 = _sha256(
        json.dumps(ledger, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return _FrozenBuildInputs(tuple(members), inclusion_scan, ledger_sha256, total)


def scan_accidental_inclusions(
    input_root: Path | str,
    *,
    included_paths: Iterable[str] | None = None,
    max_files: int = MAX_INCLUSION_SCAN_FILES,
    max_bytes: int = MAX_INCLUSION_SCAN_BYTES,
) -> AccidentalInclusionReport:
    """Inspect the exact proposed member set for common review/staging debris.

    The caller supplies the paths proposed for inclusion. Files elsewhere below ``input_root``
    are intentionally outside the finding set because the deterministic builder does not copy
    them. The scan is bounded, reparse-safe, case-aware, and stable across enumeration order.
    """
    if (
        not isinstance(max_files, int)
        or isinstance(max_files, bool)
        or not 1 <= max_files <= MAX_INCLUSION_SCAN_FILES
    ):
        raise BuildGuardError(
            f"max_files must be between 1 and {MAX_INCLUSION_SCAN_FILES}"
        )
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= MAX_INCLUSION_SCAN_BYTES
    ):
        raise BuildGuardError(
            f"max_bytes must be between 1 and {MAX_INCLUSION_SCAN_BYTES}"
        )
    root = Path(input_root)
    if not root.is_dir() or _is_reparse(root):
        raise BuildGuardError("inclusion scan root must be an existing non-reparse directory")
    resolved_root = root.resolve(strict=True)
    if included_paths is None:
        discovered: list[str] = []
        for current, directory_names, file_names in os.walk(root, followlinks=False):
            current_path = Path(current)
            directory_names.sort()
            file_names.sort()
            for name in directory_names:
                if _is_reparse(current_path / name):
                    raise BuildGuardError(
                        "accidental inclusion scan does not traverse reparse points"
                    )
            for name in file_names:
                path = current_path / name
                if _is_reparse(path):
                    raise BuildGuardError(
                        "accidental inclusion scan accepts regular files only"
                    )
                discovered.append(path.relative_to(root).as_posix())
                if len(discovered) > max_files:
                    raise BuildGuardError("accidental inclusion scan exceeds max_files")
        included_paths = discovered
    try:
        logical_paths = sorted({_safe_logical_path(value) for value in included_paths})
    except TypeError as exc:
        raise BuildGuardError("included_paths must be an iterable of logical paths") from exc
    if len(logical_paths) > max_files:
        raise BuildGuardError("accidental inclusion scan exceeds max_files")

    findings: list[AccidentalInclusionFinding] = []
    total = 0
    folded_paths: dict[str, str] = {}
    for logical in logical_paths:
        source = resolved_root.joinpath(*PurePosixPath(logical).parts)
        resolved_source = source.resolve(strict=True)
        if resolved_source.parent != resolved_root and resolved_root not in resolved_source.parents:
            raise BuildGuardError("inclusion scan path escapes the declared root")
        if not resolved_source.is_file() or _is_reparse(source):
            raise BuildGuardError(f"inclusion scan member is not a regular file: {logical}")
        total += resolved_source.stat().st_size
        if total > max_bytes:
            raise BuildGuardError("accidental inclusion scan exceeds max_bytes")

        folded = logical.casefold()
        previous = folded_paths.get(folded)
        if previous is not None and previous != logical:
            findings.append(
                AccidentalInclusionFinding(
                    logical,
                    AccidentalInclusionCategory.DUPLICATE,
                    f"case-insensitive path collision with {previous}",
                )
            )
        folded_paths[folded] = logical
        findings.extend(_path_inclusion_findings(logical))

    findings.sort(key=lambda item: (item.logical_path.encode("utf-8"), item.category.value))
    return AccidentalInclusionReport(len(logical_paths), total, tuple(findings))


def _path_inclusion_findings(logical_path: str) -> list[AccidentalInclusionFinding]:
    parts = PurePosixPath(logical_path).parts
    folded_parts = tuple(part.casefold() for part in parts)
    name = folded_parts[-1]
    stem_tokens = tuple(token for token in re.split(r"[. _()\[\]-]+", name) if token)
    component_tokens = set(folded_parts[:-1]) | set(stem_tokens)
    matches: list[tuple[AccidentalInclusionCategory, str]] = []
    if component_tokens & {"ref", "refs", "reference", "references"}:
        matches.append(
            (AccidentalInclusionCategory.REFERENCE, "reference material marker in path")
        )
    if (
        component_tokens & {"temp", "tmp", "temporary"}
        or name.endswith((".tmp", ".temp"))
        or name.startswith("~")
    ):
        matches.append(
            (AccidentalInclusionCategory.TEMPORARY, "temporary-work marker in path")
        )
    if component_tokens & {"old", "bak", "backup", "backups"} or name.endswith(".bak"):
        matches.append((AccidentalInclusionCategory.OLD, "old/backup marker in path"))
    if component_tokens & {"copy", "duplicate", "duplicates", "dup"}:
        matches.append(
            (AccidentalInclusionCategory.DUPLICATE, "copy/duplicate marker in path")
        )
    return [
        AccidentalInclusionFinding(logical_path, category, reason)
        for category, reason in matches
    ]


def _write_deterministic_pak(
    destination: Path,
    members: Iterable[_FrozenBuildMember],
    member_methods: Mapping[str, str],
) -> None:
    with zipfile.ZipFile(destination, "w", compresslevel=9) as archive:
        for member in members:
            method = member_methods[member.logical_path]
            compression = zipfile.ZIP_STORED if method == "stored" else zipfile.ZIP_DEFLATED
            info = zipfile.ZipInfo(member.logical_path, date_time=_FIXED_ZIP_TIME)
            info.compress_type = compression
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.extra = b""
            info.comment = b""
            info.file_size = len(member.data)
            with archive.open(
                info,
                "w",
                force_zip64=info.file_size >= zipfile.ZIP64_LIMIT,
            ) as output_stream:
                output_stream.write(member.data)


def _safe_logical_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BuildGuardError("logical paths must be non-empty canonical POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildGuardError("logical path is absolute, noncanonical, or contains traversal")
    canonical = path.as_posix()
    if canonical != value or re.match(r"^[A-Za-z]:", value):
        raise BuildGuardError("logical path is not canonical or contains a drive prefix")
    return canonical


def _is_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):
        return False


def _reject_reparse_tree(root: Path) -> None:
    if _is_reparse(root):
        raise BuildGuardError("staging path is a symlink or reparse point")
    if not root.is_dir():
        return
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in [*names, *files]:
            if _is_reparse(base / name):
                raise BuildGuardError("staging tree contains a symlink or reparse point")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detached_json_object(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        detached = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise BuildGuardError(f"{label} must contain JSON values only") from exc
    if not isinstance(detached, dict):
        raise BuildGuardError(f"{label} must be a JSON object")
    return detached


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json_write(path: Path, payload: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    temporary.write_text(data + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, path)
