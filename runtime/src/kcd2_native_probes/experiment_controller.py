"""Immutable transaction controller for one bounded native experiment."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from kcd2_toolchain_core.cross_tool_identity import (
    CrossToolIdentity,
    IdentityMismatchError,
    assert_same_identity,
    bind_cross_tool_identity,
)


RECEIPT_VERSION = "kcd2.native-experiment-receipt.v1"
MAX_EVIDENCE_RECEIPTS = 64
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_FAILURE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_RECEIPT_FIELDS = {
    "schema_version",
    "receipt_id",
    "receipt_sha256",
    "experiment_id",
    "sequence",
    "mode",
    "stage",
    "status",
    "identity_id",
    "cross_tool_identity",
    "previous_receipt_sha256",
    "evidence_receipt_ids",
    "approval_id",
    "approval_operation",
    "approval_binding_sha256",
    "readiness_status",
    "debugger_state",
    "failure_code",
    "recorded_at",
}


class ExperimentMode(str, Enum):
    CURRENT = "current"
    LEGACY_AUDIT = "legacy_audit"


class NativeExperimentStage(str, Enum):
    CREATED = "CREATED"
    FINGERPRINT_VERIFIED = "FINGERPRINT_VERIFIED"
    STATIC_EVIDENCE_VERIFIED = "STATIC_EVIDENCE_VERIFIED"
    MANIFEST_SOURCE_VERIFIED = "MANIFEST_SOURCE_VERIFIED"
    DOUBLE_BUILD_VERIFIED = "DOUBLE_BUILD_VERIFIED"
    DLL_DESCRIPTOR_VERIFIED = "DLL_DESCRIPTOR_VERIFIED"
    INSTALL_APPROVED = "INSTALL_APPROVED"
    INSTALLED = "INSTALLED"
    DEBUGGER_READY = "DEBUGGER_READY"
    HANDOFF_READY = "HANDOFF_READY"
    CAPTURED = "CAPTURED"
    IMPORTED = "IMPORTED"
    INTERPRETED = "INTERPRETED"
    CLEANUP_APPROVED = "CLEANUP_APPROVED"
    CLEANUP_VERIFIED = "CLEANUP_VERIFIED"
    FAILED = "FAILED"


_CURRENT_TRANSITIONS = {
    NativeExperimentStage.CREATED: NativeExperimentStage.FINGERPRINT_VERIFIED,
    NativeExperimentStage.FINGERPRINT_VERIFIED: (
        NativeExperimentStage.STATIC_EVIDENCE_VERIFIED
    ),
    NativeExperimentStage.STATIC_EVIDENCE_VERIFIED: (
        NativeExperimentStage.MANIFEST_SOURCE_VERIFIED
    ),
    NativeExperimentStage.MANIFEST_SOURCE_VERIFIED: (
        NativeExperimentStage.DOUBLE_BUILD_VERIFIED
    ),
    NativeExperimentStage.DOUBLE_BUILD_VERIFIED: (
        NativeExperimentStage.DLL_DESCRIPTOR_VERIFIED
    ),
    NativeExperimentStage.DLL_DESCRIPTOR_VERIFIED: NativeExperimentStage.INSTALL_APPROVED,
    NativeExperimentStage.INSTALL_APPROVED: NativeExperimentStage.INSTALLED,
    NativeExperimentStage.INSTALLED: NativeExperimentStage.DEBUGGER_READY,
    NativeExperimentStage.DEBUGGER_READY: NativeExperimentStage.HANDOFF_READY,
    NativeExperimentStage.HANDOFF_READY: NativeExperimentStage.CAPTURED,
    NativeExperimentStage.CAPTURED: NativeExperimentStage.IMPORTED,
    NativeExperimentStage.IMPORTED: NativeExperimentStage.INTERPRETED,
    NativeExperimentStage.INTERPRETED: NativeExperimentStage.CLEANUP_APPROVED,
    NativeExperimentStage.CLEANUP_APPROVED: NativeExperimentStage.CLEANUP_VERIFIED,
}

_LEGACY_TRANSITIONS = {
    NativeExperimentStage.CREATED: NativeExperimentStage.FINGERPRINT_VERIFIED,
    NativeExperimentStage.FINGERPRINT_VERIFIED: (
        NativeExperimentStage.STATIC_EVIDENCE_VERIFIED
    ),
    NativeExperimentStage.STATIC_EVIDENCE_VERIFIED: NativeExperimentStage.IMPORTED,
    NativeExperimentStage.IMPORTED: NativeExperimentStage.INTERPRETED,
    NativeExperimentStage.INTERPRETED: NativeExperimentStage.CLEANUP_VERIFIED,
}


class ExperimentGateError(ValueError):
    """The requested transition did not satisfy the controller contract."""


class IdentityDriftError(ExperimentGateError):
    """A transition supplied a different cross-tool identity."""

    def __init__(self, message: str, failure_receipt: NativeExperimentReceipt) -> None:
        super().__init__(message)
        self.failure_receipt = failure_receipt


def _bounded_string(value: object, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ExperimentGateError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ExperimentGateError(f"{field} must be a SHA-256 digest")
    return value.lower()


def _recorded_at(value: object) -> str:
    text = _bounded_string(value, "recorded_at", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExperimentGateError("recorded_at must be an ISO-8601 date-time") from exc
    if parsed.tzinfo is None:
        raise ExperimentGateError("recorded_at must include a timezone")
    return text


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExperimentGateError("receipt is not canonical-JSON serializable") from exc


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    """The exact one-time approval facts copied from a verified approval receipt."""

    approval_id: str
    operation: str
    binding_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "approval_id", _bounded_string(self.approval_id, "approval_id"))
        object.__setattr__(self, "operation", _bounded_string(self.operation, "operation", 64))
        object.__setattr__(
            self,
            "binding_sha256",
            _digest(self.binding_sha256, "approval binding_sha256"),
        )


@dataclass(frozen=True, slots=True)
class NativeExperimentReceipt:
    """One immutable, hash-chained controller decision."""

    schema_version: str
    receipt_id: str
    receipt_sha256: str
    experiment_id: str
    sequence: int
    mode: str
    stage: str
    status: str
    identity_id: str
    cross_tool_identity: CrossToolIdentity
    previous_receipt_sha256: str | None
    evidence_receipt_ids: tuple[str, ...]
    approval_id: str | None
    approval_operation: str | None
    approval_binding_sha256: str | None
    readiness_status: str | None
    debugger_state: str | None
    failure_code: str | None
    recorded_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "experiment_id": self.experiment_id,
            "sequence": self.sequence,
            "mode": self.mode,
            "stage": self.stage,
            "status": self.status,
            "identity_id": self.identity_id,
            "cross_tool_identity": self.cross_tool_identity.to_dict(),
            "previous_receipt_sha256": self.previous_receipt_sha256,
            "evidence_receipt_ids": list(self.evidence_receipt_ids),
            "approval_id": self.approval_id,
            "approval_operation": self.approval_operation,
            "approval_binding_sha256": self.approval_binding_sha256,
            "readiness_status": self.readiness_status,
            "debugger_state": self.debugger_state,
            "failure_code": self.failure_code,
            "recorded_at": self.recorded_at,
        }


def _new_receipt(
    *,
    receipt_id: str,
    experiment_id: str,
    sequence: int,
    mode: ExperimentMode,
    stage: NativeExperimentStage,
    status: str,
    identity: CrossToolIdentity,
    previous_receipt_sha256: str | None,
    evidence_receipt_ids: tuple[str, ...],
    approval: ApprovalBinding | None,
    readiness_status: str | None,
    debugger_state: str | None,
    failure_code: str | None,
    recorded_at: str,
) -> NativeExperimentReceipt:
    payload = {
        "schema_version": RECEIPT_VERSION,
        "receipt_id": receipt_id,
        "experiment_id": experiment_id,
        "sequence": sequence,
        "mode": mode.value,
        "stage": stage.value,
        "status": status,
        "identity_id": identity.identity_id,
        "cross_tool_identity": identity.to_dict(),
        "previous_receipt_sha256": previous_receipt_sha256,
        "evidence_receipt_ids": list(evidence_receipt_ids),
        "approval_id": None if approval is None else approval.approval_id,
        "approval_operation": None if approval is None else approval.operation,
        "approval_binding_sha256": None if approval is None else approval.binding_sha256,
        "readiness_status": readiness_status,
        "debugger_state": debugger_state,
        "failure_code": failure_code,
        "recorded_at": recorded_at,
    }
    receipt_sha256 = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    return NativeExperimentReceipt(
        receipt_sha256=receipt_sha256,
        cross_tool_identity=identity,
        evidence_receipt_ids=evidence_receipt_ids,
        approval_id=payload["approval_id"],
        approval_operation=payload["approval_operation"],
        approval_binding_sha256=payload["approval_binding_sha256"],
        **{key: value for key, value in payload.items() if key not in {
            "evidence_receipt_ids",
            "approval_id",
            "approval_operation",
            "approval_binding_sha256",
            "cross_tool_identity",
        }},
    )


def verify_native_experiment_receipt(
    value: Mapping[str, Any] | NativeExperimentReceipt,
) -> CrossToolIdentity:
    """Verify one serialized receipt's hash, identity, and stage-local invariants."""
    record = value.to_dict() if isinstance(value, NativeExperimentReceipt) else dict(value)
    if set(record) != _RECEIPT_FIELDS:
        raise ExperimentGateError("native experiment receipt fields do not match the v1 contract")
    if record["schema_version"] != RECEIPT_VERSION:
        raise ExperimentGateError("native experiment receipt schema_version is unsupported")
    claimed_hash = _digest(record["receipt_sha256"], "receipt_sha256")
    payload = {key: item for key, item in record.items() if key != "receipt_sha256"}
    calculated_hash = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    if claimed_hash != calculated_hash:
        raise ExperimentGateError("native experiment receipt hash does not match its content")
    identity_value = record["cross_tool_identity"]
    if not isinstance(identity_value, Mapping):
        raise ExperimentGateError("cross_tool_identity must be an object")
    identity = bind_cross_tool_identity(identity_value)
    if record["identity_id"] != identity.identity_id:
        raise ExperimentGateError("receipt identity_id differs from cross_tool_identity")
    receipt_id = _bounded_string(record["receipt_id"], "receipt_id")
    if receipt_id not in identity.to_dict()["receipt_ids"]:
        raise ExperimentGateError("receipt_id is not identity-declared")
    _bounded_string(record["experiment_id"], "experiment_id")
    if (
        not isinstance(record["sequence"], int)
        or isinstance(record["sequence"], bool)
        or not 0 <= record["sequence"] <= 1000
    ):
        raise ExperimentGateError("sequence must be an integer between 0 and 1000")
    try:
        ExperimentMode(record["mode"])
        stage = NativeExperimentStage(record["stage"])
    except ValueError as exc:
        raise ExperimentGateError("receipt mode or stage is unsupported") from exc
    previous = record["previous_receipt_sha256"]
    if previous is not None:
        _digest(previous, "previous_receipt_sha256")
    evidence = record["evidence_receipt_ids"]
    if not isinstance(evidence, list):
        raise ExperimentGateError("serialized evidence_receipt_ids must be an array")
    _evidence_ids(evidence, identity, receipt_id)
    status = record["status"]
    failure_code = record["failure_code"]
    if status == "FAILED":
        if stage is not NativeExperimentStage.FAILED:
            raise ExperimentGateError("a failed receipt must use the FAILED stage")
        if not isinstance(failure_code, str) or _FAILURE_CODE.fullmatch(failure_code) is None:
            raise ExperimentGateError("a failed receipt requires a valid failure_code")
    elif status != "PASS" or failure_code is not None:
        raise ExperimentGateError("a passing receipt must not carry failure_code")
    _verify_optional_stage_fields(record, stage)
    _recorded_at(record["recorded_at"])
    return identity


def _verify_optional_stage_fields(
    record: Mapping[str, Any], stage: NativeExperimentStage
) -> None:
    approval_values = (
        record["approval_id"],
        record["approval_operation"],
        record["approval_binding_sha256"],
    )
    if stage in {
        NativeExperimentStage.INSTALL_APPROVED,
        NativeExperimentStage.CLEANUP_APPROVED,
    }:
        if not all(isinstance(value, str) and value for value in approval_values):
            raise ExperimentGateError("an approval stage requires the complete approval binding")
        expected_operation = (
            "deploy_native_component"
            if stage is NativeExperimentStage.INSTALL_APPROVED
            else "rollback"
        )
        if record["approval_operation"] != expected_operation:
            raise ExperimentGateError("approval operation does not match its stage")
        _digest(record["approval_binding_sha256"], "approval_binding_sha256")
    elif any(value is not None for value in approval_values):
        raise ExperimentGateError("approval binding is only valid on an approval stage")
    if stage is NativeExperimentStage.HANDOFF_READY:
        if record["readiness_status"] != "READY":
            raise ExperimentGateError("HANDOFF_READY requires READY")
    elif record["readiness_status"] is not None:
        raise ExperimentGateError("readiness_status is only valid on HANDOFF_READY")
    if stage is NativeExperimentStage.DEBUGGER_READY:
        if record["debugger_state"] != "connected_running":
            raise ExperimentGateError("DEBUGGER_READY requires connected_running")
    elif record["debugger_state"] is not None:
        raise ExperimentGateError("debugger_state is only valid on DEBUGGER_READY")


def verify_native_experiment_chain(
    receipts: Sequence[Mapping[str, Any] | NativeExperimentReceipt],
) -> CrossToolIdentity:
    """Verify a bounded receipt chain and return its byte-identical identity."""
    if isinstance(receipts, (str, bytes)) or not isinstance(receipts, Sequence):
        raise ExperimentGateError("receipts must be an array")
    if not 1 <= len(receipts) <= 1000:
        raise ExperimentGateError("receipts must contain 1..1000 items")
    expected_identity: CrossToolIdentity | None = None
    expected_experiment: str | None = None
    expected_mode: str | None = None
    previous_hash: str | None = None
    seen_ids: set[str] = set()
    for index, value in enumerate(receipts):
        record = value.to_dict() if isinstance(value, NativeExperimentReceipt) else dict(value)
        identity = verify_native_experiment_receipt(record)
        if record["sequence"] != index:
            raise ExperimentGateError("receipt sequence is not contiguous")
        if record["previous_receipt_sha256"] != previous_hash:
            raise ExperimentGateError("receipt previous hash does not match the chain")
        if record["receipt_id"] in seen_ids:
            raise ExperimentGateError("receipt_id is duplicated in the chain")
        seen_ids.add(record["receipt_id"])
        if index == 0:
            if record["stage"] != NativeExperimentStage.CREATED.value:
                raise ExperimentGateError("the first receipt must be CREATED")
            expected_identity = identity
            expected_experiment = record["experiment_id"]
            expected_mode = record["mode"]
        else:
            assert expected_identity is not None
            assert_same_identity(expected_identity, identity)
            if (
                record["experiment_id"] != expected_experiment
                or record["mode"] != expected_mode
            ):
                raise ExperimentGateError("experiment or mode drifted within the receipt chain")
        previous_hash = record["receipt_sha256"]
    assert expected_identity is not None
    return expected_identity


def _evidence_ids(
    values: Sequence[str], identity: CrossToolIdentity, receipt_id: str
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ExperimentGateError("evidence_receipt_ids must be an array")
    if not 1 <= len(values) <= MAX_EVIDENCE_RECEIPTS:
        raise ExperimentGateError(
            f"evidence_receipt_ids must contain 1..{MAX_EVIDENCE_RECEIPTS} items"
        )
    normalized = tuple(
        _bounded_string(value, f"evidence_receipt_ids[{index}]")
        for index, value in enumerate(values)
    )
    if len(set(normalized)) != len(normalized):
        raise ExperimentGateError("evidence_receipt_ids must be unique")
    declared = set(identity.to_dict()["receipt_ids"])
    undeclared = sorted(set(normalized) - declared)
    if undeclared:
        raise ExperimentGateError(f"evidence receipts are not identity-declared: {undeclared}")
    if receipt_id not in declared:
        raise ExperimentGateError("controller receipt_id is not identity-declared")
    if receipt_id in normalized:
        raise ExperimentGateError("a controller receipt cannot cite itself as evidence")
    return normalized


@dataclass(frozen=True, slots=True)
class NativeExperimentController:
    """Return a new controller for every accepted receipt; never mutate earlier state."""

    experiment_id: str
    mode: ExperimentMode
    identity: CrossToolIdentity
    stage: NativeExperimentStage
    receipts: tuple[NativeExperimentReceipt, ...]
    install_approval: ApprovalBinding | None = None
    cleanup_required: bool = False
    failure_code: str | None = None

    @classmethod
    def start(
        cls,
        *,
        experiment_id: str,
        mode: ExperimentMode | str,
        identity: Mapping[str, Any] | CrossToolIdentity,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
    ) -> NativeExperimentController:
        experiment_id = _bounded_string(experiment_id, "experiment_id")
        try:
            selected_mode = ExperimentMode(mode)
        except ValueError as exc:
            raise ExperimentGateError("mode must be current or legacy_audit") from exc
        bound = bind_cross_tool_identity(identity)
        receipt_id = _bounded_string(receipt_id, "receipt_id")
        evidence = _evidence_ids(evidence_receipt_ids, bound, receipt_id)
        receipt = _new_receipt(
            receipt_id=receipt_id,
            experiment_id=experiment_id,
            sequence=0,
            mode=selected_mode,
            stage=NativeExperimentStage.CREATED,
            status="PASS",
            identity=bound,
            previous_receipt_sha256=None,
            evidence_receipt_ids=evidence,
            approval=None,
            readiness_status=None,
            debugger_state=None,
            failure_code=None,
            recorded_at=_recorded_at(recorded_at),
        )
        return cls(
            experiment_id=experiment_id,
            mode=selected_mode,
            identity=bound,
            stage=NativeExperimentStage.CREATED,
            receipts=(receipt,),
        )

    @property
    def gameplay_handoff_allowed(self) -> bool:
        """Authorization is edge-triggered and exists only at the ready handoff stage."""
        return (
            self.mode is ExperimentMode.CURRENT
            and self.stage is NativeExperimentStage.HANDOFF_READY
        )

    def _validate_identity(
        self,
        identity: Mapping[str, Any] | CrossToolIdentity,
        *,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
    ) -> None:
        try:
            assert_same_identity(self.identity, identity)
        except (IdentityMismatchError, TypeError, ValueError) as exc:
            failure = self._standalone_failure_receipt(
                failure_code="IDENTITY_DRIFT",
                receipt_id=receipt_id,
                recorded_at=recorded_at,
                evidence_receipt_ids=evidence_receipt_ids,
            )
            raise IdentityDriftError(
                "cross-tool identity drift halted progression", failure
            ) from exc

    def _standalone_failure_receipt(
        self,
        *,
        failure_code: str,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
    ) -> NativeExperimentReceipt:
        receipt_id = _bounded_string(receipt_id, "receipt_id")
        evidence = _evidence_ids(evidence_receipt_ids, self.identity, receipt_id)
        return _new_receipt(
            receipt_id=receipt_id,
            experiment_id=self.experiment_id,
            sequence=len(self.receipts),
            mode=self.mode,
            stage=NativeExperimentStage.FAILED,
            status="FAILED",
            identity=self.identity,
            previous_receipt_sha256=self.receipts[-1].receipt_sha256,
            evidence_receipt_ids=evidence,
            approval=None,
            readiness_status=None,
            debugger_state=None,
            failure_code=failure_code,
            recorded_at=_recorded_at(recorded_at),
        )

    def _expected_stage(self) -> NativeExperimentStage:
        if self.stage is NativeExperimentStage.FAILED and self.cleanup_required:
            return NativeExperimentStage.CLEANUP_APPROVED
        transitions = (
            _CURRENT_TRANSITIONS if self.mode is ExperimentMode.CURRENT else _LEGACY_TRANSITIONS
        )
        expected = transitions.get(self.stage)
        if expected is None:
            raise ExperimentGateError(f"stage {self.stage.value} is terminal")
        return expected

    def advance(
        self,
        stage: NativeExperimentStage | str,
        *,
        identity: Mapping[str, Any] | CrossToolIdentity,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
        approval: ApprovalBinding | None = None,
        readiness_status: str | None = None,
        gameplay_handoff_allowed: bool | None = None,
        debugger_state: str | None = None,
    ) -> NativeExperimentController:
        try:
            requested = NativeExperimentStage(stage)
        except ValueError as exc:
            raise ExperimentGateError("unknown native experiment stage") from exc
        self._validate_identity(
            identity,
            receipt_id=receipt_id,
            recorded_at=recorded_at,
            evidence_receipt_ids=evidence_receipt_ids,
        )
        expected = self._expected_stage()
        if requested is not expected:
            qualifier = (
                "audit-only route expected"
                if self.mode is ExperimentMode.LEGACY_AUDIT
                else "expected"
            )
            raise ExperimentGateError(
                f"{qualifier} {expected.value}, not {requested.value}"
            )
        receipt_id = _bounded_string(receipt_id, "receipt_id")
        if receipt_id in {receipt.receipt_id for receipt in self.receipts}:
            raise ExperimentGateError("controller receipt_id was already consumed")
        evidence = _evidence_ids(evidence_receipt_ids, self.identity, receipt_id)
        selected_approval = self._validate_stage_gate(
            requested,
            approval=approval,
            readiness_status=readiness_status,
            gameplay_handoff_allowed=gameplay_handoff_allowed,
            debugger_state=debugger_state,
        )
        receipt = _new_receipt(
            receipt_id=receipt_id,
            experiment_id=self.experiment_id,
            sequence=len(self.receipts),
            mode=self.mode,
            stage=requested,
            status="PASS",
            identity=self.identity,
            previous_receipt_sha256=self.receipts[-1].receipt_sha256,
            evidence_receipt_ids=evidence,
            approval=selected_approval,
            readiness_status=readiness_status,
            debugger_state=debugger_state,
            failure_code=None,
            recorded_at=_recorded_at(recorded_at),
        )
        install_approval = self.install_approval
        if requested is NativeExperimentStage.INSTALL_APPROVED:
            install_approval = selected_approval
        return NativeExperimentController(
            experiment_id=self.experiment_id,
            mode=self.mode,
            identity=self.identity,
            stage=requested,
            receipts=(*self.receipts, receipt),
            install_approval=install_approval,
            cleanup_required=(
                False
                if requested is NativeExperimentStage.CLEANUP_VERIFIED
                else self.cleanup_required
                or requested
                in {
                    NativeExperimentStage.INSTALLED,
                    NativeExperimentStage.DEBUGGER_READY,
                    NativeExperimentStage.HANDOFF_READY,
                    NativeExperimentStage.CAPTURED,
                    NativeExperimentStage.IMPORTED,
                    NativeExperimentStage.INTERPRETED,
                    NativeExperimentStage.CLEANUP_APPROVED,
                }
            ),
            failure_code=self.failure_code,
        )

    def _validate_stage_gate(
        self,
        stage: NativeExperimentStage,
        *,
        approval: ApprovalBinding | None,
        readiness_status: str | None,
        gameplay_handoff_allowed: bool | None,
        debugger_state: str | None,
    ) -> ApprovalBinding | None:
        if stage is NativeExperimentStage.INSTALL_APPROVED:
            if approval is None or approval.operation != "deploy_native_component":
                raise ExperimentGateError(
                    "install requires an exact deploy_native_component approval"
                )
            return approval
        if stage is NativeExperimentStage.CLEANUP_APPROVED:
            if approval is None or approval.operation != "rollback":
                raise ExperimentGateError("cleanup requires an exact rollback approval")
            if self.install_approval is None:
                raise ExperimentGateError("cleanup cannot precede install approval")
            if (
                approval.approval_id == self.install_approval.approval_id
                or approval.binding_sha256 == self.install_approval.binding_sha256
            ):
                raise ExperimentGateError("install and cleanup approvals must be distinct")
            return approval
        if approval is not None:
            raise ExperimentGateError("approval may only be attached to an approval stage")
        if stage is NativeExperimentStage.DEBUGGER_READY:
            if debugger_state != "connected_running":
                raise ExperimentGateError("debugger readiness requires connected_running")
        elif debugger_state is not None:
            raise ExperimentGateError("debugger_state may only be attached to DEBUGGER_READY")
        if stage is NativeExperimentStage.HANDOFF_READY:
            if readiness_status != "READY" or gameplay_handoff_allowed is not True:
                raise ExperimentGateError(
                    "gameplay handoff requires a positive readiness receipt"
                )
        elif readiness_status is not None or gameplay_handoff_allowed is not None:
            raise ExperimentGateError("readiness may only be attached to HANDOFF_READY")
        return None

    def fail(
        self,
        *,
        failure_code: str,
        identity: Mapping[str, Any] | CrossToolIdentity,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
    ) -> NativeExperimentController:
        self._validate_identity(
            identity,
            receipt_id=receipt_id,
            recorded_at=recorded_at,
            evidence_receipt_ids=evidence_receipt_ids,
        )
        if self.stage in {NativeExperimentStage.CLEANUP_VERIFIED, NativeExperimentStage.FAILED}:
            raise ExperimentGateError(f"stage {self.stage.value} is terminal")
        if not isinstance(failure_code, str) or _FAILURE_CODE.fullmatch(failure_code) is None:
            raise ExperimentGateError("failure_code must be bounded uppercase snake case")
        receipt = self._standalone_failure_receipt(
            failure_code=failure_code,
            receipt_id=receipt_id,
            recorded_at=recorded_at,
            evidence_receipt_ids=evidence_receipt_ids,
        )
        return NativeExperimentController(
            experiment_id=self.experiment_id,
            mode=self.mode,
            identity=self.identity,
            stage=NativeExperimentStage.FAILED,
            receipts=(*self.receipts, receipt),
            install_approval=self.install_approval,
            cleanup_required=self.cleanup_required,
            failure_code=failure_code,
        )

    def complete_cleanup(
        self,
        *,
        succeeded: bool,
        failure_code: str | None,
        identity: Mapping[str, Any] | CrossToolIdentity,
        receipt_id: str,
        recorded_at: str,
        evidence_receipt_ids: Sequence[str],
    ) -> NativeExperimentController:
        if self.stage is not NativeExperimentStage.CLEANUP_APPROVED:
            raise ExperimentGateError("cleanup completion requires CLEANUP_APPROVED")
        if succeeded:
            if failure_code is not None:
                raise ExperimentGateError("successful cleanup cannot carry failure_code")
            return self.advance(
                NativeExperimentStage.CLEANUP_VERIFIED,
                identity=identity,
                receipt_id=receipt_id,
                recorded_at=recorded_at,
                evidence_receipt_ids=evidence_receipt_ids,
            )
        code = failure_code or "CLEANUP_FAILED"
        return self.fail(
            failure_code=code,
            identity=identity,
            receipt_id=receipt_id,
            recorded_at=recorded_at,
            evidence_receipt_ids=evidence_receipt_ids,
        )


__all__ = [
    "ApprovalBinding",
    "ExperimentGateError",
    "ExperimentMode",
    "IdentityDriftError",
    "NativeExperimentController",
    "NativeExperimentReceipt",
    "NativeExperimentStage",
    "verify_native_experiment_chain",
    "verify_native_experiment_receipt",
]
