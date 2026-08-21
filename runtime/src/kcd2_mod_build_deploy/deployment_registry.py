"""Immutable exact-deployment identities and fail-closed active-snapshot gates."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import ClassVar

from .candidate_registry import CandidateRegistry


MAX_DEPLOYMENTS = 10_000
MAX_COMPANIONS = 128
MAX_FILE_BYTES = 1_099_511_627_776
MAX_SNAPSHOT_AGE_SECONDS = 31 * 24 * 60 * 60
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_CANDIDATE_ID = re.compile(r"^cand:sha256:[A-Fa-f0-9]{64}$")
_DEPLOYMENT_ID = re.compile(r"^deploy:sha256:[A-Fa-f0-9]{64}$")
_MOD_ID = re.compile(r"^[a-z0-9_]+$")
_HEX = re.compile(r"^0x[A-Fa-f0-9]+$")


class DeploymentRegistryError(ValueError):
    """Exact deployment evidence is malformed or not registry-consistent."""


class SnapshotScope(StrEnum):
    EXACT_DEPLOYMENT = "exact_deployment"
    BROAD_PROVIDER_LAYER = "broad_provider_layer"


class SnapshotCoverage(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class DeploymentOperation(StrEnum):
    INSTALL_VALIDATION = "install_validation"
    WINNER_CLAIM = "winner_claim"
    CANDIDATE_SCOPED_PROBE = "candidate_scoped_probe"


def _text(value: object, field: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise DeploymentRegistryError(
            f"{field} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DeploymentRegistryError(f"{field} must be a SHA-256 digest")
    return value.lower()


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise DeploymentRegistryError(f"{field} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class DeploymentFileIdentity:
    path: str
    sha256: str
    bytes: int

    def __post_init__(self) -> None:
        _text(self.path, "file path")
        object.__setattr__(self, "sha256", _digest(self.sha256, "file sha256"))
        if (
            not isinstance(self.bytes, int)
            or isinstance(self.bytes, bool)
            or not 0 <= self.bytes <= MAX_FILE_BYTES
        ):
            raise DeploymentRegistryError(
                f"file bytes must be between 0 and {MAX_FILE_BYTES}"
            )

    def identity_payload(self) -> dict[str, object]:
        return {"bytes": self.bytes, "path": self.path, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class DeploymentComponentIdentity:
    role: str
    path: str
    sha256: str

    def __post_init__(self) -> None:
        _text(self.role, "component role", 128)
        _text(self.path, "component path")
        object.__setattr__(
            self, "sha256", _digest(self.sha256, "component sha256")
        )

    def identity_payload(self) -> dict[str, str]:
        return {"path": self.path, "role": self.role, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class DeploymentPeIdentity:
    name: str
    sha256: str
    timestamp: str
    image_size: int

    def __post_init__(self) -> None:
        _text(self.name, "PE name", 260)
        object.__setattr__(self, "sha256", _digest(self.sha256, "PE sha256"))
        if not isinstance(self.timestamp, str) or _HEX.fullmatch(self.timestamp) is None:
            raise DeploymentRegistryError("PE timestamp must be an emitted hexadecimal value")
        number = int(self.timestamp, 16)
        if number > 2**64 - 1:
            raise DeploymentRegistryError("PE timestamp exceeds the 64-bit bound")
        object.__setattr__(self, "timestamp", f"0x{number:X}")
        if (
            not isinstance(self.image_size, int)
            or isinstance(self.image_size, bool)
            or not 1 <= self.image_size <= MAX_FILE_BYTES
        ):
            raise DeploymentRegistryError("PE image_size is outside the valid bound")

    def identity_payload(self) -> dict[str, object]:
        return {
            "image_size": self.image_size,
            "name": self.name,
            "sha256": self.sha256,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class DeploymentGameIdentity:
    version: str
    executable: DeploymentPeIdentity
    whgame: DeploymentPeIdentity

    def __post_init__(self) -> None:
        _text(self.version, "game version", 128)
        if not isinstance(self.executable, DeploymentPeIdentity) or not isinstance(
            self.whgame, DeploymentPeIdentity
        ):
            raise DeploymentRegistryError("game executable and WHGame must be PE identities")

    def identity_payload(self) -> dict[str, object]:
        return {
            "executable": self.executable.identity_payload(),
            "version": self.version,
            "whgame": self.whgame.identity_payload(),
        }


@dataclass(frozen=True, slots=True)
class TargetModIdentity:
    mod_id: str
    folder_name_exact: str

    def __post_init__(self) -> None:
        if not isinstance(self.mod_id, str) or _MOD_ID.fullmatch(self.mod_id) is None:
            raise DeploymentRegistryError("mod_id must match ^[a-z0-9_]+$")
        _text(self.folder_name_exact, "folder_name_exact", 260)

    def identity_payload(self) -> dict[str, str]:
        return {"folder_name_exact": self.folder_name_exact, "mod_id": self.mod_id}


@dataclass(frozen=True, slots=True)
class ExactDeploymentIdentity:
    candidate_id: str
    target_mod: TargetModIdentity
    target_pak: DeploymentFileIdentity
    target_manifest: DeploymentFileIdentity
    mod_order: DeploymentFileIdentity
    companion_components: tuple[DeploymentComponentIdentity, ...]
    game: DeploymentGameIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.candidate_id, str) or _CANDIDATE_ID.fullmatch(
            self.candidate_id
        ) is None:
            raise DeploymentRegistryError("candidate_id must be content-addressed")
        object.__setattr__(self, "candidate_id", self.candidate_id.lower())
        if not isinstance(self.target_mod, TargetModIdentity):
            raise DeploymentRegistryError("target_mod must be a TargetModIdentity")
        for field in ("target_pak", "target_manifest", "mod_order"):
            if not isinstance(getattr(self, field), DeploymentFileIdentity):
                raise DeploymentRegistryError(f"{field} must be a file identity")
        companions = tuple(self.companion_components)
        if len(companions) > MAX_COMPANIONS or any(
            not isinstance(item, DeploymentComponentIdentity) for item in companions
        ):
            raise DeploymentRegistryError(
                f"companion_components must contain at most {MAX_COMPANIONS} identities"
            )
        keys = [(item.role, item.path) for item in companions]
        if len(keys) != len(set(keys)):
            raise DeploymentRegistryError("companion role/path identities must be unique")
        object.__setattr__(
            self,
            "companion_components",
            tuple(sorted(companions, key=lambda item: (item.role, item.path, item.sha256))),
        )
        if not isinstance(self.game, DeploymentGameIdentity):
            raise DeploymentRegistryError("game must be a DeploymentGameIdentity")

    def identity_payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "companion_components": [
                item.identity_payload() for item in self.companion_components
            ],
            "game": self.game.identity_payload(),
            "mod_order": self.mod_order.identity_payload(),
            "target_manifest": self.target_manifest.identity_payload(),
            "target_mod": self.target_mod.identity_payload(),
            "target_pak": self.target_pak.identity_payload(),
        }


@dataclass(frozen=True, slots=True)
class ExactActiveSnapshot:
    snapshot_id: str
    snapshot_sha256: str
    captured_at: datetime
    scope: SnapshotScope
    coverage: SnapshotCoverage
    identity: ExactDeploymentIdentity

    def __post_init__(self) -> None:
        _text(self.snapshot_id, "snapshot_id", 256)
        object.__setattr__(
            self, "snapshot_sha256", _digest(self.snapshot_sha256, "snapshot sha256")
        )
        object.__setattr__(self, "captured_at", _timestamp(self.captured_at, "captured_at"))
        try:
            object.__setattr__(self, "scope", SnapshotScope(self.scope))
            object.__setattr__(self, "coverage", SnapshotCoverage(self.coverage))
        except (TypeError, ValueError) as exc:
            raise DeploymentRegistryError("snapshot scope or coverage is invalid") from exc
        if not isinstance(self.identity, ExactDeploymentIdentity):
            raise DeploymentRegistryError("snapshot identity must be exact deployment identity")


@dataclass(frozen=True, slots=True)
class DeploymentNode:
    deployment_id: str
    candidate_id: str
    snapshot_id: str
    snapshot_sha256: str
    identity: ExactDeploymentIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.deployment_id, str) or _DEPLOYMENT_ID.fullmatch(
            self.deployment_id
        ) is None:
            raise DeploymentRegistryError("deployment_id must be content-addressed")
        object.__setattr__(self, "deployment_id", self.deployment_id.lower())
        if self.candidate_id != self.identity.candidate_id:
            raise DeploymentRegistryError("deployment candidate_id differs from its identity")
        _text(self.snapshot_id, "snapshot_id", 256)
        object.__setattr__(
            self, "snapshot_sha256", _digest(self.snapshot_sha256, "snapshot sha256")
        )
        expected = canonical_deployment_id(
            identity=self.identity,
            snapshot_id=self.snapshot_id,
            snapshot_sha256=self.snapshot_sha256,
        )
        if self.deployment_id != expected:
            raise DeploymentRegistryError(
                f"deployment_id does not match immutable identity: expected {expected}"
            )

    @property
    def folder_name_exact(self) -> str:
        return self.identity.target_mod.folder_name_exact

    def identity_payload(self) -> dict[str, object]:
        return {
            "deployment_identity": self.identity.identity_payload(),
            "identity_version": "kcd2.exact-deployment-identity.v1",
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
        }


def canonical_deployment_id(
    *,
    identity: ExactDeploymentIdentity,
    snapshot_id: str,
    snapshot_sha256: str,
) -> str:
    """Hash every immutable deployment and active-snapshot identity dimension."""

    if not isinstance(identity, ExactDeploymentIdentity):
        raise DeploymentRegistryError("identity must be an ExactDeploymentIdentity")
    checked_id = _text(snapshot_id, "snapshot_id", 256)
    checked_hash = _digest(snapshot_sha256, "snapshot sha256")
    payload = {
        "deployment_identity": identity.identity_payload(),
        "identity_version": "kcd2.exact-deployment-identity.v1",
        "snapshot_id": checked_id,
        "snapshot_sha256": checked_hash,
    }
    return "deploy:sha256:" + hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def create_deployment_node(snapshot: ExactActiveSnapshot) -> DeploymentNode:
    """Create one immutable node from caller-supplied exact snapshot evidence."""

    if not isinstance(snapshot, ExactActiveSnapshot):
        raise DeploymentRegistryError("snapshot must be an ExactActiveSnapshot")
    if (
        snapshot.scope is not SnapshotScope.EXACT_DEPLOYMENT
        or snapshot.coverage is not SnapshotCoverage.COMPLETE
    ):
        raise DeploymentRegistryError(
            "deployment nodes require a complete exact-deployment snapshot"
        )
    deployment_id = canonical_deployment_id(
        identity=snapshot.identity,
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
    )
    return DeploymentNode(
        deployment_id=deployment_id,
        candidate_id=snapshot.identity.candidate_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
        identity=snapshot.identity,
    )


@dataclass(frozen=True, slots=True)
class DeploymentRegistry:
    nodes: tuple[DeploymentNode, ...]
    candidates: CandidateRegistry
    MAX_RECORDS: ClassVar[int] = MAX_DEPLOYMENTS

    def __post_init__(self) -> None:
        nodes = tuple(self.nodes)
        if len(nodes) > self.MAX_RECORDS or any(
            not isinstance(node, DeploymentNode) for node in nodes
        ):
            raise DeploymentRegistryError(
                f"deployment registry accepts at most {self.MAX_RECORDS} nodes"
            )
        if not isinstance(self.candidates, CandidateRegistry):
            raise DeploymentRegistryError("candidates must be a CandidateRegistry")
        identifiers = [node.deployment_id for node in nodes]
        if len(identifiers) != len(set(identifiers)):
            raise DeploymentRegistryError("deployment registry contains duplicate IDs")
        by_candidate = {
            record.candidate_id: record for record in self.candidates.records
        }
        for node in nodes:
            record = by_candidate.get(node.candidate_id)
            if record is None:
                raise DeploymentRegistryError(
                    f"deployment references unknown candidate {node.candidate_id}"
                )
            expected_mod = record.identity
            if node.identity.target_mod.mod_id != expected_mod.mod_id:
                raise DeploymentRegistryError("deployment mod_id differs from candidate")
            if node.folder_name_exact != expected_mod.folder_name_exact:
                raise DeploymentRegistryError(
                    "deployment folder case differs from immutable candidate identity"
                )
            if node.identity.target_manifest.sha256 != expected_mod.manifest_sha256:
                raise DeploymentRegistryError("deployment manifest differs from candidate")
            runtime_paks = {
                (artifact.sha256, artifact.bytes)
                for artifact in expected_mod.artifacts
                if artifact.required_at_runtime
                and artifact.role in {"data_pak", "localization_pak"}
            }
            observed_pak = (node.identity.target_pak.sha256, node.identity.target_pak.bytes)
            if observed_pak not in runtime_paks:
                raise DeploymentRegistryError("deployment PAK is not a candidate artifact")
            required_native = {
                artifact.sha256
                for artifact in expected_mod.artifacts
                if artifact.required_at_runtime and artifact.role == "native_component"
            }
            observed_companions = {
                component.sha256 for component in node.identity.companion_components
            }
            if not required_native.issubset(observed_companions):
                raise DeploymentRegistryError(
                    "deployment companions omit a required native candidate artifact"
                )
        object.__setattr__(self, "nodes", tuple(sorted(nodes, key=lambda item: item.deployment_id)))

    def get(self, deployment_id: str) -> DeploymentNode | None:
        if not isinstance(deployment_id, str) or _DEPLOYMENT_ID.fullmatch(deployment_id) is None:
            return None
        normalized = deployment_id.lower()
        return next((node for node in self.nodes if node.deployment_id == normalized), None)

    def add(self, node: DeploymentNode) -> DeploymentRegistry:
        existing = self.get(node.deployment_id) if isinstance(node, DeploymentNode) else None
        if existing is not None:
            if existing == node:
                return self
            raise DeploymentRegistryError("deployment ID already has a different record")
        return DeploymentRegistry(self.nodes + (node,), self.candidates)


@dataclass(frozen=True, slots=True)
class SnapshotGateDecision:
    operation: DeploymentOperation
    deployment_id: str
    snapshot_id: str
    snapshot_sha256: str
    allowed: bool
    status: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "operation", DeploymentOperation(self.operation))
        except (TypeError, ValueError) as exc:
            raise DeploymentRegistryError("snapshot decision operation is invalid") from exc
        if not isinstance(self.deployment_id, str) or _DEPLOYMENT_ID.fullmatch(
            self.deployment_id
        ) is None:
            raise DeploymentRegistryError("snapshot decision deployment_id is invalid")
        object.__setattr__(self, "deployment_id", self.deployment_id.lower())
        _text(self.snapshot_id, "snapshot decision snapshot_id", 256)
        object.__setattr__(
            self,
            "snapshot_sha256",
            _digest(self.snapshot_sha256, "snapshot decision snapshot sha256"),
        )
        if not isinstance(self.allowed, bool):
            raise DeploymentRegistryError("snapshot decision allowed must be boolean")
        if self.status not in {"fresh_exact", "capture_inconclusive"}:
            raise DeploymentRegistryError("snapshot decision status is invalid")
        reasons = tuple(self.reason_codes)
        if any(not isinstance(reason, str) or not reason for reason in reasons):
            raise DeploymentRegistryError("snapshot decision reason codes are invalid")
        if len(set(reasons)) != len(reasons):
            raise DeploymentRegistryError("snapshot decision reason codes must be unique")
        if self.allowed != (self.status == "fresh_exact" and not reasons):
            raise DeploymentRegistryError("snapshot decision status is internally inconsistent")
        object.__setattr__(self, "reason_codes", tuple(sorted(reasons)))

    def authorizes(self, operation: DeploymentOperation | str) -> bool:
        try:
            requested = DeploymentOperation(operation)
        except (TypeError, ValueError):
            return False
        return self.allowed and self.operation is requested


def authorize_fresh_snapshot(
    *,
    registry: DeploymentRegistry,
    deployment_id: str,
    snapshot: ExactActiveSnapshot,
    operation: DeploymentOperation | str,
    evaluated_at: datetime,
    max_age_seconds: int,
) -> SnapshotGateDecision:
    """Fail closed unless one fresh, complete, exact snapshot matches the registry node."""

    if not isinstance(registry, DeploymentRegistry):
        raise DeploymentRegistryError("registry must be a DeploymentRegistry")
    if not isinstance(snapshot, ExactActiveSnapshot):
        raise DeploymentRegistryError("snapshot must be an ExactActiveSnapshot")
    try:
        checked_operation = DeploymentOperation(operation)
    except (TypeError, ValueError) as exc:
        raise DeploymentRegistryError("operation is not snapshot-gated") from exc
    evaluated = _timestamp(evaluated_at, "evaluated_at")
    if (
        not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or not 1 <= max_age_seconds <= MAX_SNAPSHOT_AGE_SECONDS
    ):
        raise DeploymentRegistryError(
            f"max_age_seconds must be from 1 through {MAX_SNAPSHOT_AGE_SECONDS}"
        )

    reasons: set[str] = set()
    node = registry.get(deployment_id)
    if node is None:
        reasons.add("DEPLOYMENT_NOT_REGISTERED")
    if snapshot.scope is not SnapshotScope.EXACT_DEPLOYMENT:
        reasons.add("SNAPSHOT_SCOPE_NOT_EXACT")
    if snapshot.coverage is not SnapshotCoverage.COMPLETE:
        reasons.add("SNAPSHOT_COVERAGE_INCOMPLETE")
    age = (evaluated - snapshot.captured_at).total_seconds()
    if age < 0:
        reasons.add("SNAPSHOT_FROM_FUTURE")
    elif age > max_age_seconds:
        reasons.add("SNAPSHOT_STALE")
    if node is not None:
        if snapshot.snapshot_id != node.snapshot_id:
            reasons.add("SNAPSHOT_ID_CHANGED")
        if snapshot.snapshot_sha256 != node.snapshot_sha256:
            reasons.add("SNAPSHOT_HASH_CHANGED")
        if snapshot.identity != node.identity:
            reasons.add("DEPLOYMENT_IDENTITY_CHANGED")

    allowed = not reasons
    return SnapshotGateDecision(
        operation=checked_operation,
        deployment_id=deployment_id,
        snapshot_id=snapshot.snapshot_id,
        snapshot_sha256=snapshot.snapshot_sha256,
        allowed=allowed,
        status="fresh_exact" if allowed else "capture_inconclusive",
        reason_codes=tuple(sorted(reasons)),
    )


@dataclass(frozen=True, slots=True)
class DeploymentBindingComparison:
    start_deployment_id: str
    close_deployment_id: str
    identity_unchanged: bool
    candidate_promotion_allowed: bool
    reason_codes: tuple[str, ...]


def compare_deployment_bindings(
    start: DeploymentNode, close: DeploymentNode
) -> DeploymentBindingComparison:
    """Compare exact start/close nodes; never fill missing or changed identity."""

    if not isinstance(start, DeploymentNode) or not isinstance(close, DeploymentNode):
        raise DeploymentRegistryError("start and close must be DeploymentNode values")
    reasons: set[str] = set()
    if start.candidate_id != close.candidate_id:
        reasons.add("CANDIDATE_CHANGED")
    if start.identity.target_mod != close.identity.target_mod:
        reasons.add("TARGET_MOD_OR_FOLDER_CASE_CHANGED")
    if start.identity.target_pak != close.identity.target_pak:
        reasons.add("TARGET_PAK_CHANGED")
    if start.identity.target_manifest != close.identity.target_manifest:
        reasons.add("TARGET_MANIFEST_CHANGED")
    if start.identity.mod_order != close.identity.mod_order:
        reasons.add("MOD_ORDER_CHANGED")
    if start.identity.companion_components != close.identity.companion_components:
        reasons.add("COMPANION_COMPONENTS_CHANGED")
    if start.identity.game != close.identity.game:
        reasons.add("GAME_IDENTITY_CHANGED")
    if start.snapshot_id != close.snapshot_id:
        reasons.add("SNAPSHOT_ID_CHANGED")
    if start.snapshot_sha256 != close.snapshot_sha256:
        reasons.add("SNAPSHOT_HASH_CHANGED")
    if start.deployment_id != close.deployment_id:
        reasons.add("DEPLOYMENT_IDENTITY_CHANGED")
    unchanged = not reasons
    return DeploymentBindingComparison(
        start_deployment_id=start.deployment_id,
        close_deployment_id=close.deployment_id,
        identity_unchanged=unchanged,
        candidate_promotion_allowed=unchanged,
        reason_codes=tuple(sorted(reasons)),
    )
