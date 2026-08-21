"""Immutable, content-addressed candidate lineage registry and DAG validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import ClassVar, Iterable


MAX_ARTIFACTS = 128
MAX_ALIASES = 64
MAX_LINEAGE_EDGES = 128
MAX_EVIDENCE_REFS = 256
MAX_RECORDS = 10_000
MAX_ARTIFACT_BYTES = 1_099_511_627_776
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_CANDIDATE_ID = re.compile(r"^cand:sha256:([A-Fa-f0-9]{64})$")
_MOD_ID = re.compile(r"^[a-z0-9_]+$")
_ARTIFACT_ROLES = frozenset(
    {"data_pak", "localization_pak", "manifest", "config", "native_component", "other"}
)
_ALIAS_TYPES = frozenset(
    {"human_candidate_label", "version", "release_name", "historical_report_label"}
)
_EDGE_TYPES = frozenset(
    {"derived_from", "rebuilt_from", "variant_of", "supersedes", "rollback_of"}
)
_PARENT_EDGE_TYPES = frozenset({"derived_from", "rebuilt_from"})


class CandidateRegistryError(ValueError):
    """Base error for invalid candidate identities and registries."""


class CandidateIdentityError(CandidateRegistryError):
    """Raised when immutable candidate identity input is malformed."""


class AliasConflictError(CandidateRegistryError):
    """Raised when one human label ambiguously names multiple identities."""


class LineageCycleError(CandidateRegistryError):
    """Raised when lineage relationships do not form a DAG."""


class UnknownInstalledArtifactError(CandidateRegistryError):
    """Raised when installed evidence does not exactly match a registered artifact."""


def _bounded_string(value: object, *, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise CandidateIdentityError(
            f"{field} must be a string containing between {minimum} and {maximum} characters"
        )
    return value


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise CandidateIdentityError(f"{field} must be a SHA-256 hex digest")
    return value.lower()


def _candidate_id(value: object, *, field: str = "candidate_id") -> str:
    if not isinstance(value, str) or (match := _CANDIDATE_ID.fullmatch(value)) is None:
        raise CandidateIdentityError(f"{field} must be a content-addressed candidate ID")
    return "cand:sha256:" + match.group(1).lower()


def _evidence_refs(values: Iterable[str]) -> tuple[str, ...]:
    refs = tuple(values)
    if not 1 <= len(refs) <= MAX_EVIDENCE_REFS:
        raise CandidateIdentityError(
            f"evidence_refs must contain between 1 and {MAX_EVIDENCE_REFS} values"
        )
    for ref in refs:
        _bounded_string(ref, field="evidence_refs item", minimum=1, maximum=512)
    if len(set(refs)) != len(refs):
        raise CandidateIdentityError("evidence_refs must not contain duplicates")
    return refs


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    role: str
    logical_path: str
    sha256: str
    bytes: int
    required_at_runtime: bool = True

    def __post_init__(self) -> None:
        if self.role not in _ARTIFACT_ROLES:
            raise CandidateIdentityError(f"unsupported artifact role: {self.role!r}")
        _bounded_string(self.logical_path, field="logical_path", minimum=1, maximum=2048)
        object.__setattr__(self, "sha256", _sha256(self.sha256, field="artifact sha256"))
        if (
            not isinstance(self.bytes, int)
            or isinstance(self.bytes, bool)
            or not 0 <= self.bytes <= MAX_ARTIFACT_BYTES
        ):
            raise CandidateIdentityError(
                f"artifact bytes must be between 0 and {MAX_ARTIFACT_BYTES}"
            )
        if not isinstance(self.required_at_runtime, bool):
            raise CandidateIdentityError("required_at_runtime must be boolean")

    def identity_payload(self) -> dict[str, object]:
        return {
            "bytes": self.bytes,
            "logical_path": self.logical_path,
            "required_at_runtime": self.required_at_runtime,
            "role": self.role,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolchainIdentity:
    id: str
    version: str
    lock_sha256: str

    def __post_init__(self) -> None:
        _bounded_string(self.id, field="toolchain id", minimum=1, maximum=256)
        _bounded_string(self.version, field="toolchain version", minimum=1, maximum=256)
        object.__setattr__(
            self,
            "lock_sha256",
            _sha256(self.lock_sha256, field="toolchain lock_sha256"),
        )

    def identity_payload(self) -> dict[str, str]:
        return {"id": self.id, "lock_sha256": self.lock_sha256, "version": self.version}


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    """Immutable inputs committed by a canonical candidate ID.

    Human aliases, lifecycle events, and timestamps are deliberately absent: rebuilding the
    same immutable inputs must reproduce the same identity.
    """

    mod_id: str
    folder_name_exact: str
    manifest_sha256: str
    artifacts: tuple[ArtifactIdentity, ...]
    parent_candidate_id: str | None
    parent_artifact_sha256: str | None
    change_ledger_sha256: str
    source_revision: str | None
    source_tree_sha256: str
    build_recipe_sha256: str
    toolchain: ToolchainIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.mod_id, str) or not _MOD_ID.fullmatch(self.mod_id):
            raise CandidateIdentityError("mod_id must match ^[a-z0-9_]+$")
        if len(self.mod_id) > 200:
            raise CandidateIdentityError("mod_id must not exceed 200 characters")
        _bounded_string(
            self.folder_name_exact,
            field="folder_name_exact",
            minimum=1,
            maximum=260,
        )
        object.__setattr__(
            self,
            "manifest_sha256",
            _sha256(self.manifest_sha256, field="manifest_sha256"),
        )
        artifacts = tuple(self.artifacts)
        if not 1 <= len(artifacts) <= MAX_ARTIFACTS:
            raise CandidateIdentityError(
                f"artifacts must contain between 1 and {MAX_ARTIFACTS} entries"
            )
        if any(not isinstance(artifact, ArtifactIdentity) for artifact in artifacts):
            raise CandidateIdentityError("artifacts accepts ArtifactIdentity values only")
        paths = [artifact.logical_path for artifact in artifacts]
        if len(set(paths)) != len(paths):
            raise CandidateIdentityError("artifact logical paths must be unique")
        object.__setattr__(self, "artifacts", artifacts)

        if (self.parent_candidate_id is None) != (self.parent_artifact_sha256 is None):
            raise CandidateIdentityError(
                "parent_candidate_id and parent_artifact_sha256 must both be null or both be set"
            )
        if self.parent_candidate_id is not None:
            object.__setattr__(
                self,
                "parent_candidate_id",
                _candidate_id(self.parent_candidate_id, field="parent_candidate_id"),
            )
            object.__setattr__(
                self,
                "parent_artifact_sha256",
                _sha256(self.parent_artifact_sha256, field="parent_artifact_sha256"),
            )
        object.__setattr__(
            self,
            "change_ledger_sha256",
            _sha256(self.change_ledger_sha256, field="change_ledger_sha256"),
        )
        if self.source_revision is not None:
            _bounded_string(
                self.source_revision,
                field="source_revision",
                minimum=1,
                maximum=256,
            )
        object.__setattr__(
            self,
            "source_tree_sha256",
            _sha256(self.source_tree_sha256, field="source_tree_sha256"),
        )
        object.__setattr__(
            self,
            "build_recipe_sha256",
            _sha256(self.build_recipe_sha256, field="build_recipe_sha256"),
        )
        if not isinstance(self.toolchain, ToolchainIdentity):
            raise CandidateIdentityError("toolchain must be a ToolchainIdentity")

    def identity_payload(self) -> dict[str, object]:
        artifacts = sorted(
            (artifact.identity_payload() for artifact in self.artifacts),
            key=lambda item: (
                str(item["logical_path"]),
                str(item["role"]),
                str(item["sha256"]),
                int(item["bytes"]),
            ),
        )
        return {
            "artifact_set": artifacts,
            "build_recipe_sha256": self.build_recipe_sha256,
            "change_ledger_sha256": self.change_ledger_sha256,
            "folder_name_exact": self.folder_name_exact,
            "identity_version": "kcd2.candidate-identity.v1",
            "manifest_sha256": self.manifest_sha256,
            "mod_id": self.mod_id,
            "parent": {
                "artifact_sha256": self.parent_artifact_sha256,
                "candidate_id": self.parent_candidate_id,
            },
            "source_revision": self.source_revision,
            "source_tree_sha256": self.source_tree_sha256,
            "toolchain": self.toolchain.identity_payload(),
        }


def canonical_candidate_id(identity: CandidateIdentity) -> str:
    """Hash a canonical serialization of every immutable candidate identity input."""
    if not isinstance(identity, CandidateIdentity):
        raise TypeError("identity must be a CandidateIdentity")
    encoded = json.dumps(
        identity.identity_payload(),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "cand:sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CandidateAlias:
    label: str
    alias_type: str
    variant_key: str | None = None

    def __post_init__(self) -> None:
        _bounded_string(self.label, field="alias label", minimum=1, maximum=256)
        if self.alias_type not in _ALIAS_TYPES:
            raise CandidateIdentityError(f"unsupported alias_type: {self.alias_type!r}")
        if self.variant_key is not None:
            _bounded_string(self.variant_key, field="variant_key", minimum=1, maximum=256)


@dataclass(frozen=True, slots=True)
class CandidateLineageEdge:
    edge_type: str
    other_candidate_id: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.edge_type not in _EDGE_TYPES:
            raise CandidateIdentityError(f"unsupported edge_type: {self.edge_type!r}")
        object.__setattr__(
            self,
            "other_candidate_id",
            _candidate_id(self.other_candidate_id, field="other_candidate_id"),
        )
        object.__setattr__(self, "evidence_refs", _evidence_refs(self.evidence_refs))


@dataclass(frozen=True, slots=True)
class CandidateRecord:
    candidate_id: str
    identity: CandidateIdentity
    aliases: tuple[CandidateAlias, ...] = ()
    lineage: tuple[CandidateLineageEdge, ...] = ()

    def __post_init__(self) -> None:
        candidate_id = _candidate_id(self.candidate_id)
        object.__setattr__(self, "candidate_id", candidate_id)
        if not isinstance(self.identity, CandidateIdentity):
            raise CandidateIdentityError("identity must be a CandidateIdentity")
        expected = canonical_candidate_id(self.identity)
        if candidate_id != expected:
            raise CandidateIdentityError(
                f"candidate_id does not match canonical immutable identity: expected {expected}"
            )
        aliases = tuple(self.aliases)
        if len(aliases) > MAX_ALIASES:
            raise CandidateIdentityError(f"aliases exceeds the limit of {MAX_ALIASES}")
        if any(not isinstance(alias, CandidateAlias) for alias in aliases):
            raise CandidateIdentityError("aliases accepts CandidateAlias values only")
        if len(set(aliases)) != len(aliases):
            raise CandidateIdentityError("aliases must not contain duplicates")
        object.__setattr__(self, "aliases", aliases)

        lineage = tuple(self.lineage)
        if len(lineage) > MAX_LINEAGE_EDGES:
            raise CandidateIdentityError(
                f"lineage exceeds the limit of {MAX_LINEAGE_EDGES} edges"
            )
        if any(not isinstance(edge, CandidateLineageEdge) for edge in lineage):
            raise CandidateIdentityError("lineage accepts CandidateLineageEdge values only")
        edge_keys = [(edge.edge_type, edge.other_candidate_id) for edge in lineage]
        if len(set(edge_keys)) != len(edge_keys):
            raise CandidateIdentityError("lineage must not contain duplicate relationships")
        if any(edge.other_candidate_id == candidate_id for edge in lineage):
            raise LineageCycleError("candidate lineage cannot contain a self-edge")
        object.__setattr__(self, "lineage", lineage)


@dataclass(frozen=True, slots=True)
class InstalledArtifact:
    candidate_id: str
    logical_path: str
    sha256: str
    bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", _candidate_id(self.candidate_id))
        _bounded_string(self.logical_path, field="logical_path", minimum=1, maximum=2048)
        object.__setattr__(self, "sha256", _sha256(self.sha256, field="installed sha256"))
        if (
            not isinstance(self.bytes, int)
            or isinstance(self.bytes, bool)
            or not 0 <= self.bytes <= MAX_ARTIFACT_BYTES
        ):
            raise CandidateIdentityError(
                f"installed artifact bytes must be between 0 and {MAX_ARTIFACT_BYTES}"
            )


@dataclass(frozen=True, slots=True)
class CandidateRegistry:
    """An immutable registry whose relationships are validated as one bounded DAG."""

    records: tuple[CandidateRecord, ...] = ()
    MAX_RECORDS: ClassVar[int] = MAX_RECORDS

    def __post_init__(self) -> None:
        records = tuple(self.records)
        if len(records) > self.MAX_RECORDS:
            raise CandidateRegistryError(
                f"candidate registry exceeds the limit of {self.MAX_RECORDS} records"
            )
        if any(not isinstance(record, CandidateRecord) for record in records):
            raise CandidateRegistryError("registry accepts CandidateRecord values only")
        identifiers = [record.candidate_id for record in records]
        if len(set(identifiers)) != len(identifiers):
            raise CandidateRegistryError("registry contains duplicate candidate IDs")
        records = tuple(sorted(records, key=lambda record: record.candidate_id))
        object.__setattr__(self, "records", records)
        by_id = {record.candidate_id: record for record in records}
        self._validate_lineage_targets(by_id)
        self._validate_parent_bindings(by_id)
        self._validate_acyclic(by_id)
        self._validate_aliases(by_id)

    def add(self, record: CandidateRecord) -> CandidateRegistry:
        """Return a new validated registry, preserving every existing record byte-for-byte."""
        if not isinstance(record, CandidateRecord):
            raise CandidateRegistryError("add accepts a CandidateRecord value only")
        existing = next(
            (item for item in self.records if item.candidate_id == record.candidate_id),
            None,
        )
        if existing is not None:
            if existing == record:
                return self
            raise CandidateRegistryError(
                f"candidate {record.candidate_id} already has a different immutable record"
            )
        return CandidateRegistry(self.records + (record,))

    def validate_installed_artifacts(self, artifacts: Iterable[InstalledArtifact]) -> None:
        """Fail closed unless every observed installed artifact is an exact registry member."""
        observed = tuple(artifacts)
        if len(observed) > MAX_ARTIFACTS * max(1, len(self.records)):
            raise UnknownInstalledArtifactError("installed artifact set exceeds registry bounds")
        if any(not isinstance(item, InstalledArtifact) for item in observed):
            raise UnknownInstalledArtifactError(
                "installed artifact evidence accepts InstalledArtifact values only"
            )
        by_id = {record.candidate_id: record for record in self.records}
        for item in observed:
            record = by_id.get(item.candidate_id)
            if record is None:
                raise UnknownInstalledArtifactError(
                    f"installed artifact references unknown candidate {item.candidate_id}"
                )
            expected = {
                (artifact.logical_path, artifact.sha256, artifact.bytes)
                for artifact in record.identity.artifacts
            }
            exact = (item.logical_path, item.sha256, item.bytes)
            if exact not in expected:
                raise UnknownInstalledArtifactError(
                    "installed artifact is unknown or differs from its registered hash/size: "
                    f"{item.candidate_id} {item.logical_path}"
                )

    @staticmethod
    def _validate_lineage_targets(by_id: dict[str, CandidateRecord]) -> None:
        for record in by_id.values():
            for edge in record.lineage:
                if edge.other_candidate_id not in by_id:
                    raise CandidateRegistryError(
                        f"lineage edge references unknown candidate {edge.other_candidate_id}"
                    )

    @staticmethod
    def _validate_parent_bindings(by_id: dict[str, CandidateRecord]) -> None:
        for record in by_id.values():
            parent_id = record.identity.parent_candidate_id
            parent_edges = [
                edge for edge in record.lineage if edge.edge_type in _PARENT_EDGE_TYPES
            ]
            if parent_id is None:
                if parent_edges:
                    raise CandidateRegistryError(
                        f"unparented candidate {record.candidate_id} declares a parent edge"
                    )
                continue
            if len(parent_edges) != 1 or parent_edges[0].other_candidate_id != parent_id:
                raise CandidateRegistryError(
                    "parented candidate must declare exactly one derived_from or rebuilt_from "
                    f"edge to its immutable parent: {record.candidate_id}"
                )
            parent = by_id.get(parent_id)
            if parent is None:
                raise CandidateRegistryError(
                    f"parent identity references unknown candidate {parent_id}"
                )
            parent_hashes = {artifact.sha256 for artifact in parent.identity.artifacts}
            if record.identity.parent_artifact_sha256 not in parent_hashes:
                raise CandidateRegistryError(
                    "parent artifact hash is not present in the immutable parent artifact set: "
                    f"{record.candidate_id}"
                )

    @staticmethod
    def _validate_acyclic(by_id: dict[str, CandidateRecord]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(candidate_id: str) -> None:
            if candidate_id in visiting:
                raise LineageCycleError(f"candidate lineage cycle includes {candidate_id}")
            if candidate_id in visited:
                return
            visiting.add(candidate_id)
            for edge in by_id[candidate_id].lineage:
                visit(edge.other_candidate_id)
            visiting.remove(candidate_id)
            visited.add(candidate_id)

        for candidate_id in sorted(by_id):
            visit(candidate_id)

    @staticmethod
    def _validate_aliases(by_id: dict[str, CandidateRecord]) -> None:
        label_members: dict[str, list[tuple[str, CandidateAlias]]] = {}
        variant_neighbors: dict[str, set[str]] = {candidate_id: set() for candidate_id in by_id}
        for record in by_id.values():
            for alias in record.aliases:
                label_members.setdefault(alias.label.casefold(), []).append(
                    (record.candidate_id, alias)
                )
            for edge in record.lineage:
                if edge.edge_type == "variant_of":
                    variant_neighbors[record.candidate_id].add(edge.other_candidate_id)
                    variant_neighbors[edge.other_candidate_id].add(record.candidate_id)

        for normalized_label, members in label_members.items():
            candidate_ids = {candidate_id for candidate_id, _ in members}
            if len(candidate_ids) < 2:
                continue
            variant_keys = {alias.variant_key for _, alias in members}
            if None in variant_keys or len(variant_keys) != 1:
                raise AliasConflictError(
                    f"duplicate human label {normalized_label!r} requires one shared variant_key"
                )
            start = min(candidate_ids)
            reachable = {start}
            pending = [start]
            while pending:
                current = pending.pop()
                for neighbor in variant_neighbors[current]:
                    if neighbor not in reachable:
                        reachable.add(neighbor)
                        pending.append(neighbor)
            if not candidate_ids.issubset(reachable):
                raise AliasConflictError(
                    f"duplicate human label {normalized_label!r} requires explicit variant_of edges"
                )


def validate_candidate_dag(records: Iterable[CandidateRecord]) -> CandidateRegistry:
    """Build and validate a bounded immutable registry DAG from candidate records."""
    return CandidateRegistry(tuple(records))
