"""Declarative combat-candidate identity, lineage-role, and transform contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


MAX_DONORS = 64
MAX_TRANSFORMS = 512
MAX_ALLOWED_PATHS = 512
MAX_JSON_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_TRANSFORM_KINDS = {
    "adb_fragment_delete",
    "adb_fragment_replace",
    "tbl_row_delete",
    "tbl_row_upsert",
    "xml_row_delete",
    "xml_row_upsert",
}


class CombatCandidateSpecError(ValueError):
    """The combat candidate declaration is ambiguous or exceeds its bounds."""


@dataclass(frozen=True, slots=True)
class ArtifactRole:
    role: str
    identity_id: str
    artifact_sha256: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "identity_id": self.identity_id,
            "artifact_sha256": self.artifact_sha256,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class SemanticDonor:
    donor_id: str
    identity_id: str
    artifact_sha256: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "donor_id": self.donor_id,
            "identity_id": self.identity_id,
            "artifact_sha256": self.artifact_sha256,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True, slots=True)
class CombatTransformDeclaration:
    transform_id: str
    kind: str
    target_path: str
    selector: Mapping[str, Any]
    donor_id: str | None
    expected_target_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "transform_id": self.transform_id,
            "kind": self.kind,
            "target_path": self.target_path,
            "selector": dict(self.selector),
            "donor_id": self.donor_id,
            "expected_target_sha256": self.expected_target_sha256,
        }


@dataclass(frozen=True, slots=True)
class CombatCandidateSpec:
    schema_version: str
    spec_id: str
    candidate_number: int
    structural_parent: ArtifactRole
    installed_predecessor: ArtifactRole | None
    semantic_donors: tuple[SemanticDonor, ...]
    allowed_paths: tuple[str, ...]
    transforms: tuple[CombatTransformDeclaration, ...]

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_number": self.candidate_number,
            "structural_parent": self.structural_parent.to_dict(),
            "installed_predecessor": (
                None if self.installed_predecessor is None else self.installed_predecessor.to_dict()
            ),
            "semantic_donors": [item.to_dict() for item in self.semantic_donors],
            "allowed_paths": list(self.allowed_paths),
            "transforms": [item.to_dict() for item in self.transforms],
        }

    def to_dict(self) -> dict[str, Any]:
        return {"spec_id": self.spec_id, **self.identity_material()}


def parse_combat_candidate_spec(document: Mapping[str, Any]) -> CombatCandidateSpec:
    if not isinstance(document, Mapping):
        raise CombatCandidateSpecError("combat candidate specification must be an object")
    expected = {
        "schema_version",
        "spec_id",
        "candidate_number",
        "structural_parent",
        "installed_predecessor",
        "semantic_donors",
        "allowed_paths",
        "transforms",
    }
    if set(document) != expected:
        raise CombatCandidateSpecError("combat candidate specification fields are invalid")
    if document["schema_version"] != "kcd2.combat-candidate-spec.v1":
        raise CombatCandidateSpecError("combat candidate schema_version is unsupported")
    candidate_number = document["candidate_number"]
    if not isinstance(candidate_number, int) or isinstance(candidate_number, bool) or candidate_number < 1:
        raise CombatCandidateSpecError("candidate_number must be a positive integer")
    parent = _artifact_role(document["structural_parent"], "structural_parent")
    predecessor_value = document["installed_predecessor"]
    predecessor = (
        None
        if predecessor_value is None
        else _artifact_role(predecessor_value, "installed_predecessor")
    )
    donors_value = document["semantic_donors"]
    if not isinstance(donors_value, list) or len(donors_value) > MAX_DONORS:
        raise CombatCandidateSpecError("semantic_donors must be a bounded array")
    donors = tuple(_semantic_donor(value) for value in donors_value)
    _unique((item.donor_id for item in donors), "semantic donor IDs")
    paths_value = document["allowed_paths"]
    if (
        not isinstance(paths_value, list)
        or not paths_value
        or len(paths_value) > MAX_ALLOWED_PATHS
    ):
        raise CombatCandidateSpecError("allowed_paths must be a non-empty bounded array")
    allowed_paths = tuple(sorted(_internal_path(value) for value in paths_value))
    _unique((item.casefold() for item in allowed_paths), "allowed paths")
    transforms_value = document["transforms"]
    if (
        not isinstance(transforms_value, list)
        or not transforms_value
        or len(transforms_value) > MAX_TRANSFORMS
    ):
        raise CombatCandidateSpecError("transforms must be a non-empty bounded array")
    donor_ids = {item.donor_id for item in donors}
    transforms = tuple(
        _transform(value, allowed_paths=set(allowed_paths), donor_ids=donor_ids)
        for value in transforms_value
    )
    _unique((item.transform_id for item in transforms), "transform IDs")
    provisional = CombatCandidateSpec(
        schema_version="kcd2.combat-candidate-spec.v1",
        spec_id="",
        candidate_number=candidate_number,
        structural_parent=parent,
        installed_predecessor=predecessor,
        semantic_donors=donors,
        allowed_paths=allowed_paths,
        transforms=transforms,
    )
    calculated = "combat-spec:sha256:" + _canonical_sha256(provisional.identity_material())
    if document["spec_id"] != calculated:
        raise CombatCandidateSpecError("spec_id does not match canonical specification material")
    return CombatCandidateSpec(
        schema_version=provisional.schema_version,
        spec_id=calculated,
        candidate_number=candidate_number,
        structural_parent=parent,
        installed_predecessor=predecessor,
        semantic_donors=donors,
        allowed_paths=allowed_paths,
        transforms=transforms,
    )


def parse_combat_candidate_spec_file(path: Path | str) -> CombatCandidateSpec:
    source = Path(path)
    if not source.is_file() or source.stat().st_size > MAX_JSON_BYTES:
        raise CombatCandidateSpecError("combat candidate file is unavailable or oversized")
    try:
        document = json.loads(source.read_bytes(), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CombatCandidateSpecError("combat candidate file is not valid JSON") from exc
    return parse_combat_candidate_spec(document)


def canonical_combat_spec_id(document: Mapping[str, Any]) -> str:
    material = dict(document)
    material.pop("spec_id", None)
    return "combat-spec:sha256:" + _canonical_sha256(material)


def _artifact_role(value: object, role: str) -> ArtifactRole:
    if not isinstance(value, Mapping) or set(value) != {
        "role",
        "identity_id",
        "artifact_sha256",
        "evidence_refs",
    }:
        raise CombatCandidateSpecError(f"{role} fields are invalid")
    if value["role"] != role:
        raise CombatCandidateSpecError(f"{role} must retain its exact lineage role")
    return ArtifactRole(
        role=role,
        identity_id=_identifier(value["identity_id"], f"{role}.identity_id"),
        artifact_sha256=_digest(value["artifact_sha256"], f"{role}.artifact_sha256"),
        evidence_refs=_references(value["evidence_refs"], f"{role}.evidence_refs"),
    )


def _semantic_donor(value: object) -> SemanticDonor:
    if not isinstance(value, Mapping) or set(value) != {
        "donor_id",
        "identity_id",
        "artifact_sha256",
        "evidence_refs",
    }:
        raise CombatCandidateSpecError("semantic donor fields are invalid")
    return SemanticDonor(
        donor_id=_identifier(value["donor_id"], "semantic donor ID"),
        identity_id=_identifier(value["identity_id"], "semantic donor identity"),
        artifact_sha256=_digest(value["artifact_sha256"], "semantic donor artifact_sha256"),
        evidence_refs=_references(value["evidence_refs"], "semantic donor evidence_refs"),
    )


def _transform(
    value: object, *, allowed_paths: set[str], donor_ids: set[str]
) -> CombatTransformDeclaration:
    if not isinstance(value, Mapping) or set(value) != {
        "transform_id",
        "kind",
        "target_path",
        "selector",
        "donor_id",
        "expected_target_sha256",
    }:
        raise CombatCandidateSpecError("transform declaration fields are invalid")
    kind = value["kind"]
    if kind not in _TRANSFORM_KINDS:
        raise CombatCandidateSpecError("transform kind is unsupported")
    path = _internal_path(value["target_path"])
    if path not in allowed_paths:
        raise CombatCandidateSpecError("transform target is outside allowed_paths")
    selector = value["selector"]
    if not isinstance(selector, Mapping) or not selector:
        raise CombatCandidateSpecError("transform selector must be a non-empty object")
    selector = json.loads(_canonical_bytes(selector))
    donor_id = value["donor_id"]
    if donor_id is not None:
        donor_id = _identifier(donor_id, "transform donor_id")
        if donor_id not in donor_ids:
            raise CombatCandidateSpecError("transform references an unknown semantic donor")
    if not kind.endswith("delete") and donor_id is None:
        raise CombatCandidateSpecError("replacement/upsert transform requires a semantic donor")
    return CombatTransformDeclaration(
        transform_id=_identifier(value["transform_id"], "transform_id"),
        kind=kind,
        target_path=path,
        selector=selector,
        donor_id=donor_id,
        expected_target_sha256=_digest(
            value["expected_target_sha256"], "transform expected_target_sha256"
        ),
    )


def _internal_path(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or "\\" in value:
        raise CombatCandidateSpecError("internal path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CombatCandidateSpecError("internal path must be canonical and relative")
    return path.as_posix()


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CombatCandidateSpecError(f"{field} is invalid")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value.lower()) is None:
        raise CombatCandidateSpecError(f"{field} is not SHA-256")
    return value.lower()


def _references(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise CombatCandidateSpecError(f"{field} must be a non-empty bounded array")
    result = tuple(_identifier(item, field) for item in value)
    _unique(result, field)
    return result


def _unique(values: object, field: str) -> None:
    material = list(values)
    if len(set(material)) != len(material):
        raise CombatCandidateSpecError(f"{field} must be unique")


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
        raise CombatCandidateSpecError("specification contains non-canonical JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CombatCandidateSpecError("combat candidate file contains duplicate JSON keys")
        result[key] = value
    return result


__all__ = [
    "ArtifactRole",
    "CombatCandidateSpec",
    "CombatCandidateSpecError",
    "CombatTransformDeclaration",
    "SemanticDonor",
    "canonical_combat_spec_id",
    "parse_combat_candidate_spec",
    "parse_combat_candidate_spec_file",
]
