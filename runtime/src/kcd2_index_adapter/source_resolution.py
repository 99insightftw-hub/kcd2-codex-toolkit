"""Deterministic source deduplication and fail-closed identity search fallbacks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Sequence

from kcd2_toolchain_core import (
    Diagnostic,
    ResponseLimits,
    ResultEnvelope,
    ToolError,
    build_bounded_envelope,
)


_SHA256 = re.compile(r"[0-9a-f]{64}")
_ALIAS_SEPARATOR = re.compile(r"[^a-z0-9]+")
MatchKind = Literal["source", "path", "token", "adb_animevent", "generic"]
CanonicalSourceLayer = Literal[
    "local_provider_catalog",
    "workshop_provider_catalog",
    "pak_entry_catalog",
    "loose_files",
    "localization_packages",
    "native_components",
    "runtime_imports",
    "project_artifacts",
]

# The canonical values follow the reviewed per-layer coverage vocabulary. Aliases are
# compatibility spellings only; they never create a new source layer.
SOURCE_LAYER_ALIASES: Mapping[CanonicalSourceLayer, tuple[str, ...]] = {
    "local_provider_catalog": ("local", "local_mods", "local_providers"),
    "workshop_provider_catalog": ("workshop", "workshop_mods", "workshop_providers"),
    "pak_entry_catalog": ("pak", "paks", "pak_entries", "archives"),
    "loose_files": ("loose", "loose_file"),
    "localization_packages": ("localization", "localisation", "localization_paks"),
    "native_components": ("native", "native_component"),
    "runtime_imports": ("runtime", "runtime_import"),
    "project_artifacts": ("project", "projects", "project_artifact"),
}
SOURCE_LAYER_VOCABULARY = tuple(sorted(SOURCE_LAYER_ALIASES))
_MAX_SOURCE_LAYER_SELECTORS = 32
_MAX_ACTIVE_SOURCE_RECORDS = 100_000
_MAX_ACTIVE_MOD_IDS = 4_096


def _normalized_alias(value: str) -> str:
    return _ALIAS_SEPARATOR.sub("", value.casefold())


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").strip("/").casefold()


def _source_layer_lookup() -> dict[str, CanonicalSourceLayer]:
    result: dict[str, CanonicalSourceLayer] = {}
    for canonical, aliases in SOURCE_LAYER_ALIASES.items():
        for value in (canonical, *aliases):
            key = _normalized_alias(value)
            existing = result.get(key)
            if existing is not None and existing != canonical:
                raise RuntimeError("source layer aliases must be unambiguous")
            result[key] = canonical
    return result


_SOURCE_LAYER_LOOKUP = _source_layer_lookup()


def normalize_source_layers(selectors: str | Sequence[str]) -> tuple[CanonicalSourceLayer, ...]:
    """Normalize documented aliases and reject every unknown or malformed selector."""
    values: Sequence[str]
    if isinstance(selectors, str):
        values = (selectors,)
    elif isinstance(selectors, Sequence) and not isinstance(selectors, bytes):
        values = selectors
    else:
        raise ValueError("source_layers must be a string or array of strings")
    if not values or len(values) > _MAX_SOURCE_LAYER_SELECTORS:
        raise ValueError(
            f"source_layers must contain between 1 and {_MAX_SOURCE_LAYER_SELECTORS} selectors"
        )
    normalized: set[CanonicalSourceLayer] = set()
    for value in values:
        if not isinstance(value, str) or not value or len(value) > 100 or "\x00" in value:
            raise ValueError("source layer selectors must be non-empty bounded strings")
        canonical = _SOURCE_LAYER_LOOKUP.get(_normalized_alias(value))
        if canonical is None:
            raise ValueError(f"unknown source layer selector: {value}")
        normalized.add(canonical)
    return tuple(sorted(normalized))


def validate_source_layer_selectors(
    selectors: str | Sequence[str],
    *,
    correlation_id: str,
    limits: ResponseLimits | None = None,
) -> ResultEnvelope:
    """Return normalized selectors or the global typed invalid-argument response."""
    selected_limits = limits or ResponseLimits()
    supplied: object
    if isinstance(selectors, str):
        supplied = selectors
    elif isinstance(selectors, Sequence) and not isinstance(selectors, bytes):
        supplied = list(selectors)
    else:
        supplied = selectors
    try:
        normalized = normalize_source_layers(selectors)
    except (TypeError, ValueError) as exc:
        error = ToolError.invalid_argument(
            message=str(exc),
            field="source_layers",
            supplied_value=supplied,
            allowed_values=SOURCE_LAYER_VOCABULARY,
            correlation_id=correlation_id,
        )
        return build_bounded_envelope(
            status="error",
            evidence_grade="E0",
            data={
                "source_layer_aliases": {
                    key: list(SOURCE_LAYER_ALIASES[key])
                    for key in SOURCE_LAYER_VOCABULARY
                }
            },
            error=error,
            limits=selected_limits,
        )
    return build_bounded_envelope(
        status="ok",
        evidence_grade="E0",
        data={
            "source_layers": list(normalized),
            "source_layer_aliases": {
                key: list(SOURCE_LAYER_ALIASES[key]) for key in SOURCE_LAYER_VOCABULARY
            },
        },
        limits=selected_limits,
    )


def _bounded_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


@dataclass(frozen=True, slots=True)
class ActiveSourceSnapshot:
    """Fresh active-mod identity used as the sole current-state authority."""

    snapshot_id: str
    snapshot_sha256: str
    fresh: bool
    active_mod_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _bounded_text(self.snapshot_id, "snapshot_id")
        if not isinstance(self.snapshot_sha256, str) or _SHA256.fullmatch(
            self.snapshot_sha256
        ) is None:
            raise ValueError("snapshot_sha256 must be lowercase SHA-256")
        if not isinstance(self.fresh, bool):
            raise TypeError("fresh must be a boolean")
        if len(self.active_mod_ids) > _MAX_ACTIVE_MOD_IDS:
            raise ValueError("active_mod_ids exceeds its hard bound")
        checked = tuple(_bounded_text(value, "active mod ID") for value in self.active_mod_ids)
        if len({value.casefold() for value in checked}) != len(checked):
            raise ValueError("active_mod_ids must be case-insensitively unique")
        object.__setattr__(self, "active_mod_ids", tuple(sorted(checked, key=str.casefold)))

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ActiveSourceSnapshot":
        expected = {"snapshot_id", "snapshot_sha256", "fresh", "active_mod_ids"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("active snapshot fields do not match v1")
        active = value["active_mod_ids"]
        if isinstance(active, (str, bytes)) or not isinstance(active, Sequence):
            raise ValueError("active_mod_ids must be an array")
        return cls(
            snapshot_id=value["snapshot_id"],  # type: ignore[arg-type]
            snapshot_sha256=value["snapshot_sha256"],  # type: ignore[arg-type]
            fresh=value["fresh"],  # type: ignore[arg-type]
            active_mod_ids=tuple(active),  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ActiveSourceRecord:
    """One immutable semantic sidecar record with its indexing snapshot identity."""

    record_id: str
    source_handle: str
    mod_id: str
    indexed_snapshot_id: str

    def __post_init__(self) -> None:
        for name in ("record_id", "source_handle", "mod_id", "indexed_snapshot_id"):
            _bounded_text(getattr(self, name), name)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ActiveSourceRecord":
        expected = {"record_id", "source_handle", "mod_id", "indexed_snapshot_id"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("active source record fields do not match v1")
        return cls(**value)  # type: ignore[arg-type]

    def to_dict(self, *, current: bool, disposition: str) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "source_handle": self.source_handle,
            "mod_id": self.mod_id,
            "indexed_snapshot_id": self.indexed_snapshot_id,
            "current": current,
            "disposition": disposition,
        }


@dataclass(frozen=True, slots=True)
class ActiveSourceReconciliation:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(json.dumps(self.payload, sort_keys=True, separators=(",", ":")))


def reconcile_active_source_records(
    *,
    snapshot: ActiveSourceSnapshot,
    records: Sequence[ActiveSourceRecord],
    active_only: bool,
) -> ActiveSourceReconciliation:
    """Overlay immutable source history with current state from one exact active snapshot."""
    if not isinstance(snapshot, ActiveSourceSnapshot):
        raise TypeError("snapshot must be ActiveSourceSnapshot")
    if not isinstance(active_only, bool):
        raise TypeError("active_only must be a boolean")
    if isinstance(records, (str, bytes)) or not isinstance(records, Sequence):
        raise TypeError("records must be a sequence")
    if len(records) > _MAX_ACTIVE_SOURCE_RECORDS:
        raise ValueError("records exceeds its hard bound")
    if any(not isinstance(record, ActiveSourceRecord) for record in records):
        raise TypeError("records must contain ActiveSourceRecord values")
    record_ids = [record.record_id.casefold() for record in records]
    if len(record_ids) != len(set(record_ids)):
        raise ValueError("record IDs must be case-insensitively unique")

    active_ids = {value.casefold() for value in snapshot.active_mod_ids}
    current: list[dict[str, object]] = []
    historical: list[dict[str, object]] = []
    for record in sorted(records, key=lambda item: (item.record_id.casefold(), item.record_id)):
        same_snapshot = record.indexed_snapshot_id == snapshot.snapshot_id
        active_mod = record.mod_id.casefold() in active_ids
        is_current = snapshot.fresh and same_snapshot and active_mod
        if is_current:
            current.append(record.to_dict(current=True, disposition="current_snapshot"))
            continue
        if not snapshot.fresh:
            disposition = "quarantined_snapshot_not_fresh"
        elif not active_mod:
            disposition = "historical_inactive_mod"
        else:
            disposition = "quarantined_stale_snapshot"
        historical.append(record.to_dict(current=False, disposition=disposition))

    status = "ok" if snapshot.fresh else "capture_inconclusive"
    reason_codes = [] if snapshot.fresh else ["ACTIVE_SNAPSHOT_STALE"]
    payload = {
        "schema_version": "kcd2.active-source-reconciliation.v1",
        "status": status,
        "active_only": active_only,
        "snapshot_binding": {
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "fresh": snapshot.fresh,
        },
        "current_records": current,
        "historical_records": historical,
        "quarantined_record_ids": [item["record_id"] for item in historical],
        "reason_codes": reason_codes,
    }
    return ActiveSourceReconciliation(payload=payload)


@dataclass(frozen=True, slots=True)
class SourceHit:
    source_root: str
    canonical_path: str
    content_sha256: str
    source_handle: str
    match_kind: MatchKind
    matched_value: str

    def __post_init__(self) -> None:
        for name in ("source_root", "canonical_path", "source_handle", "matched_value"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if not _SHA256.fullmatch(self.content_sha256):
            raise ValueError("content_sha256 must be lowercase SHA-256")
        if self.match_kind not in {"source", "path", "token", "adb_animevent", "generic"}:
            raise ValueError("unsupported source match_kind")

    @property
    def logical_key(self) -> tuple[str, str]:
        return (_normalized_path(self.canonical_path), self.content_sha256)


@dataclass(frozen=True, slots=True)
class LogicalSourceHit:
    canonical_path: str
    content_sha256: str
    source_handles: tuple[str, ...]
    source_roots: tuple[str, ...]
    matches: tuple[tuple[str, str], ...]
    duplicate_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical_path": self.canonical_path,
            "content_sha256": self.content_sha256,
            "source_handles": list(self.source_handles),
            "source_roots": list(self.source_roots),
            "matches": [
                {"kind": match_kind, "value": value}
                for match_kind, value in self.matches
            ],
            "duplicate_count": self.duplicate_count,
        }


def deduplicate_source_hits(hits: Sequence[SourceHit]) -> tuple[LogicalSourceHit, ...]:
    """Collapse mirrored content while retaining deterministic expanded provenance."""
    groups: dict[tuple[str, str], list[SourceHit]] = {}
    for hit in hits:
        if not isinstance(hit, SourceHit):
            raise TypeError("hits must contain SourceHit values")
        groups.setdefault(hit.logical_key, []).append(hit)

    logical: list[LogicalSourceHit] = []
    for key in sorted(groups):
        occurrences = groups[key]
        canonical_path = min(item.canonical_path.replace("\\", "/") for item in occurrences)
        logical.append(
            LogicalSourceHit(
                canonical_path=canonical_path,
                content_sha256=key[1],
                source_handles=tuple(sorted({item.source_handle for item in occurrences})),
                source_roots=tuple(sorted({item.source_root for item in occurrences})),
                matches=tuple(
                    sorted({(item.match_kind, item.matched_value) for item in occurrences})
                ),
                duplicate_count=len(occurrences),
            )
        )
    return tuple(logical)


@dataclass(frozen=True, slots=True)
class IdentityCandidate:
    identity: str
    aliases: tuple[str, ...]
    source_handles: tuple[str, ...]
    evidence_kind: MatchKind

    def __post_init__(self) -> None:
        if not self.identity or not self.aliases:
            raise ValueError("identity and aliases must not be empty")
        if self.evidence_kind not in {"source", "path", "token", "adb_animevent", "generic"}:
            raise ValueError("unsupported identity evidence_kind")
        if any(not value for value in self.aliases + self.source_handles):
            raise ValueError("aliases and source handles must not contain empty values")


@dataclass(frozen=True, slots=True)
class IdentityResolution:
    query: str
    identity: str | None
    resolution_method: str
    source_handles: tuple[str, ...]
    used_generic_candidate: bool


def resolve_identity_with_fallback(
    query: str,
    candidates: Sequence[IdentityCandidate],
) -> IdentityResolution:
    """Resolve an exact alias and require source provenance before accepting identity."""
    normalized = _normalized_alias(query)
    if not normalized:
        raise ValueError("query must contain an identity token")
    exact = [
        candidate
        for candidate in candidates
        if normalized in {_normalized_alias(alias) for alias in candidate.aliases}
    ]
    rank = {"generic": 0, "source": 1, "path": 2, "token": 3, "adb_animevent": 4}
    exact.sort(key=lambda item: (rank[item.evidence_kind], item.identity, item.source_handles))

    generic = next((item for item in exact if item.evidence_kind == "generic"), None)
    if generic is not None and generic.source_handles:
        return IdentityResolution(
            query=query,
            identity=generic.identity,
            resolution_method="exact_generic",
            source_handles=tuple(sorted(set(generic.source_handles))),
            used_generic_candidate=True,
        )
    fallback = next(
        (item for item in exact if item.evidence_kind != "generic" and item.source_handles),
        None,
    )
    if fallback is not None:
        return IdentityResolution(
            query=query,
            identity=fallback.identity,
            resolution_method=f"exact_{fallback.evidence_kind}",
            source_handles=tuple(sorted(set(fallback.source_handles))),
            used_generic_candidate=False,
        )
    return IdentityResolution(
        query=query,
        identity=generic.identity if generic is not None else None,
        resolution_method="unresolved_no_source_handle",
        source_handles=(),
        used_generic_candidate=False,
    )


@dataclass(frozen=True, slots=True)
class StructuredTokenAudit:
    consistency: Literal["consistent", "disagreement", "not_evaluated"]
    absence_claim_allowed: bool
    result_status: Literal["ok", "capture_inconclusive"]
    diagnostics: tuple[Diagnostic, ...]


def audit_structured_token_consistency(
    *,
    structured_hits: Sequence[SourceHit],
    token_hits: Sequence[SourceHit],
    structured_complete: bool = False,
    token_complete: bool = False,
) -> StructuredTokenAudit:
    """Cross-check structured XML evidence without turning disagreement into absence."""
    structured_keys = {item.logical_key for item in structured_hits}
    token_keys = {item.logical_key for item in token_hits}
    if structured_keys != token_keys:
        diagnostic = Diagnostic(
            code="KCD2_STRUCTURED_TOKEN_DISAGREEMENT",
            cause="structured_and_token_logical_hits_differ",
            message="Structured XML and token evidence disagree; absence is inconclusive.",
            severity="warning",
            example=f"structured={len(structured_keys)},token={len(token_keys)}",
        )
        return StructuredTokenAudit(
            consistency="disagreement",
            absence_claim_allowed=False,
            result_status="capture_inconclusive",
            diagnostics=(diagnostic,),
        )
    evaluated = bool(structured_hits or token_hits or (structured_complete and token_complete))
    return StructuredTokenAudit(
        consistency="consistent" if evaluated else "not_evaluated",
        absence_claim_allowed=bool(
            structured_complete and token_complete and not structured_keys and not token_keys
        ),
        result_status="ok",
        diagnostics=(),
    )


def build_source_search_result(
    hits: Sequence[SourceHit],
    *,
    limits: ResponseLimits | None = None,
    continuation_token: str | None = None,
) -> ResultEnvelope:
    """Return logical source hits through the shared bounded continuation contract."""
    selected_limits = limits or ResponseLimits()
    logical = deduplicate_source_hits(hits)
    return build_bounded_envelope(
        status="partial" if len(logical) > selected_limits.page_size else "ok",
        evidence_grade="E1",
        data={"logical_hit_count": len(logical), "physical_hit_count": len(hits)},
        items=tuple(item.to_dict() for item in logical),
        limits=selected_limits,
        continuation_token=continuation_token,
        continuation_scope="kcd2-index-source-logical-hits-v1",
    )
