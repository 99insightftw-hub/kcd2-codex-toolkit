"""Bounded resolution of exact world-behavior records into a typed graph."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from kcd2_toolchain_core.paths import canonical_relative_path


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 8192
_MAX_SOURCES = 4096
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_NODES = 100_000
_MAX_EDGES = 250_000

_DOMAIN_ORDER = (
    "xgen",
    "smart_object",
    "scheduler",
    "spawn",
    "role",
    "faction",
    "persistence",
)
_KIND_CONTRACT = {
    "smart_object": ("smart_object", "smart_object"),
    "smart_object_helper": ("smart_object", "helper"),
    "xgen_node": ("xgen", "behavior"),
    "scheduler": ("scheduler", "scheduler"),
    "schedule_entry": ("scheduler", "schedule"),
    "spawn_definition": ("spawn", "spawn"),
    "entity": ("spawn", "entity"),
    "soul": ("role", "soul"),
    "soul_pool": ("role", "soul_pool"),
    "role": ("role", "role"),
    "faction": ("faction", "faction"),
    "ai_signal": ("xgen", "signal"),
    "reputation_effect": ("faction", "reputation"),
    "persistence_owner": ("persistence", "owner"),
    "persistent_state": ("persistence", "state"),
}
_EDGE_KINDS = frozenset(
    {
        "owns",
        "references",
        "uses_helper",
        "schedules",
        "spawns",
        "resolves_entity",
        "resolves_soul",
        "assigns_role",
        "member_of_faction",
        "signals",
        "affects_reputation",
        "persists",
        "loads",
    }
)


class WorldBehaviorResolutionError(ValueError):
    """Exact record evidence cannot support a deterministic bounded resolution."""


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise WorldBehaviorResolutionError(
            f"{name} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _timestamp(value: object, name: str) -> str:
    checked = _text(value, name, maximum=128)
    try:
        parsed = datetime.fromisoformat(checked.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorldBehaviorResolutionError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise WorldBehaviorResolutionError(f"{name} must include a timezone")
    return checked


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
        raise WorldBehaviorResolutionError("value must be JSON-compatible") from exc


def _copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _array(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise WorldBehaviorResolutionError(f"{name} must be an array")
    if len(value) > maximum:
        raise WorldBehaviorResolutionError(f"{name} exceeds the {maximum}-item hard bound")
    return value


@dataclass(frozen=True, slots=True)
class ExactWorldBehaviorSource:
    """One immutable, hash-verified normalized record document from an exact provider."""

    source_id: str
    provider_id: str
    source_path: str
    canonical_path: str
    content: bytes
    expected_sha256: str
    captured_at: str
    coverage_complete: bool

    def __post_init__(self) -> None:
        _text(self.source_id, "source_id", maximum=1024)
        _text(self.provider_id, "provider_id", maximum=1024)
        _text(self.source_path, "source_path")
        try:
            canonical = canonical_relative_path(self.canonical_path)
        except (TypeError, ValueError) as exc:
            raise WorldBehaviorResolutionError(
                "canonical_path must be a canonical relative path"
            ) from exc
        object.__setattr__(self, "canonical_path", canonical)
        if not isinstance(self.content, bytes):
            raise WorldBehaviorResolutionError("content must be exact source bytes")
        if len(self.content) > _MAX_DOCUMENT_BYTES:
            raise WorldBehaviorResolutionError("content exceeds the document byte bound")
        if not isinstance(self.expected_sha256, str) or not _SHA256.fullmatch(
            self.expected_sha256
        ):
            raise WorldBehaviorResolutionError("expected_sha256 must be a lowercase digest")
        if hashlib.sha256(self.content).hexdigest() != self.expected_sha256:
            raise WorldBehaviorResolutionError("content SHA-256 does not match expected_sha256")
        _timestamp(self.captured_at, "captured_at")
        if not isinstance(self.coverage_complete, bool):
            raise WorldBehaviorResolutionError("coverage_complete must be a boolean")


@dataclass(frozen=True, slots=True)
class WorldBehaviorResolution:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class _Record:
    source: ExactWorldBehaviorSource
    index: int
    record_id: str
    domain: str
    kind: str
    identity_type: str
    identity: str
    identity_key: str
    owner: str | None
    raw: Mapping[str, object]

    @property
    def locator(self) -> str:
        return f"{self.source.source_path}!/{self.source.canonical_path}#/records/{self.index}"


@dataclass(frozen=True, slots=True)
class _Reference:
    source: ExactWorldBehaviorSource
    index: int
    reference_id: str
    from_key: str
    to_key: str
    kind: str

    @property
    def locator(self) -> str:
        return (
            f"{self.source.source_path}!/{self.source.canonical_path}"
            f"#/references/{self.index}"
        )


def _parse_source(
    source: ExactWorldBehaviorSource,
) -> tuple[list[_Record], list[_Reference]]:
    try:
        payload = json.loads(source.content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorldBehaviorResolutionError("source content must be valid UTF-8 JSON") from exc
    if not isinstance(payload, Mapping):
        raise WorldBehaviorResolutionError("source document must be an object")
    if payload.get("schema_version") != "kcd2.world-behavior-records.v1":
        raise WorldBehaviorResolutionError("source schema_version is unsupported")
    if set(payload) != {"schema_version", "records", "references"}:
        raise WorldBehaviorResolutionError("source document contains unknown properties")

    record_values = _array(payload.get("records"), "records", _MAX_NODES)
    reference_values = _array(payload.get("references"), "references", _MAX_EDGES)
    records: list[_Record] = []
    for index, value in enumerate(record_values):
        if not isinstance(value, Mapping):
            raise WorldBehaviorResolutionError("each record must be an object")
        allowed = {"record_id", "domain", "kind", "identity_type", "identity", "owner"}
        if not set(value).issubset(allowed) or not allowed.difference({"owner"}).issubset(
            value
        ):
            raise WorldBehaviorResolutionError("record properties do not match the contract")
        record_id = _text(value.get("record_id"), "record_id", maximum=1024)
        domain = _text(value.get("domain"), "domain", maximum=64)
        kind = _text(value.get("kind"), "kind", maximum=128)
        identity_type = _text(value.get("identity_type"), "identity_type", maximum=128)
        identity = _text(value.get("identity"), "identity", maximum=1024)
        expected = _KIND_CONTRACT.get(kind)
        if expected is None or expected != (domain, identity_type):
            raise WorldBehaviorResolutionError(
                f"record {record_id} has an unsupported domain/kind/identity_type tuple"
            )
        owner_value = value.get("owner")
        owner = None if owner_value is None else _text(owner_value, "owner", maximum=2048)
        records.append(
            _Record(
                source,
                index,
                record_id,
                domain,
                kind,
                identity_type,
                identity,
                f"{identity_type}:{identity}",
                owner,
                value,
            )
        )

    references: list[_Reference] = []
    for index, value in enumerate(reference_values):
        if not isinstance(value, Mapping) or set(value) != {
            "reference_id",
            "from",
            "to",
            "kind",
        }:
            raise WorldBehaviorResolutionError("reference properties do not match the contract")
        reference_id = _text(value.get("reference_id"), "reference_id", maximum=1024)
        from_key = _text(value.get("from"), "reference from", maximum=2048)
        to_key = _text(value.get("to"), "reference to", maximum=2048)
        kind = _text(value.get("kind"), "reference kind", maximum=128)
        if kind not in _EDGE_KINDS:
            raise WorldBehaviorResolutionError(f"reference {reference_id} has unknown kind")
        references.append(
            _Reference(source, index, reference_id, from_key, to_key, kind)
        )
    return records, references


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _evidence(source: ExactWorldBehaviorSource, locator: str) -> dict[str, object]:
    return {
        "evidence_id": _stable_id("static", source.expected_sha256, locator),
        "evidence_layer": "static",
        "evidence_kind": "active_source_exact",
        "exact_locator": locator,
    }


def _metadata(record: _Record) -> dict[str, object]:
    return {
        "source_id": record.source.source_id,
        "provider_id": record.source.provider_id,
        "source_path": record.source.source_path,
        "canonical_path": record.source.canonical_path,
        "content_sha256": record.source.expected_sha256,
        "record_id": record.record_id,
        "identity_type": record.identity_type,
        "raw_record": dict(record.raw),
    }


def resolve_world_behavior_graph(
    *, graph_id: str, sources: Sequence[ExactWorldBehaviorSource]
) -> WorldBehaviorResolution:
    """Join reviewed normalized records without inferring missing identities or links."""

    checked_graph = _text(graph_id, "graph_id", maximum=1024)
    source_values = _array(sources, "sources", _MAX_SOURCES)
    if not source_values:
        raise WorldBehaviorResolutionError("sources must contain at least one exact document")
    if any(not isinstance(item, ExactWorldBehaviorSource) for item in source_values):
        raise WorldBehaviorResolutionError(
            "sources must contain ExactWorldBehaviorSource values"
        )
    if sum(len(item.content) for item in source_values) > _MAX_TOTAL_BYTES:
        raise WorldBehaviorResolutionError("source content exceeds the aggregate byte bound")

    records: list[_Record] = []
    references: list[_Reference] = []
    for source in sorted(
        source_values,
        key=lambda item: (item.canonical_path.casefold(), item.provider_id.casefold()),
    ):
        parsed_records, parsed_references = _parse_source(source)
        records.extend(parsed_records)
        references.extend(parsed_references)
    if len(records) > _MAX_NODES or len(references) > _MAX_EDGES:
        raise WorldBehaviorResolutionError("aggregate graph exceeds a hard bound")

    record_by_key: dict[str, _Record] = {}
    record_ids: set[str] = set()
    for record in records:
        if record.identity_key in record_by_key:
            raise WorldBehaviorResolutionError(
                f"duplicate typed identity {record.identity_key} is ambiguous"
            )
        if record.record_id in record_ids:
            raise WorldBehaviorResolutionError(f"duplicate record_id {record.record_id}")
        record_by_key[record.identity_key] = record
        record_ids.add(record.record_id)
    reference_ids = [reference.reference_id for reference in references]
    if len(reference_ids) != len(set(reference_ids)):
        raise WorldBehaviorResolutionError("reference_id values must be unique")

    node_id_by_key = {
        key: _stable_id("node", record.source.expected_sha256, record.locator, key)
        for key, record in record_by_key.items()
    }
    unresolved_owner_keys: set[str] = set()
    nodes: list[dict[str, object]] = []
    for key, record in record_by_key.items():
        evidence = _evidence(record.source, record.locator)
        if record.owner is None:
            ownership = {
                "state": "not_applicable",
                "owner_node_id": None,
                "evidence_ids": [],
            }
        elif record.owner in node_id_by_key:
            ownership = {
                "state": "declared",
                "owner_node_id": node_id_by_key[record.owner],
                "evidence_ids": [evidence["evidence_id"]],
            }
        else:
            unresolved_owner_keys.add(key)
            ownership = {
                "state": "unresolved",
                "owner_node_id": None,
                "evidence_ids": [evidence["evidence_id"]],
            }
        nodes.append(
            {
                "node_id": node_id_by_key[key],
                "domain": record.domain,
                "raw_kind": record.kind,
                "normalized_kind": record.kind,
                "support_state": "supported",
                "reason_code": None,
                "identity_key": key,
                "exact_locator": record.locator,
                "ownership": ownership,
                "evidence": [evidence],
                "metadata": _metadata(record),
            }
        )

    edges: list[dict[str, object]] = []
    resolved_checks: list[dict[str, object]] = []
    unresolved_checks: list[dict[str, object]] = []
    incomplete_domains: dict[str, set[str]] = {
        domain: set() for domain in _DOMAIN_ORDER
    }
    for key in unresolved_owner_keys:
        incomplete_domains[record_by_key[key].domain].add("unresolved_owner_retained")
    for reference in references:
        from_record = record_by_key.get(reference.from_key)
        to_record = record_by_key.get(reference.to_key)
        supported = from_record is not None and to_record is not None
        evidence = _evidence(reference.source, reference.locator)
        reason = None if supported else "missing_reference_target"
        edge = {
            "edge_id": _stable_id(
                "edge", reference.source.expected_sha256, reference.locator, reference.reference_id
            ),
            "from_node_id": node_id_by_key.get(reference.from_key)
            or f"unresolved:{_stable_id('identity', reference.from_key).split(':', 1)[1]}",
            "to_node_id": node_id_by_key.get(reference.to_key)
            or f"unresolved:{_stable_id('identity', reference.to_key).split(':', 1)[1]}",
            "raw_kind": reference.kind,
            "normalized_kind": reference.kind if supported else None,
            "support_state": "supported" if supported else "unresolved",
            "reason_code": reason,
            "exact_locator": reference.locator,
            "evidence": [evidence],
            "metadata": {
                "reference_id": reference.reference_id,
                "from_identity_key": reference.from_key,
                "to_identity_key": reference.to_key,
                "provider_id": reference.source.provider_id,
                "content_sha256": reference.source.expected_sha256,
            },
        }
        edges.append(edge)
        check = {
            "reference_id": reference.reference_id,
            "kind": reference.kind,
            "from_identity_key": reference.from_key,
            "to_identity_key": reference.to_key,
            "status": "resolved" if supported else "unresolved",
            "reason_code": reason,
            "exact_locator": reference.locator,
        }
        (resolved_checks if supported else unresolved_checks).append(check)
        if not supported:
            if from_record is not None:
                incomplete_domains[from_record.domain].add("unresolved_reference_retained")
            if to_record is not None:
                incomplete_domains[to_record.domain].add("unresolved_reference_retained")

    for source in source_values:
        if not source.coverage_complete:
            source_domains = {record.domain for record in records if record.source is source}
            for domain in source_domains:
                incomplete_domains[domain].add("source_coverage_incomplete")

    domains = [domain for domain in _DOMAIN_ORDER if any(r.domain == domain for r in records)]
    coverage: list[dict[str, object]] = []
    for domain in domains:
        reasons = sorted(incomplete_domains[domain])
        status = "complete" if not reasons else "partial"
        coverage.append(
            {
                "domain": domain,
                "status": status,
                "enumerated_count": sum(record.domain == domain for record in records),
                "retained_unsupported_count": 0,
                "absence_claim_allowed": status == "complete",
                "reason_codes": reasons,
            }
        )

    global_reasons = sorted(
        {reason for reasons in incomplete_domains.values() for reason in reasons}
    )
    verdict = "valid" if not global_reasons else "capture_inconclusive"
    source_hashes = sorted(source.expected_sha256 for source in source_values)
    aggregate_sha256 = hashlib.sha256(_canonical_bytes(source_hashes)).hexdigest()
    audit = {
        "schema_version": "kcd2.ai-quest-graph-audit.v1",
        "graph_id": checked_graph,
        "domains": domains,
        "source": {
            "sha256": aggregate_sha256,
            "byte_size": sum(len(source.content) for source in source_values),
            "exact_locator": f"world-behavior://{checked_graph}",
            "captured_at": max(source.captured_at for source in source_values),
        },
        "nodes": sorted(nodes, key=lambda item: str(item["node_id"])),
        "edges": sorted(edges, key=lambda item: str(item["edge_id"])),
        "runtime_markers": [],
        "coverage": coverage,
        "verdict": verdict,
        "reason_codes": global_reasons,
    }

    persistence_checks: list[dict[str, object]] = []
    for record in sorted(records, key=lambda item: item.identity_key):
        if record.kind != "persistent_state":
            continue
        owner = record_by_key.get(record.owner) if record.owner is not None else None
        persistence_checks.append(
            {
                "state_identity_key": record.identity_key,
                "owner_identity_key": record.owner,
                "status": "resolved"
                if owner is not None and owner.kind == "persistence_owner"
                else "unresolved",
                "reason_code": None
                if owner is not None and owner.kind == "persistence_owner"
                else "persistence_owner_unresolved",
                "exact_locator": record.locator,
            }
        )

    payload = {
        "schema_version": "kcd2.world-behavior-resolution.v1",
        "graph_audit": audit,
        "reference_checks": {
            "resolved": sorted(resolved_checks, key=lambda item: str(item["reference_id"])),
            "unresolved": sorted(
                unresolved_checks, key=lambda item: str(item["reference_id"])
            ),
        },
        "persistence_checks": persistence_checks,
        "compact_audit": {
            "status": verdict,
            "source_count": len(source_values),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "resolved_reference_count": len(resolved_checks),
            "unresolved_reference_count": len(unresolved_checks),
            "typed_entity_count": sum(record.kind == "entity" for record in records),
            "typed_soul_count": sum(record.kind == "soul" for record in records),
            "resolved_persistence_owner_count": sum(
                item["status"] == "resolved" for item in persistence_checks
            ),
            "reason_codes": global_reasons,
        },
    }
    return WorldBehaviorResolution(payload=payload)
