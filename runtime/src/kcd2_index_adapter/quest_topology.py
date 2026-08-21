"""Bounded automatic quest and XGEN topology acquisition from exact XML sources."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path


ProviderKind = Literal[
    "vanilla", "local", "workshop", "explicit", "generated", "unknown"
]
SourceKind = Literal["pak_member", "loose_file"]
CoverageStatus = Literal["complete", "partial", "unsupported", "capture_inconclusive"]
WinnerConclusion = Literal[
    "winner",
    "multiple_contributors",
    "parallel_contributors",
    "no_provider_observed",
    "inconclusive",
]

_PROVIDER_KINDS = frozenset(
    {"vanilla", "local", "workshop", "explicit", "generated", "unknown"}
)
_SOURCE_KINDS = frozenset({"pak_member", "loose_file"})
_COVERAGE_STATUSES = frozenset(
    {"complete", "partial", "unsupported", "capture_inconclusive"}
)
_WINNER_CONCLUSIONS = frozenset(
    {
        "winner",
        "multiple_contributors",
        "parallel_contributors",
        "no_provider_observed",
        "inconclusive",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 8192
_MAX_SOURCES = 4096
_MAX_WINNERS = 4096
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_NODES = 100_000
_MAX_EDGES = 250_000
_MAX_ELEMENTS = _MAX_NODES + _MAX_EDGES

_DOMAIN_ORDER = ("quest_graph", "xgen")
_NODE_KINDS = frozenset(
    {
        "quest_graph",
        "quest_module",
        "quest_node",
        "quest_port",
        "quest_condition",
        "quest_action",
        "quest_variable",
        "dialog_selector",
        "xgen_graph",
        "xgen_node",
    }
)
_EDGE_KINDS = frozenset(
    {
        "contains",
        "connects_to",
        "owns",
        "references",
        "conditions",
        "executes",
        "reads",
        "writes",
        "selects",
        "loads",
    }
)
_TAG_ALIASES = {
    "questgraph": "quest_graph",
    "quest_graph": "quest_graph",
    "xgengraph": "xgen_graph",
    "xgen_graph": "xgen_graph",
    "module": "quest_module",
    "questmodule": "quest_module",
    "quest_module": "quest_module",
    "port": "quest_port",
    "questport": "quest_port",
    "quest_port": "quest_port",
    "condition": "quest_condition",
    "questcondition": "quest_condition",
    "quest_condition": "quest_condition",
    "action": "quest_action",
    "questaction": "quest_action",
    "quest_action": "quest_action",
    "variable": "quest_variable",
    "questvariable": "quest_variable",
    "quest_variable": "quest_variable",
    "dialogselector": "dialog_selector",
    "dialog_selector": "dialog_selector",
}


class TopologyAcquisitionError(ValueError):
    """Exact source evidence cannot support a bounded deterministic acquisition."""


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise TopologyAcquisitionError(
            f"{name} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TopologyAcquisitionError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, name: str) -> str:
    checked = _text(value, name, maximum=128)
    try:
        parsed = datetime.fromisoformat(checked.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TopologyAcquisitionError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise TopologyAcquisitionError(f"{name} must include a timezone")
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
        raise TopologyAcquisitionError("result must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _bounded_sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TopologyAcquisitionError(f"{name} must be an array")
    if len(value) > maximum:
        raise TopologyAcquisitionError(f"{name} exceeds the {maximum}-item hard bound")
    return value


@dataclass(frozen=True, slots=True)
class ExactTopologySource:
    """One immutable, hash-verified PAK member or loose XML source."""

    provider_id: str
    provider_kind: ProviderKind
    source_kind: SourceKind
    source_path: str
    canonical_path: str
    content: bytes
    expected_sha256: str
    captured_at: str
    topology_complete: bool

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id", maximum=1024)
        if self.provider_kind not in _PROVIDER_KINDS:
            raise TopologyAcquisitionError("provider_kind is not supported")
        if self.source_kind not in _SOURCE_KINDS:
            raise TopologyAcquisitionError("source_kind must be pak_member or loose_file")
        _text(self.source_path, "source_path")
        try:
            path = canonical_relative_path(self.canonical_path)
        except (TypeError, ValueError) as exc:
            raise TopologyAcquisitionError(
                "canonical_path must be a canonical relative path"
            ) from exc
        _text(path, "canonical_path", maximum=4096)
        object.__setattr__(self, "canonical_path", path)
        if not isinstance(self.content, bytes):
            raise TopologyAcquisitionError("content must be exact source bytes")
        if len(self.content) > _MAX_DOCUMENT_BYTES:
            raise TopologyAcquisitionError(
                f"content exceeds the {_MAX_DOCUMENT_BYTES}-byte document bound"
            )
        expected = _sha256(self.expected_sha256, "expected_sha256")
        actual = hashlib.sha256(self.content).hexdigest()
        if actual != expected:
            raise TopologyAcquisitionError("content SHA-256 does not match expected_sha256")
        _timestamp(self.captured_at, "captured_at")
        if not isinstance(self.topology_complete, bool):
            raise TopologyAcquisitionError("topology_complete must be a boolean")

    @property
    def content_sha256(self) -> str:
        return self.expected_sha256


@dataclass(frozen=True, slots=True)
class ProviderWinnerEvidence:
    """Exact active-snapshot provider resolution joined to one canonical path."""

    canonical_path: str
    coverage_id: str
    coverage_status: CoverageStatus
    snapshot_id: str
    snapshot_sha256: str
    fresh: bool
    conclusion: WinnerConclusion
    winner_provider_id: str | None
    exact_locator: str

    def __post_init__(self) -> None:
        try:
            path = canonical_relative_path(self.canonical_path)
        except (TypeError, ValueError) as exc:
            raise TopologyAcquisitionError(
                "winner canonical_path must be a canonical relative path"
            ) from exc
        _text(path, "winner canonical_path", maximum=4096)
        object.__setattr__(self, "canonical_path", path)
        _text(self.coverage_id, "coverage_id", maximum=1024)
        if self.coverage_status not in _COVERAGE_STATUSES:
            raise TopologyAcquisitionError("coverage_status is not supported")
        _text(self.snapshot_id, "snapshot_id", maximum=1024)
        _sha256(self.snapshot_sha256, "snapshot_sha256")
        if not isinstance(self.fresh, bool):
            raise TopologyAcquisitionError("fresh must be a boolean")
        if self.conclusion not in _WINNER_CONCLUSIONS:
            raise TopologyAcquisitionError("winner conclusion is not supported")
        if self.winner_provider_id is not None:
            _text(self.winner_provider_id, "winner_provider_id", maximum=1024)
        if self.conclusion == "winner" and self.winner_provider_id is None:
            raise TopologyAcquisitionError("winner conclusion requires winner_provider_id")
        if self.conclusion != "winner" and self.winner_provider_id is not None:
            raise TopologyAcquisitionError(
                "non-winner conclusion cannot name winner_provider_id"
            )
        _text(self.exact_locator, "winner exact_locator")

    @classmethod
    def from_path_contribution(
        cls,
        contribution_set: object,
        *,
        coverage_status: CoverageStatus,
        snapshot_id: str,
        snapshot_sha256: str,
        fresh: bool,
        exact_locator: str,
    ) -> "ProviderWinnerEvidence":
        """Join the reviewed IDX-010 contribution result without inferring a winner."""

        if hasattr(contribution_set, "to_dict") and callable(contribution_set.to_dict):
            contribution_set = contribution_set.to_dict()
        if not isinstance(contribution_set, Mapping):
            raise TopologyAcquisitionError("contribution_set must be a mapping")
        resolution = contribution_set.get("resolution")
        if not isinstance(resolution, Mapping):
            raise TopologyAcquisitionError("contribution_set.resolution must be an object")
        conclusion = resolution.get("conclusion")
        winner = resolution.get("winner_provider_id")
        return cls(
            canonical_path=contribution_set.get("canonical_path"),  # type: ignore[arg-type]
            coverage_id=contribution_set.get("coverage_id"),  # type: ignore[arg-type]
            coverage_status=coverage_status,
            snapshot_id=snapshot_id,
            snapshot_sha256=snapshot_sha256,
            fresh=fresh,
            conclusion=conclusion,  # type: ignore[arg-type]
            winner_provider_id=winner,  # type: ignore[arg-type]
            exact_locator=exact_locator,
        )


@dataclass(frozen=True, slots=True)
class TopologyAcquisitionResult:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class _ElementRecord:
    element: ET.Element
    tag: str
    locator: str
    parent_index: int | None
    index: int


@dataclass(frozen=True, slots=True)
class _JoinDecision:
    canonical_path: str
    source_states: tuple[tuple[ExactTopologySource, str], ...]
    selected_sources: tuple[ExactTopologySource, ...]
    payload: Mapping[str, Any]
    reason_codes: tuple[str, ...]


def _local_tag(value: object) -> str:
    tag = str(value)
    if "}" in tag:
        tag = tag.rsplit("}", 1)[-1]
    return tag


def _domain_for_root(root: ET.Element) -> str:
    tag = _local_tag(root.tag).replace("-", "_").casefold()
    alias = _TAG_ALIASES.get(tag)
    if alias == "quest_graph":
        return "quest_graph"
    if alias == "xgen_graph":
        return "xgen"
    domain = root.attrib.get("domain")
    if domain in _DOMAIN_ORDER:
        return domain
    raise TopologyAcquisitionError(
        "source root must identify quest_graph or xgen without inference"
    )


def _normalized_kind(tag: str, raw_kind: str, domain: str) -> str | None:
    normalized_tag = tag.replace("-", "_").casefold()
    normalized_raw = raw_kind.replace("-", "_").casefold()
    if normalized_tag == "node":
        if normalized_raw not in {"node", "quest_node", "xgen_node"}:
            candidate = _TAG_ALIASES.get(normalized_raw, normalized_raw)
            return candidate if candidate in _NODE_KINDS else None
        return "quest_node" if domain == "quest_graph" else "xgen_node"
    candidate = _TAG_ALIASES.get(normalized_tag)
    if candidate is None:
        candidate = _TAG_ALIASES.get(normalized_raw, normalized_raw)
    if candidate == "quest_node" and domain == "xgen":
        return "xgen_node"
    return candidate if candidate in _NODE_KINDS else None


def _is_edge(element: ET.Element) -> bool:
    return _local_tag(element.tag).replace("-", "_").casefold() in {
        "edge",
        "transition",
        "connection",
    }


def _collect_elements(source: ExactTopologySource, root: ET.Element) -> list[_ElementRecord]:
    records: list[_ElementRecord] = []
    root_tag = _local_tag(root.tag)
    base = f"{source.source_path}!/{source.canonical_path}#/{root_tag}[1]"
    pending: list[tuple[ET.Element, int | None, str]] = [(root, None, base)]
    while pending:
        element, parent_index, locator = pending.pop()
        _text(locator, "exact element locator")
        index = len(records)
        if index >= _MAX_ELEMENTS:
            raise TopologyAcquisitionError("XML element count exceeds the hard bound")
        tag = _local_tag(element.tag)
        records.append(_ElementRecord(element, tag, locator, parent_index, index))
        counts: dict[str, int] = {}
        children: list[tuple[ET.Element, int, str]] = []
        for child in list(element):
            child_tag = _local_tag(child.tag)
            counts[child_tag] = counts.get(child_tag, 0) + 1
            children.append(
                (child, index, f"{locator}/{child_tag}[{counts[child_tag]}]")
            )
        pending.extend(reversed(children))
    return records


def _parse_xml(source: ExactTopologySource) -> tuple[ET.Element, list[_ElementRecord], str]:
    lowered = source.content.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise TopologyAcquisitionError("DTD and entity declarations are not accepted")
    try:
        root = ET.fromstring(source.content)
    except ET.ParseError as exc:
        raise TopologyAcquisitionError(
            f"malformed XML at exact source {source.canonical_path}"
        ) from exc
    domain = _domain_for_root(root)
    return root, _collect_elements(source, root), domain


def _evidence(record: _ElementRecord, source: ExactTopologySource) -> dict[str, object]:
    digest = hashlib.sha256(
        f"{source.content_sha256}\0{record.locator}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "evidence_id": f"static:{digest}",
        "evidence_layer": "static",
        "evidence_kind": "active_source_exact",
        "exact_locator": record.locator,
    }


def _node_identifier(source: ExactTopologySource, record: _ElementRecord) -> str:
    digest = hashlib.sha256(
        f"{source.content_sha256}\0{record.locator}".encode("utf-8")
    ).hexdigest()[:24]
    return f"node:{digest}"


def _edge_identifier(source: ExactTopologySource, locator: str, prefix: str) -> str:
    digest = hashlib.sha256(
        f"{source.content_sha256}\0{locator}\0{prefix}".encode("utf-8")
    ).hexdigest()[:24]
    return f"edge:{digest}"


def _source_metadata(
    source: ExactTopologySource, selection_state: str, element: ET.Element
) -> dict[str, object]:
    return {
        "provider_id": source.provider_id,
        "provider_kind": source.provider_kind,
        "source_kind": source.source_kind,
        "source_path": source.source_path,
        "canonical_path": source.canonical_path,
        "content_sha256": source.content_sha256,
        "selection_state": selection_state,
        "raw_attributes": {
            str(key): str(value)
            for key, value in sorted(element.attrib.items(), key=lambda item: item[0])
        },
    }


def _extract_document(
    source: ExactTopologySource, selection_state: str
) -> tuple[list[dict[str, object]], list[dict[str, object]], str]:
    _root, records, domain = _parse_xml(source)
    node_records = [record for record in records if not _is_edge(record.element)]
    if len(node_records) > _MAX_NODES:
        raise TopologyAcquisitionError("document node count exceeds the hard bound")

    node_id_by_index = {
        record.index: _node_identifier(source, record) for record in node_records
    }
    identity_candidates: dict[str, list[str]] = {}
    for record in node_records:
        identity = record.element.attrib.get("id") or record.element.attrib.get("name")
        if identity is not None:
            checked = _text(identity, "element identity", maximum=1024)
            identity_candidates.setdefault(checked, []).append(
                node_id_by_index[record.index]
            )
    identity_by_exact = {
        identity: node_ids[0]
        for identity, node_ids in identity_candidates.items()
        if len(node_ids) == 1
    }

    nodes: list[dict[str, object]] = []
    for record in node_records:
        raw_kind = record.element.attrib.get("kind") or record.tag
        raw_kind = _text(raw_kind, "raw_kind", maximum=256)
        normalized = _normalized_kind(record.tag, raw_kind, domain)
        supported = normalized is not None
        identity = record.element.attrib.get("id") or record.element.attrib.get("name")
        if identity is None:
            identity = f"anonymous:{node_id_by_index[record.index].removeprefix('node:')}"
        evidence = _evidence(record, source)
        owner_ref = record.element.attrib.get("owner") or record.element.attrib.get("owner_id")
        owner_node_id = identity_by_exact.get(owner_ref) if owner_ref is not None else None
        if owner_ref is not None and owner_node_id is not None:
            ownership = {
                "state": "declared",
                "owner_node_id": owner_node_id,
                "evidence_ids": [evidence["evidence_id"]],
            }
        elif normalized in {"quest_graph", "xgen_graph", "quest_module"}:
            ownership = {
                "state": "not_applicable",
                "owner_node_id": None,
                "evidence_ids": [],
            }
        else:
            ownership = {
                "state": "unresolved",
                "owner_node_id": None,
                "evidence_ids": [evidence["evidence_id"]] if owner_ref else [],
            }
        nodes.append(
            {
                "node_id": node_id_by_index[record.index],
                "domain": domain,
                "raw_kind": raw_kind,
                "normalized_kind": normalized,
                "support_state": "supported" if supported else "unsupported",
                "reason_code": None if supported else "unsupported_kind",
                "identity_key": identity,
                "exact_locator": record.locator,
                "ownership": ownership,
                "evidence": [evidence],
                "metadata": _source_metadata(source, selection_state, record.element),
            }
        )

    edges: list[dict[str, object]] = []
    for record in node_records:
        if record.parent_index not in node_id_by_index:
            continue
        locator = f"{record.locator}#contains"
        evidence = _evidence(record, source)
        edges.append(
            {
                "edge_id": _edge_identifier(source, locator, "contains"),
                "from_node_id": node_id_by_index[record.parent_index],
                "to_node_id": node_id_by_index[record.index],
                "raw_kind": "contains",
                "normalized_kind": "contains",
                "support_state": "supported",
                "reason_code": None,
                "exact_locator": locator,
                "evidence": [evidence],
                "metadata": _source_metadata(source, selection_state, record.element),
            }
        )

    for record in records:
        if not _is_edge(record.element):
            continue
        raw_kind = record.element.attrib.get("kind") or record.tag
        raw_kind = _text(raw_kind, "edge raw_kind", maximum=256)
        candidate = raw_kind.replace("-", "_").casefold()
        if candidate in {"edge", "transition", "connection"}:
            candidate = "connects_to"
        from_ref = record.element.attrib.get("from") or record.element.attrib.get("source")
        to_ref = record.element.attrib.get("to") or record.element.attrib.get("target")
        from_node = identity_by_exact.get(from_ref) if from_ref is not None else None
        to_node = identity_by_exact.get(to_ref) if to_ref is not None else None
        supported = candidate in _EDGE_KINDS and from_node is not None and to_node is not None
        evidence = _evidence(record, source)
        edges.append(
            {
                "edge_id": _edge_identifier(source, record.locator, raw_kind),
                "from_node_id": from_node
                or f"unresolved:{hashlib.sha256(str(from_ref).encode()).hexdigest()[:24]}",
                "to_node_id": to_node
                or f"unresolved:{hashlib.sha256(str(to_ref).encode()).hexdigest()[:24]}",
                "raw_kind": raw_kind,
                "normalized_kind": candidate if supported else None,
                "support_state": "supported" if supported else "unresolved",
                "reason_code": None if supported else "unresolved_endpoint_or_kind",
                "exact_locator": record.locator,
                "evidence": [evidence],
                "metadata": _source_metadata(source, selection_state, record.element),
            }
        )

    if len(edges) > _MAX_EDGES:
        raise TopologyAcquisitionError("document edge count exceeds the hard bound")
    return nodes, edges, domain


def _join_path(
    path: str,
    sources: Sequence[ExactTopologySource],
    winner: ProviderWinnerEvidence | None,
) -> _JoinDecision:
    reasons: set[str] = set()
    selected: list[ExactTopologySource] = []
    states: list[tuple[ExactTopologySource, str]] = []
    effective_conclusion = "inconclusive"
    effective_winner: str | None = None

    if winner is None:
        reasons.add("provider_winner_evidence_missing")
        states = [(source, "unresolved") for source in sources]
        selected = list(sources)
    elif not winner.fresh:
        reasons.add("stale_provider_coverage")
        states = [(source, "unresolved") for source in sources]
        selected = list(sources)
    elif winner.coverage_status != "complete":
        reasons.add("provider_coverage_incomplete")
        states = [(source, "unresolved") for source in sources]
        selected = list(sources)
    elif winner.conclusion == "winner":
        matches = [source for source in sources if source.provider_id == winner.winner_provider_id]
        if len(matches) != 1:
            reasons.add("winner_source_not_unique")
            states = [(source, "unresolved") for source in sources]
            selected = list(sources)
        else:
            effective_conclusion = "winner"
            effective_winner = winner.winner_provider_id
            selected = matches
            states = [
                (source, "winner" if source is matches[0] else "shadowed")
                for source in sources
            ]
    elif winner.conclusion in {"multiple_contributors", "parallel_contributors"}:
        effective_conclusion = winner.conclusion
        states = [(source, "contributes") for source in sources]
        selected = list(sources)
    elif winner.conclusion == "no_provider_observed" and not sources:
        effective_conclusion = "no_provider_observed"
    else:
        reasons.add("provider_resolution_inconclusive")
        states = [(source, "unresolved") for source in sources]
        selected = list(sources)

    payload = {
        "canonical_path": path,
        "coverage_id": winner.coverage_id if winner else None,
        "coverage_status": winner.coverage_status if winner else "capture_inconclusive",
        "snapshot_id": winner.snapshot_id if winner else None,
        "snapshot_sha256": winner.snapshot_sha256 if winner else None,
        "fresh": winner.fresh if winner else False,
        "reported_conclusion": winner.conclusion if winner else "inconclusive",
        "reported_winner_provider_id": winner.winner_provider_id if winner else None,
        "effective_conclusion": effective_conclusion,
        "effective_winner_provider_id": effective_winner,
        "exact_locator": winner.exact_locator if winner else None,
        "reason_codes": sorted(reasons),
    }
    return _JoinDecision(
        canonical_path=path,
        source_states=tuple(states),
        selected_sources=tuple(selected),
        payload=payload,
        reason_codes=tuple(sorted(reasons)),
    )


def acquire_quest_xgen_topology(
    *,
    query_id: str,
    graph_id: str,
    sources: Sequence[ExactTopologySource],
    provider_winners: Sequence[ProviderWinnerEvidence],
) -> TopologyAcquisitionResult:
    """Extract topology directly from exact XML bytes and join exact provider evidence."""

    query = _text(query_id, "query_id", maximum=1024)
    graph = _text(graph_id, "graph_id", maximum=1024)
    source_values = _bounded_sequence(sources, "sources", _MAX_SOURCES)
    if not source_values:
        raise TopologyAcquisitionError("sources must contain at least one exact document")
    if any(not isinstance(source, ExactTopologySource) for source in source_values):
        raise TopologyAcquisitionError("sources must contain ExactTopologySource values")
    if sum(len(source.content) for source in source_values) > _MAX_TOTAL_BYTES:
        raise TopologyAcquisitionError("source content exceeds the aggregate byte bound")

    winner_values = _bounded_sequence(
        provider_winners, "provider_winners", _MAX_WINNERS
    )
    if any(not isinstance(item, ProviderWinnerEvidence) for item in winner_values):
        raise TopologyAcquisitionError(
            "provider_winners must contain ProviderWinnerEvidence values"
        )
    winner_by_path: dict[str, ProviderWinnerEvidence] = {}
    for winner in winner_values:
        key = canonical_path_key(winner.canonical_path)
        if key in winner_by_path:
            raise TopologyAcquisitionError("provider_winners contains a duplicate path")
        winner_by_path[key] = winner

    sources_by_path: dict[str, list[ExactTopologySource]] = {}
    exact_source_keys: set[tuple[str, str, str]] = set()
    for source in source_values:
        source_key = (
            source.provider_id.casefold(),
            canonical_path_key(source.canonical_path),
            source.source_path.casefold(),
        )
        if source_key in exact_source_keys:
            raise TopologyAcquisitionError("sources contains a duplicate exact provider source")
        exact_source_keys.add(source_key)
        sources_by_path.setdefault(canonical_path_key(source.canonical_path), []).append(source)

    decisions: list[_JoinDecision] = []
    for path_key in sorted(sources_by_path):
        path_sources = sorted(
            sources_by_path[path_key],
            key=lambda item: (
                item.provider_id.casefold(),
                item.provider_id,
                item.source_path.casefold(),
                item.source_path,
            ),
        )
        decisions.append(
            _join_path(
                min(source.canonical_path for source in path_sources),
                path_sources,
                winner_by_path.get(path_key),
            )
        )
    unmatched_winners = sorted(set(winner_by_path) - set(sources_by_path))
    if unmatched_winners:
        raise TopologyAcquisitionError(
            "provider_winners names a path without an exact topology source"
        )

    all_nodes: list[dict[str, object]] = []
    all_edges: list[dict[str, object]] = []
    selected_sources: list[ExactTopologySource] = []
    source_rows: list[dict[str, object]] = []
    global_reasons: set[str] = set()
    domain_complete: dict[str, bool] = {domain: True for domain in _DOMAIN_ORDER}
    domain_reasons: dict[str, set[str]] = {domain: set() for domain in _DOMAIN_ORDER}
    seen_domains: set[str] = set()

    for decision in decisions:
        global_reasons.update(decision.reason_codes)
        state_by_identity = {id(source): state for source, state in decision.source_states}
        selected_identities = {id(source) for source in decision.selected_sources}
        for source, selection_state in decision.source_states:
            source_rows.append(
                {
                    "canonical_path": source.canonical_path,
                    "provider_id": source.provider_id,
                    "provider_kind": source.provider_kind,
                    "source_kind": source.source_kind,
                    "source_path": source.source_path,
                    "content_sha256": source.content_sha256,
                    "selection_state": selection_state,
                    "topology_complete": source.topology_complete,
                }
            )
        for source in decision.selected_sources:
            nodes, edges, domain = _extract_document(
                source, state_by_identity[id(source)]
            )
            selected_sources.append(source)
            seen_domains.add(domain)
            all_nodes.extend(nodes)
            all_edges.extend(edges)
            if not source.topology_complete:
                domain_complete[domain] = False
                global_reasons.add("topology_coverage_incomplete")
                domain_reasons[domain].add("topology_coverage_incomplete")
            for reason in decision.reason_codes:
                domain_reasons[domain].add(reason)
                if reason in {
                    "stale_provider_coverage",
                    "provider_coverage_incomplete",
                    "provider_resolution_inconclusive",
                    "provider_winner_evidence_missing",
                    "winner_source_not_unique",
                }:
                    domain_complete[domain] = False
        if decision.reason_codes and not decision.selected_sources:
            for source, _selection_state in decision.source_states:
                _root, _records, domain = _parse_xml(source)
                domain_complete[domain] = False
        if not selected_identities:
            global_reasons.add("no_effective_source_selected")

    if len(all_nodes) > _MAX_NODES:
        raise TopologyAcquisitionError("aggregate node count exceeds the hard bound")
    if len(all_edges) > _MAX_EDGES:
        raise TopologyAcquisitionError("aggregate edge count exceeds the hard bound")

    unsupported_by_domain = {domain: 0 for domain in _DOMAIN_ORDER}
    unresolved_edge_domains: set[str] = set()
    node_domain_by_id = {str(node["node_id"]): str(node["domain"]) for node in all_nodes}
    for node in all_nodes:
        if node["support_state"] != "supported":
            unsupported_by_domain[str(node["domain"])] += 1
            domain_complete[str(node["domain"])] = False
            domain_reasons[str(node["domain"])].add("unsupported_kind_retained")
            global_reasons.add("unsupported_kind_retained")
    for edge in all_edges:
        if edge["support_state"] != "supported":
            domain = node_domain_by_id.get(str(edge["from_node_id"]))
            if domain is None:
                domain = node_domain_by_id.get(str(edge["to_node_id"]))
            if domain is not None:
                unresolved_edge_domains.add(domain)
                domain_complete[domain] = False
                domain_reasons[domain].add("unresolved_edge_retained")
            global_reasons.add("unresolved_edge_retained")

    coverage: list[dict[str, object]] = []
    for domain in _DOMAIN_ORDER:
        if domain not in seen_domains:
            continue
        domain_nodes = [node for node in all_nodes if node["domain"] == domain]
        stale = any(
            reason in {"stale_provider_coverage", "provider_coverage_incomplete"}
            for reason in domain_reasons[domain]
        )
        if stale:
            status = "capture_inconclusive"
        elif domain_complete[domain]:
            status = "complete"
        else:
            status = "partial"
        reasons = set(domain_reasons[domain])
        if not domain_complete[domain] and not reasons:
            reasons.add("topology_coverage_incomplete")
        coverage.append(
            {
                "domain": domain,
                "status": status,
                "enumerated_count": len(domain_nodes),
                "retained_unsupported_count": unsupported_by_domain[domain],
                "absence_claim_allowed": status == "complete",
                "reason_codes": sorted(reasons),
            }
        )

    selected_hashes = sorted(source.content_sha256 for source in selected_sources)
    aggregate_sha256 = hashlib.sha256(_canonical_bytes(selected_hashes)).hexdigest()
    captured_at = max(source.captured_at for source in selected_sources)
    verdict = (
        "valid"
        if coverage and all(item["status"] == "complete" for item in coverage)
        else "capture_inconclusive"
    )
    if verdict == "capture_inconclusive" and not global_reasons:
        global_reasons.add("partial_domain_coverage")
    audit = {
        "schema_version": "kcd2.ai-quest-graph-audit.v1",
        "graph_id": graph,
        "domains": [domain for domain in _DOMAIN_ORDER if domain in seen_domains],
        "source": {
            "sha256": aggregate_sha256,
            "byte_size": sum(len(source.content) for source in selected_sources),
            "exact_locator": f"acquisition://{query}",
            "captured_at": captured_at,
        },
        "nodes": sorted(all_nodes, key=lambda item: str(item["node_id"])),
        "edges": sorted(all_edges, key=lambda item: str(item["edge_id"])),
        "runtime_markers": [],
        "coverage": coverage,
        "verdict": verdict,
        "reason_codes": sorted(global_reasons),
    }
    compact = {
        "status": verdict,
        "graph_id": graph,
        "source_count": len(source_values),
        "selected_source_count": len(selected_sources),
        "node_count": len(all_nodes),
        "edge_count": len(all_edges),
        "declared_owner_count": sum(
            node["ownership"]["state"] == "declared" for node in all_nodes  # type: ignore[index]
        ),
        "unresolved_owner_count": sum(
            node["ownership"]["state"] == "unresolved" for node in all_nodes  # type: ignore[index]
        ),
        "provider_winner_count": sum(
            decision.payload["effective_conclusion"] == "winner" for decision in decisions
        ),
        "stale_coverage_paths": sorted(
            decision.canonical_path
            for decision in decisions
            if "stale_provider_coverage" in decision.reason_codes
        ),
        "sources": sorted(
            source_rows,
            key=lambda item: (
                str(item["canonical_path"]).casefold(),
                str(item["provider_id"]).casefold(),
                str(item["source_path"]).casefold(),
            ),
        ),
        "reason_codes": sorted(global_reasons),
    }
    payload = {
        "schema_version": "kcd2.ai-quest-topology-acquisition.v1",
        "query_id": query,
        "graph_audit": audit,
        "provider_join": [dict(decision.payload) for decision in decisions],
        "compact_audit": compact,
    }
    return TopologyAcquisitionResult(payload=payload)
