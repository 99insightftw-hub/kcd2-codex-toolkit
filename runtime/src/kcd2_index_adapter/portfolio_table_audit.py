"""Bounded portfolio table winner, reference, and restoration audit."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .coverage import CoverageValidity
from .reference_integrity import (
    ReferenceDefinition,
    ReferenceUse,
    check_reference_integrity,
)
from .table_semantics import (
    ExactTableDocument,
    TableSemanticsRegistry,
    extract_table_record_contributions,
)


_MAX_TABLES = 256
_MAX_DOCUMENTS = 256
_MAX_TEXT = 1024
_COMPLETE_COVERAGE = {"COMPLETE", "COMPLETE_FOR_REQUESTED_SCOPE"}


class PortfolioTableAuditError(ValueError):
    """The requested audit is malformed or exceeds its hard bounds."""


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise PortfolioTableAuditError(f"{field} must be a non-empty bounded string")
    return value


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
        raise PortfolioTableAuditError("audit result must be JSON-compatible") from exc


def _copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class PortfolioTableInput:
    """One canonical table and its exact active provider sequence."""

    query_id: str
    canonical_path: str
    documents: tuple[ExactTableDocument, ...]

    def __post_init__(self) -> None:
        _text(self.query_id, "query_id")
        _text(self.canonical_path, "canonical_path")
        if len(self.documents) > _MAX_DOCUMENTS:
            raise PortfolioTableAuditError("documents exceed the 256-item hard bound")
        if any(not isinstance(item, ExactTableDocument) for item in self.documents):
            raise PortfolioTableAuditError("documents must contain ExactTableDocument values")


@dataclass(frozen=True, slots=True)
class PortfolioTableAudit:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _key(record: Mapping[str, Any], *, case_sensitive: bool) -> tuple[tuple[str, str], ...]:
    if case_sensitive:
        return tuple((item["name"], item["value"]) for item in record["record_key"])
    return tuple(
        (item["name"].casefold(), item["value"].casefold())
        for item in record["record_key"]
    )


def _provider_citation(
    contribution: Mapping[str, Any],
    project_by_provider: Mapping[str, str],
    provider_sha_by_provider: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "provider_id": contribution["provider_id"],
        "provider_kind": contribution["provider_kind"],
        "project_id": project_by_provider.get(contribution["provider_id"].casefold()),
        "active_provider_sha256": provider_sha_by_provider.get(
            contribution["provider_id"].casefold()
        ),
        "load_order_index": contribution["load_order_index"],
        "source_path": contribution["source_path"],
        "content_sha256": contribution["content_sha256"],
    }


def _active_provider_bindings(
    active_state: Mapping[str, object],
) -> tuple[
    dict[str, tuple[str, str | None, tuple[str, ...]]],
    dict[str, str],
    dict[str, str],
    list[str],
]:
    if active_state.get("schema_version") != "kcd2.portfolio-active-state.v1":
        raise PortfolioTableAuditError("active_state must be portfolio-active-state v1")
    projects = active_state.get("projects")
    if not isinstance(projects, Sequence) or isinstance(projects, (str, bytes)):
        raise PortfolioTableAuditError("active_state.projects must be an array")
    if len(projects) > 256:
        raise PortfolioTableAuditError("active_state.projects exceeds the 256-item hard bound")
    bindings: dict[str, tuple[str, str | None, tuple[str, ...]]] = {}
    project_by_provider: dict[str, str] = {}
    provider_sha_by_provider: dict[str, str] = {}
    reasons: set[str] = set()
    for project in projects:
        if not isinstance(project, Mapping):
            raise PortfolioTableAuditError("active_state project entries must be objects")
        project_id = _text(project.get("project_id"), "active_state project_id")
        if project.get("status") != "current":
            reasons.add("ACTIVE_PROJECT_STATE_NOT_CURRENT")
        providers = project.get("providers")
        if not isinstance(providers, Sequence) or isinstance(providers, (str, bytes)):
            raise PortfolioTableAuditError("active_state project providers must be an array")
        if len(providers) > 4096:
            raise PortfolioTableAuditError("active_state providers exceed the 4096-item hard bound")
        for provider in providers:
            if not isinstance(provider, Mapping):
                raise PortfolioTableAuditError("active_state provider entries must be objects")
            provider_id = _text(provider.get("provider_id"), "active_state provider_id")
            states_value = provider.get("states")
            if not isinstance(states_value, Sequence) or isinstance(states_value, (str, bytes)):
                raise PortfolioTableAuditError("active_state provider states must be an array")
            states = tuple(_text(item, "active_state provider state") for item in states_value)
            key = provider_id.casefold()
            if key in bindings:
                reasons.add("DUPLICATE_ACTIVE_PROVIDER_BINDING")
                continue
            digest = provider.get("sha256")
            if digest is not None:
                _text(digest, "active_state provider sha256")
            bindings[key] = (project_id, digest, states)
            project_by_provider[key] = project_id
            if isinstance(digest, str):
                provider_sha_by_provider[key] = digest
    coverage = active_state.get("coverage")
    if not isinstance(coverage, Mapping):
        raise PortfolioTableAuditError("active_state.coverage must be an object")
    if (
        active_state.get("status") != "exact_current"
        or coverage.get("status") != "complete"
        or coverage.get("absence_claim_allowed") is not True
    ):
        reasons.add("PARTIAL_PORTFOLIO_COVERAGE")
    return bindings, project_by_provider, provider_sha_by_provider, sorted(reasons)


def _validate_document_bindings(
    tables: Sequence[PortfolioTableInput],
    bindings: Mapping[str, tuple[str, str | None, tuple[str, ...]]],
) -> list[str]:
    reasons: set[str] = set()
    for table in tables:
        for document in table.documents:
            if document.provider_kind == "vanilla":
                continue
            binding = bindings.get(document.provider_id.casefold())
            if binding is None:
                reasons.add("ACTIVE_PROVIDER_BINDING_MISSING")
                continue
            _project_id, digest, states = binding
            if "loaded" not in states:
                reasons.add("PROVIDER_NOT_LATEST_LOADED")
            if digest is None:
                reasons.add("ACTIVE_PROVIDER_HASH_MISSING")
    return sorted(reasons)


def _attribute_map(contribution: Mapping[str, Any]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in contribution["attributes"]}


def _semantic_children(contribution: Mapping[str, Any]) -> bytes:
    return _canonical_bytes(contribution["nested_children"])


def _record_audits(
    contributions: Sequence[Mapping[str, Any]],
    *,
    table_type: str,
    list_behavior: str,
    case_sensitive: bool,
    project_by_provider: Mapping[str, str],
    provider_sha_by_provider: Mapping[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[tuple[str, str], ...], list[Mapping[str, Any]]] = {}
    duplicates: dict[tuple[str, tuple[tuple[str, str], ...]], list[Mapping[str, Any]]] = {}
    for contribution in contributions:
        if not contribution["record_key"]:
            continue
        record_key = _key(contribution, case_sensitive=case_sensitive)
        grouped.setdefault(record_key, []).append(contribution)
        duplicates.setdefault((contribution["provider_id"].casefold(), record_key), []).append(contribution)

    duplicate_rows = []
    for (_provider_key, _record_key), items in sorted(
        duplicates.items(), key=lambda item: _canonical_bytes(item[0])
    ):
        if len(items) < 2:
            continue
        duplicate_rows.append(
            {
                "record_key": _copy(items[0]["record_key"]),
                "provider_id": items[0]["provider_id"],
                "row_indices": [item["record_index"] for item in items],
                "count": len(items),
            }
        )

    records: list[dict[str, Any]] = []
    for _record_key, raw_items in sorted(grouped.items(), key=lambda item: _canonical_bytes(item[0])):
        seen_providers: set[str] = set()
        items = []
        for item in raw_items:
            provider_key = item["provider_id"].casefold()
            if provider_key in seen_providers:
                continue
            seen_providers.add(provider_key)
            items.append(item)
        if not items:
            continue
        winner = items[-1]
        attribute_winners: dict[str, Mapping[str, Any]] = {}
        if table_type == "old":
            attribute_winners = {name: winner for name in _attribute_map(winner)}
        else:
            for item in items:
                for name in _attribute_map(item):
                    attribute_winners[name] = item

        child_winners: list[dict[str, Any]] = []
        if list_behavior == "append":
            for item in items:
                for index, _child in enumerate(item["nested_children"]):
                    child_winners.append(
                        {"child_index": index, **_provider_citation(item, project_by_provider, provider_sha_by_provider)}
                    )
        elif items:
            child_winner = items[-1]
            child_winners = [
                {"child_index": index, **_provider_citation(child_winner, project_by_provider, provider_sha_by_provider)}
                for index, _child in enumerate(child_winner["nested_children"])
            ]

        restorations: list[dict[str, Any]] = []
        vanilla = next((item for item in items if item["provider_kind"] == "vanilla"), None)
        candidate = next((item for item in reversed(items) if item["provider_kind"] == "candidate"), None)
        if vanilla is not None and candidate is not None:
            candidate_position = items.index(candidate)
            upstream_items = [
                item
                for item in items[:candidate_position]
                if item["provider_kind"] in {"dependency", "parent"}
            ]
            if upstream_items:
                upstream = upstream_items[-1]
                vanilla_attributes = _attribute_map(vanilla)
                upstream_attributes = _attribute_map(upstream)
                candidate_attributes = _attribute_map(candidate)
                for name in sorted(set(vanilla_attributes) & set(upstream_attributes) & set(candidate_attributes), key=str.casefold):
                    if candidate_attributes[name] == vanilla_attributes[name] != upstream_attributes[name]:
                        restorations.append(
                            {
                                "scope": "attribute",
                                "name": name,
                                "restored_value": candidate_attributes[name],
                                "overwritten_upstream_value": upstream_attributes[name],
                                "vanilla_provider_id": vanilla["provider_id"],
                                "upstream_provider_id": upstream["provider_id"],
                                "restoring_provider_id": candidate["provider_id"],
                            }
                        )
                if (
                    _semantic_children(candidate) == _semantic_children(vanilla)
                    and _semantic_children(candidate) != _semantic_children(upstream)
                ):
                    restorations.append(
                        {
                            "scope": "children",
                            "name": None,
                            "restored_value": hashlib.sha256(_semantic_children(candidate)).hexdigest(),
                            "overwritten_upstream_value": hashlib.sha256(_semantic_children(upstream)).hexdigest(),
                            "vanilla_provider_id": vanilla["provider_id"],
                            "upstream_provider_id": upstream["provider_id"],
                            "restoring_provider_id": candidate["provider_id"],
                        }
                    )

        records.append(
            {
                "record_key": _copy(winner["record_key"]),
                "record_winner": _provider_citation(winner, project_by_provider, provider_sha_by_provider),
                "attribute_winners": [
                    {"name": name, **_provider_citation(item, project_by_provider, provider_sha_by_provider)}
                    for name, item in sorted(attribute_winners.items(), key=lambda pair: pair[0].casefold())
                ],
                "child_winners": child_winners,
                "contributing_provider_ids": [item["provider_id"] for item in items],
                "upstream_restorations": restorations,
            }
        )
    return records, duplicate_rows


def audit_portfolio_tables(
    *,
    audit_id: str,
    registry: TableSemanticsRegistry,
    game_build: str,
    source_build: str,
    active_state: Mapping[str, object],
    tables: Sequence[PortfolioTableInput],
    definitions: Sequence[ReferenceDefinition],
    references: Sequence[ReferenceUse],
    coverage: CoverageValidity,
) -> PortfolioTableAudit:
    """Audit exact active portfolio tables using reviewed table semantics."""

    checked_id = _text(audit_id, "audit_id")
    _text(game_build, "game_build")
    _text(source_build, "source_build")
    if not isinstance(registry, TableSemanticsRegistry):
        raise PortfolioTableAuditError("registry must be a TableSemanticsRegistry")
    if not isinstance(active_state, Mapping):
        raise PortfolioTableAuditError("active_state must be an object")
    if not isinstance(coverage, CoverageValidity):
        raise PortfolioTableAuditError("coverage must be CoverageValidity")
    if isinstance(tables, (str, bytes)) or not isinstance(tables, Sequence):
        raise PortfolioTableAuditError("tables must be an array")
    if not tables or len(tables) > _MAX_TABLES:
        raise PortfolioTableAuditError("tables must contain 1 through 256 entries")
    if any(not isinstance(item, PortfolioTableInput) for item in tables):
        raise PortfolioTableAuditError("tables must contain PortfolioTableInput values")
    paths = [item.canonical_path.casefold() for item in tables]
    if len(paths) != len(set(paths)):
        raise PortfolioTableAuditError("canonical table paths must be unique")

    bindings, project_by_provider, provider_sha_by_provider, active_reasons = _active_provider_bindings(active_state)
    binding_reasons = _validate_document_bindings(tables, bindings)
    coverage_payload = coverage.to_dict()
    coverage_status = coverage_payload.get("overall_status")
    partial = coverage_status not in _COMPLETE_COVERAGE
    if partial:
        active_reasons.append("PARTIAL_PORTFOLIO_COVERAGE")

    reference_report = check_reference_integrity(
        report_id=f"{checked_id}:references",
        definitions=definitions,
        references=references,
        coverage=coverage,
    ).to_dict()
    table_payloads: list[dict[str, Any]] = []
    issue_observed = reference_report["status"] == "issues_found"
    semantic_inconclusive = False
    for table in sorted(tables, key=lambda item: item.canonical_path.casefold()):
        profile = registry.resolve(
            game_build=game_build,
            source_build=source_build,
            canonical_path=table.canonical_path,
        )
        contribution_set = extract_table_record_contributions(
            query_id=table.query_id,
            registry=registry,
            game_build=game_build,
            source_build=source_build,
            canonical_path=table.canonical_path,
            documents=table.documents,
        ).to_dict()
        records, duplicates = _record_audits(
            contribution_set["contributions"],
            table_type=profile.table_type,
            list_behavior=profile.list_behavior,
            case_sensitive=profile.case_sensitive,
            project_by_provider=project_by_provider,
            provider_sha_by_provider=provider_sha_by_provider,
        )
        table_reference_ids = {
            item.reference_id
            for item in references
            if item.source_path.casefold() == table.canonical_path.casefold()
        }
        table_resolutions = [
            item
            for item in reference_report["resolutions"]
            if item["reference_id"] in table_reference_ids
        ]
        reference_issues = [
            {"reference_id": item["reference_id"], "classification": item["classification"]}
            for item in table_resolutions
            if item["classification"] != "resolved_active"
        ]
        restorations = sum(len(record["upstream_restorations"]) for record in records)
        if duplicates or reference_issues or restorations:
            issue_observed = True
        if contribution_set["semantics_status"] == "capture_inconclusive":
            semantic_inconclusive = True
        elif contribution_set["semantics_status"] == "unresolved":
            issue_observed = True
        table_payloads.append(
            {
                "canonical_path": contribution_set["canonical_path"],
                "profile_id": profile.profile_id,
                "table_type": profile.table_type,
                "semantics_status": contribution_set["semantics_status"],
                "reason_codes": contribution_set["reason_codes"],
                "provider_documents": contribution_set["provider_documents"],
                "semantic_comparison": {
                    "mode": "profile_proven_merge",
                    "plain_xml_diff_sufficient": False,
                    "restoration_count": restorations,
                },
                "records": records,
                "duplicate_rows": duplicates,
                "reference_issues": reference_issues,
            }
        )

    reasons = sorted(set(active_reasons + binding_reasons))
    capture_inconclusive = bool(reasons) or partial or semantic_inconclusive or reference_report["status"] == "capture_inconclusive"
    status = "capture_inconclusive" if capture_inconclusive else "issues_found" if issue_observed else "resolved"
    no_conflict_allowed = status == "resolved" and coverage_status in _COMPLETE_COVERAGE
    localization_links = [
        item for item in reference_report["resolutions"] if item["family"] == "localization"
    ]
    material = {
        "audit_id": checked_id,
        "game_build": game_build,
        "source_build": source_build,
        "active_state_link_id": active_state.get("link_id"),
        "coverage_id": coverage_payload.get("coverage_id"),
        "tables": table_payloads,
        "reference_input_sha256": reference_report["input_sha256"],
    }
    payload = {
        "schema_version": "kcd2.table-rpg-audit.v1",
        "audit_id": checked_id,
        "input_sha256": hashlib.sha256(_canonical_bytes(material)).hexdigest(),
        "game_build": game_build,
        "source_build": source_build,
        "active_state": {
            "link_id": active_state.get("link_id"),
            "status": active_state.get("status"),
        },
        "status": status,
        "reason_codes": reasons,
        "coverage": {
            "coverage_id": coverage_payload.get("coverage_id"),
            "overall_status": coverage_status,
            "absence_claim_allowed": coverage_payload.get("claim_permissions", {}).get("absence_claim_allowed") is True and not capture_inconclusive,
        },
        "no_conflict_claim_allowed": no_conflict_allowed,
        "tables": table_payloads,
        "reference_graph": {
            "status": reference_report["status"],
            "graph": reference_report["graph"],
            "resolutions": reference_report["resolutions"],
        },
        "localization_links": localization_links,
        "bounds": {
            "max_tables": _MAX_TABLES,
            "max_documents_per_table": _MAX_DOCUMENTS,
            "tables_considered": len(table_payloads),
        },
    }
    return PortfolioTableAudit(payload=_copy(payload))
