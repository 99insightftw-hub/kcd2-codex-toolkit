"""Fail-closed balance, table, and RPG compatibility-stack acceptance."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .compatibility_stacks import evaluate_compatibility_stack


_INPUT_FIELDS = {
    "schema_version",
    "acceptance_id",
    "stack_manifest",
    "table_audit",
    "semantic_baselines",
    "inventory_baselines",
    "inventory_resolutions",
    "compounded_effects",
    "tbl_contract_reports",
}
_MAX_TABLES = 256
_MAX_RECORDS = 20_000
_MAX_ATTRIBUTES = 256
_MAX_CHAINS = 4_096
_MAX_EFFECTS = 4_096
_MAX_OPERANDS = 256
_MISSING_REFERENCES = {
    "missing_globally",
    "missing_from_active_set",
    "available_only_in_dependency",
    "defined_by_later_mod",
    "defined_wrong_case",
    "ambiguous_duplicate_definition",
}


class BalanceTableRpgAcceptanceError(ValueError):
    """Balance-stack evidence is malformed, ambiguous, or exceeds its bounds."""


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise BalanceTableRpgAcceptanceError(f"{field} must be an object")
    return value


def _sequence(value: object, field: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise BalanceTableRpgAcceptanceError(f"{field} must be an array")
    if len(value) > maximum:
        raise BalanceTableRpgAcceptanceError(f"{field} exceeds {maximum} items")
    return value


def _text(value: object, field: str, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise BalanceTableRpgAcceptanceError(f"{field} must be bounded text")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], field: str) -> None:
    missing = fields - set(value)
    unknown = set(value) - fields
    if missing or unknown:
        raise BalanceTableRpgAcceptanceError(
            f"{field} fields are invalid; missing={sorted(missing)}, "
            f"unknown={sorted(unknown)}"
        )


def _key(value: object, field: str) -> tuple[tuple[str, str], ...]:
    rows = _sequence(value, field, 16)
    if not rows:
        raise BalanceTableRpgAcceptanceError(f"{field} must not be empty")
    result = []
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"{field}[{index}]")
        _exact(row, {"name", "value"}, f"{field}[{index}]")
        result.append(
            (_text(row["name"], f"{field}[{index}].name"), str(row["value"]))
        )
    if len(result) != len(set(result)):
        raise BalanceTableRpgAcceptanceError(f"{field} contains duplicate keys")
    return tuple(sorted(result, key=lambda item: item[0].casefold()))


def _status(failures: set[str], inconclusive: set[str]) -> str:
    if failures:
        return "FAIL"
    if inconclusive:
        return "INCONCLUSIVE"
    return "PASS"


def _gate(gate_id: str, failures: set[str], inconclusive: set[str]) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "status": _status(failures, inconclusive),
        "reason_codes": sorted(failures | inconclusive),
    }


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise BalanceTableRpgAcceptanceError("evidence must be JSON-compatible") from exc


@dataclass(frozen=True, slots=True)
class BalanceTableRpgAcceptanceReceipt:
    """Detached deterministic acceptance receipt."""

    _payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return _canonical(self._payload).decode("utf-8")


def evaluate_balance_table_rpg_acceptance(
    value: Mapping[str, Any],
) -> BalanceTableRpgAcceptanceReceipt:
    """Evaluate reviewed semantic baselines against exact stack evidence."""
    document = _mapping(value, "acceptance")
    _exact(document, _INPUT_FIELDS, "acceptance")
    if document["schema_version"] != "kcd2.balance-table-rpg-stack-input.v1":
        raise BalanceTableRpgAcceptanceError("unsupported schema_version")
    acceptance_id = _text(document["acceptance_id"], "acceptance_id")

    manifest = evaluate_compatibility_stack(
        _mapping(document["stack_manifest"], "stack_manifest")
    ).to_dict()
    stack_failures: set[str] = set()
    stack_inconclusive: set[str] = set()
    if manifest["family"] != "BALANCE_TABLE":
        stack_failures.add("STACK_FAMILY_MISMATCH")
    if manifest["result"] == "FAIL":
        stack_failures.add("STACK_MANIFEST_FAILED")
    elif manifest["result"] != "PASS":
        stack_inconclusive.add("STACK_MANIFEST_INCONCLUSIVE")
    member_ids = {row["project_id"] for row in manifest["members"]}
    intended = {
        row["resource"].casefold(): row["provider_project_id"]
        for row in manifest["intended_winners"]
    }

    audit = _mapping(document["table_audit"], "table_audit")
    audit_status = audit.get("status")
    coverage = _mapping(audit.get("coverage"), "table_audit.coverage")
    table_inconclusive: set[str] = set()
    table_audit_failures: set[str] = set()
    if audit_status == "capture_inconclusive" or not coverage.get(
        "absence_claim_allowed", False
    ):
        table_inconclusive.add("CAPTURE_INCONCLUSIVE")
    elif audit_status == "issues_found":
        table_audit_failures.add("TABLE_AUDIT_ISSUES")
    elif audit_status != "resolved":
        raise BalanceTableRpgAcceptanceError("table_audit.status is invalid")

    tables_raw = _sequence(audit.get("tables"), "table_audit.tables", _MAX_TABLES)
    tables: dict[str, Mapping[str, Any]] = {}
    record_count = 0
    for index, raw in enumerate(tables_raw):
        table = _mapping(raw, f"table_audit.tables[{index}]")
        path = _text(table.get("canonical_path"), f"table[{index}].canonical_path")
        if path.casefold() in tables:
            raise BalanceTableRpgAcceptanceError("table paths must be unique")
        tables[path.casefold()] = table
        records = _sequence(table.get("records"), f"table[{index}].records", _MAX_RECORDS)
        record_count += len(records)
        if record_count > _MAX_RECORDS:
            raise BalanceTableRpgAcceptanceError("record total exceeds hard bound")

    semantic_failures: set[str] = set()
    winner_failures: set[str] = set()
    observations: dict[str, float] = {}
    baselines_raw = _sequence(
        document["semantic_baselines"], "semantic_baselines", _MAX_RECORDS
    )
    seen_baselines: set[str] = set()
    for index, raw in enumerate(baselines_raw):
        baseline = _mapping(raw, f"semantic_baselines[{index}]")
        _exact(
            baseline,
            {
                "baseline_id",
                "canonical_path",
                "table_type",
                "record_key",
                "record_project_id",
                "attributes",
            },
            f"semantic_baselines[{index}]",
        )
        baseline_id = _text(baseline["baseline_id"], f"baseline[{index}].baseline_id")
        if baseline_id in seen_baselines:
            raise BalanceTableRpgAcceptanceError("baseline_id values must be unique")
        seen_baselines.add(baseline_id)
        path = _text(baseline["canonical_path"], f"baseline[{index}].canonical_path")
        if baseline["table_type"] not in {"old", "new"}:
            raise BalanceTableRpgAcceptanceError(
                "semantic baselines support only reviewed old/new table semantics"
            )
        table = tables.get(path.casefold())
        if table is None:
            semantic_failures.add("SEMANTIC_BASELINE_TABLE_MISSING")
            continue
        if table.get("semantics_status") != "resolved":
            table_inconclusive.add("CAPTURE_INCONCLUSIVE")
        if table.get("table_type") != baseline["table_type"]:
            semantic_failures.add("TABLE_SEMANTICS_MISMATCH")
        expected_record_project = _text(
            baseline["record_project_id"], f"baseline[{index}].record_project_id"
        )
        if expected_record_project not in member_ids:
            raise BalanceTableRpgAcceptanceError("baseline project is not a stack member")
        if intended.get(path.casefold()) != expected_record_project:
            winner_failures.add("RESOURCE_WINNER_MISMATCH")
        target_key = _key(baseline["record_key"], f"baseline[{index}].record_key")
        matches = [
            record
            for record in _sequence(table.get("records"), "table.records", _MAX_RECORDS)
            if _key(_mapping(record, "record").get("record_key"), "record.record_key")
            == target_key
        ]
        if len(matches) != 1:
            winner_failures.add("RECORD_WINNER_MISMATCH")
            continue
        record = _mapping(matches[0], "record")
        record_winner = _mapping(record.get("record_winner"), "record.record_winner")
        if record_winner.get("project_id") != expected_record_project:
            winner_failures.add("RECORD_WINNER_MISMATCH")
        actual_attributes = {
            _text(row.get("name"), "attribute.name"): row
            for row in (
                _mapping(item, "attribute")
                for item in _sequence(
                    record.get("attribute_winners"),
                    "record.attribute_winners",
                    _MAX_ATTRIBUTES,
                )
            )
        }
        for attr_index, attr_raw in enumerate(
            _sequence(baseline["attributes"], "baseline.attributes", _MAX_ATTRIBUTES)
        ):
            attr = _mapping(attr_raw, f"baseline.attributes[{attr_index}]")
            _exact(
                attr,
                {"name", "provider_project_id", "value_id", "expected_value", "observed_value"},
                f"baseline.attributes[{attr_index}]",
            )
            name = _text(attr["name"], "baseline.attribute.name")
            winner = actual_attributes.get(name)
            if winner is None:
                winner_failures.add("ATTRIBUTE_LOSS")
                continue
            if attr["provider_project_id"] not in member_ids:
                raise BalanceTableRpgAcceptanceError(
                    "attribute baseline project is not a stack member"
                )
            if winner.get("project_id") != attr["provider_project_id"]:
                winner_failures.add("ATTRIBUTE_WINNER_MISMATCH")
            try:
                expected = float(attr["expected_value"])
                observed = float(attr["observed_value"])
            except (TypeError, ValueError, OverflowError) as exc:
                raise BalanceTableRpgAcceptanceError(
                    "attribute values must be finite numbers"
                ) from exc
            if not math.isfinite(expected) or not math.isfinite(observed):
                raise BalanceTableRpgAcceptanceError("attribute values must be finite numbers")
            if not math.isclose(expected, observed, rel_tol=1e-9, abs_tol=1e-9):
                semantic_failures.add("ATTRIBUTE_VALUE_MISMATCH")
            value_id = _text(attr["value_id"], "baseline.attribute.value_id")
            if value_id in observations:
                raise BalanceTableRpgAcceptanceError("value_id values must be unique")
            observations[value_id] = observed

    reference_failures: set[str] = set()
    reference_inconclusive: set[str] = set()
    resolutions = _sequence(
        _mapping(audit.get("reference_graph"), "table_audit.reference_graph").get(
            "resolutions"
        ),
        "reference_graph.resolutions",
        _MAX_RECORDS,
    )
    if any(
        _mapping(row, "reference").get("classification") in _MISSING_REFERENCES
        for row in resolutions
    ):
        reference_failures.add("MISSING_REFERENCE")
    if any(
        _mapping(row, "reference").get("classification") == "capture_inconclusive"
        for row in resolutions
    ):
        reference_inconclusive.add("CAPTURE_INCONCLUSIVE")
    if any(
        _sequence(
            _mapping(record, "record").get("upstream_restorations"),
            "upstream_restorations",
            _MAX_ATTRIBUTES,
        )
        for table in tables.values()
        for record in _sequence(table.get("records"), "table.records", _MAX_RECORDS)
    ):
        reference_failures.add("UPSTREAM_RESTORATION")

    effect_failures: set[str] = set()
    effect_ids: set[str] = set()
    effects_raw = _sequence(
        document["compounded_effects"], "compounded_effects", _MAX_EFFECTS
    )
    for index, raw in enumerate(effects_raw):
        effect = _mapping(raw, f"compounded_effects[{index}]")
        _exact(
            effect,
            {
                "effect_id",
                "operation",
                "operand_value_ids",
                "expected_result",
                "observed_result",
            },
            f"compounded_effects[{index}]",
        )
        effect_id = _text(effect["effect_id"], f"compounded_effects[{index}].effect_id")
        if effect_id in effect_ids:
            raise BalanceTableRpgAcceptanceError("effect_id values must be unique")
        effect_ids.add(effect_id)
        operand_ids = [
            _text(item, "operand_value_id")
            for item in _sequence(
                effect["operand_value_ids"], "operand_value_ids", _MAX_OPERANDS
            )
        ]
        if not operand_ids or any(item not in observations for item in operand_ids):
            effect_failures.add("COMPOUNDED_EFFECT_UNBOUND")
            continue
        values = [observations[item] for item in operand_ids]
        operation = effect["operation"]
        if operation == "MULTIPLY":
            calculated = math.prod(values)
        elif operation == "ADD":
            calculated = sum(values)
        else:
            raise BalanceTableRpgAcceptanceError("unsupported compounded operation")
        try:
            expected_result = float(effect["expected_result"])
            observed_result = float(effect["observed_result"])
        except (TypeError, ValueError, OverflowError) as exc:
            raise BalanceTableRpgAcceptanceError("effect results must be numbers") from exc
        if not (
            math.isfinite(expected_result)
            and math.isfinite(observed_result)
            and math.isclose(calculated, expected_result, rel_tol=1e-9, abs_tol=1e-9)
            and math.isclose(calculated, observed_result, rel_tol=1e-9, abs_tol=1e-9)
        ):
            effect_failures.add("COMPOUNDED_EFFECT_MISMATCH")

    inventory_failures: set[str] = set()
    inventory_inconclusive: set[str] = set()
    chain_baselines = _sequence(
        document["inventory_baselines"], "inventory_baselines", _MAX_CHAINS
    )
    inventory_resolutions = _sequence(
        document["inventory_resolutions"], "inventory_resolutions", _MAX_CHAINS
    )
    resolutions_by_id = {
        _text(
            _mapping(row, "inventory_resolution").get("resolution_id"),
            "resolution_id",
        ): _mapping(row, "inventory_resolution")
        for row in inventory_resolutions
    }
    if len(resolutions_by_id) != len(inventory_resolutions):
        raise BalanceTableRpgAcceptanceError("inventory resolution IDs must be unique")
    chain_ids: set[str] = set()
    for index, raw in enumerate(chain_baselines):
        baseline = _mapping(raw, f"inventory_baselines[{index}]")
        _exact(
            baseline,
            {"chain_id", "resolution_id", "root_preset", "required_items"},
            f"inventory_baselines[{index}]",
        )
        chain_id = _text(baseline["chain_id"], f"inventory_baselines[{index}].chain_id")
        if chain_id in chain_ids:
            raise BalanceTableRpgAcceptanceError("chain_id values must be unique")
        chain_ids.add(chain_id)
        resolution = resolutions_by_id.get(baseline["resolution_id"])
        if resolution is None:
            inventory_failures.add("INVENTORY_CHAIN_INCOMPLETE")
            continue
        resolution_reasons = set(
            _sequence(resolution.get("reason_codes"), "reason_codes", 128)
        )
        incomplete_capture_reasons = {
            "CAPTURE_INCONCLUSIVE",
            "MAX_DEPTH_REACHED",
            "MAX_NODES_REACHED",
            "OUTPUT_TRUNCATED",
            "TABLE_SEMANTICS_UNRESOLVED",
        }
        if resolution.get("complete") is not True or resolution_reasons:
            if resolution_reasons & incomplete_capture_reasons:
                inventory_inconclusive.add("CAPTURE_INCONCLUSIVE")
            else:
                inventory_failures.add("INVENTORY_CHAIN_INCOMPLETE")
        if resolution.get("root_preset") != baseline["root_preset"]:
            inventory_failures.add("INVENTORY_CHAIN_MISMATCH")
        outcomes = {
            _mapping(row, "item_outcome").get("item_name"): _mapping(row, "item_outcome")
            for row in _sequence(resolution.get("item_outcomes"), "item_outcomes", _MAX_RECORDS)
        }
        for item in _sequence(baseline["required_items"], "required_items", _MAX_RECORDS):
            outcome = outcomes.get(item)
            if outcome is None:
                inventory_failures.add("INVENTORY_CHAIN_MISMATCH")
            elif outcome.get("semantics_complete") is not True:
                inventory_failures.add("INVENTORY_CHAIN_INCOMPLETE")

    tbl_failures: set[str] = set()
    reports = _sequence(document["tbl_contract_reports"], "tbl_contract_reports", _MAX_TABLES)
    covered_tbl_paths: set[str] = set()
    for raw in reports:
        report = _mapping(raw, "tbl_contract_report")
        if report.get("schema_version") != "kcd2.xml-tbl-contract-report.v1":
            raise BalanceTableRpgAcceptanceError("unsupported TBL contract report")
        covered_tbl_paths.update(
            _text(path, "tbl_contract_report.changed_path").casefold()
            for path in _sequence(
                report.get("changed_paths"), "tbl_contract_report.changed_paths", _MAX_TABLES
            )
        )
        if (
            report.get("package_promotion") != "PACKAGE_VALIDATED"
            or report.get("xml_tbl_gate") not in {"CLEAR", "NOT_APPLICABLE"}
        ):
            tbl_failures.add("TBL_RELEASE_BLOCKED")
    if set(tables) - covered_tbl_paths:
        tbl_failures.add("TBL_REPORT_MISSING")

    gates = [
        _gate("stack_identity", stack_failures, stack_inconclusive),
        _gate(
            "table_semantics",
            semantic_failures | table_audit_failures,
            table_inconclusive,
        ),
        _gate("record_attribute_winners", winner_failures, set()),
        _gate(
            "references_restoration", reference_failures, reference_inconclusive
        ),
        _gate("compounded_effects", effect_failures, set()),
        _gate("inventory_chains", inventory_failures, inventory_inconclusive),
        _gate("tbl_release", tbl_failures, set()),
    ]
    failures = set().union(
        *(set(gate["reason_codes"]) for gate in gates if gate["status"] == "FAIL")
    )
    inconclusive = set().union(
        *(
            set(gate["reason_codes"])
            for gate in gates
            if gate["status"] == "INCONCLUSIVE"
        )
    )
    payload = {
        "schema_version": "kcd2.balance-table-rpg-stack-acceptance.v1",
        "acceptance_id": acceptance_id,
        "stack_id": manifest["stack_id"],
        "status": _status(failures, inconclusive),
        "reason_codes": sorted(failures | inconclusive),
        "absence_claim_allowed": not inconclusive and bool(
            coverage.get("absence_claim_allowed")
        ),
        "gates": gates,
        "summary": {
            "table_count": len(tables),
            "semantic_baseline_count": len(baselines_raw),
            "inventory_chain_count": len(chain_baselines),
            "compounded_effect_count": len(effects_raw),
            "tbl_report_count": len(reports),
        },
        "bounds": {
            "max_tables": _MAX_TABLES,
            "max_records": _MAX_RECORDS,
            "max_inventory_chains": _MAX_CHAINS,
            "max_compounded_effects": _MAX_EFFECTS,
        },
    }
    return BalanceTableRpgAcceptanceReceipt(json.loads(_canonical(payload)))


__all__ = [
    "BalanceTableRpgAcceptanceError",
    "BalanceTableRpgAcceptanceReceipt",
    "evaluate_balance_table_rpg_acceptance",
]
