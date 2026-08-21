"""Fail-closed, profile-driven preflight for static combat route chains."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path


_MAX_PAIRINGS = 256
_MAX_ROUTES = 4096
_MAX_TAGS = 64
_MAX_TEXT = 1024
_BASE_MODES = ("normal", "lethal")
_BASE_ORIENTATIONS = ("master_to_slave", "slave_to_master")


class CombatRoutePreflightError(ValueError):
    """The supplied preflight inputs are malformed or exceed a hard bound."""


@dataclass(frozen=True, slots=True)
class CombatRoutePreflightReport:
    """Deterministic machine report plus a compact human route-chain report."""

    payload: Mapping[str, Any]
    human_report: str
    report_path: Path | None = None
    human_report_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise CombatRoutePreflightError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CombatRoutePreflightError(f"{name} must be an object")
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CombatRoutePreflightError(f"{name} must be an array")
    if len(value) > maximum:
        raise CombatRoutePreflightError(f"{name} exceeds the {maximum}-entry hard bound")
    return value


def _string_set(value: object, name: str, maximum: int) -> tuple[str, ...]:
    raw = _sequence(value, name, maximum)
    parsed = tuple(_text(item, f"{name} item") for item in raw)
    folded = [item.casefold() for item in parsed]
    if len(folded) != len(set(folded)):
        raise CombatRoutePreflightError(f"{name} must be case-insensitively unique")
    return tuple(sorted(parsed, key=lambda item: (item.casefold(), item)))


def _detached(value: object, name: str) -> Any:
    try:
        return json.loads(
            json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
        )
    except (TypeError, ValueError) as exc:
        raise CombatRoutePreflightError(f"{name} must contain JSON values only") from exc


def _gate(
    code: str,
    scope: str,
    detail: str,
    *,
    severity: str,
) -> dict[str, str]:
    return {
        "code": code,
        "scope": scope,
        "detail": detail,
        "severity": severity,
        "evidence_layer": "static",
    }


def _route_text(
    value: object,
    field: str,
    route_id: str,
    gates: list[dict[str, str]],
) -> str | None:
    try:
        return _text(value, field)
    except CombatRoutePreflightError:
        gates.append(
            _gate(
                "ROUTE_SELECTOR_MISSING",
                route_id,
                f"route does not provide a valid {field}",
                severity="fail",
            )
        )
        return None


def _winner_for_path(
    path: str,
    reports: Mapping[str, Mapping[str, Any]],
) -> tuple[str | None, tuple[str, ...]]:
    report = reports.get(canonical_path_key(path))
    if report is None:
        return None, ("EFFECTIVE_PATH_REPORT_MISSING",)
    resolution_container = _mapping(
        report.get("canonical_path_resolution"), "canonical_path_resolution"
    )
    resolution = _mapping(resolution_container.get("resolution"), "resolution")
    conclusion = resolution.get("conclusion")
    winner = resolution.get("winner_provider_id")
    reasons_raw = resolution.get("reason_codes", [])
    reasons = _string_set(reasons_raw, "resolution.reason_codes", 256)
    if conclusion != "winner" or not isinstance(winner, str) or not winner:
        return None, reasons or ("RESOLUTION_DID_NOT_PRODUCE_WINNER",)
    return winner, reasons


def combat_route_preflight(
    *,
    profile: Mapping[str, Any],
    effective_path_reports: Mapping[str, Mapping[str, Any]],
    parent_diff_report: Mapping[str, Any] | Any,
    output_directory: Path | str | None = None,
) -> CombatRoutePreflightReport:
    """Verify one parameterized combat route profile without reading live state.

    The mandatory normal/lethal and master/slave matrix is engine policy. Pairing,
    selectors, tags, paths, provider identities, and evidence references are supplied
    entirely by the profile; no incident pairing is compiled into this module.
    """

    profile_data = _mapping(_detached(profile, "profile"), "profile")
    if profile_data.get("schema_version") != "kcd2.combat-route-profile.v1":
        raise CombatRoutePreflightError("unsupported combat route profile schema_version")
    profile_id = _text(profile_data.get("profile_id"), "profile_id")
    raw_pairings = _sequence(profile_data.get("pairings"), "pairings", _MAX_PAIRINGS)
    raw_routes = _sequence(profile_data.get("routes"), "routes", _MAX_ROUTES)
    if not raw_pairings:
        raise CombatRoutePreflightError("pairings must contain at least one entry")

    raw_reports = _mapping(effective_path_reports, "effective_path_reports")
    reports: dict[str, Mapping[str, Any]] = {}
    for raw_path, raw_report in raw_reports.items():
        path = canonical_relative_path(_text(raw_path, "effective path report key"))
        key = canonical_path_key(path)
        if key in reports:
            raise CombatRoutePreflightError("effective path report keys case-collide")
        reports[key] = _mapping(_detached(raw_report, "effective path report"), "report")

    pairings: dict[str, dict[str, Any]] = {}
    gates: list[dict[str, str]] = []
    for index, raw_pairing in enumerate(raw_pairings):
        pairing = _mapping(raw_pairing, f"pairings[{index}]")
        pairing_id = _text(pairing.get("pairing_id"), "pairing_id")
        key = pairing_id.casefold()
        if key in pairings:
            raise CombatRoutePreflightError("pairing_id values must be unique")
        modes = _string_set(pairing.get("required_modes"), "required_modes", 32)
        orientations = _string_set(
            pairing.get("required_orientations"), "required_orientations", 32
        )
        _text(pairing.get("actor_selector"), "actor_selector")
        _text(pairing.get("opponent_selector"), "opponent_selector")
        for required in _BASE_MODES:
            if required not in {item.casefold() for item in modes}:
                gates.append(
                    _gate(
                        "REQUIRED_MODE_UNDECLARED",
                        pairing_id,
                        f"mandatory mode {required!r} is absent from required_modes",
                        severity="inconclusive",
                    )
                )
        for required in _BASE_ORIENTATIONS:
            if required not in {item.casefold() for item in orientations}:
                gates.append(
                    _gate(
                        "REQUIRED_ORIENTATION_UNDECLARED",
                        pairing_id,
                        f"mandatory orientation {required!r} is absent",
                        severity="inconclusive",
                    )
                )
        pairings[key] = {
            "pairing_id": pairing_id,
            "modes": tuple(sorted(set(modes) | set(_BASE_MODES))),
            "orientations": tuple(
                sorted(set(orientations) | set(_BASE_ORIENTATIONS))
            ),
        }

    routes_by_slot: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    selector_owners: dict[tuple[str, str, tuple[str, ...]], list[str]] = defaultdict(list)
    route_ids: set[str] = set()
    for index, raw_route in enumerate(raw_routes):
        route = _mapping(raw_route, f"routes[{index}]")
        route_id = _text(route.get("route_id"), "route_id")
        route_key = route_id.casefold()
        if route_key in route_ids:
            raise CombatRoutePreflightError("route_id values must be unique")
        route_ids.add(route_key)
        pairing_id = _text(route.get("pairing_id"), "route pairing_id")
        pairing_key = pairing_id.casefold()
        if pairing_key not in pairings:
            raise CombatRoutePreflightError(f"route {route_id} names an unknown pairing_id")
        mode = _text(route.get("mode"), "route mode").casefold()
        orientation = _text(route.get("orientation"), "route orientation").casefold()
        declared_modes = {
            value.casefold() for value in pairings[pairing_key]["modes"]
        }
        declared_orientations = {
            value.casefold() for value in pairings[pairing_key]["orientations"]
        }
        if mode not in declared_modes:
            gates.append(
                _gate(
                    "ROUTE_MODE_UNDECLARED",
                    route_id,
                    f"route mode {mode!r} is outside the pairing requirements",
                    severity="fail",
                )
            )
        if orientation not in declared_orientations:
            gates.append(
                _gate(
                    "ROUTE_ORIENTATION_UNDECLARED",
                    route_id,
                    f"route orientation {orientation!r} is outside pairing requirements",
                    severity="fail",
                )
            )
        table_selector = _route_text(
            route.get("table_row_selector"), "table_row_selector", route_id, gates
        )
        fragment_guid = _route_text(
            route.get("fragment_guid"), "fragment_guid", route_id, gates
        )
        adb_selector = _route_text(
            route.get("adb_selector"), "adb_selector", route_id, gates
        )
        tags = (
            ()
            if route.get("tags") is None
            else _string_set(route.get("tags"), "route tags", _MAX_TAGS)
        )
        if not tags:
            gates.append(
                _gate(
                    "ROUTE_TAGS_MISSING",
                    route_id,
                    "route has no explicit ADB tags",
                    severity="fail",
                )
            )
        else:
            folded_tags = {tag.casefold() for tag in tags}
            if mode not in folded_tags:
                gates.append(
                    _gate(
                        "ROUTE_MODE_TAG_MISSING",
                        route_id,
                        f"route tags do not bind mode {mode!r}",
                        severity="fail",
                    )
                )
            if orientation not in folded_tags:
                gates.append(
                    _gate(
                        "ROUTE_ORIENTATION_TAG_MISSING",
                        route_id,
                        f"route tags do not bind orientation {orientation!r}",
                        severity="fail",
                    )
                )
        path = canonical_relative_path(
            _text(route.get("canonical_path"), "route canonical_path")
        )
        expected_winner = _text(
            route.get("expected_winner_provider_id"), "expected_winner_provider_id"
        )
        evidence_refs = (
            ()
            if route.get("evidence_refs") is None
            else _string_set(route.get("evidence_refs"), "evidence_refs", 256)
        )
        if not evidence_refs:
            gates.append(
                _gate(
                    "ROUTE_EVIDENCE_MISSING",
                    route_id,
                    "route has no static evidence reference",
                    severity="inconclusive",
                )
            )
        parsed = {
            "route_id": route_id,
            "pairing_id": pairings[pairing_key]["pairing_id"],
            "mode": mode,
            "orientation": orientation,
            "table_row_selector": table_selector,
            "fragment_guid": fragment_guid,
            "adb_selector": adb_selector,
            "tags": list(tags),
            "canonical_path": path,
            "expected_winner_provider_id": expected_winner,
            "evidence_refs": list(evidence_refs),
        }
        routes_by_slot[(pairing_key, mode, orientation)].append(parsed)
        if table_selector is not None and adb_selector is not None and tags:
            selector_owners[
                (table_selector, adb_selector, tuple(tag.casefold() for tag in tags))
            ].append(route_id)

    for owners in selector_owners.values():
        if len(owners) > 1:
            for route_id in sorted(owners):
                gates.append(
                    _gate(
                        "SELECTOR_SCOPE_OVERLAP",
                        route_id,
                        "the same table/ADB/tag selector scope is owned by: "
                        + ", ".join(sorted(owners)),
                        severity="fail",
                    )
                )

    matrix: list[dict[str, Any]] = []
    resolved_routes = 0
    for pairing_key, pairing in sorted(pairings.items()):
        for mode in pairing["modes"]:
            for orientation in pairing["orientations"]:
                slot = (pairing_key, mode.casefold(), orientation.casefold())
                candidates = routes_by_slot.get(slot, [])
                scope = f"{pairing['pairing_id']}:{mode}:{orientation}"
                if not candidates:
                    gates.append(
                        _gate(
                            "REQUIRED_ROUTE_MISSING",
                            scope,
                            "no route supplies the required pairing/mode/orientation slot",
                            severity="inconclusive",
                        )
                    )
                    matrix.append(
                        {
                            "pairing_id": pairing["pairing_id"],
                            "mode": mode,
                            "orientation": orientation,
                            "route_id": None,
                            "status": "unresolved",
                        }
                    )
                    continue
                if len(candidates) > 1:
                    gates.append(
                        _gate(
                            "ROUTE_SLOT_AMBIGUOUS",
                            scope,
                            "multiple routes supply one required slot: "
                            + ", ".join(sorted(item["route_id"] for item in candidates)),
                            severity="fail",
                        )
                    )
                route = sorted(candidates, key=lambda item: item["route_id"])[0]
                winner, winner_reasons = _winner_for_path(route["canonical_path"], reports)
                row_status = "resolved"
                if winner is None:
                    row_status = "unresolved"
                    gates.append(
                        _gate(
                            "ACTIVE_WINNER_UNRESOLVED",
                            route["route_id"],
                            "effective path did not prove a winner: "
                            + ", ".join(winner_reasons),
                            severity="inconclusive",
                        )
                    )
                elif winner.casefold() != route["expected_winner_provider_id"].casefold():
                    row_status = "failed"
                    gates.append(
                        _gate(
                            "ACTIVE_WINNER_MISMATCH",
                            route["route_id"],
                            f"expected {route['expected_winner_provider_id']!r}, got {winner!r}",
                            severity="fail",
                        )
                    )
                else:
                    resolved_routes += 1
                matrix.append(
                    {
                        "pairing_id": pairing["pairing_id"],
                        "mode": mode,
                        "orientation": orientation,
                        "route_id": route["route_id"],
                        "status": row_status,
                        "selectors": {
                            "table_row": route["table_row_selector"],
                            "fragment_guid": route["fragment_guid"],
                            "adb": route["adb_selector"],
                            "tags": route["tags"],
                        },
                        "active_path": route["canonical_path"],
                        "active_winner_provider_id": winner,
                        "expected_winner_provider_id": route[
                            "expected_winner_provider_id"
                        ],
                        "evidence_refs": route["evidence_refs"],
                    }
                )

    if hasattr(parent_diff_report, "to_dict"):
        parent_diff_report = parent_diff_report.to_dict()
    parent = _mapping(_detached(parent_diff_report, "parent_diff_report"), "parent diff")
    summary = _mapping(parent.get("summary"), "parent diff summary")
    preservation_failed = (
        parent.get("status") != "PASS"
        or parent.get("parent_contamination_detected") is not False
        or summary.get("undeclared_change_count") != 0
    )
    if preservation_failed:
        gates.append(
            _gate(
                "UNRELATED_PRESERVATION_FAILED",
                profile_id,
                "candidate parent diff contains contamination or undeclared changes",
                severity="fail",
            )
        )
    elif not isinstance(summary.get("identical_member_count"), int) or summary.get(
        "identical_member_count", 0
    ) < 1:
        gates.append(
            _gate(
                "UNRELATED_PRESERVATION_UNPROVEN",
                profile_id,
                "candidate parent diff contains no byte-identical unrelated member proof",
                severity="inconclusive",
            )
        )

    gates.sort(key=lambda item: (item["code"], item["scope"], item["detail"]))
    matrix.sort(
        key=lambda item: (
            item["pairing_id"].casefold(),
            item["mode"],
            item["orientation"],
            item.get("route_id") or "",
        )
    )
    status = (
        "FAIL"
        if any(item["severity"] == "fail" for item in gates)
        else "capture_inconclusive"
        if gates
        else "PASS"
    )
    payload = {
        "schema_version": "kcd2.combat-route-preflight.v1",
        "profile_id": profile_id,
        "status": status,
        "summary": {
            "pairing_count": len(pairings),
            "required_route_count": len(matrix),
            "resolved_route_count": resolved_routes,
            "unresolved_gate_count": len(gates),
        },
        "route_matrix": matrix,
        "unresolved_gates": gates,
        "unrelated_preservation": {
            "status": parent.get("status"),
            "parent_contamination_detected": parent.get(
                "parent_contamination_detected"
            ),
            "undeclared_change_count": summary.get("undeclared_change_count"),
            "identical_member_count": summary.get("identical_member_count"),
        },
    }
    human = _render_human_report(payload)
    report = CombatRoutePreflightReport(payload, human)
    if output_directory is None:
        return report
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "combat-route-preflight.json"
    human_path = output / "combat-route-chain-report.md"
    _atomic_text(report_path, report.to_json() + "\n")
    _atomic_text(human_path, human)
    return CombatRoutePreflightReport(payload, human, report_path, human_path)


def _render_human_report(payload: Mapping[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Combat route chain preflight",
        "",
        f"Status: **{payload['status']}**",
        f"Profile: `{payload['profile_id']}`",
        f"Resolved routes: **{summary['resolved_route_count']}/{summary['required_route_count']}**",
        "",
        "## Route chains",
        "",
    ]
    for row in payload["route_matrix"]:
        route_id = row.get("route_id") or "MISSING"
        lines.append(
            f"- `{row['pairing_id']}` / `{row['mode']}` / `{row['orientation']}`: "
            f"`{route_id}` [{row['status']}]"
        )
    lines.extend(["", "## Unresolved gates", ""])
    if not payload["unresolved_gates"]:
        lines.append("None.")
    else:
        for gate in payload["unresolved_gates"]:
            lines.append(
                f"- `{gate['code']}` `{gate['scope']}`: {gate['detail']}"
            )
    return "\n".join(lines) + "\n"


def _atomic_text(path: Path, data: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="utf-8", newline="\n")
    os.replace(temporary, path)
