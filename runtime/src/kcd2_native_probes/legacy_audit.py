"""Read-only, byte-bound audit records for legacy native probes."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from kcd2_toolchain_core.atomic import atomic_write_text

from .legacy_kcse import summarize


PLAN_SCHEMA_VERSION = "kcd2.legacy-probe-migration-plan.v2"
AUDIT_SCHEMA_VERSION = "kcd2.legacy-probe-audit.v1"
MAX_PLAN_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
ARTIFACT_ROLES = ("manifest", "source", "installed_dll", "log")
EVENT_NAME_RE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
DATE_TIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def validate_legacy_probe_migration_plan(plan: Any) -> list[str]:
    """Return deterministic diagnostics for a bounded reviewed migration plan."""
    diagnostics: list[str] = []
    if not isinstance(plan, Mapping):
        return ["$: expected an object"]
    expected = {
        "schema_version",
        "legacy_probe_id",
        "artifacts",
        "event_contract",
        "cleanup_requirements",
        "v2_target",
    }
    _check_keys(plan, expected, "$", diagnostics)
    if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        diagnostics.append(f"$.schema_version: expected {PLAN_SCHEMA_VERSION}")
    _check_string(plan.get("legacy_probe_id"), "$.legacy_probe_id", diagnostics, 1, 256)

    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, Mapping):
        diagnostics.append("$.artifacts: expected an object")
    else:
        _check_keys(artifacts, set(ARTIFACT_ROLES), "$.artifacts", diagnostics)
        normalized: list[str] = []
        for role in ARTIFACT_ROLES:
            value = artifacts.get(role)
            _check_string(value, f"$.artifacts.{role}", diagnostics, 1, 512)
            if isinstance(value, str):
                candidate = Path(value)
                if candidate.is_absolute() or ".." in candidate.parts:
                    diagnostics.append(
                        f"$.artifacts.{role}: path must be relative without parent traversal"
                    )
                normalized.append(candidate.as_posix().casefold())
        if len(set(normalized)) != len(normalized):
            diagnostics.append("$.artifacts: every artifact role must use a distinct path")

    event_contract = plan.get("event_contract")
    if not isinstance(event_contract, Mapping):
        diagnostics.append("$.event_contract: expected an object")
    else:
        _check_keys(
            event_contract,
            {"startup_events", "target_events", "required_controls"},
            "$.event_contract",
            diagnostics,
        )
        groups: dict[str, list[str]] = {}
        for name in ("startup_events", "target_events", "required_controls"):
            groups[name] = _check_event_names(
                event_contract.get(name), f"$.event_contract.{name}", diagnostics
            )
        overlap = sorted(set(groups["startup_events"]) & set(groups["target_events"]))
        if overlap:
            diagnostics.append(
                "$.event_contract: startup and target events overlap: " + ", ".join(overlap)
            )

    _check_string_list(
        plan.get("cleanup_requirements"),
        "$.cleanup_requirements",
        diagnostics,
        maximum_items=32,
    )
    target = plan.get("v2_target")
    if not isinstance(target, Mapping):
        diagnostics.append("$.v2_target: expected an object")
    else:
        _check_keys(
            target,
            {"probe_contract_schema_version", "probe_bundle_schema_version"},
            "$.v2_target",
            diagnostics,
        )
        if target.get("probe_contract_schema_version") != "kcd2.probe-contract.v2":
            diagnostics.append(
                "$.v2_target.probe_contract_schema_version: expected kcd2.probe-contract.v2"
            )
        if target.get("probe_bundle_schema_version") != "kcd2.probe-bundle.v2":
            diagnostics.append(
                "$.v2_target.probe_bundle_schema_version: expected kcd2.probe-bundle.v2"
            )
    return diagnostics


def validate_legacy_probe_audit(receipt: Any) -> list[str]:
    """Validate the safety and identity invariants specific to a legacy audit receipt."""
    diagnostics: list[str] = []
    if not isinstance(receipt, Mapping):
        return ["$: expected an object"]
    required = {
        "schema_version",
        "audit_id",
        "recorded_at",
        "legacy_probe_id",
        "verdict",
        "target_event_classification",
        "execution",
        "migration_plan_identity",
        "legacy_artifacts",
        "installed_dll_identity",
        "events",
        "controls",
        "migration",
        "cleanup",
        "reasons",
    }
    _check_keys(receipt, required, "$", diagnostics)
    if receipt.get("schema_version") != AUDIT_SCHEMA_VERSION:
        diagnostics.append(f"$.schema_version: expected {AUDIT_SCHEMA_VERSION}")
    audit_id = receipt.get("audit_id")
    if not isinstance(audit_id, str) or re.fullmatch(
        r"legacy-probe-audit:sha256:[a-f0-9]{64}", audit_id
    ) is None:
        diagnostics.append("$.audit_id: invalid content identity")
    if not isinstance(receipt.get("recorded_at"), str) or DATE_TIME_RE.fullmatch(
        receipt.get("recorded_at", "")
    ) is None:
        diagnostics.append("$.recorded_at: invalid date-time")
    if receipt.get("verdict") != "capture_inconclusive":
        diagnostics.append("$.verdict: legacy audit cannot promote runtime evidence")

    execution = receipt.get("execution")
    if not isinstance(execution, Mapping):
        diagnostics.append("$.execution: expected an object")
    elif execution != {
        "mode": "read_only",
        "gameplay_requested": False,
        "live_changes_performed": False,
    }:
        diagnostics.append("$.execution: audit must be read-only with no gameplay")

    artifacts = receipt.get("legacy_artifacts")
    identities: dict[str, Mapping[str, Any]] = {}
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_ROLES):
        diagnostics.append("$.legacy_artifacts: expected four exact artifact identities")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, Mapping):
                diagnostics.append(f"$.legacy_artifacts[{index}]: expected an object")
                continue
            role = artifact.get("role")
            if role not in ARTIFACT_ROLES or role in identities:
                diagnostics.append(f"$.legacy_artifacts[{index}].role: invalid or duplicate")
                continue
            identities[role] = artifact
            _check_sha256(
                artifact.get("sha256"),
                f"$.legacy_artifacts[{index}].sha256",
                diagnostics,
            )
            size = artifact.get("size_bytes")
            size_valid = (
                isinstance(size, int)
                and not isinstance(size, bool)
                and 0 <= size <= MAX_ARTIFACT_BYTES
            )
            if not size_valid:
                diagnostics.append(f"$.legacy_artifacts[{index}].size_bytes: invalid size")

    dll = receipt.get("installed_dll_identity")
    if not isinstance(dll, Mapping):
        diagnostics.append("$.installed_dll_identity: expected an object")
    else:
        for name in ("sha256_before", "sha256_after"):
            _check_sha256(dll.get(name), f"$.installed_dll_identity.{name}", diagnostics)
        if dll.get("modified") is not False:
            diagnostics.append("$.installed_dll_identity.modified: must be false")
        installed = identities.get("installed_dll")
        if installed and not (
            installed.get("sha256") == dll.get("sha256_before") == dll.get("sha256_after")
        ):
            diagnostics.append("$.installed_dll_identity: hashes do not bind the DLL artifact")

    migration = receipt.get("migration")
    if not isinstance(migration, Mapping):
        diagnostics.append("$.migration: expected an object")
    elif migration.get("disposition") != "derived_record_only":
        diagnostics.append("$.migration.disposition: must preserve legacy artifacts")
    elif isinstance(migration.get("exact_legacy_artifact_sha256s"), Mapping):
        bound = migration["exact_legacy_artifact_sha256s"]
        for role, identity in identities.items():
            if bound.get(role) != identity.get("sha256"):
                diagnostics.append(f"$.migration.exact_legacy_artifact_sha256s.{role}: mismatch")
    else:
        diagnostics.append("$.migration.exact_legacy_artifact_sha256s: expected an object")

    reasons = receipt.get("reasons")
    if not isinstance(reasons, list) or "LEGACY_VALIDITY_GATES_UNPROVEN" not in reasons:
        diagnostics.append("$.reasons: missing legacy validity reason")
    classification = receipt.get("target_event_classification")
    events = receipt.get("events")
    if classification == "startup_only_inconclusive":
        if not isinstance(events, Mapping) or events.get("target_events_observed") != []:
            diagnostics.append("$.events: startup-only classification cannot contain target events")
        if not isinstance(reasons, list) or "NO_TARGET_EVENTS" not in reasons:
            diagnostics.append("$.reasons: startup-only classification requires NO_TARGET_EVENTS")
    return diagnostics


def audit_legacy_probe(
    plan_path: str | Path,
    *,
    recorded_at: str,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Audit exact legacy artifacts and optionally write one derived receipt."""
    selected_plan = Path(plan_path).resolve(strict=True)
    plan_bytes = _read_bounded(selected_plan, MAX_PLAN_BYTES, "migration plan")
    plan = json.loads(plan_bytes.decode("utf-8-sig"))
    diagnostics = validate_legacy_probe_migration_plan(plan)
    if diagnostics:
        raise ValueError("invalid migration plan: " + "; ".join(diagnostics))
    if DATE_TIME_RE.fullmatch(recorded_at) is None:
        raise ValueError("recorded_at must be an RFC 3339 date-time")

    paths = _resolve_artifacts(selected_plan.parent, plan["artifacts"])
    selected_output = Path(output_path).resolve() if output_path is not None else None
    if selected_output is not None:
        if selected_output in {selected_plan, *paths.values()}:
            raise ValueError("output must not alias a migration plan or legacy artifact")
        if selected_output.exists():
            raise ValueError("output must not overwrite an existing file")

    artifact_bytes = {
        role: _read_bounded(paths[role], MAX_ARTIFACT_BYTES, f"legacy {role}")
        for role in ARTIFACT_ROLES
    }
    dll_before = _sha256(artifact_bytes["installed_dll"])
    manifest = json.loads(artifact_bytes["manifest"].decode("utf-8-sig"))
    if not isinstance(manifest, Mapping):
        raise ValueError("legacy manifest root must be an object")
    log_summary = summarize(paths["log"])
    dll_after = _sha256(_read_bounded(paths["installed_dll"], MAX_ARTIFACT_BYTES, "legacy DLL"))
    if dll_before != dll_after:
        raise ValueError("installed DLL changed during read-only audit")

    event_contract = plan["event_contract"]
    counts = log_summary["event_counts"]
    startup_observed = sorted(set(counts) & set(event_contract["startup_events"]))
    target_observed = sorted(set(counts) & set(event_contract["target_events"]))
    unknown_observed = sorted(
        set(counts) - set(event_contract["startup_events"]) - set(event_contract["target_events"])
    )
    classification = _classify_events(counts, startup_observed, target_observed, unknown_observed)
    declared_controls = _manifest_controls(manifest)
    observed_controls = sorted(set(counts) & set(event_contract["required_controls"]))
    missing_controls = sorted(set(event_contract["required_controls"]) - set(observed_controls))
    identities = [
        {
            "role": role,
            "path": Path(plan["artifacts"][role]).as_posix(),
            "sha256": _sha256(artifact_bytes[role]),
            "size_bytes": len(artifact_bytes[role]),
        }
        for role in ARTIFACT_ROLES
    ]
    exact_hashes = {item["role"]: item["sha256"] for item in identities}
    reasons = _audit_reasons(
        classification,
        missing_controls,
        log_summary["malformed_nonempty_lines"],
    )
    body: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "recorded_at": recorded_at,
        "legacy_probe_id": plan["legacy_probe_id"],
        "verdict": "capture_inconclusive",
        "target_event_classification": classification,
        "execution": {
            "mode": "read_only",
            "gameplay_requested": False,
            "live_changes_performed": False,
        },
        "migration_plan_identity": {
            "path": selected_plan.name,
            "sha256": _sha256(plan_bytes),
            "size_bytes": len(plan_bytes),
        },
        "legacy_artifacts": identities,
        "installed_dll_identity": {
            "module_name": paths["installed_dll"].name,
            "sha256_before": dll_before,
            "sha256_after": dll_after,
            "size_bytes": len(artifact_bytes["installed_dll"]),
            "modified": False,
        },
        "events": {
            "counts": counts,
            "startup_events_observed": startup_observed,
            "target_events_observed": target_observed,
            "unknown_events_observed": unknown_observed,
            "missing_target_events": sorted(
                set(event_contract["target_events"]) - set(target_observed)
            ),
            "malformed_nonempty_lines": log_summary["malformed_nonempty_lines"],
            "diagnostics_truncated": log_summary["diagnostics_truncated"],
        },
        "controls": {
            "required": event_contract["required_controls"],
            "declared_in_legacy_manifest": declared_controls,
            "observed": observed_controls,
            "missing": missing_controls,
        },
        "migration": {
            "disposition": "derived_record_only",
            "target": plan["v2_target"],
            "exact_legacy_artifact_sha256s": exact_hashes,
            "required_actions": [
                "regenerate_v2_manifest",
                "generate_source_from_v2_manifest",
                "rebuild_and_validate_v2_dll",
                "require_probe_emitted_runtime_and_deployment_identity",
                "satisfy_playtest_readiness_before_any_gameplay",
            ],
        },
        "cleanup": {
            "required": True,
            "requirements": plan["cleanup_requirements"],
            "performed": False,
            "status": "not_performed_audit_only",
        },
        "reasons": reasons,
    }
    receipt = {
        **body,
        "audit_id": f"legacy-probe-audit:sha256:{_canonical_sha256(body)}",
    }
    receipt = {
        "schema_version": receipt.pop("schema_version"),
        "audit_id": receipt.pop("audit_id"),
        **receipt,
    }
    receipt_diagnostics = validate_legacy_probe_audit(receipt)
    if receipt_diagnostics:
        raise ValueError("generated invalid audit: " + "; ".join(receipt_diagnostics))
    if selected_output is not None:
        atomic_write_text(selected_output, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def _resolve_artifacts(base: Path, artifacts: Mapping[str, str]) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for role in ARTIFACT_ROLES:
        path = (base / artifacts[role]).resolve(strict=True)
        if not path.is_relative_to(base.resolve()):
            raise ValueError(f"legacy {role} escapes the migration-plan directory")
        if not path.is_file():
            raise ValueError(f"legacy {role} is not a regular file")
        paths[role] = path
    return paths


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")
    data = path.read_bytes()
    if len(data) != size:
        raise ValueError(f"{label} changed while it was read")
    return data


def _classify_events(
    counts: Mapping[str, int],
    startup: list[str],
    target: list[str],
    unknown: list[str],
) -> str:
    if target:
        return "target_events_observed_legacy_unvalidated"
    if counts and startup and not unknown:
        return "startup_only_inconclusive"
    if counts:
        return "no_target_events_inconclusive"
    return "no_parseable_events_inconclusive"


def _manifest_controls(manifest: Mapping[str, Any]) -> list[str]:
    controls = manifest.get("controls")
    if isinstance(controls, list):
        return sorted(item for item in controls if isinstance(item, str))
    if isinstance(controls, Mapping):
        return sorted(item for item in controls if isinstance(item, str))
    return []


def _audit_reasons(classification: str, missing_controls: list[str], malformed: int) -> list[str]:
    reasons = ["LEGACY_DEPLOYMENT_IDENTITY_UNPROVEN", "LEGACY_VALIDITY_GATES_UNPROVEN"]
    if classification == "startup_only_inconclusive":
        reasons.extend(["NO_TARGET_EVENTS", "STARTUP_ONLY_LOG"])
    elif classification == "no_target_events_inconclusive":
        reasons.append("NO_TARGET_EVENTS")
    elif classification == "no_parseable_events_inconclusive":
        reasons.extend(["NO_PARSEABLE_EVENTS", "NO_TARGET_EVENTS"])
    if missing_controls:
        reasons.append("MISSING_REQUIRED_CONTROLS")
    if malformed:
        reasons.append("LEGACY_LOG_MALFORMED_LINES")
    return sorted(reasons)


def _check_keys(
    value: Mapping[str, Any], expected: set[str], path: str, diagnostics: list[str]
) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        diagnostics.append(f"{path}: missing keys: {', '.join(missing)}")
    if extra:
        diagnostics.append(f"{path}: unexpected keys: {', '.join(extra)}")


def _check_string(
    value: Any, path: str, diagnostics: list[str], minimum: int, maximum: int
) -> None:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        diagnostics.append(f"{path}: expected a string of {minimum} to {maximum} characters")


def _check_event_names(value: Any, path: str, diagnostics: list[str]) -> list[str]:
    names = _check_string_list(value, path, diagnostics, maximum_items=128)
    for index, name in enumerate(names):
        if EVENT_NAME_RE.fullmatch(name) is None:
            diagnostics.append(f"{path}[{index}]: invalid event or control name")
    return names


def _check_string_list(
    value: Any,
    path: str,
    diagnostics: list[str],
    *,
    maximum_items: int,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        diagnostics.append(f"{path}: expected 1 to {maximum_items} strings")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not 1 <= len(item) <= 256:
            diagnostics.append(f"{path}[{index}]: expected a nonempty bounded string")
        else:
            strings.append(item)
    if len(set(strings)) != len(strings):
        diagnostics.append(f"{path}: values must be unique")
    return strings


def _check_sha256(value: Any, path: str, diagnostics: list[str]) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        diagnostics.append(f"{path}: invalid SHA-256")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256(encoded)
