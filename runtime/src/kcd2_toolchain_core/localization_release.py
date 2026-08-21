"""Bounded localization, dialog, and asset release acceptance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .paths import canonical_relative_path


_ROOT_FIELDS = {
    "release_id",
    "candidate_provider_id",
    "required_languages",
    "required_keys",
    "required_dialog_ids",
    "localization_audit",
    "packages",
    "duration_validation",
    "runtime_evidence",
    "limits",
}
_PACKAGE_FIELDS = {
    "package_path",
    "mount_id",
    "language",
    "provider_id",
    "contained_languages",
}
_DURATION_FIELDS = {"enabled", "tolerance_ms", "checks"}
_DURATION_CHECK_FIELDS = {"dialog_id", "subtitle_duration_ms", "audio_duration_ms"}
_RUNTIME_FIELDS = {"capture_complete", "correlation_valid", "observations"}
_OBSERVATION_FIELDS = {
    "dialog_id",
    "language",
    "displayed_key",
    "displayed_provider_id",
    "voice_filename",
    "voice_provider_id",
    "resolution",
    "fallback",
}
_FALLBACK_FIELDS = {
    "from_resource_id",
    "to_resource_id",
    "reason",
    "winner_provider_id",
}
_LIMIT_FIELDS = {
    "maximum_languages",
    "maximum_keys",
    "maximum_dialogs",
    "maximum_packages",
    "maximum_runtime_observations",
    "maximum_diagnostics",
}
_HARD_LIMITS = {
    "maximum_languages": 256,
    "maximum_keys": 20000,
    "maximum_dialogs": 20000,
    "maximum_packages": 4096,
    "maximum_runtime_observations": 20000,
    "maximum_diagnostics": 60000,
}
_MAX_TEXT = 2048


class LocalizationReleaseAcceptanceError(ValueError):
    """The release input is malformed or exceeds a hard bound."""


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
        raise LocalizationReleaseAcceptanceError("input must be JSON-compatible") from exc


def _copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LocalizationReleaseAcceptanceError(f"{name} fields do not match the contract")
    return value


def _array(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise LocalizationReleaseAcceptanceError(f"{name} must be an array")
    if len(value) > maximum:
        raise LocalizationReleaseAcceptanceError(f"{name} exceeds {maximum}")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise LocalizationReleaseAcceptanceError(f"{name} must be a bounded NUL-free string")
    return value


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise LocalizationReleaseAcceptanceError(f"{name} must be a boolean")
    return value


def _integer(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise LocalizationReleaseAcceptanceError(f"{name} must be an integer from 0 to {maximum}")
    return value


def _unique(values: Sequence[str], name: str) -> None:
    folded = [value.casefold() for value in values]
    if len(folded) != len(set(folded)):
        raise LocalizationReleaseAcceptanceError(f"{name} must be case-insensitively unique")


def _audit_array(audit: Mapping[str, object], name: str, maximum: int) -> Sequence[object]:
    return _array(audit.get(name), f"localization_audit.{name}", maximum)


@dataclass(frozen=True, slots=True)
class LocalizationReleaseReceipt:
    """Immutable, schema-ready release receipt."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def evaluate_localization_release_acceptance(
    value: Mapping[str, object],
) -> LocalizationReleaseReceipt:
    """Evaluate static, package, optional duration, and runtime release evidence."""

    root = _mapping(value, _ROOT_FIELDS, "release input")
    release_id = _text(root["release_id"], "release_id")
    candidate_provider_id = _text(root["candidate_provider_id"], "candidate_provider_id")
    limits_row = _mapping(root["limits"], _LIMIT_FIELDS, "limits")
    limits = {
        name: _integer(limits_row[name], f"limits.{name}", hard)
        for name, hard in _HARD_LIMITS.items()
    }
    if any(value == 0 for value in limits.values()):
        raise LocalizationReleaseAcceptanceError("limits must be greater than zero")

    required_languages = [
        _text(item, "required_languages item")
        for item in _array(
            root["required_languages"],
            "required_languages",
            limits["maximum_languages"],
        )
    ]
    required_keys = [
        _text(item, "required_keys item")
        for item in _array(root["required_keys"], "required_keys", limits["maximum_keys"])
    ]
    required_dialog_ids = [
        _text(item, "required_dialog_ids item")
        for item in _array(
            root["required_dialog_ids"],
            "required_dialog_ids",
            limits["maximum_dialogs"],
        )
    ]
    if not required_languages:
        raise LocalizationReleaseAcceptanceError("required_languages must not be empty")
    _unique(required_languages, "required_languages")
    _unique(required_keys, "required_keys")
    _unique(required_dialog_ids, "required_dialog_ids")

    audit_value = root["localization_audit"]
    if not isinstance(audit_value, Mapping):
        raise LocalizationReleaseAcceptanceError("localization_audit must be an object")
    audit = audit_value
    schema_version = audit.get("schema_version")
    if schema_version != "kcd2.localization-asset-audit.v1":
        raise LocalizationReleaseAcceptanceError("localization_audit schema is unsupported")
    audit_status = audit.get("status")
    audit_verdict = audit.get("verdict")
    if audit_status not in {"resolved", "issues_found", "capture_inconclusive"}:
        raise LocalizationReleaseAcceptanceError("localization_audit status is unsupported")
    if audit_verdict not in {"VALID", "INVALID", "INCONCLUSIVE"}:
        raise LocalizationReleaseAcceptanceError("localization_audit verdict is unsupported")
    if not isinstance(audit.get("no_conflict_claim_allowed"), bool):
        raise LocalizationReleaseAcceptanceError(
            "localization_audit.no_conflict_claim_allowed must be a boolean"
        )
    audit_reasons = [
        _text(item, "localization_audit.reason_codes item")
        for item in _audit_array(audit, "reason_codes", 32)
    ]
    languages = _audit_array(audit, "languages", _HARD_LIMITS["maximum_packages"])
    conflicts = _audit_array(audit, "conflicts", _HARD_LIMITS["maximum_dialogs"])
    graph = audit.get("localization_graph")
    if not isinstance(graph, Mapping):
        raise LocalizationReleaseAcceptanceError("localization_audit graph must be an object")
    key_nodes = _array(
        graph.get("keys"),
        "localization_audit graph keys",
        _HARD_LIMITS["maximum_keys"],
    )
    dialogs = _array(
        graph.get("dialogs"),
        "localization_audit graph dialogs",
        _HARD_LIMITS["maximum_dialogs"],
    )

    diagnostics: list[dict[str, object]] = []

    def diagnostic(code: str, message: str, **scope: object) -> None:
        diagnostics.append({"code": code, "message": message, **scope})

    language_by_name: dict[str, list[Mapping[str, object]]] = {}
    for item in languages:
        if not isinstance(item, Mapping):
            raise LocalizationReleaseAcceptanceError("localization_audit language is malformed")
        language = _text(item.get("language"), "localization_audit language")
        language_by_name.setdefault(language.casefold(), []).append(item)

    key_scopes: set[tuple[str, str]] = set()
    for item in key_nodes:
        if not isinstance(item, Mapping):
            raise LocalizationReleaseAcceptanceError("localization_audit key is malformed")
        if item.get("winner") is not None:
            key_scopes.add(
                (
                    _text(item.get("language"), "key language").casefold(),
                    _text(item.get("key"), "key").casefold(),
                )
            )

    dialog_by_id: dict[str, Mapping[str, object]] = {}
    for item in dialogs:
        if not isinstance(item, Mapping):
            raise LocalizationReleaseAcceptanceError("localization_audit dialog is malformed")
        dialog_id = _text(item.get("dialog_id"), "dialog_id")
        key = dialog_id.casefold()
        if key in dialog_by_id:
            raise LocalizationReleaseAcceptanceError("dialog ids must be unique")
        dialog_by_id[key] = item

    partial_coverage = (
        audit_status == "capture_inconclusive"
        or audit_verdict == "INCONCLUSIVE"
        or "INCOMPLETE_LANGUAGE_COVERAGE" in audit_reasons
        or not bool(audit.get("no_conflict_claim_allowed"))
    )
    for language in required_languages:
        records = language_by_name.get(language.casefold(), [])
        if not records:
            diagnostic(
                "MISSING_REQUIRED_LANGUAGE",
                "required language has no audited mount",
                language=language,
            )
            continue
        if not any(item.get("coverage") == "COMPLETE" for item in records):
            partial_coverage = True
        for key in required_keys:
            if (language.casefold(), key.casefold()) not in key_scopes and not partial_coverage:
                diagnostic(
                    "MISSING_REQUIRED_KEY",
                    "required key has no resolved winner in the language scope",
                    language=language,
                    key=key,
                )

    required_dialogs: dict[str, Mapping[str, object]] = {}
    for dialog_id in required_dialog_ids:
        dialog = dialog_by_id.get(dialog_id.casefold())
        if dialog is None:
            if not partial_coverage:
                diagnostic(
                    "MISSING_REQUIRED_DIALOG",
                    "required dialog is absent from the localization graph",
                    dialog_id=dialog_id,
                )
            continue
        required_dialogs[dialog_id.casefold()] = dialog
        translation = dialog.get("translation_resolution")
        voice = dialog.get("voice_resolution")
        if not isinstance(translation, Mapping) or translation.get("status") != "resolved":
            if not partial_coverage:
                diagnostic(
                    "UNRESOLVED_DIALOG_TRANSLATION",
                    "required dialog localization link is unresolved",
                    dialog_id=dialog_id,
                    language=dialog.get("language"),
                )
        if not isinstance(voice, Mapping) or voice.get("status") != "resolved":
            if not partial_coverage:
                diagnostic(
                    "UNRESOLVED_DIALOG_VOICE",
                    "required dialog voice link is unresolved",
                    dialog_id=dialog_id,
                    language=dialog.get("language"),
                )

    package_rows = _array(
        root["packages"], "packages", limits["maximum_packages"]
    )
    package_receipts: list[dict[str, object]] = []
    package_scopes: set[tuple[str, str]] = set()
    isolated_packages = 0
    for index, raw in enumerate(package_rows):
        row = _mapping(raw, _PACKAGE_FIELDS, f"packages[{index}]")
        try:
            path = canonical_relative_path(_text(row["package_path"], "package_path"))
        except (TypeError, ValueError) as exc:
            raise LocalizationReleaseAcceptanceError("package_path must be canonical") from exc
        language = _text(row["language"], "package language")
        mount_id = _text(row["mount_id"], "package mount_id")
        provider_id = _text(row["provider_id"], "package provider_id")
        contained = [
            _text(item, "contained_languages item")
            for item in _array(
                row["contained_languages"],
                "contained_languages",
                limits["maximum_languages"],
            )
        ]
        _unique(contained, "contained_languages")
        isolated = bool(contained) and {item.casefold() for item in contained} == {
            language.casefold()
        }
        if isolated:
            isolated_packages += 1
        else:
            diagnostic(
                "CROSS_LANGUAGE_PACKAGE_CONTENT",
                "package content is not isolated to its declared language",
                language=language,
                package_path=path,
            )
        matching_mount = any(
            str(item.get("language", "")).casefold() == language.casefold()
            and str(item.get("mount_id", "")).casefold() == mount_id.casefold()
            and str(item.get("provider_id", "")).casefold() == provider_id.casefold()
            for item in languages
            if isinstance(item, Mapping)
        )
        if not matching_mount:
            diagnostic(
                "PACKAGE_MOUNT_MISMATCH",
                "package does not match an audited language mount and provider",
                language=language,
                package_path=path,
            )
        package_scopes.add((language.casefold(), mount_id.casefold()))
        package_receipts.append(
            {
                "package_path": path,
                "mount_id": mount_id,
                "language": language,
                "provider_id": provider_id,
                "contained_languages": sorted(contained, key=str.casefold),
                "isolated": isolated,
                "audit_mount_matched": matching_mount,
            }
        )
    for language in required_languages:
        mounts = language_by_name.get(language.casefold(), [])
        if mounts and not any(
            (language.casefold(), str(item.get("mount_id", "")).casefold()) in package_scopes
            for item in mounts
        ):
            diagnostic(
                "MISSING_LANGUAGE_PACKAGE",
                "required language has no matching package receipt",
                language=language,
            )

    duration_row = _mapping(root["duration_validation"], _DURATION_FIELDS, "duration_validation")
    duration_enabled = _boolean(duration_row["enabled"], "duration_validation.enabled")
    tolerance_ms = _integer(
        duration_row["tolerance_ms"], "duration_validation.tolerance_ms", 600000
    )
    duration_rows = _array(
        duration_row["checks"], "duration_validation.checks", limits["maximum_dialogs"]
    )
    if not duration_enabled and duration_rows:
        raise LocalizationReleaseAcceptanceError("disabled duration validation requires no checks")
    duration_receipts: list[dict[str, object]] = []
    duration_dialogs: set[str] = set()
    for index, raw in enumerate(duration_rows):
        row = _mapping(raw, _DURATION_CHECK_FIELDS, f"duration check[{index}]")
        dialog_id = _text(row["dialog_id"], "duration dialog_id")
        if dialog_id.casefold() in duration_dialogs:
            raise LocalizationReleaseAcceptanceError("duration dialog ids must be unique")
        duration_dialogs.add(dialog_id.casefold())
        subtitle_ms = _integer(row["subtitle_duration_ms"], "subtitle_duration_ms", 3600000)
        audio_ms = _integer(row["audio_duration_ms"], "audio_duration_ms", 3600000)
        delta_ms = abs(subtitle_ms - audio_ms)
        matched = delta_ms <= tolerance_ms
        if not matched:
            diagnostic(
                "SUBTITLE_AUDIO_DURATION_MISMATCH",
                "subtitle and audio durations exceed the configured tolerance",
                dialog_id=dialog_id,
            )
        duration_receipts.append(
            {
                "dialog_id": dialog_id,
                "subtitle_duration_ms": subtitle_ms,
                "audio_duration_ms": audio_ms,
                "delta_ms": delta_ms,
                "matched": matched,
            }
        )
    if duration_enabled:
        for dialog_id in required_dialog_ids:
            if dialog_id.casefold() not in duration_dialogs:
                diagnostic(
                    "MISSING_DURATION_CHECK",
                    "enabled duration validation lacks a required dialog check",
                    dialog_id=dialog_id,
                )

    runtime_row = _mapping(root["runtime_evidence"], _RUNTIME_FIELDS, "runtime_evidence")
    capture_complete = _boolean(runtime_row["capture_complete"], "capture_complete")
    correlation_valid = _boolean(runtime_row["correlation_valid"], "correlation_valid")
    observation_rows = _array(
        runtime_row["observations"],
        "maximum_runtime_observations",
        limits["maximum_runtime_observations"],
    )
    observation_receipts: list[dict[str, object]] = []
    observation_dialogs: set[str] = set()
    explicit_fallbacks = 0
    for index, raw in enumerate(observation_rows):
        row = _mapping(raw, _OBSERVATION_FIELDS, f"runtime observation[{index}]")
        dialog_id = _text(row["dialog_id"], "runtime dialog_id")
        if dialog_id.casefold() in observation_dialogs:
            raise LocalizationReleaseAcceptanceError("runtime dialog ids must be unique")
        observation_dialogs.add(dialog_id.casefold())
        language = _text(row["language"], "runtime language")
        displayed_key = _text(row["displayed_key"], "displayed_key")
        displayed_provider = _text(row["displayed_provider_id"], "displayed_provider_id")
        voice_filename = _text(row["voice_filename"], "voice_filename")
        voice_provider = _text(row["voice_provider_id"], "voice_provider_id")
        resolution = row["resolution"]
        if resolution not in {"exact", "fallback"}:
            raise LocalizationReleaseAcceptanceError("runtime resolution is unsupported")
        fallback_value = row["fallback"]
        fallback: dict[str, str] | None
        if resolution == "fallback":
            if fallback_value is None:
                raise LocalizationReleaseAcceptanceError(
                    "fallback resolution requires explicit fallback evidence"
                )
            fallback_row = _mapping(
                fallback_value, _FALLBACK_FIELDS, f"runtime observation[{index}].fallback"
            )
            fallback = {
                name: _text(fallback_row[name], f"fallback.{name}")
                for name in sorted(_FALLBACK_FIELDS)
            }
            if fallback["winner_provider_id"].casefold() != displayed_provider.casefold():
                raise LocalizationReleaseAcceptanceError(
                    "fallback winner must equal the displayed provider"
                )
            explicit_fallbacks += 1
        else:
            if fallback_value is not None:
                raise LocalizationReleaseAcceptanceError("exact resolution cannot carry fallback")
            fallback = None
        dialog = required_dialogs.get(dialog_id.casefold())
        matched = dialog is not None
        if dialog is not None:
            matched = (
                str(dialog.get("language", "")).casefold() == language.casefold()
                and str(dialog.get("localization_key", "")).casefold()
                == displayed_key.casefold()
                and str(dialog.get("voice_filename", "")).casefold()
                == voice_filename.casefold()
            )
            voice_resolution = dialog.get("voice_resolution")
            if isinstance(voice_resolution, Mapping):
                provider = voice_resolution.get("provider")
                if isinstance(provider, Mapping):
                    matched = matched and (
                        str(provider.get("provider_id", "")).casefold()
                        == voice_provider.casefold()
                    )
        if not matched:
            diagnostic(
                "RUNTIME_RESOURCE_MISMATCH",
                "displayed resource evidence does not match the audited dialog links",
                dialog_id=dialog_id,
                language=language,
            )
        observation_receipts.append(
            {
                "dialog_id": dialog_id,
                "language": language,
                "displayed_key": displayed_key,
                "displayed_provider_id": displayed_provider,
                "voice_filename": voice_filename,
                "voice_provider_id": voice_provider,
                "resolution": resolution,
                "fallback": fallback,
                "audit_links_matched": matched,
            }
        )
    runtime_inconclusive = not capture_complete or not correlation_valid
    if not runtime_inconclusive:
        for dialog_id in required_dialog_ids:
            if dialog_id.casefold() not in observation_dialogs:
                diagnostic(
                    "MISSING_RUNTIME_DISPLAY_EVIDENCE",
                    "complete runtime capture lacks a required displayed dialog",
                    dialog_id=dialog_id,
                )

    reason_codes: set[str] = set()
    if partial_coverage:
        reason_codes.add("PARTIAL_LANGUAGE_COVERAGE")
    if not capture_complete:
        reason_codes.add("RUNTIME_CAPTURE_INCOMPLETE")
    if not correlation_valid:
        reason_codes.add("RUNTIME_CORRELATION_INVALID")
    if audit_status == "issues_found" or audit_verdict == "INVALID" or conflicts:
        reason_codes.add("LOCALIZATION_AUDIT_ISSUES")
    inconclusive = partial_coverage or runtime_inconclusive
    if len(diagnostics) > limits["maximum_diagnostics"]:
        diagnostics = diagnostics[: limits["maximum_diagnostics"]]
        reason_codes.add("DIAGNOSTICS_TRUNCATED")
        inconclusive = True

    rejected = bool(diagnostics) or "LOCALIZATION_AUDIT_ISSUES" in reason_codes
    if inconclusive:
        status, verdict, release_allowed = "capture_inconclusive", "INCONCLUSIVE", False
    elif rejected:
        status, verdict, release_allowed = "rejected", "INVALID", False
    else:
        status, verdict, release_allowed = "accepted", "VALID", True

    diagnostics.sort(
        key=lambda item: (
            str(item["code"]),
            str(item.get("language", "")).casefold(),
            str(item.get("dialog_id", "")).casefold(),
            str(item.get("key", "")).casefold(),
            str(item.get("package_path", "")).casefold(),
        )
    )
    package_receipts.sort(
        key=lambda item: (
            str(item["language"]).casefold(),
            str(item["package_path"]).casefold(),
        )
    )
    duration_receipts.sort(key=lambda item: str(item["dialog_id"]).casefold())
    observation_receipts.sort(key=lambda item: str(item["dialog_id"]).casefold())
    permitted_claims: list[str] = []
    if release_allowed:
        permitted_claims.extend(
            [
                "required_localization_links_resolved",
                "language_packages_isolated",
                "runtime_displayed_resources_observed",
            ]
        )
        if duration_enabled:
            permitted_claims.append("subtitle_audio_durations_within_tolerance")
    if explicit_fallbacks and not runtime_inconclusive:
        permitted_claims.append("runtime_fallback_explicit")

    payload = {
        "schema_version": "kcd2.localization-release-acceptance.v1",
        "release_id": release_id,
        "input_sha256": hashlib.sha256(_canonical_bytes(root)).hexdigest(),
        "candidate_provider_id": candidate_provider_id,
        "status": status,
        "verdict": verdict,
        "release_allowed": release_allowed,
        "reason_codes": sorted(reason_codes),
        "permitted_claims": sorted(permitted_claims),
        "localization_audit": {
            "snapshot_id": _text(audit.get("snapshot_id"), "localization_audit.snapshot_id"),
            "input_sha256": _text(audit.get("input_sha256"), "localization_audit.input_sha256"),
            "status": audit_status,
            "verdict": audit_verdict,
            "no_conflict_claim_allowed": audit.get("no_conflict_claim_allowed"),
        },
        "package_isolation": package_receipts,
        "duration_validation": {
            "enabled": duration_enabled,
            "tolerance_ms": tolerance_ms,
            "status": "not_requested"
            if not duration_enabled
            else ("passed" if all(item["matched"] for item in duration_receipts) else "failed"),
            "checks": duration_receipts,
        },
        "runtime_evidence": {
            "capture_complete": capture_complete,
            "correlation_valid": correlation_valid,
            "status": "inconclusive"
            if runtime_inconclusive
            else (
                "matched"
                if all(item["audit_links_matched"] for item in observation_receipts)
                else "mismatched"
            ),
            "observations": observation_receipts,
        },
        "diagnostics": diagnostics,
        "counts": {
            "required_languages": len(required_languages),
            "required_keys": len(required_keys),
            "required_dialogs": len(required_dialog_ids),
            "packages_checked": len(package_receipts),
            "isolated_packages": isolated_packages,
            "duration_checks": len(duration_receipts),
            "runtime_observations_checked": len(observation_receipts),
            "explicit_fallbacks": explicit_fallbacks,
            "diagnostics_returned": len(diagnostics),
        },
        "bounds": limits,
    }
    return LocalizationReleaseReceipt(payload)
