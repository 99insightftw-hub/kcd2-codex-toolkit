"""Bounded, mount-aware localization and dialog provider.

The provider treats ``(language, mount_id, key)`` as the localization namespace.
Consequently, identical keys in different languages are never classified as
conflicts.  Missing-value claims are emitted only for mounts whose static
coverage is complete.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_toolchain_core.paths import canonical_relative_path


_MAX_TEXT = 2048
_MAX_PROVIDERS = 4096
_MAX_MOUNTS = 4096
_MAX_KEYS = 20000
_MAX_DIALOGS = 20000
_MAX_VOICES = 20000
_MAX_ASSETS = 20000
_MAX_DIAGNOSTICS = 60000
_ROOT_FIELDS = {
    "snapshot_id",
    "required_languages",
    "required_keys",
    "providers",
    "mounts",
    "translations",
    "dialogs",
    "voices",
    "assets",
}
_PROVIDER_FIELDS = {
    "provider_id",
    "project_id",
    "state",
    "priority",
    "active_provider_sha256",
    "source_ref",
}
_MOUNT_FIELDS = {
    "mount_id",
    "language",
    "mount_context",
    "provider_id",
    "coverage",
    "source_ref",
}
_TRANSLATION_FIELDS = {
    "language",
    "mount_id",
    "key",
    "text",
    "provider_id",
    "source_ref",
}
_DIALOG_FIELDS = {
    "dialog_id",
    "language",
    "mount_id",
    "localization_key",
    "voice_filename",
    "provider_id",
    "source_ref",
}
_VOICE_FIELDS = {
    "language",
    "mount_id",
    "filename",
    "provider_id",
    "source_ref",
}
_ASSET_FIELDS = {"canonical_path", "kind", "resolved", "provider_id", "diagnostics"}
_COVERAGE = {"COMPLETE", "PARTIAL", "UNSUPPORTED"}
_PROVIDER_STATES = {"loaded", "present", "inactive", "malformed", "unknown"}
_ASSET_KINDS = {
    "GFX",
    "DDS",
    "MATERIAL",
    "PARTICLE",
    "MODEL",
    "AUDIO",
    "ANIMEVENT",
    "OTHER",
}


class LocalizationProviderError(ValueError):
    """The localization input is malformed or exceeds a hard bound."""


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
        raise LocalizationProviderError("localization data must be JSON-compatible") from exc


def _copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LocalizationProviderError(f"{name} fields do not match the contract")
    return value


def _array(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise LocalizationProviderError(f"{name} must be an array")
    if len(value) > maximum:
        raise LocalizationProviderError(f"{name} exceeds its {maximum}-item hard bound")
    return value


def _text(value: object, field: str, *, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not empty and not value)
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise LocalizationProviderError(f"{field} must be a bounded NUL-free string")
    return value


def _path(value: object, field: str) -> str:
    try:
        return canonical_relative_path(_text(value, field))
    except (TypeError, ValueError) as exc:
        raise LocalizationProviderError(f"{field} must be a canonical relative path") from exc


def _unique(values: Sequence[str], name: str) -> None:
    folded = [value.casefold() for value in values]
    if len(folded) != len(set(folded)):
        raise LocalizationProviderError(f"{name} values must be case-insensitively unique")


def _citation(provider: Mapping[str, object], source_ref: str) -> dict[str, object]:
    return {
        "provider_id": provider["provider_id"],
        "project_id": provider["project_id"],
        "active_provider_sha256": provider["active_provider_sha256"],
        "priority": provider["priority"],
        "source_ref": source_ref,
    }


def _scope(language: str, mount_id: str, value: str) -> tuple[str, str, str]:
    return language.casefold(), mount_id.casefold(), value.casefold()


@dataclass(frozen=True, slots=True)
class LocalizationDialogAudit:
    """Immutable, schema-ready localization graph and audit result."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def audit_localization_dialog_mapping(value: Mapping[str, object]) -> LocalizationDialogAudit:
    """Validate exact static inputs and construct a mount-aware localization graph."""

    root = _mapping(value, _ROOT_FIELDS, "localization input")
    snapshot_id = _text(root["snapshot_id"], "snapshot_id")
    required_languages = [
        _text(item, "required_languages item")
        for item in _array(root["required_languages"], "required_languages", _MAX_MOUNTS)
    ]
    required_keys = [
        _text(item, "required_keys item")
        for item in _array(root["required_keys"], "required_keys", _MAX_KEYS)
    ]
    if not required_languages:
        raise LocalizationProviderError("required_languages must not be empty")
    _unique(required_languages, "required_languages")
    _unique(required_keys, "required_keys")

    provider_rows = [
        _mapping(item, _PROVIDER_FIELDS, "provider")
        for item in _array(root["providers"], "providers", _MAX_PROVIDERS)
    ]
    providers: list[dict[str, object]] = []
    for row in provider_rows:
        state = row["state"]
        if state not in _PROVIDER_STATES:
            raise LocalizationProviderError("provider.state is not supported")
        priority = row["priority"]
        if (
            isinstance(priority, bool)
            or not isinstance(priority, int)
            or not 0 <= priority <= 65535
        ):
            raise LocalizationProviderError("provider.priority must be an integer from 0 to 65535")
        digest = _text(row["active_provider_sha256"], "active_provider_sha256")
        if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
            raise LocalizationProviderError("active_provider_sha256 must be a SHA-256 hex digest")
        providers.append(
            {
                "provider_id": _text(row["provider_id"], "provider_id"),
                "project_id": _text(row["project_id"], "project_id"),
                "state": state,
                "priority": priority,
                "active_provider_sha256": digest.lower(),
                "source_ref": _text(row["source_ref"], "provider.source_ref"),
            }
        )
    _unique([str(item["provider_id"]) for item in providers], "provider_id")
    provider_by_id = {str(item["provider_id"]).casefold(): item for item in providers}

    mount_rows = [
        _mapping(item, _MOUNT_FIELDS, "mount")
        for item in _array(root["mounts"], "mounts", _MAX_MOUNTS)
    ]
    mounts: list[dict[str, object]] = []
    for row in mount_rows:
        coverage = row["coverage"]
        if coverage not in _COVERAGE:
            raise LocalizationProviderError("mount.coverage is not supported")
        provider_key = _text(row["provider_id"], "mount.provider_id").casefold()
        if provider_key not in provider_by_id:
            raise LocalizationProviderError("mount references an unknown provider")
        mounts.append(
            {
                "mount_id": _text(row["mount_id"], "mount_id"),
                "language": _text(row["language"], "mount.language"),
                "mount_context": _path(row["mount_context"], "mount.mount_context"),
                "provider_id": provider_by_id[provider_key]["provider_id"],
                "coverage": coverage,
                "source_ref": _text(row["source_ref"], "mount.source_ref"),
            }
        )
    _unique([str(item["mount_id"]) for item in mounts], "mount_id")
    mount_by_id = {str(item["mount_id"]).casefold(): item for item in mounts}

    def checked_binding(
        row: Mapping[str, object], prefix: str
    ) -> tuple[str, dict[str, object], dict[str, object]]:
        language = _text(row["language"], f"{prefix}.language")
        mount_key = _text(row["mount_id"], f"{prefix}.mount_id").casefold()
        provider_key = _text(row["provider_id"], f"{prefix}.provider_id").casefold()
        if mount_key not in mount_by_id:
            raise LocalizationProviderError(f"{prefix} references an unknown mount")
        if provider_key not in provider_by_id:
            raise LocalizationProviderError(f"{prefix} references an unknown provider")
        mount = mount_by_id[mount_key]
        if language.casefold() != str(mount["language"]).casefold():
            raise LocalizationProviderError(f"{prefix} language does not match its mount")
        return language, mount, provider_by_id[provider_key]

    translation_rows = [
        _mapping(item, _TRANSLATION_FIELDS, "translation")
        for item in _array(root["translations"], "translations", _MAX_KEYS)
    ]
    translations: list[dict[str, object]] = []
    for row in translation_rows:
        language, mount, provider = checked_binding(row, "translation")
        text = _text(row["text"], "translation.text", empty=True)
        source_ref = _text(row["source_ref"], "translation.source_ref")
        translations.append(
            {
                "language": language,
                "mount_id": mount["mount_id"],
                "mount_context": mount["mount_context"],
                "key": _text(row["key"], "translation.key"),
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "provider": _citation(provider, source_ref),
            }
        )

    voice_rows = [
        _mapping(item, _VOICE_FIELDS, "voice")
        for item in _array(root["voices"], "voices", _MAX_VOICES)
    ]
    voices: list[dict[str, object]] = []
    for row in voice_rows:
        language, mount, provider = checked_binding(row, "voice")
        filename = _path(row["filename"], "voice.filename")
        source_ref = _text(row["source_ref"], "voice.source_ref")
        identity = {
            "language": language.casefold(),
            "mount_id": str(mount["mount_id"]).casefold(),
            "filename": filename.casefold(),
            "provider_id": str(provider["provider_id"]).casefold(),
            "source_ref": source_ref,
        }
        voices.append(
            {
                "voice_id": (
                    f"voice:sha256:{hashlib.sha256(_canonical_bytes(identity)).hexdigest()}"
                ),
                "language": language,
                "mount_id": mount["mount_id"],
                "mount_context": mount["mount_context"],
                "filename": filename,
                "provider": _citation(provider, source_ref),
            }
        )

    grouped: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for item in translations:
        grouped.setdefault(
            _scope(str(item["language"]), str(item["mount_id"]), str(item["key"])), []
        ).append(item)
    key_nodes: list[dict[str, object]] = []
    conflicts: list[dict[str, object]] = []
    winner_by_scope: dict[tuple[str, str, str], dict[str, object] | None] = {}
    inconclusive_reasons: set[str] = set()
    for scope_key, candidates in sorted(grouped.items()):
        candidates.sort(
            key=lambda item: (
                -int(item["provider"]["priority"]),
                str(item["provider"]["provider_id"]).casefold(),
                str(item["provider"]["source_ref"]),
            )
        )
        loaded = [
            item
            for item in candidates
            if provider_by_id[str(item["provider"]["provider_id"]).casefold()]["state"]
            == "loaded"
        ]
        winner = loaded[0]["provider"] if loaded else None
        if len(loaded) > 1 and int(loaded[0]["provider"]["priority"]) == int(
            loaded[1]["provider"]["priority"]
        ):
            winner = None
            inconclusive_reasons.add("AMBIGUOUS_PROVIDER_PRIORITY")
        winner_by_scope[scope_key] = winner
        node = {
            "language": candidates[0]["language"],
            "mount_id": candidates[0]["mount_id"],
            "mount_context": candidates[0]["mount_context"],
            "key": candidates[0]["key"],
            "candidates": [
                {"text_sha256": item["text_sha256"], "provider": item["provider"]}
                for item in candidates
            ],
            "winner": winner,
        }
        key_nodes.append(node)
        if len({str(item["text_sha256"]) for item in loaded}) > 1:
            conflicts.append(
                {
                    "language": node["language"],
                    "mount_id": node["mount_id"],
                    "mount_context": node["mount_context"],
                    "key": node["key"],
                    "candidate_providers": [item["provider"] for item in loaded],
                    "winner": winner,
                }
            )

    voices_by_scope: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    for item in voices:
        voices_by_scope.setdefault(
            _scope(str(item["language"]), str(item["mount_id"]), str(item["filename"])),
            [],
        ).append(item)
    voice_by_scope: dict[tuple[str, str, str], dict[str, object]] = {}
    for scope_key, candidates in voices_by_scope.items():
        loaded = [
            item
            for item in candidates
            if provider_by_id[str(item["provider"]["provider_id"]).casefold()]["state"]
            == "loaded"
        ]
        loaded.sort(
            key=lambda item: (
                -int(item["provider"]["priority"]),
                str(item["provider"]["provider_id"]).casefold(),
                str(item["provider"]["source_ref"]),
            )
        )
        if loaded:
            if len(loaded) > 1 and int(loaded[0]["provider"]["priority"]) == int(
                loaded[1]["provider"]["priority"]
            ):
                inconclusive_reasons.add("AMBIGUOUS_PROVIDER_PRIORITY")
            else:
                voice_by_scope[scope_key] = loaded[0]
    diagnostics: list[dict[str, object]] = []
    mounts_by_language: dict[str, list[dict[str, object]]] = {}
    for mount in mounts:
        mounts_by_language.setdefault(str(mount["language"]).casefold(), []).append(mount)
    raw_dialog_rows = _array(root["dialogs"], "dialogs", _MAX_DIALOGS)
    maximum_scoped_diagnostics = (
        sum(
            len(mounts_by_language.get(language.casefold(), [])) or 1
            for language in required_languages
        )
        * len(required_keys)
        + (2 * len(raw_dialog_rows))
        + len(required_languages)
    )
    if maximum_scoped_diagnostics > _MAX_DIAGNOSTICS:
        raise LocalizationProviderError(
            "requested language, key, and dialog scope exceeds the diagnostic hard bound"
        )
    for language in required_languages:
        language_mounts = mounts_by_language.get(language.casefold(), [])
        if not language_mounts:
            inconclusive_reasons.add("REQUIRED_LANGUAGE_MOUNT_MISSING")
            diagnostics.append(
                {"code": "REQUIRED_LANGUAGE_MOUNT_MISSING", "language": language}
            )
            continue
        for mount in language_mounts:
            if mount["coverage"] != "COMPLETE":
                inconclusive_reasons.add("INCOMPLETE_LANGUAGE_COVERAGE")
                diagnostics.append(
                    {
                        "code": "INCOMPLETE_LANGUAGE_COVERAGE",
                        "language": mount["language"],
                        "mount_id": mount["mount_id"],
                        "mount_context": mount["mount_context"],
                    }
                )
                continue
            for key in required_keys:
                if winner_by_scope.get(_scope(language, str(mount["mount_id"]), key)) is None:
                    diagnostics.append(
                        {
                            "code": "MISSING_TRANSLATION",
                            "language": mount["language"],
                            "mount_id": mount["mount_id"],
                            "mount_context": mount["mount_context"],
                            "key": key,
                        }
                    )

    dialog_rows = [
        _mapping(item, _DIALOG_FIELDS, "dialog")
        for item in raw_dialog_rows
    ]
    dialogs: list[dict[str, object]] = []
    dialog_ids: list[str] = []
    for row in dialog_rows:
        language, mount, provider = checked_binding(row, "dialog")
        dialog_id = _text(row["dialog_id"], "dialog.dialog_id")
        dialog_ids.append(dialog_id)
        key = _text(row["localization_key"], "dialog.localization_key")
        voice_filename = _path(row["voice_filename"], "dialog.voice_filename")
        translation_winner = winner_by_scope.get(
            _scope(language, str(mount["mount_id"]), key)
        )
        voice = voice_by_scope.get(
            _scope(language, str(mount["mount_id"]), voice_filename)
        )
        if translation_winner is None and mount["coverage"] == "COMPLETE":
            diagnostics.append(
                {
                    "code": "MISSING_DIALOG_TRANSLATION",
                    "dialog_id": dialog_id,
                    "language": language,
                    "mount_id": mount["mount_id"],
                    "mount_context": mount["mount_context"],
                    "key": key,
                }
            )
        if voice is None and mount["coverage"] == "COMPLETE":
            diagnostics.append(
                {
                    "code": "MISSING_VOICE_REFERENCE",
                    "dialog_id": dialog_id,
                    "language": language,
                    "mount_id": mount["mount_id"],
                    "mount_context": mount["mount_context"],
                    "voice_filename": voice_filename,
                }
            )
        dialogs.append(
            {
                "dialog_id": dialog_id,
                "language": language,
                "mount_id": mount["mount_id"],
                "mount_context": mount["mount_context"],
                "localization_key": key,
                "voice_filename": voice_filename,
                "provider": _citation(provider, _text(row["source_ref"], "dialog.source_ref")),
                "translation_resolution": {
                    "status": "resolved" if translation_winner is not None else "missing",
                    "provider": translation_winner,
                },
                "voice_resolution": {
                    "status": "resolved" if voice is not None else "missing",
                    "provider": None if voice is None else voice["provider"],
                },
            }
        )
    _unique(dialog_ids, "dialog_id")

    assets: list[dict[str, object]] = []
    for raw in _array(root["assets"], "assets", _MAX_ASSETS):
        row = _mapping(raw, _ASSET_FIELDS, "asset")
        if row["kind"] not in _ASSET_KINDS:
            raise LocalizationProviderError("asset.kind is not supported")
        if not isinstance(row["resolved"], bool):
            raise LocalizationProviderError("asset.resolved must be a boolean")
        provider_id = row["provider_id"]
        if provider_id is not None:
            provider_id = _text(provider_id, "asset.provider_id")
            if provider_id.casefold() not in provider_by_id:
                raise LocalizationProviderError("asset references an unknown provider")
        asset_diagnostics = [
            _text(item, "asset diagnostic")
            for item in _array(row["diagnostics"], "asset.diagnostics", 1024)
        ]
        assets.append(
            {
                "canonical_path": _path(row["canonical_path"], "asset.canonical_path"),
                "kind": row["kind"],
                "resolved": row["resolved"],
                "provider_id": provider_id,
                "diagnostics": asset_diagnostics,
            }
        )

    issue_codes = {str(item["code"]) for item in diagnostics} - {
        "INCOMPLETE_LANGUAGE_COVERAGE",
        "REQUIRED_LANGUAGE_MOUNT_MISSING",
    }
    if conflicts:
        issue_codes.add("LOCALIZATION_PAYLOAD_CONFLICT")
    status = (
        "capture_inconclusive"
        if inconclusive_reasons
        else "issues_found"
        if issue_codes
        else "resolved"
    )
    complete_required = all(
        mounts_by_language.get(language.casefold())
        and all(item["coverage"] == "COMPLETE" for item in mounts_by_language[language.casefold()])
        for language in required_languages
    )
    no_conflict_claim_allowed = status == "resolved" and complete_required
    languages = [
        {
            "language": mount["language"],
            "mount_id": mount["mount_id"],
            "mount_context": mount["mount_context"],
            "provider_id": mount["provider_id"],
            "keys": sorted(
                {
                    str(item["key"])
                    for item in key_nodes
                    if str(item["mount_id"]).casefold() == str(mount["mount_id"]).casefold()
                },
                key=str.casefold,
            ),
            "voice_files": sorted(
                {
                    str(item["filename"])
                    for item in voices
                    if str(item["mount_id"]).casefold() == str(mount["mount_id"]).casefold()
                },
                key=str.casefold,
            ),
            "coverage": mount["coverage"],
        }
        for mount in sorted(
            mounts,
            key=lambda item: (
                str(item["language"]).casefold(),
                str(item["mount_id"]).casefold(),
            ),
        )
    ]
    key_nodes.sort(
        key=lambda item: (
            str(item["language"]).casefold(),
            str(item["mount_id"]).casefold(),
            str(item["key"]).casefold(),
        )
    )
    voices.sort(
        key=lambda item: (
            str(item["language"]).casefold(),
            str(item["mount_id"]).casefold(),
            str(item["filename"]).casefold(),
        )
    )
    dialogs.sort(key=lambda item: str(item["dialog_id"]).casefold())
    conflicts.sort(
        key=lambda item: (
            str(item["language"]).casefold(),
            str(item["mount_id"]).casefold(),
            str(item["key"]).casefold(),
        )
    )
    diagnostics.sort(key=lambda item: _canonical_bytes(item))
    payload: dict[str, Any] = {
        "schema_version": "kcd2.localization-asset-audit.v1",
        "snapshot_id": snapshot_id,
        "input_sha256": hashlib.sha256(_canonical_bytes(root)).hexdigest(),
        "status": status,
        "reason_codes": sorted(inconclusive_reasons),
        "no_conflict_claim_allowed": no_conflict_claim_allowed,
        "providers": sorted(providers, key=lambda item: str(item["provider_id"]).casefold()),
        "languages": languages,
        "localization_graph": {
            "keys": key_nodes,
            "dialogs": dialogs,
            "voices": voices,
        },
        "conflicts": conflicts,
        "diagnostics": diagnostics,
        "assets": sorted(assets, key=lambda item: str(item["canonical_path"]).casefold()),
        "bounds": {
            "max_providers": _MAX_PROVIDERS,
            "max_mounts": _MAX_MOUNTS,
            "max_keys": _MAX_KEYS,
            "max_dialogs": _MAX_DIALOGS,
            "max_voices": _MAX_VOICES,
            "providers_considered": len(providers),
            "mounts_considered": len(mounts),
            "translations_considered": len(translations),
            "dialogs_considered": len(dialogs),
            "voices_considered": len(voices),
        },
        "verdict": (
            "INCONCLUSIVE"
            if status == "capture_inconclusive"
            else "INVALID"
            if status == "issues_found"
            else "VALID"
        ),
    }
    return LocalizationDialogAudit(payload=_copy(payload))


__all__ = [
    "LocalizationDialogAudit",
    "LocalizationProviderError",
    "audit_localization_dialog_mapping",
]
