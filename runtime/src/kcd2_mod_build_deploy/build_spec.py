"""Bounded parser and semantic diagnostics for declarative candidate build specs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

from .candidate_manifest import (
    CandidateManifestError,
    CandidateManifestMetadata,
    parse_candidate_manifest_metadata,
)

from kcd2_toolchain_core.variant_selection import (
    VariantSelectionError,
    validate_variant_selection,
)


MAX_SPEC_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTICS = 256
BUILDER_EVENT_ALLOWLIST = ("BUILD_FAILED", "BUILD_STATIC_VALIDATED")
_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _ROOT / "schemas" / "build-spec-v1.schema.json"


@dataclass(frozen=True, slots=True)
class BuildSpecDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class ParentIdentity:
    mode: Literal["new_candidate", "derived_candidate"]
    candidate_id: str | None
    artifact_sha256: str | None
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExternalComponent:
    role: str
    logical_path: str
    sha256: str
    bytes: int
    required_at_runtime: bool


@dataclass(frozen=True, slots=True)
class BuildSpec:
    schema_version: Literal["kcd2.build-spec.v1", "kcd2.build-spec.v2"]
    spec_id: str
    created_at: str
    mod_id: str
    folder_name_exact: str
    human_aliases: tuple[str, ...]
    manifest_metadata: CandidateManifestMetadata | None
    parent: ParentIdentity
    external_components: tuple[ExternalComponent, ...]
    lifecycle_intent: Literal[
        "build_static_validation_only", "package_validation_requested"
    ]
    variant_selection_id: str | None
    selected_variant_member_ids: tuple[str, ...]
    excluded_variant_member_ids: tuple[str, ...]

    @property
    def candidate_scope(self) -> Literal["package_only", "package_with_external_components"]:
        if self.external_components:
            return "package_with_external_components"
        return "package_only"

    @property
    def canonical_mod_identity(self) -> Mapping[str, str]:
        """Return identity fields only; display labels are intentionally excluded."""
        return MappingProxyType(
            {"mod_id": self.mod_id, "folder_name_exact": self.folder_name_exact}
        )

    @property
    def builder_event_allowlist(self) -> tuple[str, ...]:
        """Events a builder may own; package, install, runtime, and causal events are excluded."""
        return BUILDER_EVENT_ALLOWLIST


@dataclass(frozen=True, slots=True)
class BuildSpecParseReport:
    valid: bool
    spec: BuildSpec | None
    diagnostics: tuple[BuildSpecDiagnostic, ...]
    diagnostics_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": "kcd2.build-spec-parse-report.v1",
            "status": "PASS" if self.valid else "FAIL",
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
        }
        if self.spec is not None:
            result["spec"] = {
                "schema_version": self.spec.schema_version,
                "spec_id": self.spec.spec_id,
                "canonical_mod_identity": dict(self.spec.canonical_mod_identity),
                "manifest_metadata": (
                    None
                    if self.spec.manifest_metadata is None
                    else self.spec.manifest_metadata.to_dict()
                ),
                "human_aliases": list(self.spec.human_aliases),
                "parent_mode": self.spec.parent.mode,
                "candidate_scope": self.spec.candidate_scope,
                "external_component_count": len(self.spec.external_components),
                "lifecycle_intent": self.spec.lifecycle_intent,
                "builder_event_allowlist": list(self.spec.builder_event_allowlist),
                "variant_selection_id": self.spec.variant_selection_id,
                "selected_variant_member_count": len(
                    self.spec.selected_variant_member_ids
                ),
            }
        return result


class _Collector:
    def __init__(self, maximum: int) -> None:
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 10_000:
            raise ValueError("max_diagnostics must be between 1 and 10000")
        self.maximum = maximum
        self.items: list[BuildSpecDiagnostic] = []
        self.truncated = False

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.items) < self.maximum:
            self.items.append(BuildSpecDiagnostic(code=code, path=path, message=message))
        else:
            self.truncated = True


def parse_build_spec(
    document: object, *, max_diagnostics: int = MAX_DIAGNOSTICS
) -> BuildSpecParseReport:
    """Validate and parse one in-memory spec without reading build inputs or live targets."""
    collector = _Collector(max_diagnostics)
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _validate_schema(document, schema, schema, "$", collector)
    if isinstance(document, Mapping):
        _validate_semantics(document, collector)
    if collector.items or collector.truncated:
        return BuildSpecParseReport(False, None, tuple(collector.items), collector.truncated)
    assert isinstance(document, Mapping)
    return BuildSpecParseReport(True, _to_spec(document), (), False)


def parse_build_spec_file(
    path: Path | str,
    *,
    max_bytes: int = MAX_SPEC_BYTES,
    max_diagnostics: int = MAX_DIAGNOSTICS,
) -> BuildSpecParseReport:
    """Read one bounded UTF-8 JSON file and return machine-readable diagnostics."""
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= MAX_SPEC_BYTES
    ):
        raise ValueError(f"max_bytes must be between 1 and {MAX_SPEC_BYTES}")
    source = Path(path)
    collector = _Collector(max_diagnostics)
    try:
        size = source.stat().st_size
    except OSError as exc:
        collector.add("SPEC_READ_FAILED", "$", f"could not stat build spec: {exc}")
        return BuildSpecParseReport(False, None, tuple(collector.items), False)
    if size > max_bytes:
        collector.add("SPEC_SIZE_LIMIT", "$", f"build spec exceeds {max_bytes} bytes")
        return BuildSpecParseReport(False, None, tuple(collector.items), False)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        collector.add("SPEC_JSON_INVALID", "$", f"build spec is not valid UTF-8 JSON: {exc}")
        return BuildSpecParseReport(False, None, tuple(collector.items), False)
    return parse_build_spec(document, max_diagnostics=max_diagnostics)


def _to_spec(document: Mapping[str, Any]) -> BuildSpec:
    mod = document["mod"]
    parent = document["parent"]
    selection_id, selected, excluded = _variant_summary(document)
    return BuildSpec(
        schema_version=document["schema_version"],
        spec_id=document["spec_id"],
        created_at=document["created_at"],
        mod_id=mod["mod_id"],
        folder_name_exact=mod["folder_name_exact"],
        human_aliases=tuple(mod["human_aliases"]),
        manifest_metadata=(
            None
            if document.get("manifest_metadata") is None
            else parse_candidate_manifest_metadata(
                document["manifest_metadata"],
                mod_id=mod["mod_id"],
                folder_name_exact=mod["folder_name_exact"],
            )
        ),
        parent=ParentIdentity(
            mode=parent["mode"],
            candidate_id=parent["candidate_id"],
            artifact_sha256=parent["artifact_sha256"],
            evidence_refs=tuple(parent["evidence_refs"]),
        ),
        external_components=tuple(
            ExternalComponent(
                role=item["role"],
                logical_path=item["logical_path"],
                sha256=item["sha256"],
                bytes=item["bytes"],
                required_at_runtime=item["required_at_runtime"],
            )
            for item in document["external_components"]
        ),
        lifecycle_intent=document["lifecycle_intent"],
        variant_selection_id=selection_id,
        selected_variant_member_ids=selected,
        excluded_variant_member_ids=excluded,
    )


def _variant_summary(
    document: Mapping[str, Any],
) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    value = document.get("variant_selection")
    if value is None:
        return None, (), ()
    receipt = validate_variant_selection(value).to_dict()
    selected = {
        member_id
        for group in receipt["groups"]
        for member_id in group["selected_member_ids"]
    }
    known = {
        member["member_id"]
        for group in receipt["groups"]
        for member in group["members"]
    }
    return receipt["selection_id"], tuple(sorted(selected)), tuple(sorted(known - selected))


def _validate_semantics(document: Mapping[str, Any], collector: _Collector) -> None:
    schema_version = document.get("schema_version")
    manifest_metadata = document.get("manifest_metadata")
    if schema_version == "kcd2.build-spec.v2" and not isinstance(
        manifest_metadata, Mapping
    ):
        collector.add(
            "MANIFEST_METADATA_REQUIRED",
            "$.manifest_metadata",
            "v2 build specifications require canonical manifest metadata",
        )
    if isinstance(manifest_metadata, Mapping):
        mod = document.get("mod")
        if isinstance(mod, Mapping):
            try:
                parse_candidate_manifest_metadata(
                    manifest_metadata,
                    mod_id=mod.get("mod_id"),
                    folder_name_exact=mod.get("folder_name_exact"),
                )
            except CandidateManifestError as exc:
                collector.add(
                    "MANIFEST_METADATA_INVALID",
                    "$.manifest_metadata",
                    str(exc),
                )
    if schema_version == "kcd2.build-spec.v2":
        for collection_name in ("inputs", "allowed_changes"):
            collection = document.get(collection_name)
            if not isinstance(collection, list):
                continue
            for index, item in enumerate(collection):
                logical_path = item.get("logical_path") if isinstance(item, Mapping) else None
                if isinstance(logical_path, str) and logical_path.replace("\\", "/").casefold() == "mod.manifest":
                    collector.add(
                        "MANIFEST_INPUT_FORBIDDEN",
                        f"$.{collection_name}[{index}].logical_path",
                        "v2 candidate manifests are generated centrally and cannot be supplied as package members",
                    )
    try:
        selection_id, selected_members, excluded_members = _variant_summary(document)
    except (TypeError, VariantSelectionError) as exc:
        collector.add(
            "VARIANT_SELECTION_INVALID",
            "$.variant_selection",
            f"variant selection is invalid: {exc}",
        )
        selection_id, selected_members, excluded_members = None, (), ()
    known_members = set(selected_members) | set(excluded_members)
    represented_selected: set[str] = set()
    inputs = document.get("inputs")
    if isinstance(inputs, list):
        for index, item in enumerate(inputs):
            if not isinstance(item, Mapping):
                continue
            member_id = item.get("variant_member_id")
            path = f"$.inputs[{index}].variant_member_id"
            if member_id is None:
                continue
            if selection_id is None:
                collector.add(
                    "VARIANT_SELECTION_REQUIRED",
                    path,
                    "variant-bound inputs require a canonical variant selection",
                )
            elif member_id not in known_members:
                collector.add(
                    "VARIANT_MEMBER_UNKNOWN",
                    path,
                    "variant-bound input references a member outside the selection receipt",
                )
            elif member_id in selected_members:
                represented_selected.add(member_id)
    missing_selected = sorted(set(selected_members) - represented_selected)
    if missing_selected:
        collector.add(
            "SELECTED_VARIANT_INPUT_MISSING",
            "$.inputs",
            "every selected variant member must bind at least one package input",
        )

    parent = document.get("parent")
    if isinstance(parent, Mapping):
        mode = parent.get("mode")
        candidate_id = parent.get("candidate_id")
        artifact = parent.get("artifact_sha256")
        evidence = parent.get("evidence_refs")
        if mode == "new_candidate" and (candidate_id is not None or artifact is not None):
            collector.add(
                "NEW_CANDIDATE_PARENT_PRESENT",
                "$.parent",
                "new candidates must not declare a parent candidate or artifact identity",
            )
        if mode == "derived_candidate":
            if not isinstance(candidate_id, str):
                collector.add(
                    "DERIVED_PARENT_CANDIDATE_REQUIRED",
                    "$.parent.candidate_id",
                    "derived candidates require an immutable parent candidate ID",
                )
            if not isinstance(artifact, str):
                collector.add(
                    "DERIVED_PARENT_ARTIFACT_REQUIRED",
                    "$.parent.artifact_sha256",
                    "derived candidates require an immutable parent artifact SHA-256",
                )
            if not isinstance(evidence, list) or not evidence:
                collector.add(
                    "DERIVED_PARENT_EVIDENCE_REQUIRED",
                    "$.parent.evidence_refs",
                    "derived candidates require at least one parent evidence reference",
                )

    changes = document.get("allowed_changes")
    components = document.get("external_components")
    component_paths = {
        item.get("logical_path")
        for item in components or []
        if isinstance(item, Mapping) and isinstance(item.get("logical_path"), str)
    }
    if isinstance(changes, list):
        for index, change in enumerate(changes):
            if not isinstance(change, Mapping):
                continue
            path = f"$.allowed_changes[{index}]"
            kind = change.get("change_kind")
            selector = change.get("record_selector")
            parent_hash = change.get("expected_parent_sha256")
            if kind == "patch_record" and not isinstance(selector, str):
                collector.add(
                    "RECORD_SELECTOR_REQUIRED",
                    f"{path}.record_selector",
                    "record patches require an explicit canonical record selector",
                )
            if kind != "patch_record" and selector is not None:
                collector.add(
                    "RECORD_SELECTOR_NOT_APPLICABLE",
                    f"{path}.record_selector",
                    "record_selector is only valid for patch_record changes",
                )
            if kind in {"replace_member", "remove_member", "patch_record"} and not isinstance(
                parent_hash, str
            ):
                collector.add(
                    "PARENT_MEMBER_HASH_REQUIRED",
                    f"{path}.expected_parent_sha256",
                    "changes to existing content require its exact parent SHA-256",
                )
            if kind in {"add_member", "add_external_component"} and parent_hash is not None:
                collector.add(
                    "ADDED_CONTENT_PARENT_HASH_NOT_APPLICABLE",
                    f"{path}.expected_parent_sha256",
                    "new content cannot declare an expected parent SHA-256",
                )
            if (
                kind == "add_external_component"
                and change.get("logical_path") not in component_paths
            ):
                collector.add(
                    "EXTERNAL_COMPONENT_UNDECLARED",
                    f"{path}.logical_path",
                    "external component changes require a matching explicit component declaration",
                )

    limits = document.get("limits")
    if isinstance(limits, Mapping):
        _check_count(
            document.get("inputs"), limits.get("max_inputs"), "INPUT", "$.inputs", collector
        )
        _check_count(
            changes,
            limits.get("max_allowed_changes"),
            "ALLOWED_CHANGE",
            "$.allowed_changes",
            collector,
        )
        _check_count(
            components,
            limits.get("max_external_components"),
            "EXTERNAL_COMPONENT",
            "$.external_components",
            collector,
        )
        inputs = document.get("inputs")
        maximum_bytes = limits.get("max_input_bytes")
        if isinstance(inputs, list) and _is_integer(maximum_bytes):
            sizes = [item.get("bytes") for item in inputs if isinstance(item, Mapping)]
            sizes_valid = all(_is_integer(size) and size >= 0 for size in sizes)
            if sizes_valid and sum(sizes) > maximum_bytes:
                collector.add(
                    "INPUT_BYTES_LIMIT_EXCEEDED",
                    "$.inputs",
                    f"declared input bytes exceed max_input_bytes ({maximum_bytes})",
                )
        max_path = limits.get("max_path_chars")
        if _is_integer(max_path):
            for collection_name in ("inputs", "allowed_changes", "external_components"):
                collection = document.get(collection_name)
                if not isinstance(collection, list):
                    continue
                for index, item in enumerate(collection):
                    value = item.get("logical_path") if isinstance(item, Mapping) else None
                    if isinstance(value, str) and len(value) > max_path:
                        collector.add(
                            "PATH_LIMIT_EXCEEDED",
                            f"$.{collection_name}[{index}].logical_path",
                            f"logical path exceeds max_path_chars ({max_path})",
                        )


def _check_count(
    value: object,
    maximum: object,
    prefix: str,
    path: str,
    collector: _Collector,
) -> None:
    if isinstance(value, list) and _is_integer(maximum) and len(value) > maximum:
        collector.add(
            f"{prefix}_LIMIT_EXCEEDED",
            path,
            f"collection contains {len(value)} entries but declared limit is {maximum}",
        )


def _resolve_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"unsupported non-local schema reference: {reference}")
    value: Any = root
    for token in reference[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def _validate_schema(
    value: object,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str,
    collector: _Collector,
) -> None:
    if "$ref" in schema:
        _validate_schema(value, _resolve_ref(root, schema["$ref"]), root, path, collector)
        return
    if "const" in schema and value != schema["const"]:
        collector.add("SCHEMA_CONST", path, "value does not match the required constant")
    if "enum" in schema and value not in schema["enum"]:
        collector.add("SCHEMA_ENUM", path, "value is not one of the allowed values")

    expected = schema.get("type")
    expected_types = [expected] if isinstance(expected, str) else expected
    if isinstance(expected_types, list) and not any(
        _matches_type(value, item) for item in expected_types
    ):
        collector.add("SCHEMA_TYPE", path, "value has an unexpected type")
        return

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            collector.add("SCHEMA_MIN_LENGTH", path, "string is shorter than the schema minimum")
        if len(value) > schema.get("maxLength", len(value)):
            collector.add("SCHEMA_MAX_LENGTH", path, "string exceeds the schema maximum")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            collector.add("SCHEMA_PATTERN", path, "string does not match the required pattern")
        if schema.get("format") == "date-time" and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
        ) is None:
            collector.add("SCHEMA_FORMAT", path, "string is not an ISO date-time")
    elif _is_integer(value):
        if value < schema.get("minimum", value):
            collector.add("SCHEMA_MINIMUM", path, "integer is below the schema minimum")
        if value > schema.get("maximum", value):
            collector.add("SCHEMA_MAXIMUM", path, "integer exceeds the schema maximum")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            collector.add("SCHEMA_MIN_ITEMS", path, "array has too few items")
        if len(value) > schema.get("maxItems", len(value)):
            collector.add("SCHEMA_MAX_ITEMS", path, "array has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                collector.add("SCHEMA_UNIQUE_ITEMS", path, "array items must be unique")
        item_schema = schema.get("items", {})
        for index, item in enumerate(value):
            _validate_schema(item, item_schema, root, f"{path}[{index}]", collector)
    elif isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for name in sorted(schema.get("required", [])):
            if name not in value:
                collector.add(
                    "SCHEMA_REQUIRED", f"{path}.{name}", f"required property {name!r} is missing"
                )
        for name in sorted(value):
            if name in properties:
                _validate_schema(value[name], properties[name], root, f"{path}.{name}", collector)
            elif schema.get("additionalProperties") is False:
                collector.add(
                    "SCHEMA_ADDITIONAL_PROPERTY",
                    f"{path}.{name}",
                    "property is not allowed",
                )


def _matches_type(value: object, expected: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": _is_integer(value),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
