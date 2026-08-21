"""Validate bounded native deployment declarations against explicit observations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping, Sequence

from .build_spec import _validate_schema


MAX_DESCRIPTOR_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTICS = 256
MAX_COMPONENTS = 256
_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _ROOT / "schemas" / "native-deployment-descriptor-v1.schema.json"
DeclarationSource = Literal["committed_descriptor", "ad_hoc_map"]
Completeness = Literal["NONE_EXPECTED", "DECLARED", "COMPLETE", "INCOMPLETE"]
Confidence = Literal["HIGH", "LOW"]


@dataclass(frozen=True, slots=True)
class NativeDeploymentDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class NativeComponentResult:
    component_id: str
    install_path: str
    state: Literal["DECLARED", "MATCHED", "MISSING", "OBSOLETE"]

    def to_dict(self) -> dict[str, str]:
        return {
            "component_id": self.component_id,
            "install_path": self.install_path,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class NativeDeploymentDescriptorReport:
    valid: bool
    completeness: Completeness
    confidence: Confidence
    descriptor_sha256: str
    expected_component_count: int
    observed_component_count: int
    observed_inventory_complete: bool
    component_results: tuple[NativeComponentResult, ...]
    diagnostics: tuple[NativeDeploymentDiagnostic, ...]
    diagnostics_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.native-deployment-descriptor-report.v1",
            "status": "PASS" if self.valid else "FAIL",
            "completeness": self.completeness,
            "confidence": self.confidence,
            "descriptor_sha256": self.descriptor_sha256,
            "expected_component_count": self.expected_component_count,
            "observed_component_count": self.observed_component_count,
            "observed_inventory_complete": self.observed_inventory_complete,
            "component_results": [item.to_dict() for item in self.component_results],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
        }


class _Collector:
    def __init__(self, maximum: int) -> None:
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 10_000:
            raise ValueError("max_diagnostics must be between 1 and 10000")
        self.maximum = maximum
        self.items: list[NativeDeploymentDiagnostic] = []
        self.truncated = False

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.items) < self.maximum:
            self.items.append(NativeDeploymentDiagnostic(code, path, message))
        else:
            self.truncated = True


def canonical_descriptor_sha256(document: Mapping[str, Any]) -> str:
    """Hash canonical UTF-8 JSON after removing the descriptor's self-hash field."""
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    payload = {key: value for key, value in document.items() if key != "descriptor_sha256"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_native_deployment_descriptor(
    document: object,
    *,
    expected_mod_id: str | None = None,
    expected_external_components: Sequence[Mapping[str, Any]] | None = None,
    observed_game: Mapping[str, Any] | None = None,
    observed_components: Sequence[Mapping[str, Any]] | None = None,
    observed_inventory_complete: bool = False,
    declaration_source: DeclarationSource = "committed_descriptor",
    max_diagnostics: int = MAX_DIAGNOSTICS,
) -> NativeDeploymentDescriptorReport:
    """Validate one descriptor using only caller-supplied, bounded non-live evidence.

    ``observed_components=None`` validates declaration completeness only. An explicit
    sequence reconciles the whole observed install scope, allowing missing, obsolete,
    and foreign components to be distinguished.
    """
    if declaration_source not in {"committed_descriptor", "ad_hoc_map"}:
        raise ValueError("declaration_source must be committed_descriptor or ad_hoc_map")
    if not isinstance(observed_inventory_complete, bool):
        raise TypeError("observed_inventory_complete must be a boolean")
    if observed_components is None and observed_inventory_complete:
        raise ValueError("complete observed inventory requires observed_components")
    collector = _Collector(max_diagnostics)
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _validate_schema(document, schema, schema, "$", collector)

    expected_count = 0
    results: list[NativeComponentResult] = []
    calculated_hash = "0" * 64
    components: list[Mapping[str, Any]] = []
    if isinstance(document, Mapping):
        calculated_hash = canonical_descriptor_sha256(document)
        claimed_hash = document.get("descriptor_sha256")
        if isinstance(claimed_hash, str) and claimed_hash.lower() != calculated_hash:
            collector.add(
                "DESCRIPTOR_HASH_MISMATCH",
                "$.descriptor_sha256",
                "descriptor SHA-256 does not bind the canonical non-hash fields",
            )
        if expected_mod_id is not None and document.get("target_mod_id") != expected_mod_id:
            collector.add(
                "TARGET_MOD_MISMATCH",
                "$.target_mod_id",
                "descriptor is bound to a different mod identity",
            )
        raw_components = document.get("components")
        if isinstance(raw_components, list):
            components = [item for item in raw_components if isinstance(item, Mapping)]
            expected_count = len(raw_components)
        _validate_component_semantics(components, collector)
        if observed_game is not None:
            _compare_game_profile(document.get("game_profile"), observed_game, collector)

    if expected_external_components is not None:
        bounded_expected = _bounded_component_sequence(
            expected_external_components, "$.expected_external_components", collector
        )
        _compare_build_declarations(components, bounded_expected, collector)

    observed_count = 0
    if observed_components is None:
        results.extend(_declared_results(components))
    else:
        observed_count = len(observed_components)
        bounded_observed = _bounded_component_sequence(
            observed_components, "$.observed_components", collector
        )
        results.extend(
            _reconcile_components(
                components,
                bounded_observed,
                collector,
                inventory_complete=observed_inventory_complete,
            )
        )

    confidence: Confidence = "HIGH"
    if declaration_source == "ad_hoc_map":
        confidence = "LOW"
        collector.add(
            "AD_HOC_MAP_LOWER_CONFIDENCE",
            "$",
            "an ad-hoc caller map cannot establish native deployment completeness",
        )

    valid = not collector.items and not collector.truncated
    if not components and valid:
        completeness: Completeness = "NONE_EXPECTED"
    elif not valid:
        completeness = "INCOMPLETE"
    elif observed_components is None or not observed_inventory_complete:
        completeness = "DECLARED"
    else:
        completeness = "COMPLETE"
    return NativeDeploymentDescriptorReport(
        valid=valid,
        completeness=completeness,
        confidence=confidence,
        descriptor_sha256=calculated_hash,
        expected_component_count=expected_count,
        observed_component_count=observed_count,
        observed_inventory_complete=observed_inventory_complete,
        component_results=tuple(results),
        diagnostics=tuple(collector.items),
        diagnostics_truncated=collector.truncated,
    )


def validate_native_deployment_descriptor_file(
    path: Path | str,
    *,
    max_bytes: int = MAX_DESCRIPTOR_BYTES,
    max_diagnostics: int = MAX_DIAGNOSTICS,
    **kwargs: Any,
) -> NativeDeploymentDescriptorReport:
    """Read one bounded UTF-8 descriptor and return machine-readable diagnostics."""
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or not 1 <= max_bytes <= MAX_DESCRIPTOR_BYTES
    ):
        raise ValueError(f"max_bytes must be between 1 and {MAX_DESCRIPTOR_BYTES}")
    source = Path(path)
    collector = _Collector(max_diagnostics)
    try:
        if source.stat().st_size > max_bytes:
            collector.add("DESCRIPTOR_SIZE_LIMIT", "$", f"descriptor exceeds {max_bytes} bytes")
            return _read_failure_report(collector)
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        collector.add("DESCRIPTOR_READ_FAILED", "$", f"descriptor is not bounded UTF-8 JSON: {exc}")
        return _read_failure_report(collector)
    return validate_native_deployment_descriptor(
        document, max_diagnostics=max_diagnostics, **kwargs
    )


def _read_failure_report(collector: _Collector) -> NativeDeploymentDescriptorReport:
    return NativeDeploymentDescriptorReport(
        False,
        "INCOMPLETE",
        "HIGH",
        "0" * 64,
        0,
        0,
        False,
        (),
        tuple(collector.items),
        collector.truncated,
    )


def _exact_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _bounded_component_sequence(
    value: Sequence[Mapping[str, Any]], path: str, collector: _Collector
) -> Sequence[Mapping[str, Any]]:
    if isinstance(value, (str, bytes)):
        collector.add("COMPONENT_INVENTORY_INVALID", path, "component inventory must be a sequence")
        return ()
    if len(value) > MAX_COMPONENTS:
        collector.add(
            "COMPONENT_INVENTORY_LIMIT",
            path,
            f"component inventory exceeds {MAX_COMPONENTS} entries",
        )
        return value[:MAX_COMPONENTS]
    return value


def _validate_component_semantics(
    components: Sequence[Mapping[str, Any]], collector: _Collector
) -> None:
    ids: set[str] = set()
    installs: set[str] = set()
    rollbacks: set[str] = set()
    for index, component in enumerate(components):
        base = f"$.components[{index}]"
        component_id = component.get("component_id")
        if isinstance(component_id, str):
            if component_id in ids:
                collector.add(
                    "DUPLICATE_COMPONENT_ID",
                    f"{base}.component_id",
                    "component ID is duplicated",
                )
            ids.add(component_id)
        for field, seen in (("install_path", installs), ("rollback_path", rollbacks)):
            value = component.get(field)
            if not _exact_path(value):
                collector.add(
                    "TARGET_PATH_NOT_EXACT",
                    f"{base}.{field}",
                    "target must be a normalized relative path",
                )
            if isinstance(value, str):
                folded = value.casefold()
                if folded in seen:
                    collector.add(
                        "DUPLICATE_TARGET_PATH",
                        f"{base}.{field}",
                        "target path is duplicated",
                    )
                seen.add(folded)
        install = component.get("install_path")
        rollback = component.get("rollback_path")
        if (
            isinstance(install, str)
            and isinstance(rollback, str)
            and install.casefold() == rollback.casefold()
        ):
            collector.add(
                "TARGET_PATH_COLLISION",
                f"{base}.rollback_path",
                "install and rollback paths must be distinct",
            )
        lifecycle = component.get("lifecycle")
        cleanup = component.get("cleanup_expectation")
        if lifecycle == "cleanup_required" and cleanup in {None, "none"}:
            collector.add(
                "CLEANUP_EXPECTATION_REQUIRED",
                f"{base}.cleanup_expectation",
                "cleanup_required components must declare a concrete cleanup action",
            )


def _compare_game_profile(
    declared: object, observed: Mapping[str, Any], collector: _Collector
) -> None:
    if not isinstance(declared, Mapping):
        return
    for field in ("game_version", "game_executable_path", "game_executable_sha256"):
        if observed.get(field) != declared.get(field):
            collector.add(
                "OBSOLETE_GAME_PROFILE",
                f"$.game_profile.{field}",
                f"observed {field} differs",
            )
    for field in ("whgame_path", "whgame_sha256"):
        if observed.get(field) != declared.get(field):
            collector.add(
                "OBSOLETE_WHGAME_PROFILE",
                f"$.game_profile.{field}",
                f"observed {field} differs",
            )


def _compare_build_declarations(
    components: Sequence[Mapping[str, Any]],
    expected: Sequence[Mapping[str, Any]],
    collector: _Collector,
) -> None:
    declared_hashes = sorted(
        item.get("sha256", "").lower()
        for item in components
        if isinstance(item.get("sha256"), str)
    )
    expected_hashes = sorted(
        item.get("sha256", "").lower()
        for item in expected
        if isinstance(item, Mapping) and isinstance(item.get("sha256"), str)
    )
    if declared_hashes != expected_hashes:
        collector.add(
            "BUILD_DESCRIPTOR_COMPONENT_MISMATCH",
            "$.components",
            "descriptor component hashes do not exactly match build-spec external components",
        )


def _declared_results(components: Sequence[Mapping[str, Any]]) -> list[NativeComponentResult]:
    return [
        NativeComponentResult(
            str(item.get("component_id", "")), str(item.get("install_path", "")), "DECLARED"
        )
        for item in components
    ]


def _reconcile_components(
    components: Sequence[Mapping[str, Any]],
    observed: Sequence[Mapping[str, Any]],
    collector: _Collector,
    *,
    inventory_complete: bool,
) -> list[NativeComponentResult]:
    results: list[NativeComponentResult] = []
    observed_by_path: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(observed):
        if not isinstance(item, Mapping):
            collector.add(
                "OBSERVED_COMPONENT_INVALID",
                f"$.observed_components[{index}]",
                "observation must be an object",
            )
            continue
        path = item.get("install_path")
        if not isinstance(path, str) or not _exact_path(path):
            collector.add(
                "OBSERVED_COMPONENT_INVALID",
                f"$.observed_components[{index}].install_path",
                "observation path must be exact",
            )
            continue
        key = path.casefold()
        if key in observed_by_path:
            collector.add(
                "OBSERVED_COMPONENT_DUPLICATE",
                f"$.observed_components[{index}].install_path",
                "observed install path is duplicated",
            )
            continue
        observed_by_path[key] = item

    declared_keys: set[str] = set()
    for index, component in enumerate(components):
        path = component.get("install_path")
        component_id = str(component.get("component_id", ""))
        if not isinstance(path, str):
            continue
        key = path.casefold()
        declared_keys.add(key)
        actual = observed_by_path.get(key)
        if actual is None:
            if inventory_complete:
                collector.add(
                    "EXPECTED_COMPONENT_MISSING",
                    f"$.components[{index}].install_path",
                    f"expected component is absent: {path}",
                )
                state: Literal["DECLARED", "MISSING"] = "MISSING"
            else:
                state = "DECLARED"
            results.append(NativeComponentResult(component_id, path, state))
            continue
        obsolete = False
        if str(actual.get("sha256", "")).lower() != str(
            component.get("sha256", "")
        ).lower():
            collector.add(
                "OBSOLETE_COMPONENT_HASH",
                f"$.components[{index}].sha256",
                f"installed bytes differ at {path}",
            )
            obsolete = True
        if actual.get("pe_architecture") != component.get("pe_architecture"):
            collector.add(
                "OBSOLETE_COMPONENT_PE",
                f"$.components[{index}].pe_architecture",
                f"installed PE architecture differs at {path}",
            )
            obsolete = True
        exports = actual.get("exports")
        if not isinstance(exports, list) or not set(
            component.get("required_exports", ())
        ).issubset(exports):
            collector.add(
                "OBSOLETE_COMPONENT_EXPORTS",
                f"$.components[{index}].required_exports",
                f"required exports are absent at {path}",
            )
            obsolete = True
        imports = actual.get("import_api_versions")
        if not isinstance(imports, list) or not set(
            component.get("import_constraints", ())
        ).issubset(imports):
            collector.add(
                "OBSOLETE_COMPONENT_IMPORT_API",
                f"$.components[{index}].import_constraints",
                f"import/API constraints differ at {path}",
            )
            obsolete = True
        if actual.get("kcse_api_version") != component.get("kcse_api_version"):
            collector.add(
                "OBSOLETE_COMPONENT_KCSE_API",
                f"$.components[{index}].kcse_api_version",
                f"KCSE API identity differs at {path}",
            )
            obsolete = True
        results.append(
            NativeComponentResult(
                component_id, path, "OBSOLETE" if obsolete else "MATCHED"
            )
        )

    for key in sorted(set(observed_by_path) - declared_keys):
        path = str(observed_by_path[key]["install_path"])
        collector.add(
            "FOREIGN_COMPONENT",
            "$.observed_components",
            f"undeclared component is present: {path}",
        )
    return results
