"""Compose bounded package, declared-component, and XML/TBL validation."""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

from kcd2_toolchain_core.containers import ContainerValidation, classify_container

from .build_spec import BuildSpec, ExternalComponent, parse_build_spec
from .native_deployment_descriptor import validate_native_deployment_descriptor
from .packaging_profiles import PackagingProfileSelectionReport, select_packaging_profile
from .xml_tbl_contract import PackagePromotion, XmlTblContractError, validate_xml_tbl_contract


MAX_DIAGNOSTICS = 256
MAX_EXAMPLES_PER_DIAGNOSTIC = 10
MAX_MANIFEST_BYTES = 1024 * 1024
ExternalExpectation = Literal[
    "NONE_EXPECTED", "DECLARED_AND_COMPLETE", "DECLARED_AND_INCOMPLETE"
]
ValidationMode = Literal[
    "package_only", "package_with_single_component", "package_with_external_components"
]


@dataclass(frozen=True, slots=True)
class NormalizedDiagnostic:
    """Package-verdict-compatible deterministic diagnostic."""

    code: str
    count: int
    examples: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "count": self.count, "examples": list(self.examples)}


@dataclass(frozen=True, slots=True)
class ExternalComponentValidation:
    logical_path: str
    supplied_path: str
    valid: bool
    diagnostics: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class PackageValidationReport:
    artifact_sha256: str
    validation_mode: ValidationMode
    structural_integrity: Literal["VALID", "CORRUPT", "UNREADABLE"]
    external_component_expectation: ExternalExpectation
    package_promotion: str
    xml_tbl_gate: str
    overall_static_readiness: bool
    validated_component_paths: tuple[str, ...]
    diagnostics: tuple[NormalizedDiagnostic, ...]
    native_descriptor_status: Literal[
        "NONE_EXPECTED", "VALID", "INVALID", "MISSING"
    ] = "NONE_EXPECTED"
    native_descriptor_confidence: Literal[
        "NOT_APPLICABLE", "HIGH", "LOW"
    ] = "NOT_APPLICABLE"
    native_descriptor_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return the validation-orchestrator receipt without implying runtime success."""
        return {
            "schema_version": "kcd2.package-validation-report.v1",
            "artifact_sha256": self.artifact_sha256,
            "validation_mode": self.validation_mode,
            "structural_integrity": self.structural_integrity,
            "external_component_expectation": self.external_component_expectation,
            "package_promotion": self.package_promotion,
            "xml_tbl_gate": self.xml_tbl_gate,
            "overall_static_readiness": self.overall_static_readiness,
            "validated_component_paths": list(self.validated_component_paths),
            "native_descriptor_status": self.native_descriptor_status,
            "native_descriptor_confidence": self.native_descriptor_confidence,
            "native_descriptor_sha256": self.native_descriptor_sha256,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }

    def to_package_verdict(self, *, profile: str) -> dict[str, Any]:
        """Project the composed result into the reviewed package-verdict-v2 draft."""
        return {
            "schema_version": "kcd2.package-verdict.v2",
            "artifact_sha256": self.artifact_sha256,
            "structural_integrity": self.structural_integrity,
            "runtime_compatibility": "UNKNOWN",
            "packaging_policy": (
                "GENERATED_OUTPUT_VALID"
                if self.structural_integrity == "VALID"
                else "POLICY_NONCOMPLIANT"
            ),
            "lineage_compatibility": "UNKNOWN",
            "runtime_open_confirmation": "NOT_CONFIRMED",
            "profile": profile,
            "manifest_topology": "NOT_APPLICABLE",
            "external_component_expectation": self.external_component_expectation,
            "overall_static_readiness": self.overall_static_readiness,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class PackageRequirement:
    """One bounded package input and the policy/topology facts needed to validate it."""

    build_spec: BuildSpec | Mapping[str, Any]
    package_path: Path | str
    required: bool = True
    requested_profile_mode: Literal["retail_strict", "lineage_inherited"] = "retail_strict"
    parent_package_path: Path | str | None = None
    declared_method_changes: tuple[str, ...] = ()
    manifest_path: Path | str | None = None
    manifest_required: bool = False
    external_component_paths: Mapping[str, Path | str] | None = None
    native_deployment_descriptor: Mapping[str, Any] | None = None
    native_descriptor_source: Literal["committed_descriptor", "ad_hoc_map"] = (
        "committed_descriptor"
    )
    observed_native_components: tuple[Mapping[str, Any], ...] | None = None
    observed_native_inventory_complete: bool = False
    observed_game: Mapping[str, Any] | None = None
    changed_xml_tables: tuple[Mapping[str, Any], ...] = ()
    xml_tbl_verdicts: tuple[Mapping[str, Any], ...] = ()


@dataclass(frozen=True, slots=True)
class UnifiedPackageReport:
    """One package verdict produced by the shared profile/topology-aware engine."""

    package_path: str
    required: bool
    package_verdict: dict[str, Any]
    base_report: PackageValidationReport

    @property
    def overall_static_readiness(self) -> bool:
        return bool(self.package_verdict["overall_static_readiness"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_path": self.package_path,
            "required": self.required,
            "package_verdict": self.package_verdict,
        }


@dataclass(frozen=True, slots=True)
class PackageSetValidationReport:
    """Readiness truth-table result for a set of required and optional packages."""

    package_reports: tuple[UnifiedPackageReport, ...]
    required_package_count: int
    invalid_required_package_count: int
    overall_static_readiness: bool
    diagnostics: tuple[NormalizedDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.package-set-validation.v1",
            "package_reports": [item.to_dict() for item in self.package_reports],
            "required_package_count": self.required_package_count,
            "invalid_required_package_count": self.invalid_required_package_count,
            "overall_static_readiness": self.overall_static_readiness,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


class UnifiedPackageValidationService:
    """Single non-live truth source for package, mod, set, and deployment validators."""

    def __init__(
        self,
        *,
        game_build: str,
        whgame_sha256: str | None = None,
        max_manifest_bytes: int = MAX_MANIFEST_BYTES,
    ) -> None:
        if not isinstance(game_build, str) or not game_build:
            raise ValueError("game_build must be a non-empty string")
        _bound("max_manifest_bytes", max_manifest_bytes, MAX_MANIFEST_BYTES)
        self.game_build = game_build
        self.whgame_sha256 = whgame_sha256
        self.max_manifest_bytes = max_manifest_bytes

    def validate(self, requirement: PackageRequirement) -> UnifiedPackageReport:
        if not isinstance(requirement, PackageRequirement):
            raise TypeError("requirement must be a PackageRequirement")
        base = _validate_candidate_dimensions(
            requirement.build_spec,
            requirement.package_path,
            external_component_paths=requirement.external_component_paths,
            native_deployment_descriptor=requirement.native_deployment_descriptor,
            native_descriptor_source=requirement.native_descriptor_source,
            observed_native_components=requirement.observed_native_components,
            observed_native_inventory_complete=(
                requirement.observed_native_inventory_complete
            ),
            observed_game=requirement.observed_game,
            changed_xml_tables=requirement.changed_xml_tables,
            xml_tbl_verdicts=requirement.xml_tbl_verdicts,
            game_build=self.game_build,
            whgame_sha256=self.whgame_sha256,
        )
        profile = select_packaging_profile(
            requested_mode=requirement.requested_profile_mode,
            parent_pak=requirement.parent_package_path,
            candidate_pak=requirement.package_path,
            declared_method_changes=requirement.declared_method_changes,
        )
        topology, topology_diagnostics = _validate_manifest_topology(
            Path(requirement.package_path),
            requirement.manifest_path,
            required=requirement.manifest_required,
            max_bytes=self.max_manifest_bytes,
        )
        diagnostics = _merge_dimension_diagnostics(
            base.diagnostics, profile, topology_diagnostics
        )
        policy_pass = profile.verdict == "PASS"
        topology_pass = topology in {"SIBLING_VALID", "NOT_APPLICABLE"}
        ready = base.overall_static_readiness and policy_pass and topology_pass
        verdict = {
            "schema_version": "kcd2.package-verdict.v2",
            "artifact_sha256": base.artifact_sha256,
            "structural_integrity": base.structural_integrity,
            "runtime_compatibility": "UNKNOWN",
            "packaging_policy": _packaging_policy(profile),
            "lineage_compatibility": _lineage_compatibility(profile),
            "runtime_open_confirmation": "NOT_CONFIRMED",
            "profile": profile.selected_profile or profile.requested_mode,
            "manifest_topology": topology,
            "external_component_expectation": base.external_component_expectation,
            "overall_static_readiness": ready,
            "diagnostics": [item.to_dict() for item in diagnostics],
        }
        return UnifiedPackageReport(
            str(Path(requirement.package_path)), requirement.required, verdict, base
        )


def validate_package_set(
    requirements: Sequence[PackageRequirement],
    *,
    service: UnifiedPackageValidationService,
) -> PackageSetValidationReport:
    """Validate a bounded package set and apply the required-package readiness truth table."""
    if not isinstance(service, UnifiedPackageValidationService):
        raise TypeError("service must be a UnifiedPackageValidationService")
    if not isinstance(requirements, Sequence) or isinstance(requirements, (str, bytes)):
        raise TypeError("requirements must be a sequence")
    if not 1 <= len(requirements) <= 256:
        raise ValueError("requirements must contain between 1 and 256 packages")
    reports = tuple(service.validate(item) for item in requirements)
    required = tuple(item for item in reports if item.required)
    invalid_required = tuple(item for item in required if not item.overall_static_readiness)
    flattened = (
        (diagnostic["code"], example)
        for report in reports
        for diagnostic in report.package_verdict["diagnostics"]
        for example in diagnostic["examples"]
        for _ in range(diagnostic["count"])
    )
    return PackageSetValidationReport(
        reports,
        len(required),
        len(invalid_required),
        required_package_readiness(
            tuple(item.overall_static_readiness for item in required)
        ),
        normalize_diagnostics(flattened),
    )


def required_package_readiness(required_package_states: Sequence[bool]) -> bool:
    """Apply the explicit truth table: every required package must be ready."""
    if not isinstance(required_package_states, Sequence) or isinstance(
        required_package_states, (str, bytes)
    ):
        raise TypeError("required_package_states must be a sequence")
    if not required_package_states or len(required_package_states) > 256:
        return False
    if any(not isinstance(item, bool) for item in required_package_states):
        raise TypeError("required package states must be booleans")
    return all(required_package_states)


# Every public validation context deliberately aliases the same service entry point. Keeping
# these named surfaces makes disagreement detectable without duplicating readiness logic.
validate_mod_folder_packages = validate_package_set
validate_mod_set_packages = validate_package_set
validate_deployment_packages = validate_package_set
validate_build_packages = validate_package_set
validate_install_packages = validate_package_set


def _validate_manifest_topology(
    package_path: Path,
    manifest_path: Path | str | None,
    *,
    required: bool,
    max_bytes: int,
) -> tuple[
    Literal["SIBLING_VALID", "SIBLING_MISSING", "INVALID", "NOT_APPLICABLE"],
    tuple[tuple[str, str], ...],
]:
    if manifest_path is None and not required:
        return "NOT_APPLICABLE", ()
    mod_root = (
        package_path.parent.parent
        if package_path.parent.name.casefold() in {"data", "localization"}
        else package_path.parent
    )
    manifest = Path(manifest_path) if manifest_path is not None else mod_root / "mod.manifest"
    if manifest.parent.resolve() != mod_root.resolve():
        return "INVALID", (("MANIFEST_NOT_SIBLING", str(manifest)),)
    try:
        size = manifest.stat().st_size
        if not manifest.is_file():
            raise FileNotFoundError(str(manifest))
        if size > max_bytes:
            return "INVALID", (("MANIFEST_SIZE_LIMIT", str(manifest)),)
        data = manifest.read_bytes()
        if len(data) != size:
            return "INVALID", (("MANIFEST_CHANGED_DURING_READ", str(manifest)),)
        # ElementTree does not retrieve an external DTD. It accepts a declaration while
        # unresolved entity references fail closed as malformed XML.
        root = ElementTree.fromstring(data)
        if root.tag.rsplit("}", 1)[-1].casefold() not in {"kcd_mod", "mod"}:
            return "INVALID", (("MANIFEST_ROOT_INVALID", root.tag),)
    except FileNotFoundError:
        return "SIBLING_MISSING", (("MANIFEST_SIBLING_MISSING", str(manifest)),)
    except (OSError, ElementTree.ParseError, UnicodeError) as exc:
        return "INVALID", (("MANIFEST_XML_INVALID", f"{manifest}: {exc}"),)
    return "SIBLING_VALID", ()


def _packaging_policy(profile: PackagingProfileSelectionReport) -> str:
    if profile.verdict != "PASS":
        return "POLICY_NONCOMPLIANT"
    if profile.selected_profile == "lineage_inherited":
        return "LEGACY_ACCEPTED"
    return "GENERATED_OUTPUT_VALID"


def _lineage_compatibility(profile: PackagingProfileSelectionReport) -> str:
    if profile.structural_integrity != "VALID":
        return "UNKNOWN"
    if profile.requested_mode == "retail_strict":
        return "NO_PARENT" if profile.verdict == "PASS" else "MISMATCHED"
    return "MATCHED" if profile.verdict == "PASS" else "MISMATCHED"


def _merge_dimension_diagnostics(
    base: tuple[NormalizedDiagnostic, ...],
    profile: PackagingProfileSelectionReport,
    topology: tuple[tuple[str, str], ...],
) -> tuple[NormalizedDiagnostic, ...]:
    expanded: list[tuple[str, str]] = []
    for item in base:
        examples = item.examples or (item.code,)
        for index in range(item.count):
            expanded.append((item.code, examples[min(index, len(examples) - 1)]))
    for item in profile.diagnostics:
        examples = tuple(f"{item.message}: {path}" for path in item.member_paths)
        examples = examples or (item.message,)
        for index in range(item.occurrences):
            expanded.append((item.code, examples[min(index, len(examples) - 1)]))
    expanded.extend(topology)
    return normalize_diagnostics(expanded)


def normalize_diagnostics(
    diagnostics: Iterable[tuple[str, str]],
    *,
    max_diagnostics: int = MAX_DIAGNOSTICS,
    max_examples: int = MAX_EXAMPLES_PER_DIAGNOSTIC,
) -> tuple[NormalizedDiagnostic, ...]:
    """Aggregate mixed validator messages into one bounded deterministic shape."""
    _bound("max_diagnostics", max_diagnostics, MAX_DIAGNOSTICS)
    _bound("max_examples", max_examples, MAX_EXAMPLES_PER_DIAGNOSTIC)
    grouped: dict[str, tuple[int, set[str]]] = {}
    for item in diagnostics:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError("diagnostics must contain (code, example) tuples")
        code, example = item
        if not isinstance(code, str) or not code or len(code) > 128:
            raise ValueError("diagnostic code must be a non-empty string up to 128 chars")
        if not isinstance(example, str) or not example or len(example) > 4096:
            raise ValueError("diagnostic example must be a non-empty string up to 4096 chars")
        count, examples = grouped.setdefault(code, (0, set()))
        examples.add(example)
        grouped[code] = (count + 1, examples)
    ordered = sorted(grouped.items(), key=lambda item: item[0])[:max_diagnostics]
    return tuple(
        NormalizedDiagnostic(code, count, tuple(sorted(examples)[:max_examples]))
        for code, (count, examples) in ordered
    )


def validate_external_component(
    declaration: ExternalComponent,
    supplied_path: Path | str,
) -> ExternalComponentValidation:
    """Validate exactly one declared component path; no parent/root enumeration occurs."""
    if not isinstance(declaration, ExternalComponent):
        raise TypeError("declaration must be an ExternalComponent")
    path = Path(supplied_path)
    diagnostics: list[tuple[str, str]] = []
    try:
        stat = path.stat()
        if not path.is_file():
            diagnostics.append(("EXTERNAL_COMPONENT_NOT_FILE", str(path)))
        else:
            if stat.st_size != declaration.bytes:
                diagnostics.append(
                    (
                        "EXTERNAL_COMPONENT_SIZE_MISMATCH",
                        f"{declaration.logical_path}: expected {declaration.bytes}, "
                        f"got {stat.st_size}",
                    )
                )
            if _hash_file(path) != declaration.sha256.lower():
                diagnostics.append(
                    (
                        "EXTERNAL_COMPONENT_HASH_MISMATCH",
                        f"{declaration.logical_path}: supplied file hash differs",
                    )
                )
            container = classify_container(path)
            if not container.container_valid:
                diagnostics.extend(_container_diagnostics("EXTERNAL_COMPONENT_INVALID", container))
    except OSError as exc:
        diagnostics.append(
            ("EXTERNAL_COMPONENT_UNREADABLE", f"{declaration.logical_path}: {exc}")
        )
    return ExternalComponentValidation(
        declaration.logical_path, str(path), not diagnostics, tuple(diagnostics)
    )


def _validate_candidate_dimensions(
    build_spec: BuildSpec | Mapping[str, Any],
    package_path: Path | str,
    *,
    external_component_paths: Mapping[str, Path | str] | None = None,
    native_deployment_descriptor: Mapping[str, Any] | None = None,
    native_descriptor_source: Literal["committed_descriptor", "ad_hoc_map"] = (
        "committed_descriptor"
    ),
    observed_native_components: Sequence[Mapping[str, Any]] | None = None,
    observed_native_inventory_complete: bool = False,
    observed_game: Mapping[str, Any] | None = None,
    changed_xml_tables: Iterable[Mapping[str, Any]] = (),
    xml_tbl_verdicts: Iterable[Mapping[str, Any]] = (),
    game_build: str,
    whgame_sha256: str | None = None,
) -> PackageValidationReport:
    """Run only the validators applicable to the candidate's declared composition."""
    spec = _coerce_spec(build_spec)
    supplied_components = dict(external_component_paths or {})
    declared_paths = {item.logical_path for item in spec.external_components}
    diagnostics: list[tuple[str, str]] = []

    package = Path(package_path)
    package_validation = classify_container(package)
    package_valid = (
        package_validation.container_type == "zip_pak" and package_validation.container_valid
    )
    if not package_valid:
        diagnostics.extend(_container_diagnostics("PACKAGE_CONTAINER_INVALID", package_validation))
    artifact_sha256 = _hash_or_zero(package)
    structural_integrity: Literal["VALID", "CORRUPT", "UNREADABLE"]
    if package_valid:
        structural_integrity = "VALID"
    elif package.exists() and package.is_file():
        structural_integrity = "CORRUPT"
    else:
        structural_integrity = "UNREADABLE"

    undeclared = sorted(set(supplied_components) - declared_paths)
    diagnostics.extend(
        ("UNDECLARED_EXTERNAL_COMPONENT", logical_path) for logical_path in undeclared
    )
    component_results: list[ExternalComponentValidation] = []
    for declaration in spec.external_components:
        supplied = supplied_components.get(declaration.logical_path)
        if supplied is None:
            diagnostics.append(("EXTERNAL_COMPONENT_MISSING", declaration.logical_path))
            continue
        result = validate_external_component(declaration, supplied)
        component_results.append(result)
        diagnostics.extend(result.diagnostics)

    descriptor_status: Literal["NONE_EXPECTED", "VALID", "INVALID", "MISSING"]
    descriptor_confidence: Literal["NOT_APPLICABLE", "HIGH", "LOW"]
    descriptor_sha256: str | None = None
    descriptor_valid = not spec.external_components
    if native_deployment_descriptor is None:
        if spec.external_components:
            descriptor_status = "MISSING"
            descriptor_confidence = "NOT_APPLICABLE"
            diagnostics.append(
                (
                    "NATIVE_DESCRIPTOR_MISSING",
                    "external components require a committed machine-readable descriptor",
                )
            )
        else:
            descriptor_status = "NONE_EXPECTED"
            descriptor_confidence = "NOT_APPLICABLE"
    else:
        descriptor = validate_native_deployment_descriptor(
            native_deployment_descriptor,
            expected_mod_id=spec.mod_id,
            expected_external_components=tuple(
                {
                    "logical_path": item.logical_path,
                    "sha256": item.sha256,
                    "bytes": item.bytes,
                }
                for item in spec.external_components
            ),
            observed_game=observed_game,
            observed_components=observed_native_components,
            observed_inventory_complete=observed_native_inventory_complete,
            declaration_source=native_descriptor_source,
        )
        descriptor_valid = descriptor.valid
        descriptor_status = (
            "NONE_EXPECTED"
            if descriptor.valid and descriptor.completeness == "NONE_EXPECTED"
            else "VALID" if descriptor.valid else "INVALID"
        )
        descriptor_confidence = descriptor.confidence
        descriptor_sha256 = descriptor.descriptor_sha256
        diagnostics.extend(
            (item.code, f"{item.path}: {item.message}") for item in descriptor.diagnostics
        )

    if not spec.external_components:
        expectation: ExternalExpectation = "NONE_EXPECTED"
        mode: ValidationMode = "package_only"
    else:
        complete = (
            len(component_results) == len(spec.external_components)
            and all(item.valid for item in component_results)
            and not undeclared
            and descriptor_valid
        )
        expectation = "DECLARED_AND_COMPLETE" if complete else "DECLARED_AND_INCOMPLETE"
        mode = (
            "package_with_single_component"
            if len(spec.external_components) == 1
            else "package_with_external_components"
        )

    try:
        xml_report = validate_xml_tbl_contract(
            changed_xml_tables,
            xml_tbl_verdicts,
            game_build=game_build,
            whgame_sha256=whgame_sha256,
        )
        promotion = xml_report.package_promotion
        xml_tbl_gate = xml_report.xml_tbl_gate
        diagnostics.extend((code, code) for code in xml_report.reason_codes)
    except XmlTblContractError as exc:
        promotion = PackagePromotion.BLOCKED
        xml_tbl_gate = "BLOCKED"
        diagnostics.append(("XML_TBL_CONTRACT_INVALID", str(exc)))

    components_ready = (
        expectation in {"NONE_EXPECTED", "DECLARED_AND_COMPLETE"}
        and not undeclared
        and descriptor_valid
    )
    ready = package_valid and components_ready and promotion is not PackagePromotion.BLOCKED
    return PackageValidationReport(
        artifact_sha256=artifact_sha256,
        validation_mode=mode,
        structural_integrity=structural_integrity,
        external_component_expectation=expectation,
        package_promotion=promotion.value,
        xml_tbl_gate=xml_tbl_gate,
        overall_static_readiness=ready,
        validated_component_paths=tuple(item.supplied_path for item in component_results),
        native_descriptor_status=descriptor_status,
        native_descriptor_confidence=descriptor_confidence,
        native_descriptor_sha256=descriptor_sha256,
        diagnostics=normalize_diagnostics(diagnostics),
    )


def validate_candidate_package(
    build_spec: BuildSpec | Mapping[str, Any],
    package_path: Path | str,
    *,
    external_component_paths: Mapping[str, Path | str] | None = None,
    native_deployment_descriptor: Mapping[str, Any] | None = None,
    native_descriptor_source: Literal["committed_descriptor", "ad_hoc_map"] = (
        "committed_descriptor"
    ),
    observed_native_components: Sequence[Mapping[str, Any]] | None = None,
    observed_native_inventory_complete: bool = False,
    observed_game: Mapping[str, Any] | None = None,
    changed_xml_tables: Iterable[Mapping[str, Any]] = (),
    xml_tbl_verdicts: Iterable[Mapping[str, Any]] = (),
    game_build: str,
    whgame_sha256: str | None = None,
) -> PackageValidationReport:
    """Compatibility entry point routed through the unified package service."""
    requirement = PackageRequirement(
        build_spec,
        package_path,
        external_component_paths=external_component_paths,
        native_deployment_descriptor=native_deployment_descriptor,
        native_descriptor_source=native_descriptor_source,
        observed_native_components=(
            tuple(observed_native_components)
            if observed_native_components is not None
            else None
        ),
        observed_native_inventory_complete=observed_native_inventory_complete,
        observed_game=observed_game,
        changed_xml_tables=tuple(changed_xml_tables),
        xml_tbl_verdicts=tuple(xml_tbl_verdicts),
    )
    return UnifiedPackageValidationService(
        game_build=game_build, whgame_sha256=whgame_sha256
    ).validate(requirement).base_report


def _coerce_spec(value: BuildSpec | Mapping[str, Any]) -> BuildSpec:
    if isinstance(value, BuildSpec):
        return value
    if not isinstance(value, Mapping):
        raise TypeError("build_spec must be a parsed BuildSpec or mapping")
    report = parse_build_spec(value)
    if not report.valid or report.spec is None:
        codes = ", ".join(item.code for item in report.diagnostics)
        raise ValueError(f"build_spec is invalid: {codes}")
    return report.spec


def _container_diagnostics(
    code: str, validation: ContainerValidation
) -> list[tuple[str, str]]:
    examples = validation.diagnostics or (
        f"{validation.path}: {validation.container_type} is not valid for this scope",
    )
    return [(code, example) for example in examples]


def _hash_or_zero(path: Path) -> str:
    try:
        return _hash_file(path)
    except OSError:
        return "0" * 64


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bound(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
