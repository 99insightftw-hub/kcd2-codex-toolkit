"""Deterministic, synthetic-fixture validation for general KCD2 mod archetypes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


EXPECTED_SCHEMA = "kcd2.mod-archetype-requirements.v1"
REQUIRED_PROFILE_IDS = frozenset(
    {
        "asset",
        "config",
        "cvar",
        "localization",
        "lua",
        "mixed",
        "native",
        "new_table",
        "old_table",
        "quest",
        "storm",
        "workshop",
    }
)
CONTRACT_STAGES = frozenset({"inspect", "build", "deploy", "component", "profile"})


@dataclass(frozen=True)
class ArchetypeRequirementProfile:
    profile_id: str
    archetypes: tuple[str, ...]
    package_required: bool
    native_identity_required: bool
    table_semantics: str
    validators: tuple[str, ...]
    contract_validators: Mapping[str, tuple[str, ...]]
    component_validators: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class ArchetypeValidationResult:
    fixture_id: str
    archetype: str
    profile_id: str | None
    status: str
    declared_components: tuple[str, ...]
    component_attribution: Mapping[str, tuple[str, ...]]
    contract_attribution: Mapping[str, tuple[str, ...]]
    requirements_applied: tuple[str, ...]
    diagnostics: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "archetype": self.archetype,
            "profile_id": self.profile_id,
            "status": self.status,
            "declared_components": list(self.declared_components),
            "component_attribution": {
                component: list(validators)
                for component, validators in sorted(self.component_attribution.items())
            },
            "contract_attribution": {
                stage: list(validators)
                for stage, validators in sorted(self.contract_attribution.items())
            },
            "requirements_applied": list(self.requirements_applied),
            "diagnostics": list(self.diagnostics),
        }


def load_requirement_profiles(path: Path | str) -> tuple[ArchetypeRequirementProfile, ...]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("schema_version") != EXPECTED_SCHEMA:
        raise ValueError(f"requirement profile must use {EXPECTED_SCHEMA}")
    if payload.get("identity_policy") != "synthetic_parameterized_only":
        raise ValueError("identity_policy must be synthetic_parameterized_only")
    raw_profiles = payload.get("profiles")
    if not isinstance(raw_profiles, list):
        raise ValueError("profiles must be a list")

    profiles: list[ArchetypeRequirementProfile] = []
    for raw in raw_profiles:
        if not isinstance(raw, Mapping):
            raise ValueError("each profile must be an object")
        component_validators = raw.get("component_validators")
        if not isinstance(component_validators, Mapping) or not component_validators:
            raise ValueError("component_validators must be a non-empty object")
        contract_validators = raw.get("contract_validators")
        if not isinstance(contract_validators, Mapping):
            raise ValueError("contract_validators must be an object")
        if set(contract_validators) != CONTRACT_STAGES:
            raise ValueError("contract_validators must cover every contract stage")
        profiles.append(
            ArchetypeRequirementProfile(
                profile_id=_required_text(raw, "profile_id"),
                archetypes=_text_tuple(raw, "archetypes"),
                package_required=_required_bool(raw, "package_required"),
                native_identity_required=_required_bool(raw, "native_identity_required"),
                table_semantics=_required_text(raw, "table_semantics"),
                validators=_text_tuple(raw, "validators"),
                contract_validators={
                    _nonempty_text(stage, "contract stage"): _text_sequence(
                        validators, f"contract_validators.{stage}"
                    )
                    for stage, validators in contract_validators.items()
                },
                component_validators={
                    _nonempty_text(component, "component name"): _text_sequence(
                        validators, f"component_validators.{component}"
                    )
                    for component, validators in component_validators.items()
                },
            )
        )
    return tuple(profiles)


class ArchetypeValidatorRegistry:
    """Registry binding fixture archetypes to declarative requirement profiles."""

    def __init__(self, profiles: Sequence[ArchetypeRequirementProfile]) -> None:
        self._profiles = {profile.profile_id: profile for profile in profiles}
        if set(self._profiles) != REQUIRED_PROFILE_IDS:
            missing = sorted(REQUIRED_PROFILE_IDS - set(self._profiles))
            extra = sorted(set(self._profiles) - REQUIRED_PROFILE_IDS)
            raise ValueError(f"profile registry mismatch; missing={missing}, extra={extra}")
        self._archetypes: dict[str, ArchetypeRequirementProfile] = {}
        for profile in profiles:
            if profile.native_identity_required != (profile.profile_id == "native"):
                raise ValueError("native identity may only be required by the native profile")
            for archetype in profile.archetypes:
                if archetype in self._archetypes:
                    raise ValueError(f"archetype registered twice: {archetype}")
                self._archetypes[archetype] = profile

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._profiles))

    @property
    def registered_archetypes(self) -> tuple[str, ...]:
        return tuple(sorted(self._archetypes))

    def profile_for(self, archetype: str) -> ArchetypeRequirementProfile:
        try:
            return self._archetypes[archetype]
        except KeyError as exc:
            raise KeyError(f"unregistered archetype: {archetype}") from exc

    def validate(self, fixture: Mapping[str, Any]) -> ArchetypeValidationResult:
        fixture_id = str(fixture.get("fixture_id", "<missing>"))
        archetype = str(fixture.get("archetype", "<missing>"))
        profile = self._archetypes.get(archetype)
        manifest = fixture.get("synthetic_manifest")
        components = (
            tuple(str(item) for item in manifest.get("components", ()))
            if isinstance(manifest, Mapping)
            else ()
        )
        if profile is None:
            return ArchetypeValidationResult(
                fixture_id=fixture_id,
                archetype=archetype,
                profile_id=None,
                status="capture_inconclusive",
                declared_components=components,
                component_attribution={},
                contract_attribution={},
                requirements_applied=(),
                diagnostics=("UNREGISTERED_ARCHETYPE",),
            )

        diagnostics: list[str] = []
        scan = fixture.get("expected_scan_receipt")
        members = tuple(scan.get("members", ())) if isinstance(scan, Mapping) else ()
        if not isinstance(scan, Mapping) or scan.get("status") != "complete":
            diagnostics.append("SCAN_INCOMPLETE")
        if fixture.get("synthetic_only") is not True:
            diagnostics.append("NON_SYNTHETIC_IDENTITY")
        if not isinstance(manifest, Mapping) or not components:
            diagnostics.append("COMPONENT_DECLARATION_MISSING")
        package_present = any(str(item).lower().endswith(".pak") for item in members)
        if profile.package_required and not package_present:
            diagnostics.append("PACKAGE_MEMBER_MISSING")
        if profile.native_identity_required:
            if "native" not in components:
                diagnostics.append("NATIVE_COMPONENT_UNDECLARED")
            if not any(str(item).lower().endswith(".dll") for item in members):
                diagnostics.append("NATIVE_MODULE_MISSING")

        attribution: dict[str, tuple[str, ...]] = {}
        for component in components:
            validators = profile.component_validators.get(component)
            if not validators:
                diagnostics.append(f"COMPONENT_UNATTRIBUTED:{component}")
            else:
                attribution[component] = validators

        requirements = list(profile.validators)
        if profile.package_required:
            requirements.append("package_identity")
        if profile.native_identity_required:
            requirements.append("native_identity")
        if profile.table_semantics != "not_applicable":
            requirements.append(f"table_semantics:{profile.table_semantics}")
        return ArchetypeValidationResult(
            fixture_id=fixture_id,
            archetype=archetype,
            profile_id=profile.profile_id,
            status="pass" if not diagnostics else "capture_inconclusive",
            declared_components=components,
            component_attribution=attribution,
            contract_attribution=profile.contract_validators,
            requirements_applied=tuple(sorted(set(requirements))),
            diagnostics=tuple(sorted(diagnostics)),
        )

    def validate_all(self, fixtures: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        results = sorted(
            (self.validate(item) for item in fixtures), key=lambda item: item.fixture_id
        )
        all_pass = bool(results) and all(item.status == "pass" for item in results)
        old_semantics = self.profile_for("old_table_patch").table_semantics
        new_semantics = self.profile_for("new_table_patch").table_semantics
        package_results = [item for item in results if item.profile_id == "mixed"]
        native_results = [item for item in results if item.profile_id == "native"]
        return {
            "schema_version": "kcd2.mod-archetype-acceptance-report.v1",
            "task_id": "DEP-216",
            "status": "pass" if all_pass else "capture_inconclusive",
            "identity_source": "synthetic_fixtures",
            "fixture_count": len(results),
            "registered_archetype_count": len(self._archetypes),
            "profile_ids": list(self.profile_ids),
            "acceptance": {
                "package_only_native_maps_not_required": bool(package_results)
                and all(
                    "native_identity" not in item.requirements_applied
                    for item in package_results
                ),
                "native_components_require_native_identity": bool(native_results)
                and all("native_identity" in item.requirements_applied for item in native_results),
                "table_semantics_distinct": old_semantics != new_semantics,
                "components_separately_attributable": all(
                    set(item.component_attribution) == set(item.declared_components)
                    for item in results
                ),
                "contract_stages_separately_attributable": all(
                    set(item.contract_attribution) == CONTRACT_STAGES for item in results
                ),
            },
            "no_current_mod_id_required": all(
                bool(item.get("synthetic_only"))
                and isinstance(item.get("synthetic_manifest"), Mapping)
                and str(item["synthetic_manifest"].get("mod_id", "")).startswith("synthetic_")
                for item in fixtures
            ),
            "fixtures": [item.to_dict() for item in results],
        }


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    return _nonempty_text(payload.get(key), key)


def _nonempty_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value


def _required_bool(payload: Mapping[str, Any], key: str) -> bool:
    value = payload.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be boolean")
    return value


def _text_tuple(payload: Mapping[str, Any], key: str) -> tuple[str, ...]:
    return _text_sequence(payload.get(key), key)


def _text_sequence(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    result = tuple(_nonempty_text(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result
