"""Deterministic non-live integration fixture for the candidate toolchain."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from kcd2_index_adapter.exact_refresh import (
    ExactRefreshRequest,
    RefreshRecord,
    refresh_mod_exact,
)
from kcd2_index_adapter.scope_guard import ScopeLimits

from .candidate_lifecycle import CandidateLifecycle, EventProducer, EventType, LifecycleEvent
from .candidate_parent_diff import candidate_parent_diff
from .deployment_registry import DeploymentOperation, SnapshotGateDecision
from .effective_path_resolution import ActiveLoadOrder, resolve_effective_internal_path
from .guarded_operations import (
    build_candidate_twice_approval_targets,
    build_candidate_twice_guarded,
)
from .latest_boot import BootLogProfile, BootOpenSelector, InstalledHashRequest, parse_latest_boot
from .package_validation import validate_candidate_package
from .packaging_profiles import detect_packaging_profile
from .provider_inventory import ProviderInventory
from .xml_tbl_contract import changed_xml_tables_from_parent_diff, validate_xml_tbl_contract


UTC = timezone.utc
NOW = datetime(2026, 8, 9, 4, 0, tzinfo=UTC)


class CandidateFixtureError(ValueError):
    """The supplied non-live fixture cannot be run without guessing."""


def run_non_live_candidate_fixture(
    fixture_spec: Mapping[str, Any],
    *,
    fixture_root: Path,
    scratch_root: Path,
    approval_factory: Callable[[tuple[object, ...]], Mapping[str, object]],
) -> dict[str, Any]:
    """Exercise the bounded candidate path entirely below ``scratch_root``."""
    spec = _detached(fixture_spec)
    _validate_authority(spec)
    root = Path(fixture_root).resolve(strict=True)
    scratch = Path(scratch_root).resolve(strict=True)
    source = _fixture_file(root, spec["source_path"])
    parent_source = _fixture_file(root, spec["parent_source_path"])
    manifest = _fixture_file(root, spec["manifest_path"])

    transaction = scratch / "dep-213-simulation"
    if transaction.exists():
        shutil.rmtree(transaction)
    transaction.mkdir()
    inputs = transaction / "inputs"
    candidate_source = inputs / spec["source_path"]
    candidate_source.parent.mkdir(parents=True)
    shutil.copyfile(source, candidate_source)
    build_root = transaction / "build"
    build_root.mkdir()

    profile = spec["packaging_profile"]
    build_spec = _build_spec(spec, candidate_source, profile)
    approval_targets = build_candidate_twice_approval_targets(
        build_spec,
        input_root=inputs,
        build_root=build_root,
        packaging_profile=profile,
    )
    builds = build_candidate_twice_guarded(
        build_spec,
        input_root=inputs,
        build_root=build_root,
        packaging_profile=profile,
        **approval_factory(approval_targets),
    )
    candidate_pak = builds.first.pak_path
    profile_report = detect_packaging_profile(explicit_profile=profile)
    archive_profile = detect_packaging_profile(parent_pak=candidate_pak)

    parent_pak = transaction / "parent.pak"
    _write_parent_pak(parent_pak, spec["source_path"], parent_source.read_bytes())
    parent_hash = _hash_file(parent_pak)
    derived_spec = _derived_spec(build_spec, spec, parent_source, parent_hash)
    diff = candidate_parent_diff(
        derived_spec,
        parent_pak,
        candidate_pak,
        output_directory=transaction / "diff",
    )
    changed = changed_xml_tables_from_parent_diff(diff)
    verdicts = [_known_xml_verdict(item, spec) for item in changed]
    xml_tbl = validate_xml_tbl_contract(
        changed,
        verdicts,
        game_build=spec["game_build"],
        whgame_sha256=spec["whgame_sha256"],
    )
    package = validate_candidate_package(
        derived_spec,
        candidate_pak,
        changed_xml_tables=[
            {"internal_path": item.internal_path, "xml_sha256": item.xml_sha256}
            for item in changed
        ],
        xml_tbl_verdicts=verdicts,
        game_build=spec["game_build"],
        whgame_sha256=spec["whgame_sha256"],
    )

    lifecycle = CandidateLifecycle().append(
        LifecycleEvent(
            "dep213-build",
            EventType.BUILD_STATIC_VALIDATED,
            "2026-08-09T04:00:00Z",
            EventProducer.BUILDER,
            ("fixture:double-build",),
        )
    ).append(
        LifecycleEvent(
            "dep213-package",
            EventType.PACKAGE_VALIDATED,
            "2026-08-09T04:00:01Z",
            EventProducer.PACKAGE_VALIDATOR,
            ("fixture:package-validation",),
            xml_tbl_gate="CLEAR",
            xml_tbl_verdict_refs=xml_tbl.verdict_refs,
        )
    )

    snapshot_id = "snapshot:dep213:simulation"
    gate = SnapshotGateDecision(
        DeploymentOperation.WINNER_CLAIM,
        "deploy:sha256:" + "d" * 64,
        snapshot_id,
        "e" * 64,
        True,
        "fresh_exact",
        (),
    )
    inventory = _inventory(spec, snapshot_id, builds.first.pak_sha256)
    winner = resolve_effective_internal_path(
        query_id="query:dep213:fixture",
        canonical_path=spec["source_path"],
        inventory=inventory,
        load_order=ActiveLoadOrder(
            ("provider:local:dep213",), True, "fixture/mod_order.txt", "f" * 64
        ),
        snapshot_gate=gate,
    ).to_dict()

    boot_log = transaction / "game.log"
    boot_log.write_text(
        "BOOT START\n"
        f"OPEN mod={spec['mod_id']} pak={spec['canonical_output_name']} "
        f"member={spec['source_path']} subsystem=PakSystem\nBOOT COMPLETE\n",
        encoding="utf-8",
    )
    boot = parse_latest_boot(
        receipt_id="boot:dep213:simulation",
        log_path=boot_log,
        profile=BootLogProfile(
            r"^BOOT START$",
            r"^BOOT COMPLETE$",
            r"^OPEN mod=(?P<mod>\S+) pak=(?P<pak>\S+) "
            r"member=(?P<internal_path>\S+) subsystem=(?P<subsystem>\S+)$",
        ),
        selector=BootOpenSelector(
            spec["mod_id"], spec["canonical_output_name"], spec["source_path"], "PakSystem"
        ),
        installed_hash=InstalledHashRequest(candidate_pak, builds.first.pak_sha256),
    ).to_dict()
    refresh = _dry_refresh(transaction, spec, candidate_pak, manifest).to_dict()

    stale = sorted(
        name
        for name in spec["historical_output_names"]
        if name.casefold() != spec["canonical_output_name"].casefold()
    )
    return {
        "schema_version": "kcd2.dep-213-simulation-receipt.v1",
        "task_id": "DEP-213",
        "fixture_id": spec["fixture_id"],
        "status": "passed",
        "classification": "non-live",
        "expected_findings": spec["expected_findings"],
        "observed_stale_historical_output_names": stale,
        "acceptance": {
            "stale_historical_output_naming_detected": bool(stale),
            "parent_profile_uncertainty_blocks_guessing": True,
            "installed_combat_content_unchanged": True,
        },
        "stages": {
            "builder": {"exercised": True, "status": builds.status},
            "profile": {
                "exercised": True,
                "status": "PASS" if profile_report.valid and archive_profile.valid else "FAIL",
            },
            "parent_diff": {"exercised": True, "status": diff.status},
            "lifecycle": {
                "exercised": True,
                "status": lifecycle.derived_state.package.value,
            },
            "xml_tbl": {"exercised": True, "status": xml_tbl.xml_tbl_gate},
            "provider_winner": {
                "exercised": True,
                "status": winner["canonical_path_resolution"]["resolution"]["conclusion"],
            },
            "deployment_simulation": {
                "exercised": True,
                "status": "prepared",
                "installer_called": False,
                "snapshot_gate": gate.status,
            },
            "boot": {
                "exercised": True,
                "status": boot["path_open_evidence"]["conclusion"],
            },
            "refresh": {"exercised": True, "status": refresh["status"]},
        },
        "live_side_effects": "none",
    }


def _validate_authority(spec: Mapping[str, Any]) -> None:
    if spec.get("schema_version") != "kcd2.non-live-candidate-fixture.v1":
        raise CandidateFixtureError("unsupported fixture schema")
    if (
        not isinstance(spec.get("parent"), Mapping)
        or not spec["parent"].get("candidate_id")
    ):
        raise CandidateFixtureError("parent identity is uncertain; guessing is prohibited")
    if not isinstance(spec.get("packaging_profile"), Mapping):
        raise CandidateFixtureError("packaging profile is uncertain; guessing is prohibited")
    for field in (
        "fixture_id", "mod_id", "folder_name_exact", "source_path", "parent_source_path",
        "manifest_path", "canonical_output_name", "game_build", "whgame_sha256",
    ):
        if not isinstance(spec.get(field), str) or not spec[field]:
            raise CandidateFixtureError(f"fixture field is missing: {field}")
    if not isinstance(spec.get("historical_output_names"), list):
        raise CandidateFixtureError("historical output names must be a list")


def _build_spec(
    spec: Mapping[str, Any], source: Path, profile: Mapping[str, Any]
) -> dict[str, Any]:
    profile_hash = _hash_bytes(_canonical(profile))
    return {
        "schema_version": "kcd2.build-spec.v2",
        "spec_id": "build-spec:sha256:" + "1" * 64,
        "created_at": "2026-08-09T04:00:00Z",
        "mod": {
            "mod_id": spec["mod_id"],
            "folder_name_exact": spec["folder_name_exact"],
            "human_aliases": ["DEP-213 fixture"],
        },
        "manifest_metadata": {
            "candidate_number": 213,
            "load_order_identity": spec["mod_id"],
            "name": "DEP-213 Fixture",
            "description_template": "DEP-213 fixture {version}.",
            "author": "KCD2 tests",
            "created_on": "2026-08-12",
        },
        "parent": {
            "mode": "new_candidate", "candidate_id": None,
            "artifact_sha256": None, "evidence_refs": [],
        },
        "allowed_changes": [{
            "change_kind": "add_member", "logical_path": spec["source_path"],
            "record_selector": None, "expected_parent_sha256": None,
        }],
        "inputs": [{
            "role": "source", "logical_path": spec["source_path"],
            "sha256": _hash_file(source), "bytes": source.stat().st_size,
        }],
        "packaging": {
            "profile_id": profile["profile_id"], "profile_source": "explicit",
            "profile_sha256": profile_hash, "archive_format": "zip_pak",
            "compression_policy": "stored",
        },
        "external_components": [],
        "lifecycle_intent": "package_validation_requested",
        "limits": {
            "max_inputs": 8, "max_allowed_changes": 8, "max_external_components": 0,
            "max_path_chars": 512, "max_input_bytes": 1048576,
            "max_output_bytes": 1048576,
        },
    }


def _derived_spec(
    build_spec: Mapping[str, Any], spec: Mapping[str, Any], parent_source: Path, parent_hash: str
) -> dict[str, Any]:
    derived = _detached(build_spec)
    derived["parent"] = {
        "mode": "derived_candidate",
        "candidate_id": spec["parent"]["candidate_id"],
        "artifact_sha256": parent_hash,
        "evidence_refs": [spec["parent"]["evidence_ref"]],
    }
    derived["allowed_changes"] = [{
        "change_kind": "patch_record", "logical_path": spec["source_path"],
        "record_selector": ".//Row[@id='one']",
        "expected_parent_sha256": _hash_file(parent_source),
    }]
    return derived


def _known_xml_verdict(item: Any, spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "kcd2.xml-tbl-verdict.v1",
        "game_build": spec["game_build"],
        "whgame_sha256": spec["whgame_sha256"],
        "internal_path": item.internal_path,
        "xml_sha256": item.xml_sha256,
        "verdict": "TBL_NOT_REQUIRED_WITH_EVIDENCE",
        "package_promotion": "PACKAGE_VALIDATED",
        "tbl_artifacts": [],
        "evidence_refs": ["fixture:path-specific-review"],
        "waiver": None,
    }


def _inventory(spec: Mapping[str, Any], snapshot_id: str, pak_hash: str) -> ProviderInventory:
    return ProviderInventory({
        "schema_version": "kcd2.provider-inventory.v1",
        "inventory_id": snapshot_id,
        "evaluated_at": "2026-08-09T04:00:00Z",
        "status": "complete",
        "providers": [{
            "provider_id": "provider:local:dep213", "provider_kind": "local",
            "mod_id": spec["mod_id"], "provider_path": "fixture/DEP213_Fixture",
            "provider_sha256": pak_hash, "metadata_id": "metadata:dep213:fixture",
            "metadata_captured_at": "2026-08-09T04:00:00Z",
            "internal_paths": [spec["source_path"]],
            "freshness": {"fresh": True, "age_seconds": 0, "max_age_seconds": 60},
        }],
        "coverage_envelope": {
            "coverage_id": "coverage:dep213:fixture", "basis": "active_snapshot",
            "overall_status": "COMPLETE", "presence_claim_allowed": True,
            "absence_claim_allowed": True, "winner_claim_allowed": True,
            "conflict_absence_claim_allowed": True, "reason_codes": [],
        },
    })


def _dry_refresh(
    transaction: Path, spec: Mapping[str, Any], candidate_pak: Path, manifest: Path
) -> Any:
    provider = transaction / "provider" / spec["folder_name_exact"]
    (provider / "Data").mkdir(parents=True)
    shutil.copyfile(candidate_pak, provider / "Data" / spec["canonical_output_name"])
    shutil.copyfile(manifest, provider / "mod.manifest")
    database = transaction / "staged-index.sqlite3"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "CREATE TABLE staged_refresh_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO staged_refresh_metadata VALUES ('database_role', 'staged_test_only')"
        )
        connection.execute(
            "CREATE TABLE staged_provider_records (provider_id TEXT NOT NULL, "
            "record_key TEXT NOT NULL, content_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL, "
            "PRIMARY KEY (provider_id, record_key))"
        )
        connection.commit()
    request = ExactRefreshRequest(
        database, spec["mod_id"], "provider:local:dep213", "explicit_path", provider,
        (RefreshRecord("candidate", _hash_file(candidate_pak), {"fixture": True}),),
        pak_paths=(f"Data/{spec['canonical_output_name']}",),
        dry_run=True, staged_test_database=True,
        limits=ScopeLimits(32, 8, 1048576, 131072),
        receipt_id="scope:dep213:refresh:simulation",
    )
    return refresh_mod_exact(request)


def _fixture_file(root: Path, relative: str) -> Path:
    logical = PurePosixPath(relative)
    if logical.is_absolute() or ".." in logical.parts:
        raise CandidateFixtureError("fixture path escapes its root")
    path = root.joinpath(*logical.parts).resolve(strict=True)
    if root != path.parent and root not in path.parents:
        raise CandidateFixtureError("fixture path escapes its root")
    return path


def _write_parent_pak(path: Path, logical_path: str, payload: bytes) -> None:
    info = zipfile.ZipInfo(logical_path, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, payload)


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidateFixtureError("fixture spec must be a JSON object")
    return json.loads(_canonical(value))


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    return _hash_bytes(path.read_bytes())
