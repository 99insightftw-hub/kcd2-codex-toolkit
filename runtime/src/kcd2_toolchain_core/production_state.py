"""Generate production state from backlog, release, and explicit evidence gates."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .atomic import atomic_write_bytes


SCHEMA_ID = "https://schemas.local/kcd2/closure-state-v1.schema.json"
SCHEMA_VERSION = "kcd2.closure-state.v1"
MAPPING_VERSION = "kcd2.closure-state-mapping.v1"
MAPPING_PATH = Path("governance/closure-state-mapping.json")
OUTPUT_PATH = Path("release/critique-closure.json")
CURRENT_STATE_PATH = Path("CURRENT_STATE.md")
MAX_INPUT_BYTES = 1024 * 1024
MAX_ITEMS = 128
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class ProductionStateError(RuntimeError):
    """Raised when production state cannot be generated from trustworthy inputs."""


def _read_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ProductionStateError(f"production-state input exceeds byte bound: {path}")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProductionStateError(f"invalid production-state JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProductionStateError(f"production-state JSON root must be an object: {path}")
    return value


def _relative_file(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ProductionStateError("evidence paths must be non-empty POSIX paths")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ProductionStateError(f"unsafe evidence path: {value!r}")
    candidate = root.joinpath(*relative.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ProductionStateError(f"evidence path escapes repository: {value!r}") from exc
    if not candidate.is_file():
        raise ProductionStateError(f"evidence file is unavailable: {value}")
    return candidate


def _canonical_backlog(root: Path) -> tuple[Path, dict[str, Any]]:
    matches = sorted(root.glob("KCD2_TOOLCHAIN_IMPLEMENTATION_BACKLOG_*.json"))
    if len(matches) != 1:
        raise ProductionStateError(f"expected one canonical backlog; found {len(matches)}")
    return matches[0], _read_object(matches[0])


def _status(task: Mapping[str, Any]) -> str:
    return str(task.get("status") or task.get("initial_status") or "blocked")


def _sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProductionStateError(f"{field} must be a lowercase SHA-256")
    return value


def _validate_gate(value: object, *, field: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("state") not in allowed:
        raise ProductionStateError(f"invalid {field} evidence state")
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence or not all(
        isinstance(item, str) and item for item in evidence
    ):
        raise ProductionStateError(f"{field} requires bounded evidence descriptions")
    return {"state": value["state"], "evidence": list(evidence)}


def _actual_resolution(
    implementation: str,
    non_live_testing: str,
    live_acceptance: str,
    external_risk: str,
) -> tuple[str, str]:
    gates = (
        implementation == "complete"
        and non_live_testing in {"passed", "not_required"}
        and live_acceptance in {"passed", "not_required"}
        and external_risk == "none"
    )
    if gates:
        return "resolved", "all required evidence gates pass and external risk is none"
    if external_risk == "present":
        return "blocked_external", "an explicit external risk prevents actual resolution"
    return "open", "one or more required evidence gates are incomplete"


def _release_state(root: Path, mapping: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    receipt_relative = mapping.get("release_receipt")
    receipt_path = _relative_file(root, receipt_relative)
    receipt = _read_object(receipt_path)
    expected_task = mapping.get("release_task_id")
    if receipt.get("task_id") != expected_task or receipt.get("classification") != "non_live":
        raise ProductionStateError("release receipt task or classification is inconsistent")
    if receipt.get("schema_version") != "kcd2.rel-602-double-build-receipt.v1":
        raise ProductionStateError("release receipt schema identity is invalid")
    builds = receipt.get("builds")
    if not isinstance(builds, list) or not builds or len(builds) > 64:
        raise ProductionStateError("release receipt builds are invalid")

    metadata_path = _relative_file(root, mapping.get("release_metadata"))
    metadata = _read_object(metadata_path)
    metadata_components = metadata.get("components")
    if not isinstance(metadata_components, list) or not metadata_components:
        raise ProductionStateError("release metadata components are invalid")
    versions = {item.get("name"): item.get("version") for item in metadata_components}
    if None in versions or len(versions) != len(metadata_components):
        raise ProductionStateError("release metadata component identities are invalid")

    components: list[dict[str, Any]] = []
    for build in builds:
        if not isinstance(build, dict):
            raise ProductionStateError("release build entry must be an object")
        name = build.get("component")
        hash_a, hash_b = build.get("build_a_package_sha256"), build.get("build_b_package_sha256")
        if name not in versions:
            raise ProductionStateError(f"release receipt component is not canonical: {name}")
        if build.get("byte_identical") is not True or hash_a != hash_b:
            raise ProductionStateError(f"release build is not reproducible: {name}")
        package_hash = _sha256(hash_a, field=f"{name} package hash")
        tree_hash = _sha256(
            build.get("source_tree_sha256"), field=f"{name} source-tree hash"
        )
        components.append(
            {
                "component": name,
                "version": versions[name],
                "package_sha256": package_hash,
                "source_tree_sha256": tree_hash,
                "source_revision_state": build.get("source_revision_state"),
            }
        )
    if set(versions) != {item["component"] for item in components}:
        raise ProductionStateError("release receipt and canonical component sets disagree")
    components.sort(key=lambda item: item["component"])
    receipt_record = {
        "path": str(receipt_relative),
        "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "task_id": receipt["task_id"],
        "classification": receipt["classification"],
        "source_revision": receipt.get("source_revision"),
        "source_auditability": receipt.get("source_auditability"),
    }
    return receipt_record, components


def build_production_state(repository_root: Path | str) -> dict[str, Any]:
    """Build deterministic closure state without translating task counts into resolution."""
    root = Path(repository_root).resolve()
    backlog_path, backlog = _canonical_backlog(root)
    tasks = backlog.get("tasks")
    if not isinstance(tasks, list):
        raise ProductionStateError("canonical backlog tasks are invalid")
    by_id = {str(task.get("id")): task for task in tasks if isinstance(task, dict)}
    if len(by_id) != len(tasks):
        raise ProductionStateError("canonical backlog contains duplicate or invalid task IDs")

    mapping = _read_object(root / MAPPING_PATH)
    if mapping.get("schema_version") != MAPPING_VERSION:
        raise ProductionStateError("closure-state mapping schema identity is invalid")
    if mapping.get("resolution_rule") != (
        "all_required_evidence_gates_pass_and_external_risk_is_none"
    ):
        raise ProductionStateError("closure-state resolution rule is invalid")
    mapped_items = mapping.get("items")
    if not isinstance(mapped_items, list) or not mapped_items or len(mapped_items) > MAX_ITEMS:
        raise ProductionStateError(f"closure-state mapping requires 1..{MAX_ITEMS} items")

    release_receipt, release_components = _release_state(root, mapping)
    closure: list[dict[str, Any]] = []
    seen: set[str] = set()
    for mapped in mapped_items:
        if not isinstance(mapped, dict):
            raise ProductionStateError("closure-state mapping item must be an object")
        item_id = mapped.get("id")
        if not isinstance(item_id, str) or not item_id or item_id in seen:
            raise ProductionStateError("closure-state item ID is missing or duplicated")
        seen.add(item_id)
        if not isinstance(mapped.get("title"), str) or not mapped["title"]:
            raise ProductionStateError(f"closure item title is invalid: {item_id}")
        if not isinstance(mapped.get("source"), str) or not mapped["source"]:
            raise ProductionStateError(f"closure item source is invalid: {item_id}")
        task_ids = mapped.get("backlog_tasks")
        if not isinstance(task_ids, list) or not task_ids or not all(
            isinstance(task_id, str) and task_id in by_id for task_id in task_ids
        ):
            raise ProductionStateError(f"closure item has unknown backlog tasks: {item_id}")
        statuses = {task_id: _status(by_id[task_id]) for task_id in task_ids}
        done_count = sum(value == "done" for value in statuses.values())
        implementation = (
            "complete" if done_count == len(statuses) else "partial" if done_count else "missing"
        )
        non_live = _validate_gate(
            mapped.get("non_live_testing"),
            field="non_live_testing",
            allowed={"passed", "failed", "not_run", "not_required"},
        )
        live = _validate_gate(
            mapped.get("live_acceptance"),
            field="live_acceptance",
            allowed={"passed", "failed", "not_run", "not_required"},
        )
        risk = _validate_gate(
            mapped.get("external_risk"),
            field="external_risk",
            allowed={"none", "present", "unknown"},
        )
        resolution, basis = _actual_resolution(
            implementation, non_live["state"], live["state"], risk["state"]
        )
        closure.append(
            {
                "id": item_id,
                "title": mapped.get("title"),
                "source": mapped.get("source"),
                "backlog": dict(sorted(statuses.items())),
                "implementation": {
                    "state": implementation,
                    "evidence": [
                        f"{task_id} backlog status is {statuses[task_id]}"
                        for task_id in sorted(statuses)
                    ],
                },
                "non_live_testing": non_live,
                "live_acceptance": live,
                "external_risk": risk,
                "actual_resolution": resolution,
                "resolution_basis": basis,
            }
        )
    closure.sort(key=lambda item: item["id"])
    unresolved = [item["id"] for item in closure if item["actual_resolution"] != "resolved"]
    return {
        "$schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "source_backlog": backlog_path.name,
        "release_receipt": release_receipt,
        "release_components": release_components,
        "critique_closure": closure,
        "operationally_unresolved": unresolved,
    }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def render_current_state(state: Mapping[str, Any]) -> bytes:
    """Render the human state document solely from the generated closure record."""
    receipt = state["release_receipt"]
    closure = state["critique_closure"]
    resolved = sum(item["actual_resolution"] == "resolved" for item in closure)
    lines = [
        "# Current state",
        "",
        "> Generated by `scripts/generate_production_state.py`; do not edit directly.",
        "",
        "## Canonical baseline",
        "",
        "- Repository role: source-controlled KCD2 toolchain monorepo.",
        "- Program handoff: R7, dated 2026-08-07.",
        f"- Canonical backlog: `{state['source_backlog']}`.",
        "- Live-effect default: non-live; staged artifacts and dry-run work only.",
        "- Combat Lab: excluded from product scope and startup.",
        "",
        "## Release evidence",
        "",
        f"- Receipt: `{receipt['path']}` (`{receipt['sha256']}`).",
        f"- Receipt classification: `{receipt['classification']}`.",
        f"- Source revision: `{receipt['source_revision']}`.",
        "",
    ]
    for component in state["release_components"]:
        lines.append(
            f"- `{component['component']}` `{component['version']}` package "
            f"`{component['package_sha256']}` (double-build byte-identical)."
        )
    lines.extend(
        [
            "",
            "## Evidence-state closure",
            "",
            f"- Actually resolved: {resolved} of {len(closure)} mapped critique items.",
            f"- Operationally unresolved: {len(state['operationally_unresolved'])}.",
            "- A backlog status of `done` is implementation evidence only; it is not an "
            "actual-resolution state.",
            "",
        ]
    )
    for item in closure:
        lines.extend(
            [
                f"### {item['id']}: {item['title']}",
                "",
                f"- Implementation: `{item['implementation']['state']}`.",
                f"- Non-live testing: `{item['non_live_testing']['state']}`.",
                f"- Live acceptance: `{item['live_acceptance']['state']}`.",
                f"- External risk: `{item['external_risk']['state']}`.",
                f"- Actual resolution: `{item['actual_resolution']}` — "
                f"{item['resolution_basis']}.",
                "",
            ]
        )
    lines.extend(
        [
            "## Evidence boundaries",
            "",
            "`references/` and historical reports remain immutable evidence. Installed game/plugin "
            "locations and production Index databases are external targets, not source trees. "
            "No live state is implied by this generated non-live record.",
            "",
            "## State routing",
            "",
            "The root registry is `state/registry.json`; capsule usage is documented in "
            "`state/INDEX.md`.",
            "",
        ]
    )
    return "\n".join(lines).encode("utf-8")


def generate_repository_production_state(repository_root: Path | str) -> tuple[Path, Path]:
    """Atomically replace generated machine and human production-state surfaces."""
    root = Path(repository_root).resolve()
    state = build_production_state(root)
    output = root / OUTPUT_PATH
    current = root / CURRENT_STATE_PATH
    atomic_write_bytes(output, _json_bytes(state))
    atomic_write_bytes(current, render_current_state(state))
    return output, current


def check_repository_production_state(repository_root: Path | str) -> None:
    """Fail when either generated production-state surface contains stale prose/data."""
    root = Path(repository_root).resolve()
    state = build_production_state(root)
    expected = ((OUTPUT_PATH, _json_bytes(state)), (CURRENT_STATE_PATH, render_current_state(state)))
    for relative, content in expected:
        path = root / relative
        try:
            observed = path.read_bytes()
        except OSError as exc:
            raise ProductionStateError(f"generated production state is missing: {relative}") from exc
        if observed != content:
            raise ProductionStateError(f"{relative.as_posix()} is stale; regenerate production state")
