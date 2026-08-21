"""Cross-record invariants for reviewed, hash-bound Ghidra exports."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .environment_profiles import EnvironmentProfile
from .hashing import sha256_bytes, sha256_file


class GhidraExportContractError(ValueError):
    """Raised when a schema-valid export violates a semantic invariant."""


class GhidraHeadlessExportError(RuntimeError):
    """Fail-closed wrapper error with a stable operational classification."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        receipt: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.receipt = dict(receipt) if receipt is not None else None


@dataclass(frozen=True, slots=True)
class GhidraHeadlessExportRequest:
    """Exact inputs and write boundaries for one persistent-project export."""

    environment_profile: EnvironmentProfile
    workflow_id: str
    source_head: str
    task_id: str
    run_id: str
    expected_ghidra_version: str
    analyze_headless_path: Path
    expected_analyze_headless_sha256: str
    project_root: Path
    project_name: str
    expected_project_sha256: str
    module_path: Path
    program_name: str
    expected_module_sha256: str
    analyzer_options_id: str
    analyzer_options_path: Path
    expected_analyzer_options_sha256: str
    script_path: Path
    expected_script_sha256: str
    output_path: Path
    approved_output_root: Path
    approved_scratch_root: Path
    export_schema_path: Path
    expected_export_schema_version: str
    max_export_bytes: int = 16 * 1024 * 1024
    timeout_seconds: int = 900
    operation_id: str = "ghidra-headless-export"


@dataclass(frozen=True, slots=True)
class GhidraHeadlessExportResult:
    export_path: Path
    export_sha256: str
    receipt: Mapping[str, Any]


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_OPERATION = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SOURCE_HEAD = re.compile(r"^[0-9a-f]{40}$")
_MAX_EXPORT_BYTES = 64 * 1024 * 1024


def _headless_error(code: str, message: str) -> GhidraHeadlessExportError:
    return GhidraHeadlessExportError(code, message)


def _blocked_lock_receipt(
    request: GhidraHeadlessExportRequest,
    profile: EnvironmentProfile,
    schema_sha256: str,
) -> dict[str, Any]:
    return _receipt(
        request,
        profile,
        schema_sha256,
        attempted=False,
        exit_code=None,
        raw_export=None,
        cleanup_errors=[],
        work_exists=False,
        lock_exists=False,
        temporary_output_exists=False,
    )


def _receipt(
    request: GhidraHeadlessExportRequest,
    profile: EnvironmentProfile,
    schema_sha256: str,
    *,
    attempted: bool,
    exit_code: int | None,
    raw_export: bytes | None,
    cleanup_errors: Sequence[str],
    work_exists: bool,
    lock_exists: bool,
    temporary_output_exists: bool,
) -> dict[str, Any]:
    export_sha256 = sha256_bytes(raw_export) if raw_export is not None else None
    export_bytes = len(raw_export) if raw_export is not None else None
    return {
        "schema_version": "kcd2.ghidra-headless-receipt.v1",
        "operation_id": request.operation_id,
        "environment_profile_id": profile.profile_id,
        "workflow_id": request.workflow_id,
        "source_identity": {
            "source_head": request.source_head,
            "task_id": request.task_id,
            "run_id": request.run_id,
        },
        "ghidra_identity": {
            "version": request.expected_ghidra_version,
            "launcher_sha256": profile.components["ghidra"].expected_sha256,
            "analyze_headless_sha256": request.expected_analyze_headless_sha256,
            "java_sha256": profile.components["java"].expected_sha256,
        },
        "project_identity": {
            "project_name": request.project_name,
            "project_sha256": request.expected_project_sha256,
        },
        "program_identity": {
            "program_name": request.program_name,
            "module_sha256": request.expected_module_sha256,
        },
        "analysis_identity": {
            "analyzer_options_id": request.analyzer_options_id,
            "analyzer_options_sha256": request.expected_analyzer_options_sha256,
        },
        "export_schema": {
            "version": request.expected_export_schema_version,
            "sha256": schema_sha256,
        },
        "invocation_attempted": attempted,
        "exit_code": exit_code,
        "read_only": True,
        "ghidra_sha256": profile.components["ghidra"].expected_sha256,
        "java_sha256": profile.components["java"].expected_sha256,
        "analyze_headless_sha256": request.expected_analyze_headless_sha256,
        "project_sha256": request.expected_project_sha256,
        "module_sha256": request.expected_module_sha256,
        "script_sha256": request.expected_script_sha256,
        "schema_sha256": schema_sha256,
        "max_export_bytes": request.max_export_bytes,
        "analyzer_options_sha256": request.expected_analyzer_options_sha256,
        "export_schema_version": request.expected_export_schema_version,
        "export_sha256": export_sha256,
        "export_bytes": export_bytes,
        "outputs": [],
        "cleanup_state": "CLEANED" if not cleanup_errors else "CLEANUP_FAILED",
        "cleanup_errors": list(cleanup_errors),
        "scratch_exists_after_cleanup": work_exists,
        "lock_exists_after_cleanup": lock_exists,
        "temporary_output_exists_after_cleanup": temporary_output_exists,
    }


def _exact_file(path: Path, expected_sha256: str, label: str) -> Path:
    if _SHA256.fullmatch(expected_sha256) is None:
        raise _headless_error("INVALID_REQUEST", f"{label} expected SHA-256 is invalid")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise _headless_error("PATH_INVALID", f"{label} path is unavailable: {error}") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise _headless_error("PATH_INVALID", f"{label} must be a non-symlink regular file")
    if sha256_file(resolved) != expected_sha256:
        raise _headless_error("HASH_MISMATCH", f"{label} SHA-256 does not match")
    return resolved


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _validate_component(
    profile: EnvironmentProfile,
    component_id: str,
    *,
    require_launch: bool,
) -> Path:
    component = profile.components[component_id]
    if not component.workflow_eligible:
        raise _headless_error(
            "CAPABILITY_UNAVAILABLE", f"{component_id} is not workflow eligible"
        )
    if require_launch and component.checks["launch"].status != "passed":
        raise _headless_error(
            "LAUNCH_NOT_VERIFIED", f"{component_id} executable launch is not verified"
        )
    return _exact_file(Path(component.path), component.expected_sha256, component_id)


def _load_bounded_export(path: Path, maximum: int) -> tuple[dict[str, Any], bytes]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise _headless_error("EXPORT_MISSING", f"headless export was not produced: {error}") from error
    if size > maximum:
        raise _headless_error("EXPORT_LIMIT_EXCEEDED", "export byte limit exceeded")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _headless_error("EXPORT_INVALID", f"export is not bounded UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise _headless_error("EXPORT_INVALID", "export root must be an object")
    return value, raw


def _schema_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise GhidraExportContractError("export schema contains a non-local reference")
    value: Any = root
    for token in reference[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    if not isinstance(value, Mapping):
        raise GhidraExportContractError("export schema reference is not an object")
    return value


def _schema_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _validate_export_schema(
    value: Any,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str = "$",
) -> None:
    """Validate the closed v1 export schema without an optional runtime package."""

    if "$ref" in schema:
        _validate_export_schema(value, _schema_ref(root, schema["$ref"]), root, path)
        return
    if "anyOf" in schema:
        for branch in schema["anyOf"]:
            try:
                _validate_export_schema(value, branch, root, path)
                return
            except GhidraExportContractError:
                pass
        raise GhidraExportContractError(f"{path} does not match any allowed schema")
    for branch in schema.get("allOf", ()):
        _validate_export_schema(value, branch, root, path)
    if "if" in schema:
        try:
            _validate_export_schema(value, schema["if"], root, path)
            selected = schema.get("then")
        except GhidraExportContractError:
            selected = schema.get("else")
        if selected is not None:
            _validate_export_schema(value, selected, root, path)
    if "const" in schema and value != schema["const"]:
        raise GhidraExportContractError(f"{path} does not match its constant")
    if "enum" in schema and value not in schema["enum"]:
        raise GhidraExportContractError(f"{path} is not an allowed value")
    expected = schema.get("type")
    if expected is not None:
        types = (expected,) if isinstance(expected, str) else tuple(expected)
        if not any(_schema_type(value, item) for item in types):
            raise GhidraExportContractError(f"{path} has an invalid type")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get(
            "maxLength", len(value)
        ):
            raise GhidraExportContractError(f"{path} exceeds its string bounds")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise GhidraExportContractError(f"{path} does not match its pattern")
        if schema.get("format") == "date-time" and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            value,
        ) is None:
            raise GhidraExportContractError(f"{path} is not an ISO date-time")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise GhidraExportContractError(f"{path} exceeds its numeric bounds")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get(
            "maxItems", len(value)
        ):
            raise GhidraExportContractError(f"{path} exceeds its collection bounds")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                raise GhidraExportContractError(f"{path} contains duplicate items")
        for index, item in enumerate(value):
            _validate_export_schema(item, schema.get("items", {}), root, f"{path}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = set(schema.get("required", ())) - set(value)
        if missing:
            raise GhidraExportContractError(f"{path} is missing {sorted(missing)[0]}")
        for name, item in value.items():
            if name in properties:
                child = properties[name]
            else:
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    raise GhidraExportContractError(f"{path} has unknown field {name}")
                child = additional if isinstance(additional, Mapping) else {}
            _validate_export_schema(item, child, root, f"{path}.{name}")


def run_ghidra_headless_export(
    request: GhidraHeadlessExportRequest,
    *,
    launcher: Any = subprocess.run,
) -> GhidraHeadlessExportResult:
    """Validate, run, validate the export, clean up, and atomically promote it.

    The child receives only a read-only persistent-project route plus an exact
    script, module hash, bounded temporary output, and export byte ceiling.
    """

    if not isinstance(request.environment_profile, EnvironmentProfile):
        raise _headless_error("INVALID_REQUEST", "environment_profile must be validated v2")
    if _SAFE_NAME.fullmatch(request.project_name) is None:
        raise _headless_error("INVALID_REQUEST", "project_name contains unsafe characters")
    if _SAFE_NAME.fullmatch(request.program_name) is None:
        raise _headless_error("INVALID_REQUEST", "program_name contains unsafe characters")
    if _SAFE_OPERATION.fullmatch(request.task_id) is None:
        raise _headless_error("INVALID_REQUEST", "task_id contains unsafe characters")
    if _SAFE_OPERATION.fullmatch(request.run_id) is None:
        raise _headless_error("INVALID_REQUEST", "run_id contains unsafe characters")
    if _SAFE_OPERATION.fullmatch(request.analyzer_options_id) is None:
        raise _headless_error("INVALID_REQUEST", "analyzer_options_id contains unsafe characters")
    if _SOURCE_HEAD.fullmatch(request.source_head) is None:
        raise _headless_error("INVALID_REQUEST", "source_head must be an exact lowercase Git commit")
    if _SAFE_OPERATION.fullmatch(request.operation_id) is None:
        raise _headless_error("INVALID_REQUEST", "operation_id contains unsafe characters")
    if not 1 <= request.max_export_bytes <= _MAX_EXPORT_BYTES:
        raise _headless_error("INVALID_REQUEST", "max_export_bytes is outside its hard bound")
    if not 1 <= request.timeout_seconds <= 3600:
        raise _headless_error("INVALID_REQUEST", "timeout_seconds is outside its hard bound")

    profile = request.environment_profile
    if request.expected_ghidra_version != profile.components["ghidra"].expected_version:
        raise _headless_error("IDENTITY_MISMATCH", "Ghidra version is not the profiled version")
    workflow = profile.workflows.get(request.workflow_id)
    if workflow is None:
        raise _headless_error("CAPABILITY_UNAVAILABLE", "environment workflow is not declared")
    mandatory = {"ghidra", "java", "whgame"}
    if not mandatory.issubset(workflow.required_components):
        raise _headless_error(
            "CAPABILITY_UNAVAILABLE",
            "environment workflow does not require ghidra, java, and whgame",
        )

    ghidra = _validate_component(profile, "ghidra", require_launch=True)
    java = _validate_component(profile, "java", require_launch=True)
    whgame = _validate_component(profile, "whgame", require_launch=False)
    analyze_headless = _exact_file(
        request.analyze_headless_path,
        request.expected_analyze_headless_sha256,
        "analyzeHeadless",
    )
    if not analyze_headless.is_relative_to(ghidra.parent):
        raise _headless_error(
            "IDENTITY_MISMATCH", "analyzeHeadless is outside the profiled Ghidra installation"
        )
    module = _exact_file(request.module_path, request.expected_module_sha256, "module")
    if request.program_name.casefold() != module.name.casefold():
        raise _headless_error("IDENTITY_MISMATCH", "program name is not the requested module")
    analyzer_options = _exact_file(
        request.analyzer_options_path,
        request.expected_analyzer_options_sha256,
        "analyzer options",
    )
    script = _exact_file(request.script_path, request.expected_script_sha256, "script")
    if not _same_path(module, whgame):
        raise _headless_error("IDENTITY_MISMATCH", "module path is not profile WHGame")
    if request.expected_module_sha256 != profile.components["whgame"].expected_sha256:
        raise _headless_error("IDENTITY_MISMATCH", "module SHA-256 is not profile WHGame")

    try:
        project_root = request.project_root.resolve(strict=True)
    except OSError as error:
        raise _headless_error("PATH_INVALID", f"project root is unavailable: {error}") from error
    if not project_root.is_dir() or project_root.is_symlink():
        raise _headless_error("PATH_INVALID", "project root must be a non-symlink directory")
    project_file = _exact_file(
        project_root / f"{request.project_name}.gpr",
        request.expected_project_sha256,
        "project",
    )
    try:
        schema_candidate = request.export_schema_path.resolve(strict=True)
        schema_sha256 = sha256_file(schema_candidate)
    except OSError as error:
        raise _headless_error("PATH_INVALID", f"export schema is unavailable: {error}") from error
    schema = _exact_file(request.export_schema_path, schema_sha256, "export schema")
    try:
        schema_document = json.loads(schema.read_text(encoding="utf-8"))
        schema_version = schema_document["properties"]["schema_version"]["const"]
    except (KeyError, TypeError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _headless_error("EXPORT_SCHEMA_INVALID", "export schema has no exact version") from error
    if schema_version != request.expected_export_schema_version:
        raise _headless_error("IDENTITY_MISMATCH", "export schema version is not the requested version")

    output_root = request.approved_output_root.resolve(strict=False)
    output = request.output_path.resolve(strict=False)
    if output == output_root or not output.is_relative_to(output_root):
        raise _headless_error("OUTPUT_ESCAPE", "output path escapes approved output root")
    if output.exists():
        raise _headless_error("OUTPUT_EXISTS", "output path already exists")
    if (
        output_root == project_root
        or output_root.is_relative_to(project_root)
        or project_root.is_relative_to(output_root)
    ):
        raise _headless_error("WORKSPACE_OVERLAP", "output root overlaps the Ghidra project")
    scratch_root = request.approved_scratch_root.resolve(strict=False)
    if (
        scratch_root == project_root
        or scratch_root.is_relative_to(project_root)
        or project_root.is_relative_to(scratch_root)
    ):
        raise _headless_error("WORKSPACE_OVERLAP", "scratch root overlaps the Ghidra project")
    work = scratch_root / f"ghidra-headless-{request.operation_id}"
    if output.is_relative_to(work):
        raise _headless_error("WORKSPACE_OVERLAP", "output path is inside the cleanup workspace")

    for suffix in (".lock", ".lock~"):
        if (project_root / f"{request.project_name}{suffix}").exists():
            raise GhidraHeadlessExportError(
                "PROJECT_LOCKED",
                "project is locked by Ghidra",
                receipt=_blocked_lock_receipt(request, profile, schema_sha256),
            )
    wrapper_lock = project_root / f".{request.project_name}.kcd2-headless.lock"
    try:
        lock_descriptor = os.open(wrapper_lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise GhidraHeadlessExportError(
            "PROJECT_LOCKED",
            "project is locked by another wrapper",
            receipt=_blocked_lock_receipt(request, profile, schema_sha256),
        ) from error
    except OSError as error:
        raise _headless_error("PROJECT_LOCK_FAILED", f"project lock cannot be acquired: {error}") from error

    temporary_output = output.parent / f".{output.name}.ghidra.tmp"
    attempted = False
    exit_code: int | None = None
    failure: GhidraHeadlessExportError | None = None
    document: dict[str, Any] | None = None
    raw_export: bytes | None = None
    cleanup_errors: list[str] = []
    try:
        os.write(lock_descriptor, request.operation_id.encode("ascii"))
        os.close(lock_descriptor)
        lock_descriptor = -1
        output.parent.mkdir(parents=True, exist_ok=True)
        scratch_root.mkdir(parents=True, exist_ok=True)
        try:
            work.mkdir()
        except FileExistsError as error:
            raise _headless_error("WORKSPACE_EXISTS", "headless scratch workspace already exists") from error
        if temporary_output.exists():
            raise _headless_error("OUTPUT_EXISTS", "temporary export path already exists")
        user_home = work / "user-home"
        temp_home = work / "temp"
        user_home.mkdir()
        temp_home.mkdir()
        command = [
            str(analyze_headless),
            str(project_root),
            request.project_name,
            "-process",
            module.name,
            "-readOnly",
            "-scriptPath",
            str(script.parent),
            "-postScript",
            script.name,
            str(temporary_output),
            request.expected_module_sha256,
            str(request.max_export_bytes),
        ]
        environment = dict(os.environ)
        for inherited_override in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
            environment.pop(inherited_override, None)
        environment.update(
            {
                "JAVA_HOME": str(java.parent.parent),
                "GHIDRA_USER_HOME": str(user_home),
                "TEMP": str(temp_home),
                "TMP": str(temp_home),
            }
        )
        attempted = True
        try:
            completed = launcher(
                command,
                cwd=work,
                env=environment,
                timeout=request.timeout_seconds,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as error:
            raise _headless_error("HEADLESS_TIMEOUT", "analyzeHeadless timed out") from error
        except OSError as error:
            raise _headless_error("HEADLESS_LAUNCH_FAILED", f"analyzeHeadless failed to launch: {error}") from error
        exit_code = completed.returncode
        if exit_code != 0:
            raise _headless_error("HEADLESS_FAILED", f"analyzeHeadless exited with code {exit_code}")
        document, raw_export = _load_bounded_export(temporary_output, request.max_export_bytes)

        try:
            _validate_export_schema(document, schema_document, schema_document)
            validate_ghidra_export(document)
        except (GhidraExportContractError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _headless_error("EXPORT_INVALID", f"export schema validation failed: {error}") from error
        if document["module"]["sha256"] != request.expected_module_sha256:
            raise _headless_error("IDENTITY_MISMATCH", "export module SHA-256 is not requested WHGame")
        if document["module"]["name"].casefold() != module.name.casefold():
            raise _headless_error("IDENTITY_MISMATCH", "export module name is not requested WHGame")
        if document["module"]["name"].casefold() != request.program_name.casefold():
            raise _headless_error("IDENTITY_MISMATCH", "export program name is not requested program")
        if document["schema_version"] != request.expected_export_schema_version:
            raise _headless_error("IDENTITY_MISMATCH", "export schema version is not requested version")
        if document["headless_access_guard"]["project_locator"] != str(project_file):
            raise _headless_error("IDENTITY_MISMATCH", "export project locator is not requested project")

        drift_checks = (
            (ghidra, profile.components["ghidra"].expected_sha256, "ghidra"),
            (java, profile.components["java"].expected_sha256, "java"),
            (analyze_headless, request.expected_analyze_headless_sha256, "analyzeHeadless"),
            (project_file, request.expected_project_sha256, "project"),
            (module, request.expected_module_sha256, "module"),
            (analyzer_options, request.expected_analyzer_options_sha256, "analyzer options"),
            (script, request.expected_script_sha256, "script"),
            (schema, schema_sha256, "export schema"),
        )
        for path, digest, label in drift_checks:
            if sha256_file(path) != digest:
                raise _headless_error("SOURCE_DRIFT", f"{label} changed during export")
    except GhidraHeadlessExportError as error:
        failure = error
    except OSError as error:
        failure = _headless_error("WORKSPACE_IO_FAILED", f"governed workspace I/O failed: {error}")
    finally:
        if lock_descriptor != -1:
            try:
                os.close(lock_descriptor)
            except OSError as error:
                cleanup_errors.append(f"lock descriptor: {error}")
        if work.exists():
            try:
                shutil.rmtree(work)
            except OSError as error:
                cleanup_errors.append(f"scratch workspace: {error}")
        try:
            wrapper_lock.unlink(missing_ok=True)
        except OSError as error:
            cleanup_errors.append(f"wrapper lock: {error}")
        if failure is not None or cleanup_errors:
            try:
                temporary_output.unlink(missing_ok=True)
            except OSError as error:
                cleanup_errors.append(f"temporary output: {error}")

    receipt = _receipt(
        request,
        profile,
        schema_sha256,
        attempted=attempted,
        exit_code=exit_code,
        raw_export=raw_export,
        cleanup_errors=cleanup_errors,
        work_exists=work.exists(),
        lock_exists=wrapper_lock.exists(),
        temporary_output_exists=temporary_output.exists(),
    )
    if failure is not None:
        failure.receipt = receipt
        raise failure
    if cleanup_errors:
        raise GhidraHeadlessExportError(
            "CLEANUP_FAILED", "headless export cleanup failed", receipt=receipt
        )
    assert document is not None and raw_export is not None
    try:
        os.replace(temporary_output, output)
    except OSError as error:
        temporary_output.unlink(missing_ok=True)
        receipt["temporary_output_exists_after_cleanup"] = temporary_output.exists()
        raise GhidraHeadlessExportError(
            "OUTPUT_PROMOTION_FAILED", f"cannot atomically promote export: {error}", receipt=receipt
        ) from error
    receipt["temporary_output_exists_after_cleanup"] = temporary_output.exists()
    durable_hash = sha256_file(output)
    if durable_hash != receipt["export_sha256"]:
        output.unlink(missing_ok=True)
        raise GhidraHeadlessExportError(
            "OUTPUT_HASH_MISMATCH", "promoted export hash changed", receipt=receipt
        )
    receipt["outputs"] = [
        {
            "path": str(output),
            "sha256": durable_hash,
            "bytes": output.stat().st_size,
        }
    ]
    return GhidraHeadlessExportResult(
        export_path=output,
        export_sha256=durable_hash,
        receipt=receipt,
    )


def _identities(record: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    found = [("identity", record["identity"])]
    for name in ("owner_identity", "target_identity"):
        identity = record.get(name)
        if identity is not None:
            found.append((name, identity))
    return found


def validate_ghidra_export(document: Mapping[str, Any]) -> None:
    """Validate invariants that JSON Schema cannot express across export records.

    The caller must validate the document against
    ``ghidra-native-export-v1.schema.json`` first. This function deliberately does
    not repair, sort, normalize, or infer values.
    """

    module = document["module"]
    module_sha256 = module["sha256"]
    image_size = module["image_size"]
    if module_sha256 != module_sha256.lower():
        raise GhidraExportContractError("module SHA-256 must use canonical lowercase hex")

    record_ids: set[str] = set()
    exports: Mapping[str, Sequence[Mapping[str, Any]]] = document["exports"]
    for section, records in exports.items():
        expected_order = sorted(
            records,
            key=lambda record: (record["identity"]["value"], record["record_id"]),
        )
        if list(records) != expected_order:
            raise GhidraExportContractError(
                f"{section} records are not in deterministic order by locator and record_id"
            )

        for record in records:
            record_id = record["record_id"]
            if record_id in record_ids:
                raise GhidraExportContractError(f"duplicate record_id: {record_id}")
            record_ids.add(record_id)

            evidence_locators = record["evidence_locators"]
            if list(evidence_locators) != sorted(evidence_locators):
                raise GhidraExportContractError(
                    f"{record_id} evidence locators are not in deterministic order"
                )

            for identity_name, identity in _identities(record):
                if identity["module_sha256"] != module_sha256:
                    raise GhidraExportContractError(
                        f"{record_id}.{identity_name} module SHA-256 does not match export module"
                    )
                if identity["value"] >= image_size:
                    raise GhidraExportContractError(
                        f"{record_id}.{identity_name} relative locator exceeds module image bounds"
                    )

    summaries = document["summaries"]
    summary_ids = [summary["summary_id"] for summary in summaries]
    if summary_ids != sorted(summary_ids):
        raise GhidraExportContractError("summaries are not in deterministic summary_id order")
    if len(summary_ids) != len(set(summary_ids)):
        raise GhidraExportContractError("duplicate summary_id")

    for summary in summaries:
        unknown_ids = set(summary["record_ids"]) - record_ids
        if unknown_ids:
            raise GhidraExportContractError(
                f"{summary['summary_id']} references unknown record_id: {sorted(unknown_ids)[0]}"
            )
        if summary["record_ids"] != sorted(summary["record_ids"]):
            raise GhidraExportContractError(
                f"{summary['summary_id']} record_ids are not in deterministic order"
            )
