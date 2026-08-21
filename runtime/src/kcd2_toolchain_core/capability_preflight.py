"""Bounded, explicit-path capability discovery for native workflow selection.

The detector reports access only.  It does not derive native identities, inspect
running processes, search installations, or turn tool presence into ABI facts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .environment_profiles import CHECK_NAMES, EnvironmentProfile


PathPredicate = Callable[[str], bool]
PrefixReader = Callable[[str, int], bytes]

MAX_CAPABILITY_ID_LENGTH = 256
MAX_INPUT_ENTRIES = 64
MAX_PATH_LENGTH = 2048
MAX_TEXT_LENGTH = 2048
MAX_VERSION_LENGTH = 256
PYGHIDRA_PROBE_CONTRACT = "governed-pyghidra-import-v1"
PYGHIDRA_PROBE_TIMEOUT_SECONDS = 5
PYGHIDRA_PROBE_OUTPUT_LIMIT = 4096
IMPORT_RECEIPTS = {
    "IMPORTED",
    "INTERPRETER_MISSING",
    "NOT_IMPORTABLE",
    "PROBE_FAILED",
    "PROBE_TIMED_OUT",
}


@dataclass(frozen=True, slots=True)
class PyGhidraObservation:
    import_succeeded: bool
    version: str | None
    interpreter_version: str | None = None
    import_receipt: str | None = None

    def __post_init__(self) -> None:
        if self.version is not None:
            _require_bounded_text(
                self.version,
                name="PyGhidra version",
                maximum=MAX_VERSION_LENGTH,
            )
        if not self.import_succeeded and self.version is not None:
            raise ValueError("a failed PyGhidra import cannot report a version")
        if self.interpreter_version is not None:
            _require_bounded_text(
                self.interpreter_version,
                name="interpreter version",
                maximum=MAX_VERSION_LENGTH,
            )
        receipt = self.import_receipt or (
            "IMPORTED" if self.import_succeeded else "NOT_IMPORTABLE"
        )
        if receipt not in IMPORT_RECEIPTS:
            raise ValueError("unknown PyGhidra import receipt")
        if self.import_succeeded != (receipt == "IMPORTED"):
            raise ValueError("PyGhidra import receipt contradicts import result")
        object.__setattr__(self, "import_receipt", receipt)


@dataclass(frozen=True, slots=True)
class CapabilityPreflightInputs:
    """Only explicitly supplied locations and tool inventory are inspected."""

    capability_id: str
    regular_ghidra_gui: str | None = None
    regular_ghidra_headless: str | None = None
    current_interpreter: str = sys.executable
    isolated_pyghidra_interpreters: tuple[str, ...] = ()
    plugin_interpreter: str | None = None
    pyghidra_required: bool = False
    x64dbg_path: str | None = None
    kcse_path: str | None = None
    compiler_paths: tuple[str, ...] = ()
    index_mcp_tools: tuple[str, ...] = ()
    game_binary_paths: tuple[str, ...] = ()
    reviewed_static_evidence: tuple[str, ...] = ()
    environment_profile: EnvironmentProfile | None = None

    def __post_init__(self) -> None:
        _require_bounded_text(
            self.capability_id,
            name="capability_id",
            maximum=MAX_CAPABILITY_ID_LENGTH,
        )
        optional_paths = (
            ("regular_ghidra_gui", self.regular_ghidra_gui),
            ("regular_ghidra_headless", self.regular_ghidra_headless),
            ("plugin_interpreter", self.plugin_interpreter),
            ("x64dbg_path", self.x64dbg_path),
            ("kcse_path", self.kcse_path),
        )
        for name, value in optional_paths:
            if value is not None:
                _require_bounded_text(value, name=name, maximum=MAX_PATH_LENGTH)
        _require_bounded_text(
            self.current_interpreter,
            name="current_interpreter",
            maximum=MAX_PATH_LENGTH,
        )
        if not isinstance(self.pyghidra_required, bool):
            raise ValueError("pyghidra_required must be a boolean")
        if self.environment_profile is not None and not isinstance(
            self.environment_profile, EnvironmentProfile
        ):
            raise ValueError("environment_profile must be a validated EnvironmentProfile")

        collections: Sequence[tuple[str, tuple[str, ...], int]] = (
            (
                "isolated_pyghidra_interpreters",
                self.isolated_pyghidra_interpreters,
                MAX_PATH_LENGTH,
            ),
            ("compiler_paths", self.compiler_paths, MAX_PATH_LENGTH),
            ("index_mcp_tools", self.index_mcp_tools, MAX_TEXT_LENGTH),
            ("game_binary_paths", self.game_binary_paths, MAX_PATH_LENGTH),
            ("reviewed_static_evidence", self.reviewed_static_evidence, MAX_TEXT_LENGTH),
        )
        for name, values, maximum in collections:
            if len(values) > MAX_INPUT_ENTRIES:
                raise ValueError(
                    f"{name} is limited to {MAX_INPUT_ENTRIES} entries"
                )
            for value in values:
                _require_bounded_text(value, name=name, maximum=maximum)


def _require_bounded_text(value: str, *, name: str, maximum: int) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} entries must contain 1 to {maximum} characters")


def _path_is_file(path: str) -> bool:
    return Path(path).is_file()


def _read_prefix(path: str, count: int) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(count)


def _observe_pyghidra(interpreter: str) -> PyGhidraObservation:
    program = (
        "import importlib.metadata as m,json,platform\n"
        "r={'interpreter_version':platform.python_version(),"
        "'import_succeeded':False,'pyghidra_version':None,"
        "'import_receipt':'NOT_IMPORTABLE'}\n"
        "try:\n"
        " import pyghidra\n"
        " r.update(import_succeeded=True,import_receipt='IMPORTED')\n"
        " try:r['pyghidra_version']=m.version('pyghidra')\n"
        " except m.PackageNotFoundError:"
        "r['pyghidra_version']=getattr(pyghidra,'__version__',None)\n"
        "except ImportError:pass\n"
        "except Exception:r['import_receipt']='PROBE_FAILED'\n"
        "print(json.dumps(r))"
    )
    try:
        process = subprocess.Popen(
            [interpreter, "-I", "-c", program],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "")},
        )
        chunks: list[bytes] = []
        output_size = 0
        output_overflow = threading.Event()

        def read_bounded_stdout() -> None:
            nonlocal output_size
            assert process.stdout is not None
            while chunk := process.stdout.read(1024):
                output_size += len(chunk)
                if output_size > PYGHIDRA_PROBE_OUTPUT_LIMIT:
                    output_overflow.set()
                    process.kill()
                    return
                chunks.append(chunk)

        reader = threading.Thread(target=read_bounded_stdout, daemon=True)
        reader.start()
        try:
            return_code = process.wait(timeout=PYGHIDRA_PROBE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            reader.join(timeout=1)
            if process.stdout is not None:
                process.stdout.close()
            return PyGhidraObservation(False, None, import_receipt="PROBE_TIMED_OUT")
        reader.join(timeout=1)
        if process.stdout is not None:
            process.stdout.close()
        if reader.is_alive() or output_overflow.is_set() or return_code != 0:
            return PyGhidraObservation(False, None, import_receipt="PROBE_FAILED")
        receipt_lines = b"".join(chunks).splitlines()
        if not receipt_lines:
            return PyGhidraObservation(False, None, import_receipt="PROBE_FAILED")
        decoded = json.loads(receipt_lines[-1].decode("utf-8"))
        succeeded = decoded["import_succeeded"] is True
        package_version = decoded["pyghidra_version"]
        return PyGhidraObservation(
            succeeded,
            str(package_version) if package_version is not None else None,
            interpreter_version=str(decoded["interpreter_version"]),
            import_receipt=str(decoded["import_receipt"]),
        )
    except FileNotFoundError:
        return PyGhidraObservation(False, None, import_receipt="INTERPRETER_MISSING")
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError):
        return PyGhidraObservation(False, None, import_receipt="PROBE_FAILED")


def _interpreter_receipt(
    path: str,
    source: str,
    observation: PyGhidraObservation,
) -> dict[str, object]:
    return {
        "path": path,
        "source": source,
        "interpreter_version": observation.interpreter_version,
        "import_succeeded": observation.import_succeeded,
        "pyghidra_version": observation.version,
        "import_receipt": observation.import_receipt,
        "probe_contract": PYGHIDRA_PROBE_CONTRACT,
    }


def _isolated_environment_root(interpreter: str) -> str:
    parent = Path(interpreter).parent
    if parent.name.casefold() in {"bin", "scripts"}:
        parent = parent.parent
    return str(parent)


def _tool(path: str | None, path_is_file: PathPredicate) -> dict[str, object]:
    return {"available": bool(path and path_is_file(path)), "path": path}


def _workflow(
    eligible: bool, evidence: Sequence[str], blockers: Sequence[str]
) -> dict[str, object]:
    return {
        "eligible": eligible,
        "evidence_sources": sorted(set(evidence)),
        "blockers": [] if eligible else sorted(set(blockers)),
    }


def _profile_component_receipts(
    profile: EnvironmentProfile | None,
) -> dict[str, object] | None:
    if profile is None:
        return None
    components: dict[str, object] = {}
    for component_id in sorted(profile.components):
        component = profile.components[component_id]
        components[component_id] = {
            "capability_level": component.capability_level,
            "expected_version": component.expected_version,
            "expected_sha256": component.expected_sha256,
            "observed_version": component.observed_version,
            "observed_sha256": component.observed_sha256,
            "proofs": {
                proof: {
                    "status": component.checks[proof].status,
                    "checked_at": component.checks[proof].checked_at,
                    "evidence": component.checks[proof].evidence,
                }
                for proof in sorted(CHECK_NAMES)
            },
        }
    return {
        "profile_id": profile.profile_id,
        "compatibility_profile_id": profile.compatibility_profile_id,
        "components": components,
    }


def _profile_route(
    profile: EnvironmentProfile | None,
    requirements: Sequence[tuple[str, tuple[str, ...]]],
) -> tuple[bool, list[str], list[str]]:
    if profile is None:
        return False, [], ["ENVIRONMENT_PROFILE_REQUIRED"]
    evidence: list[str] = []
    blockers: list[str] = []
    for component_id, proofs in requirements:
        component = profile.components[component_id]
        evidence.append(f"environment_profile:{component_id}")
        for proof in proofs:
            status = component.checks[proof].status
            if status == "passed":
                continue
            if proof == "version_profile":
                failure = (
                    "VERSION_PROFILE_MISMATCH"
                    if status == "failed"
                    else "VERSION_PROFILE_UNPROVEN"
                )
            elif proof == "launch":
                failure = "LAUNCH_FAILED" if status == "failed" else "LAUNCH_UNVERIFIED"
            elif proof == "provider":
                label = (
                    "API_CONNECTIVITY"
                    if component_id == "kcse"
                    else "PROVIDER_CONNECTIVITY"
                )
                failure = f"{label}_FAILED" if status == "failed" else f"{label}_UNVERIFIED"
            else:
                suffix = "FAILED" if status == "failed" else "UNVERIFIED"
                failure = f"{proof.upper()}_{suffix}"
            blockers.append(f"{failure}:{component_id}")
        if not component.workflow_eligible and not any(
            blocker.endswith(f":{component_id}") for blocker in blockers
        ):
            blockers.append(f"CAPABILITY_LEVEL_INSUFFICIENT:{component_id}")
    return not blockers, evidence, sorted(set(blockers))


def detect_capabilities(
    inputs: CapabilityPreflightInputs,
    *,
    path_is_file: PathPredicate = _path_is_file,
    read_prefix: PrefixReader = _read_prefix,
    observe_pyghidra: Callable[[str], PyGhidraObservation] = _observe_pyghidra,
) -> dict[str, object]:
    """Return a deterministic capability receipt and fail-closed workflow matrix."""

    gui = bool(inputs.regular_ghidra_gui and path_is_file(inputs.regular_ghidra_gui))
    headless = bool(
        inputs.regular_ghidra_headless and path_is_file(inputs.regular_ghidra_headless)
    )
    if gui and headless:
        ghidra_mode = "both"
    else:
        ghidra_mode = "gui" if gui else "headless" if headless else "none"
    ghidra_path = (
        inputs.regular_ghidra_gui
        if gui
        else inputs.regular_ghidra_headless
        if headless
        else None
    )
    regular_ghidra = {"available": gui or headless, "path": ghidra_path, "mode": ghidra_mode}

    current = (
        observe_pyghidra(inputs.current_interpreter)
        if path_is_file(inputs.current_interpreter)
        else PyGhidraObservation(False, None, import_receipt="INTERPRETER_MISSING")
    )
    isolated: list[dict[str, object]] = []
    for interpreter in sorted(set(inputs.isolated_pyghidra_interpreters)):
        observation = (
            observe_pyghidra(interpreter)
            if path_is_file(interpreter)
            else PyGhidraObservation(False, None, import_receipt="INTERPRETER_MISSING")
        )
        receipt = _interpreter_receipt(interpreter, "isolated", observation)
        receipt["environment_root"] = _isolated_environment_root(interpreter)
        receipt["interpreter_path"] = receipt.pop("path")
        isolated.append(receipt)
    plugin_observation = None
    plugin_receipt = None
    if inputs.plugin_interpreter is not None:
        plugin_observation = (
            observe_pyghidra(inputs.plugin_interpreter)
            if path_is_file(inputs.plugin_interpreter)
            else PyGhidraObservation(False, None, import_receipt="INTERPRETER_MISSING")
        )
        plugin_receipt = _interpreter_receipt(
            inputs.plugin_interpreter, "plugin", plugin_observation
        )
    selected_isolated = next(
        (item["interpreter_path"] for item in isolated if item["import_succeeded"]), None
    )
    selected_plugin = (
        inputs.plugin_interpreter
        if plugin_observation is not None and plugin_observation.import_succeeded
        else None
    )
    if current.import_succeeded:
        pyghidra_status = "AVAILABLE_CURRENT_INTERPRETER"
        selected_interpreter: object = inputs.current_interpreter
    elif selected_isolated or selected_plugin:
        pyghidra_status = "AVAILABLE_ISOLATED"
        selected_interpreter = selected_isolated or selected_plugin
    else:
        pyghidra_status = (
            "UNAVAILABLE_REQUIRED" if inputs.pyghidra_required else "UNAVAILABLE_OPTIONAL"
        )
        selected_interpreter = None
    pyghidra = {
        "effective_status": pyghidra_status,
        "required": inputs.pyghidra_required,
        "current_interpreter": _interpreter_receipt(
            inputs.current_interpreter, "current", current
        ),
        "isolated_installations": isolated,
        "plugin_interpreter": plugin_receipt,
        "selected_interpreter": selected_interpreter,
    }

    x64dbg = _tool(inputs.x64dbg_path, path_is_file)
    kcse = _tool(inputs.kcse_path, path_is_file)
    compiler_paths = sorted({path for path in inputs.compiler_paths if path_is_file(path)})
    compiler = {"available": bool(compiler_paths), "paths": compiler_paths}
    index_tools = sorted(set(inputs.index_mcp_tools))
    index_mcp = {"available": bool(index_tools), "tool_names": index_tools}

    observed_game = sorted({path for path in inputs.game_binary_paths if path_is_file(path)})
    missing_game = sorted(set(inputs.game_binary_paths) - set(observed_game))
    game_binaries = {
        "available": bool(observed_game),
        "observed_paths": observed_game,
        "missing_paths": missing_game,
    }
    verified_pe: list[str] = []
    unreadable_pe: list[str] = []
    invalid_pe: list[str] = []
    for path in observed_game:
        try:
            prefix = read_prefix(path, 2)
        except OSError:
            unreadable_pe.append(path)
            continue
        if prefix == b"MZ":
            verified_pe.append(path)
        else:
            invalid_pe.append(path)
    raw_pe = {
        "available": bool(verified_pe),
        "verified_paths": verified_pe,
        "unreadable_paths": unreadable_pe,
        "invalid_paths": invalid_pe,
    }

    reviewed = sorted(set(inputs.reviewed_static_evidence))
    profile_receipt = _profile_component_receipts(inputs.environment_profile)
    regular_profile_ok, regular_profile_evidence, regular_profile_blockers = _profile_route(
        inputs.environment_profile,
        (
            ("ghidra", ("launch", "version_profile")),
            ("java", ("launch", "version_profile")),
            ("whgame", ("version_profile",)),
        ),
    )
    x64dbg_profile_ok, x64dbg_profile_evidence, x64dbg_profile_blockers = _profile_route(
        inputs.environment_profile,
        (
            ("x64dbg", ("launch", "provider", "version_profile")),
            ("game", ("version_profile",)),
            ("whgame", ("version_profile",)),
        ),
    )
    kcse_profile_ok, kcse_profile_evidence, kcse_profile_blockers = _profile_route(
        inputs.environment_profile,
        (
            ("kcse", ("provider", "version_profile")),
            ("compiler", ("launch", "version_profile")),
            ("game", ("version_profile",)),
            ("whgame", ("version_profile",)),
        ),
    )
    raw_profile_ok, raw_profile_evidence, raw_profile_blockers = _profile_route(
        inputs.environment_profile,
        (("whgame", ("version_profile",)),),
    )
    pyghidra_available = current.import_succeeded or bool(selected_isolated or selected_plugin)
    pyghidra_profile_ok, pyghidra_profile_evidence, pyghidra_profile_blockers = (
        _profile_route(
            inputs.environment_profile,
            (
                ("ghidra", ("launch", "version_profile")),
                ("java", ("launch", "version_profile")),
                ("whgame", ("version_profile",)),
            ),
        )
    )
    pyghidra_eligible = pyghidra_available and pyghidra_profile_ok
    static_access = regular_profile_ok or pyghidra_eligible or bool(reviewed)
    static_sources = []
    if regular_profile_ok:
        static_sources.extend(regular_profile_evidence)
    if pyghidra_eligible:
        static_sources.extend(pyghidra_profile_evidence)
    if reviewed:
        static_sources.append("reviewed_static_evidence")

    x64dbg_eligible = x64dbg_profile_ok
    kcse_eligible = kcse_profile_ok and static_access
    raw_pe_eligible = bool(raw_pe["available"] and raw_profile_ok)
    workflow_matrix = {
        "ghidra_first": _workflow(
            bool(static_access), static_sources, ("NO_GHIDRA_OR_REVIEWED_STATIC_EVIDENCE",)
        ),
        "regular_ghidra": _workflow(
            regular_profile_ok,
            regular_profile_evidence,
            regular_profile_blockers,
        ),
        "pyghidra": _workflow(
            pyghidra_eligible,
            ["pyghidra", *pyghidra_profile_evidence] if pyghidra_eligible else [],
            [
                *(
                    []
                    if pyghidra_available
                    else [
                        "PYGHIDRA_UNAVAILABLE_REQUIRED"
                        if inputs.pyghidra_required
                        else "PYGHIDRA_UNAVAILABLE_OPTIONAL"
                    ]
                ),
                *pyghidra_profile_blockers,
            ],
        ),
        "x64dbg": _workflow(
            x64dbg_eligible,
            x64dbg_profile_evidence,
            x64dbg_profile_blockers,
        ),
        "kcse": _workflow(
            kcse_eligible,
            [*kcse_profile_evidence, *static_sources],
            [
                *kcse_profile_blockers,
                *([] if static_access else ["NO_GHIDRA_OR_REVIEWED_STATIC_EVIDENCE"]),
            ],
        ),
        "raw_pe_preflight": _workflow(
            raw_pe_eligible,
            ["raw_pe_access", *raw_profile_evidence] if raw_pe_eligible else [],
            [
                *([] if raw_pe["available"] else ["RAW_PE_UNAVAILABLE"]),
                *raw_profile_blockers,
            ],
        ),
    }
    native_blocked = not (static_access or x64dbg_eligible or kcse_eligible)

    reason_codes = []
    checks = (
        (regular_ghidra["available"], "REGULAR_GHIDRA_AVAILABLE", "REGULAR_GHIDRA_UNAVAILABLE"),
        (pyghidra_available, f"PYGHIDRA_{pyghidra_status}", f"PYGHIDRA_{pyghidra_status}"),
        (x64dbg["available"], "X64DBG_AVAILABLE", "X64DBG_UNAVAILABLE"),
        (kcse["available"], "KCSE_AVAILABLE", "KCSE_UNAVAILABLE"),
        (compiler["available"], "COMPILER_AVAILABLE", "COMPILER_UNAVAILABLE"),
        (index_mcp["available"], "INDEX_MCP_AVAILABLE", "INDEX_MCP_UNAVAILABLE"),
        (game_binaries["available"], "GAME_BINARIES_AVAILABLE", "GAME_BINARIES_UNAVAILABLE"),
        (raw_pe["available"], "RAW_PE_AVAILABLE", "RAW_PE_UNAVAILABLE"),
    )
    reason_codes.extend(
        available if condition else unavailable
        for condition, available, unavailable in checks
    )
    if reviewed:
        reason_codes.append("REVIEWED_STATIC_EVIDENCE_AVAILABLE")
    if native_blocked:
        reason_codes.append("NATIVE_WORKFLOW_BLOCKED")

    return {
        "schema_version": "kcd2.capability-discovery.v1",
        "capability_id": inputs.capability_id,
        "regular_ghidra": regular_ghidra,
        "pyghidra": pyghidra,
        "x64dbg": x64dbg,
        "kcse": kcse,
        "compiler": compiler,
        "index_mcp": index_mcp,
        "game_binaries": game_binaries,
        "raw_pe_access": raw_pe,
        "reviewed_static_evidence": reviewed,
        "environment_profile": profile_receipt,
        "workflow_matrix": workflow_matrix,
        "native_workflow_blocked": native_blocked,
        "reason_codes": sorted(reason_codes),
    }
