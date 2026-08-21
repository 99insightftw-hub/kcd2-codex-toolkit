"""Approval-bound, fail-closed x64dbg session control."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kcd2_toolchain_core.approvals import ApprovalTarget, ApprovalVerifier


MINIMUM_HANDOFF_WAIT_MS = 750
MAXIMUM_HANDOFF_WAIT_MS = 60_000
MAX_BREAKPOINTS = 64
MAX_IDENTITY_CHARS = 256
MAX_PATH_CHARS = 2048
MAX_CHECKPOINT_BYTES = 4096
MAX_REGISTERS = 64
_SESSION_LOCK = threading.Lock()
_RVA_PATTERN = re.compile(r"^0x[0-9A-Fa-f]{1,16}$")
_MODULE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REGISTER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,15}$")


class DebuggerHandoffError(ValueError):
    """The requested debugger handoff is malformed or cannot be safely attempted."""


def _bounded_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_IDENTITY_CHARS
        or "\x00" in value
    ):
        raise DebuggerHandoffError(f"{label} is invalid")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DebuggerHandoffError("handoff value is not canonical JSON") from exc


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise DebuggerHandoffError("debugger executable is unavailable") from exc
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class DebuggerIdentity:
    provider_id: str
    provider_version: str
    executable_path: str
    executable_sha256: str

    def __post_init__(self) -> None:
        for field in ("provider_id", "provider_version"):
            object.__setattr__(self, field, _bounded_text(getattr(self, field), field))
        if (
            not isinstance(self.executable_path, str)
            or not 1 <= len(self.executable_path) <= MAX_PATH_CHARS
            or "\x00" in self.executable_path
        ):
            raise DebuggerHandoffError("executable_path is invalid")
        path = Path(self.executable_path).resolve(strict=False)
        object.__setattr__(self, "executable_path", path.as_posix())
        digest = self.executable_sha256
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in digest)
        ):
            raise DebuggerHandoffError("executable_sha256 is invalid")
        object.__setattr__(self, "executable_sha256", digest.lower())

    @classmethod
    def from_executable(
        cls,
        *,
        provider_id: str,
        provider_version: str,
        executable_path: Path | str,
    ) -> DebuggerIdentity:
        path = Path(executable_path).resolve(strict=True)
        if not path.is_file():
            raise DebuggerHandoffError("debugger executable is not a regular file")
        return cls(provider_id, provider_version, path.as_posix(), _hash_file(path))

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
        }


@dataclass(frozen=True, slots=True)
class DebuggerSnapshot:
    connected: bool
    debugging: bool
    running: bool
    paused: bool
    active_breakpoints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field in ("connected", "debugging", "running", "paused"):
            if not isinstance(getattr(self, field), bool):
                raise DebuggerHandoffError(f"snapshot {field} must be Boolean")
        if (
            not isinstance(self.active_breakpoints, tuple)
            or len(self.active_breakpoints) > MAX_BREAKPOINTS
        ):
            raise DebuggerHandoffError("active_breakpoints is invalid")
        checked = tuple(
            _bounded_text(value, "breakpoint") for value in self.active_breakpoints
        )
        if len(set(checked)) != len(checked):
            raise DebuggerHandoffError("active_breakpoints contains duplicates")
        object.__setattr__(self, "active_breakpoints", checked)
        if self.running and self.paused:
            raise DebuggerHandoffError("debugger cannot be both running and paused")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> DebuggerSnapshot:
        if not isinstance(value, Mapping):
            raise DebuggerHandoffError("snapshot must be an object")
        required = {"connected", "debugging", "running", "paused", "active_breakpoints"}
        if set(value) != required or not isinstance(value["active_breakpoints"], list):
            raise DebuggerHandoffError("snapshot fields do not match the contract")
        return cls(
            connected=value["connected"],  # type: ignore[arg-type]
            debugging=value["debugging"],  # type: ignore[arg-type]
            running=value["running"],  # type: ignore[arg-type]
            paused=value["paused"],  # type: ignore[arg-type]
            active_breakpoints=tuple(value["active_breakpoints"]),
        )

    @property
    def gameplay_safe(self) -> bool:
        return self.connected and self.debugging and self.running and not self.paused

    @property
    def state_name(self) -> str:
        if not self.connected:
            return "DETACHED"
        return "CONNECTED_PAUSED" if self.paused or not self.running else "CONNECTED_RUNNING"

    def to_check(self) -> dict[str, object]:
        return {
            "connected": self.connected,
            "debugging": self.debugging,
            "running": self.running,
            "paused": self.paused,
            "active_breakpoints": list(self.active_breakpoints),
        }


@dataclass(frozen=True, slots=True)
class GameplayHandoffRequest:
    session_id: str
    cross_tool_identity_id: str
    debugger_identity: DebuggerIdentity
    temporary_breakpoints: tuple[str, ...] = ()
    wait_interval_ms: int = MINIMUM_HANDOFF_WAIT_MS

    def __post_init__(self) -> None:
        for field in ("session_id", "cross_tool_identity_id"):
            object.__setattr__(self, field, _bounded_text(getattr(self, field), field))
        if not isinstance(self.debugger_identity, DebuggerIdentity):
            raise DebuggerHandoffError("debugger_identity is invalid")
        if (
            not isinstance(self.wait_interval_ms, int)
            or isinstance(self.wait_interval_ms, bool)
            or not MINIMUM_HANDOFF_WAIT_MS
            <= self.wait_interval_ms
            <= MAXIMUM_HANDOFF_WAIT_MS
        ):
            raise DebuggerHandoffError("wait_interval_ms is outside the safe bounds")
        if (
            not isinstance(self.temporary_breakpoints, tuple)
            or len(self.temporary_breakpoints) > MAX_BREAKPOINTS
        ):
            raise DebuggerHandoffError("temporary_breakpoints is invalid")
        checked = tuple(
            _bounded_text(value, "temporary breakpoint")
            for value in self.temporary_breakpoints
        )
        if len(set(checked)) != len(checked):
            raise DebuggerHandoffError("temporary_breakpoints contains duplicates")
        object.__setattr__(self, "temporary_breakpoints", checked)

    def approval_payload(self) -> dict[str, object]:
        return {
            "operation": "prepare_gameplay_handoff",
            "session_id": self.session_id,
            "cross_tool_identity_id": self.cross_tool_identity_id,
            "debugger_identity": self.debugger_identity.to_dict(),
            "temporary_breakpoints": list(self.temporary_breakpoints),
            "wait_interval_ms": self.wait_interval_ms,
        }


def _checked_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise DebuggerHandoffError(f"{label} is invalid")
    return value.lower()


def _checked_rva(value: object, label: str) -> str:
    if not isinstance(value, str) or _RVA_PATTERN.fullmatch(value) is None:
        raise DebuggerHandoffError(f"{label} is invalid")
    return f"0x{int(value, 16):X}"


@dataclass(frozen=True, slots=True)
class CheckpointCaptureRequest:
    session_id: str
    cross_tool_identity_id: str
    debugger_identity: DebuggerIdentity
    module_name: str
    module_sha256: str
    checkpoint_rva: str
    maximum_bytes: int = 256

    def __post_init__(self) -> None:
        for field in ("session_id", "cross_tool_identity_id"):
            object.__setattr__(self, field, _bounded_text(getattr(self, field), field))
        if not isinstance(self.debugger_identity, DebuggerIdentity):
            raise DebuggerHandoffError("debugger_identity is invalid")
        if not isinstance(self.module_name, str) or _MODULE_PATTERN.fullmatch(
            self.module_name
        ) is None:
            raise DebuggerHandoffError("module_name is invalid")
        object.__setattr__(
            self, "module_sha256", _checked_sha256(self.module_sha256, "module_sha256")
        )
        object.__setattr__(
            self, "checkpoint_rva", _checked_rva(self.checkpoint_rva, "checkpoint_rva")
        )
        if (
            not isinstance(self.maximum_bytes, int)
            or isinstance(self.maximum_bytes, bool)
            or not 1 <= self.maximum_bytes <= MAX_CHECKPOINT_BYTES
        ):
            raise DebuggerHandoffError("maximum_bytes is outside the safe bounds")

    def approval_payload(self) -> dict[str, object]:
        return {
            "operation": "capture_checkpoint",
            "session_id": self.session_id,
            "cross_tool_identity_id": self.cross_tool_identity_id,
            "debugger_identity": self.debugger_identity.to_dict(),
            "module_name": self.module_name,
            "module_sha256": self.module_sha256,
            "checkpoint_rva": self.checkpoint_rva,
            "maximum_bytes": self.maximum_bytes,
        }


@dataclass(frozen=True, slots=True)
class CloseDebugSessionRequest:
    session_id: str
    cross_tool_identity_id: str
    debugger_identity: DebuggerIdentity
    temporary_breakpoints: tuple[str, ...] = ()
    wait_interval_ms: int = MINIMUM_HANDOFF_WAIT_MS

    def __post_init__(self) -> None:
        handoff = GameplayHandoffRequest(
            session_id=self.session_id,
            cross_tool_identity_id=self.cross_tool_identity_id,
            debugger_identity=self.debugger_identity,
            temporary_breakpoints=self.temporary_breakpoints,
            wait_interval_ms=self.wait_interval_ms,
        )
        for field in (
            "session_id",
            "cross_tool_identity_id",
            "debugger_identity",
            "temporary_breakpoints",
            "wait_interval_ms",
        ):
            object.__setattr__(self, field, getattr(handoff, field))

    def approval_payload(self) -> dict[str, object]:
        return {
            "operation": "close_debug_session",
            "session_id": self.session_id,
            "cross_tool_identity_id": self.cross_tool_identity_id,
            "debugger_identity": self.debugger_identity.to_dict(),
            "temporary_breakpoints": list(self.temporary_breakpoints),
            "wait_interval_ms": self.wait_interval_ms,
        }


@dataclass(frozen=True, slots=True)
class CapturedCheckpoint:
    module_name: str
    module_sha256: str
    checkpoint_rva: str
    bytes_hex: str
    registers: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.module_name, str) or _MODULE_PATTERN.fullmatch(
            self.module_name
        ) is None:
            raise DebuggerHandoffError("captured module_name is invalid")
        object.__setattr__(
            self,
            "module_sha256",
            _checked_sha256(self.module_sha256, "captured module_sha256"),
        )
        object.__setattr__(
            self,
            "checkpoint_rva",
            _checked_rva(self.checkpoint_rva, "captured checkpoint_rva"),
        )
        if (
            not isinstance(self.bytes_hex, str)
            or not self.bytes_hex
            or len(self.bytes_hex) % 2
            or len(self.bytes_hex) > MAX_CHECKPOINT_BYTES * 2
            or re.fullmatch(r"[0-9A-Fa-f]*", self.bytes_hex) is None
        ):
            raise DebuggerHandoffError("captured bytes_hex is invalid")
        if not isinstance(self.registers, Mapping) or len(self.registers) > MAX_REGISTERS:
            raise DebuggerHandoffError("captured registers are invalid")
        checked: dict[str, str] = {}
        for name, value in self.registers.items():
            if not isinstance(name, str) or _REGISTER_PATTERN.fullmatch(name) is None:
                raise DebuggerHandoffError("captured register name is invalid")
            checked[name] = _checked_rva(value, f"captured register {name}")
        object.__setattr__(self, "bytes_hex", self.bytes_hex.lower())
        object.__setattr__(self, "registers", checked)

    @property
    def byte_count(self) -> int:
        return len(self.bytes_hex) // 2

    def to_artifact(self, request: CheckpointCaptureRequest) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": "kcd2.x64dbg-checkpoint.v1",
            "session_id": request.session_id,
            "cross_tool_identity_id": request.cross_tool_identity_id,
            "module_name": self.module_name,
            "module_sha256": self.module_sha256,
            "checkpoint_rva": self.checkpoint_rva,
            "bytes": self.byte_count,
            "bytes_hex": self.bytes_hex,
            "registers": dict(sorted(self.registers.items())),
            "maximum_bytes": request.maximum_bytes,
        }
        digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        return {"artifact_id": f"x64dbg-checkpoint:{digest}", **body}


class _DebuggerInspectionProvider(Protocol):
    identity: DebuggerIdentity

    def inspect(self, session_id: str) -> DebuggerSnapshot: ...


class _HandoffProvider(_DebuggerInspectionProvider, Protocol):
    def resume(self, session_id: str) -> None: ...


class _CheckpointProvider(_DebuggerInspectionProvider, Protocol):
    def capture(self, request: CheckpointCaptureRequest) -> CapturedCheckpoint: ...


class _CloseProvider(_DebuggerInspectionProvider, Protocol):
    def clear_temporary_breakpoint(self, session_id: str, breakpoint: str) -> None: ...

    def detach(self, session_id: str) -> None: ...


SessionOperationRequest = (
    GameplayHandoffRequest | CheckpointCaptureRequest | CloseDebugSessionRequest
)


def session_operation_approval_targets(
    request: SessionOperationRequest,
) -> tuple[ApprovalTarget, ...]:
    """Bind one exact debugger operation to executable bytes and session controls."""
    if not isinstance(
        request, (GameplayHandoffRequest, CheckpointCaptureRequest, CloseDebugSessionRequest)
    ):
        raise DebuggerHandoffError("request is invalid")
    identity = request.debugger_identity
    if _hash_file(Path(identity.executable_path)) != identity.executable_sha256:
        raise DebuggerHandoffError("debugger executable identity has changed")
    operation = request.approval_payload()["operation"]
    role = (
        "x64dbg_gameplay_handoff"
        if operation == "prepare_gameplay_handoff"
        else f"x64dbg_{operation}"
    )
    return (
        ApprovalTarget.from_payload(
            role=role,
            path=identity.executable_path,
            proposed_payload=request.approval_payload(),
        ),
    )


def gameplay_handoff_approval_targets(
    request: GameplayHandoffRequest,
) -> tuple[ApprovalTarget, ...]:
    """Bind approval to debugger bytes, provider/session identity, and exact handoff controls."""
    if not isinstance(request, GameplayHandoffRequest):
        raise DebuggerHandoffError("request is invalid")
    return session_operation_approval_targets(request)


def _unexpected(snapshot: DebuggerSnapshot, expected: frozenset[str]) -> set[str]:
    return set(snapshot.active_breakpoints) - expected


def _blockers(
    snapshots: tuple[DebuggerSnapshot, ...], unexpected: set[str]
) -> list[str]:
    blockers: set[str] = set()
    if unexpected:
        blockers.add("UNEXPECTED_BREAKPOINT_ACTIVE")
    for snapshot in snapshots:
        if not snapshot.connected:
            blockers.add("DEBUGGER_DISCONNECTED")
        if not snapshot.debugging:
            blockers.add("DEBUGGER_NOT_DEBUGGING")
        if not snapshot.running:
            blockers.add("DEBUGGER_NOT_RUNNING")
        if snapshot.paused:
            blockers.add("DEBUGGER_PAUSED_AFTER_RESUME")
    return sorted(blockers)


def _receipt(
    request: GameplayHandoffRequest,
    *,
    approval_id: str,
    before: DebuggerSnapshot,
    checks: tuple[DebuggerSnapshot, ...],
    unexpected: set[str],
    blockers: list[str],
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": "kcd2.x64dbg-session-receipt.v1",
        "session_id": request.session_id,
        "operation": "prepare_gameplay_handoff",
        "debugger_identity": request.debugger_identity.to_dict(),
        "debugger_state_before": before.state_name,
        "debugger_state_after": checks[-1].state_name if checks else before.state_name,
        "wait_interval_ms": request.wait_interval_ms,
        "process_running_checks": [snapshot.gameplay_safe for snapshot in checks],
        "debugger_state_checks": [snapshot.to_check() for snapshot in checks],
        "temporary_breakpoints": list(request.temporary_breakpoints),
        "unexpected_breakpoints": sorted(unexpected),
        "cross_tool_identity_id": request.cross_tool_identity_id,
        "result": "PASS" if not blockers and len(checks) == 2 else "BLOCKED",
        "checkpoint_artifact_sha256": None,
        "approval_id": approval_id,
        "blockers": blockers,
    }
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return {"receipt_id": f"x64dbg-handoff:{digest}", **body}


def _prepare_gameplay_handoff_impl(
    request: GameplayHandoffRequest,
    *,
    provider: _HandoffProvider,
    approval_id: str,
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    if provider.identity != request.debugger_identity:
        raise DebuggerHandoffError("live debugger identity differs from the approved request")
    before = provider.inspect(request.session_id)
    if not before.connected or not before.debugging:
        blockers = _blockers((before,), set())
        return _receipt(
            request,
            approval_id=approval_id,
            before=before,
            checks=(),
            unexpected=set(),
            blockers=blockers,
        )
    expected = frozenset(request.temporary_breakpoints)
    unexpected = _unexpected(before, expected)
    if unexpected:
        return _receipt(
            request,
            approval_id=approval_id,
            before=before,
            checks=(),
            unexpected=unexpected,
            blockers=["UNEXPECTED_BREAKPOINT_ACTIVE"],
        )

    provider.resume(request.session_id)
    sleeper(request.wait_interval_ms / 1000)
    checks = (provider.inspect(request.session_id), provider.inspect(request.session_id))
    for snapshot in checks:
        unexpected.update(_unexpected(snapshot, expected))
    blockers = _blockers(checks, unexpected)
    return _receipt(
        request,
        approval_id=approval_id,
        before=before,
        checks=checks,
        unexpected=unexpected,
        blockers=blockers,
    )


def prepare_gameplay_handoff(
    request: GameplayHandoffRequest,
    *,
    provider: _HandoffProvider,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Resume and prove gameplay-safe x64dbg state under one exact approval transaction."""
    if not isinstance(request, GameplayHandoffRequest):
        raise DebuggerHandoffError("request is invalid")
    if not isinstance(approval_verifier, ApprovalVerifier):
        raise DebuggerHandoffError("approval_verifier is invalid")
    if not callable(sleeper):
        raise DebuggerHandoffError("sleeper is invalid")
    targets = gameplay_handoff_approval_targets(request)
    approval_id = approval.get("approval_id") if isinstance(approval, Mapping) else None
    if not isinstance(approval_id, str):
        raise DebuggerHandoffError("approval_id is invalid")
    with _SESSION_LOCK:
        return approval_verifier.execute(
            approval,
            operation="debugger_mutation",
            targets=targets,
            mutation=lambda: _prepare_gameplay_handoff_impl(
                request,
                provider=provider,
                approval_id=approval_id,
                sleeper=sleeper,
            ),
        )


def _approval_id(approval: Mapping[str, object]) -> str:
    value = approval.get("approval_id") if isinstance(approval, Mapping) else None
    if not isinstance(value, str):
        raise DebuggerHandoffError("approval_id is invalid")
    return value


def _require_controller_inputs(
    request: object,
    request_type: type[CheckpointCaptureRequest] | type[CloseDebugSessionRequest],
    approval_verifier: ApprovalVerifier,
) -> None:
    if not isinstance(request, request_type):
        raise DebuggerHandoffError("request is invalid")
    if not isinstance(approval_verifier, ApprovalVerifier):
        raise DebuggerHandoffError("approval_verifier is invalid")


def _capture_checkpoint_impl(
    request: CheckpointCaptureRequest,
    *,
    provider: _CheckpointProvider,
    approval_id: str,
) -> dict[str, Any]:
    if provider.identity != request.debugger_identity:
        raise DebuggerHandoffError("live debugger identity differs from the approved request")
    before = provider.inspect(request.session_id)
    if not before.connected or not before.debugging:
        raise DebuggerHandoffError("capture requires a connected debugging session")
    captured = provider.capture(request)
    if not isinstance(captured, CapturedCheckpoint):
        raise DebuggerHandoffError("provider returned an invalid checkpoint")
    if (
        captured.module_name != request.module_name
        or captured.module_sha256 != request.module_sha256
        or captured.checkpoint_rva != request.checkpoint_rva
    ):
        raise DebuggerHandoffError("captured checkpoint identity differs from the request")
    if captured.byte_count > request.maximum_bytes:
        raise DebuggerHandoffError("capture exceeds the approved byte bound")
    artifact = captured.to_artifact(request)
    artifact_sha256 = hashlib.sha256(_canonical_bytes(artifact)).hexdigest()
    body: dict[str, Any] = {
        "schema_version": "kcd2.x64dbg-session-receipt.v1",
        "session_id": request.session_id,
        "operation": "capture_checkpoint",
        "debugger_identity": request.debugger_identity.to_dict(),
        "debugger_state_before": before.state_name,
        "debugger_state_after": before.state_name,
        "process_running_checks": [],
        "temporary_breakpoints": [],
        "cross_tool_identity_id": request.cross_tool_identity_id,
        "result": "PASS",
        "checkpoint_artifact_sha256": artifact_sha256,
        "checkpoint_artifact": artifact,
        "approval_id": approval_id,
        "blockers": [],
    }
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return {"receipt_id": f"x64dbg-capture:{digest}", **body}


def capture_checkpoint(
    request: CheckpointCaptureRequest,
    *,
    provider: _CheckpointProvider,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
) -> dict[str, Any]:
    """Capture one exact, bounded, module-relative checkpoint under approval."""
    _require_controller_inputs(request, CheckpointCaptureRequest, approval_verifier)
    targets = session_operation_approval_targets(request)
    approval_id = _approval_id(approval)
    with _SESSION_LOCK:
        return approval_verifier.execute(
            approval,
            operation="debugger_mutation",
            targets=targets,
            mutation=lambda: _capture_checkpoint_impl(
                request, provider=provider, approval_id=approval_id
            ),
        )


def _close_blockers(checks: tuple[DebuggerSnapshot, ...]) -> list[str]:
    blockers: set[str] = set()
    for snapshot in checks:
        if snapshot.connected or snapshot.debugging:
            blockers.add("DEBUGGER_STILL_ATTACHED")
        if snapshot.paused:
            blockers.add("GAME_PAUSED_AFTER_DETACH")
        if snapshot.active_breakpoints:
            blockers.add("BREAKPOINT_REMAINS")
    return sorted(blockers)


def _close_debug_session_impl(
    request: CloseDebugSessionRequest,
    *,
    provider: _CloseProvider,
    approval_id: str,
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    if provider.identity != request.debugger_identity:
        raise DebuggerHandoffError("live debugger identity differs from the approved request")
    before = provider.inspect(request.session_id)
    expected = frozenset(request.temporary_breakpoints)
    unexpected = _unexpected(before, expected)
    cleared: list[str] = []
    checks: tuple[DebuggerSnapshot, ...] = ()
    if not unexpected:
        for breakpoint in request.temporary_breakpoints:
            provider.clear_temporary_breakpoint(request.session_id, breakpoint)
            cleared.append(breakpoint)
        if before.connected:
            provider.detach(request.session_id)
        sleeper(request.wait_interval_ms / 1000)
        checks = (provider.inspect(request.session_id), provider.inspect(request.session_id))
    blockers = (
        ["UNEXPECTED_BREAKPOINT_ACTIVE"] if unexpected else _close_blockers(checks)
    )
    cleanup: dict[str, Any] = {
        "schema_version": "kcd2.x64dbg-session-cleanup.v1",
        "session_id": request.session_id,
        "temporary_breakpoints_requested": list(request.temporary_breakpoints),
        "breakpoints_cleared": cleared,
        "detach_attempted": before.connected and not unexpected,
        "verification_checks": [snapshot.to_check() for snapshot in checks],
        "result": "PASS" if not blockers and len(checks) == 2 else "BLOCKED",
        "blockers": blockers,
    }
    body: dict[str, Any] = {
        "schema_version": "kcd2.x64dbg-session-receipt.v1",
        "session_id": request.session_id,
        "operation": "close_debug_session",
        "debugger_identity": request.debugger_identity.to_dict(),
        "debugger_state_before": before.state_name,
        "debugger_state_after": checks[-1].state_name if checks else before.state_name,
        "process_running_checks": [not snapshot.paused for snapshot in checks],
        "debugger_state_checks": [snapshot.to_check() for snapshot in checks],
        "wait_interval_ms": request.wait_interval_ms,
        "temporary_breakpoints": list(request.temporary_breakpoints),
        "breakpoints_cleared": cleared,
        "unexpected_breakpoints": sorted(unexpected),
        "cross_tool_identity_id": request.cross_tool_identity_id,
        "result": cleanup["result"],
        "checkpoint_artifact_sha256": None,
        "approval_id": approval_id,
        "cleanup": cleanup,
        "blockers": blockers,
    }
    digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    return {"receipt_id": f"x64dbg-close:{digest}", **body}


def close_debug_session(
    request: CloseDebugSessionRequest,
    *,
    provider: _CloseProvider,
    approval: Mapping[str, object],
    approval_verifier: ApprovalVerifier,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Clear declared temporary breakpoints, detach, and verify unpaused twice."""
    _require_controller_inputs(request, CloseDebugSessionRequest, approval_verifier)
    if not callable(sleeper):
        raise DebuggerHandoffError("sleeper is invalid")
    targets = session_operation_approval_targets(request)
    approval_id = _approval_id(approval)
    with _SESSION_LOCK:
        return approval_verifier.execute(
            approval,
            operation="debugger_mutation",
            targets=targets,
            mutation=lambda: _close_debug_session_impl(
                request,
                provider=provider,
                approval_id=approval_id,
                sleeper=sleeper,
            ),
        )


__all__ = [
    "DebuggerHandoffError",
    "DebuggerIdentity",
    "DebuggerSnapshot",
    "GameplayHandoffRequest",
    "CapturedCheckpoint",
    "CheckpointCaptureRequest",
    "CloseDebugSessionRequest",
    "capture_checkpoint",
    "close_debug_session",
    "gameplay_handoff_approval_targets",
    "prepare_gameplay_handoff",
    "session_operation_approval_targets",
]
