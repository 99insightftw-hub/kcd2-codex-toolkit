"""One-time, content-bound authorization for every persistent mutation boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath
from typing import Any, Literal, TypeVar


Operation = Literal[
    "build_candidate",
    "repack_package",
    "install_candidate",
    "replace_candidate",
    "rollback",
    "install_plugin",
    "restore_plugin",
    "persistent_index_write",
    "persistent_graph_write",
    "deploy_native_component",
    "debugger_mutation",
]
DebuggerState = Literal[
    "not_running",
    "detached",
    "connected_running",
    "connected_paused",
    "not_applicable",
]

ALLOWED_OPERATIONS = frozenset(Operation.__args__)
ALLOWED_DEBUGGER_STATES = frozenset(DebuggerState.__args__)
GAME_CLOSED_OPERATIONS = frozenset(
    {
        "install_candidate",
        "replace_candidate",
        "rollback",
        "install_plugin",
        "restore_plugin",
        "deploy_native_component",
    }
)
MAX_TARGETS = 256
MAX_PROCESS_NAMES = 4096
MAX_PROCESS_OBSERVATION_AGE = timedelta(seconds=5)
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_NONCE = re.compile(r"[A-Za-z0-9._~+/-]{16,256}")
_T = TypeVar("_T")


class ApprovalError(RuntimeError):
    """The mutation approval did not exactly authorize the requested transaction."""


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
        raise ApprovalError("approval is not canonical-JSON serializable") from exc


def approval_binding_sha256(approval: Mapping[str, object]) -> str:
    """Hash every approval field except the self-referential binding digest."""
    if not isinstance(approval, Mapping):
        raise ApprovalError("approval must be an object")
    payload = dict(approval)
    payload.pop("binding_sha256", None)
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _portable_resolved(path: Path | str) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise ApprovalError("target path must be path-like")
    value = Path(path)
    try:
        resolved = value.resolve(strict=False)
    except OSError as exc:
        raise ApprovalError("target path could not be resolved") from exc
    if "\x00" in str(resolved):
        raise ApprovalError("target path contains NUL")
    return resolved.as_posix()


def _path_identity(path: Path) -> str | None:
    if not path.exists() and not path.is_symlink():
        return None
    try:
        info = path.lstat()
    except OSError as exc:
        raise ApprovalError("target identity could not be read") from exc
    if _is_reparse(info):
        raise ApprovalError("approval targets must not be symlinks or reparse points")
    if path.is_file():
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    if not path.is_dir():
        raise ApprovalError("approval target is neither a regular file nor directory")
    digest = hashlib.sha256()
    for child in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = child.relative_to(path).as_posix()
        child_info = child.lstat()
        if _is_reparse(child_info):
            raise ApprovalError("approval target tree contains a symlink or reparse point")
        kind = b"D" if child.is_dir() else b"F" if child.is_file() else None
        if kind is None:
            raise ApprovalError("approval target tree contains a special filesystem entry")
        digest.update(kind + b"\0" + relative.encode("utf-8") + b"\0")
        if kind == b"F":
            child_digest = hashlib.sha256()
            with child.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    child_digest.update(chunk)
            digest.update(str(child_info.st_size).encode("ascii"))
            digest.update(b"\0" + child_digest.digest())
    return digest.hexdigest()


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


@dataclass(frozen=True, slots=True)
class ApprovalTarget:
    role: str
    path: str
    expected_current_sha256: str | None
    proposed_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.role, str) or not 1 <= len(self.role) <= 128 or "\x00" in self.role:
            raise ApprovalError("target role is invalid")
        canonical = _portable_resolved(self.path)
        object.__setattr__(self, "path", canonical)
        for field in ("expected_current_sha256", "proposed_sha256"):
            value = getattr(self, field)
            if value is not None and (not isinstance(value, str) or _SHA256.fullmatch(value) is None):
                raise ApprovalError(f"target {field} is invalid")
            if value is not None:
                object.__setattr__(self, field, value.lower())

    @classmethod
    def from_payload(
        cls,
        *,
        role: str,
        path: Path | str,
        proposed_payload: object,
    ) -> ApprovalTarget:
        target = Path(path).resolve(strict=False)
        return cls(
            role=role,
            path=target.as_posix(),
            expected_current_sha256=_path_identity(target),
            proposed_sha256=hashlib.sha256(_canonical_bytes(proposed_payload)).hexdigest(),
        )

    @classmethod
    def from_bytes(
        cls,
        *,
        role: str,
        path: Path | str,
        proposed_bytes: bytes,
    ) -> ApprovalTarget:
        if not isinstance(proposed_bytes, bytes):
            raise ApprovalError("proposed_bytes must be bytes")
        target = Path(path).resolve(strict=False)
        return cls(
            role=role,
            path=target.as_posix(),
            expected_current_sha256=_path_identity(target),
            proposed_sha256=hashlib.sha256(proposed_bytes).hexdigest(),
        )

    @classmethod
    def from_paths(
        cls,
        *,
        role: str,
        path: Path | str,
        proposed_path: Path | str | None = None,
    ) -> ApprovalTarget:
        target = Path(path).resolve(strict=False)
        proposed = None if proposed_path is None else _path_identity(Path(proposed_path))
        return cls(
            role=role,
            path=target.as_posix(),
            expected_current_sha256=_path_identity(target),
            proposed_sha256=proposed,
        )

    def recheck(self, *, proposed_path: Path | str | None = None) -> ApprovalTarget:
        return ApprovalTarget.from_paths(
            role=self.role,
            path=self.path,
            proposed_path=proposed_path,
        )

    def to_record(self) -> dict[str, str | None]:
        return {
            "role": self.role,
            "path": self.path,
            "expected_current_sha256": self.expected_current_sha256,
            "proposed_sha256": self.proposed_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProcessStateSnapshot:
    observed_at: datetime
    game_running: bool
    debugger_state: DebuggerState
    running_processes: tuple[str, ...]

    def __post_init__(self) -> None:
        observed = self.observed_at
        if not isinstance(observed, datetime) or observed.tzinfo is None:
            raise ApprovalError("process observation timestamp must be timezone-aware")
        object.__setattr__(self, "observed_at", observed.astimezone(timezone.utc))
        if not isinstance(self.game_running, bool):
            raise ApprovalError("game_running must be boolean")
        if self.debugger_state not in ALLOWED_DEBUGGER_STATES:
            raise ApprovalError("debugger_state is invalid")
        names = tuple(self.running_processes)
        if len(names) > MAX_PROCESS_NAMES or any(
            not isinstance(name, str) or not 1 <= len(name) <= 260 or "\x00" in name
            for name in names
        ):
            raise ApprovalError("running process inventory is invalid")
        object.__setattr__(self, "running_processes", tuple(sorted(set(names))))


class DirectProcessStateProbe:
    """Enumerate OS processes at call time; never accept a caller acknowledgement."""

    def __init__(
        self,
        *,
        game_process_names: Sequence[str] = ("KingdomCome.exe",),
        debugger_process_names: Sequence[str] = ("x64dbg.exe", "x32dbg.exe"),
        debugger_inspector: Callable[[], DebuggerState] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._game = frozenset(name.casefold() for name in game_process_names)
        self._debugger = frozenset(name.casefold() for name in debugger_process_names)
        self._debugger_inspector = debugger_inspector
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def __call__(self) -> ProcessStateSnapshot:
        names = tuple(_running_process_names())
        folded = {name.casefold() for name in names}
        debugger_running = bool(folded & self._debugger)
        if self._debugger_inspector is not None:
            debugger_state = self._debugger_inspector()
        else:
            debugger_state = "detached" if debugger_running else "not_running"
        return ProcessStateSnapshot(
            observed_at=self._clock(),
            game_running=bool(folded & self._game),
            debugger_state=debugger_state,
            running_processes=names,
        )


def _running_process_names() -> tuple[str, ...]:
    if sys.platform == "win32":
        return _windows_process_names()
    proc = Path("/proc")
    if not proc.is_dir():
        raise ApprovalError("direct process enumeration is unavailable")
    names: list[str] = []
    try:
        entries = list(proc.iterdir())
    except OSError as exc:
        raise ApprovalError("direct process enumeration failed") from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name:
            names.append(name)
        if len(names) > MAX_PROCESS_NAMES:
            raise ApprovalError("direct process enumeration exceeded its hard bound")
    return tuple(sorted(set(names)))


def _windows_process_names() -> tuple[str, ...]:
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid = ctypes.c_void_p(-1).value
    if snapshot == invalid:
        raise ApprovalError("direct process enumeration failed")
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    names: list[str] = []
    try:
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            names.append(entry.szExeFile)
            if len(names) > MAX_PROCESS_NAMES:
                raise ApprovalError("direct process enumeration exceeded its hard bound")
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return tuple(sorted(set(names)))


class ApprovalLedger:
    """Atomic nonce consumption, optionally durable across processes via claim files."""

    def __init__(self, directory: Path | str | None = None) -> None:
        self._consumed: set[tuple[str, str]] = set()
        self._lock = threading.Lock()
        self._directory = None if directory is None else Path(directory).resolve(strict=False)
        if self._directory is not None:
            self._directory.mkdir(parents=True, exist_ok=True)

    def consume(self, approval_id: str, nonce: str) -> None:
        key = (approval_id, nonce)
        with self._lock:
            if key in self._consumed:
                raise ApprovalError("approval nonce has already been consumed")
            if self._directory is not None:
                claim_name = hashlib.sha256(_canonical_bytes(key)).hexdigest() + ".consumed"
                claim = self._directory / claim_name
                try:
                    with claim.open("xb") as stream:
                        stream.write(_canonical_bytes({"approval_id": approval_id, "nonce": nonce}))
                except FileExistsError as exc:
                    raise ApprovalError("approval nonce has already been consumed") from exc
                except OSError as exc:
                    raise ApprovalError("approval nonce could not be durably consumed") from exc
            self._consumed.add(key)


class ApprovalVerifier:
    """Validate exact content, probe process state, consume once, then mutate."""

    def __init__(
        self,
        *,
        process_probe: Callable[[], ProcessStateSnapshot] | None = None,
        ledger: ApprovalLedger | None = None,
        clock: Callable[[], datetime] | None = None,
        max_process_observation_age: timedelta = MAX_PROCESS_OBSERVATION_AGE,
    ) -> None:
        self._probe = process_probe or DirectProcessStateProbe()
        self._ledger = ledger or ApprovalLedger()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._maximum_age = max_process_observation_age

    def execute(
        self,
        approval: Mapping[str, object],
        *,
        operation: Operation,
        targets: Sequence[ApprovalTarget],
        mutation: Callable[[], _T],
    ) -> _T:
        """Run ``mutation`` only after the last possible direct safety check."""
        checked = self._validate_document(approval, operation=operation, targets=targets)
        snapshot = self._probe()
        checked_now = self._now()
        age = checked_now - snapshot.observed_at
        if age < timedelta(0) or age > self._maximum_age:
            raise ApprovalError("direct process state observation is not current")
        expected = checked["process_preconditions"]
        if (
            snapshot.game_running is not expected["game_running"]
            or snapshot.debugger_state != expected["debugger_state"]
        ):
            raise ApprovalError("direct process state differs from approval preconditions")
        self._ledger.consume(str(checked["approval_id"]), str(checked["nonce"]))
        return mutation()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ApprovalError("approval verifier clock must be timezone-aware")
        return value.astimezone(timezone.utc)

    def _validate_document(
        self,
        approval: Mapping[str, object],
        *,
        operation: Operation,
        targets: Sequence[ApprovalTarget],
    ) -> dict[str, Any]:
        if not isinstance(approval, Mapping):
            raise ApprovalError("approval must be an object")
        checked = dict(approval)
        required = {
            "schema_version", "approval_id", "operation", "decision", "issued_at",
            "nonce", "targets", "process_preconditions", "user_decision", "consumed",
            "binding_sha256",
        }
        allowed = required | {"expires_at", "requester"}
        if set(checked) - allowed or not required.issubset(checked):
            raise ApprovalError("approval fields do not match the v1 contract")
        binding = checked.get("binding_sha256")
        if not isinstance(binding, str) or _SHA256.fullmatch(binding) is None:
            raise ApprovalError("approval binding is invalid")
        if approval_binding_sha256(checked) != binding.lower():
            raise ApprovalError("approval binding does not match its content")
        if checked["schema_version"] != "kcd2.transaction-approval.v1":
            raise ApprovalError("approval schema_version is unsupported")
        if checked["decision"] != "approved" or checked["consumed"] is not False:
            raise ApprovalError("approval is not an unconsumed approved decision")
        approval_id = checked["approval_id"]
        if not isinstance(approval_id, str) or not 1 <= len(approval_id) <= 256:
            raise ApprovalError("approval_id is invalid")
        nonce = checked["nonce"]
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise ApprovalError("approval nonce is invalid")
        if operation not in ALLOWED_OPERATIONS or checked["operation"] != operation:
            raise ApprovalError("approval operation differs from the mutation")
        self._validate_time_window(checked)
        records = checked["targets"]
        target_tuple = tuple(targets)
        if (
            not isinstance(records, list)
            or not 1 <= len(records) <= MAX_TARGETS
            or len(records) != len(target_tuple)
        ):
            raise ApprovalError("approval target set is invalid")
        expected_records = [target.to_record() for target in target_tuple]
        if records != expected_records:
            raise ApprovalError("approval target path or hash differs from current content")
        process = checked["process_preconditions"]
        if (
            not isinstance(process, Mapping)
            or set(process) != {"game_running", "debugger_state"}
            or not isinstance(process.get("game_running"), bool)
            or process.get("debugger_state") not in ALLOWED_DEBUGGER_STATES
        ):
            raise ApprovalError("approval process preconditions are invalid")
        if operation in GAME_CLOSED_OPERATIONS and process["game_running"] is not False:
            raise ApprovalError(f"{operation} requires a game-closed process precondition")
        decision = checked["user_decision"]
        if not isinstance(decision, str) or not 1 <= len(decision) <= 8192:
            raise ApprovalError("approval user_decision is invalid")
        return checked

    def _validate_time_window(self, approval: Mapping[str, object]) -> None:
        issued = _timestamp(approval.get("issued_at"), "issued_at")
        expires_raw = approval.get("expires_at")
        expires = None if expires_raw is None else _timestamp(expires_raw, "expires_at")
        now = self._now()
        if issued > now:
            raise ApprovalError("approval has not been issued yet")
        if expires is not None and (expires < issued or now > expires):
            raise ApprovalError("approval has expired")


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ApprovalError(f"approval {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalError(f"approval {field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ApprovalError(f"approval {field} must include a timezone")
    return parsed.astimezone(timezone.utc)


__all__ = [
    "ALLOWED_DEBUGGER_STATES",
    "ALLOWED_OPERATIONS",
    "ApprovalError",
    "ApprovalLedger",
    "ApprovalTarget",
    "ApprovalVerifier",
    "DirectProcessStateProbe",
    "ProcessStateSnapshot",
    "approval_binding_sha256",
]
