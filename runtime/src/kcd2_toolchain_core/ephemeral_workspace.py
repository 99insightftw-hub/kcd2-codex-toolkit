"""Governed temporary workspaces for isolated read-only analysis copies."""

from __future__ import annotations

import copy
import os
import re
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .atomic import atomic_write_bytes
from .cross_tool_identity import CrossToolIdentity, bind_cross_tool_identity
from .hashing import sha256_file, sha256_json
from .paths import canonical_relative_path


_SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_WRITABLE_NAMESPACES = frozenset({"parsed", "reports"})
_COPY_NAMESPACES = frozenset({"inputs", "extracted"})


class WorkspacePolicyError(ValueError):
    """The requested workspace or member violates the analysis-only policy."""


class WorkspaceCleanupError(RuntimeError):
    """An ephemeral workspace could not be deterministically removed."""


class EphemeralAnalysisWorkspace:
    """A deterministic temp-root workspace that never writes its source or a candidate."""

    def __init__(
        self,
        *,
        approved_temp_root: str | Path,
        repository_root: str | Path,
        identity: Mapping[str, Any] | CrossToolIdentity,
        operation_id: str,
        cleanup_receipt_id: str,
    ) -> None:
        self.identity = bind_cross_tool_identity(identity)
        if _SAFE_OPERATION_ID.fullmatch(operation_id) is None:
            raise WorkspacePolicyError("operation_id contains unsafe workspace characters")
        self.operation_id = operation_id
        if cleanup_receipt_id not in self.identity.to_dict()["receipt_ids"]:
            raise WorkspacePolicyError("cleanup_receipt_id is not declared by the identity")
        self.cleanup_receipt_id = cleanup_receipt_id

        repository = Path(repository_root).resolve(strict=True)
        approved = Path(approved_temp_root).resolve(strict=False)
        overlaps_repository = (
            approved == repository
            or approved.is_relative_to(repository)
            or repository.is_relative_to(approved)
        )
        if overlaps_repository:
            raise WorkspacePolicyError(
                "approved_temp_root must be outside and must not contain the repository"
            )
        self.approved_temp_root = approved
        workspace_key = sha256_json(
            {
                "identity_id": self.identity.identity_id,
                "operation_id": operation_id,
                "cleanup_receipt_id": cleanup_receipt_id,
            }
        )
        self.workspace_name = f"analysis-{workspace_key}"
        self.root = approved / self.workspace_name
        self._entered = False
        self._cleanup_receipt: dict[str, Any] | None = None

    @property
    def cleanup_receipt(self) -> dict[str, Any]:
        if self._cleanup_receipt is None:
            raise WorkspacePolicyError("cleanup has not completed")
        return copy.deepcopy(self._cleanup_receipt)

    def __enter__(self) -> EphemeralAnalysisWorkspace:
        if self._entered:
            raise WorkspacePolicyError("workspace cannot be entered more than once")
        self.approved_temp_root.mkdir(parents=True, exist_ok=True)
        if self.approved_temp_root.resolve(strict=True) != self.approved_temp_root:
            raise WorkspacePolicyError("approved_temp_root resolved unexpectedly")
        try:
            self.root.mkdir()
        except FileExistsError as error:
            raise WorkspacePolicyError(
                "deterministic workspace already exists; cleanup or change operation_id: "
                f"{self.root.name}"
            ) from error
        self._entered = True
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.cleanup()

    def _destination(self, relative_path: str, namespaces: frozenset[str]) -> Path:
        if not self._entered or self._cleanup_receipt is not None or not self.root.is_dir():
            raise WorkspacePolicyError("workspace is not active")
        try:
            canonical = canonical_relative_path(relative_path)
        except (TypeError, ValueError) as error:
            raise WorkspacePolicyError(str(error)) from error
        namespace = canonical.split("/", 1)[0]
        if namespace not in namespaces:
            allowed = ", ".join(sorted(namespaces))
            raise WorkspacePolicyError(
                f"workspace member namespace {namespace!r} is not allowed; "
                f"expected one of {allowed}"
            )
        destination = self.root.joinpath(*canonical.split("/"))
        if not destination.resolve(strict=False).is_relative_to(self.root):
            raise WorkspacePolicyError("workspace member escapes the deterministic root")
        if destination.exists():
            raise WorkspacePolicyError("workspace members are immutable after creation")
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination

    def copy_input(self, source: str | Path, relative_path: str) -> Path:
        """Copy one source file without modifying it, rejecting a concurrent source drift."""
        source_path = Path(source).resolve(strict=True)
        if not source_path.is_file():
            raise WorkspacePolicyError("analysis input must be a regular file")
        if source_path.is_relative_to(self.root):
            raise WorkspacePolicyError("analysis input must be outside the workspace")
        destination = self._destination(relative_path, _COPY_NAMESPACES)
        before = sha256_file(source_path)
        shutil.copyfile(source_path, destination)
        after = sha256_file(source_path)
        copied = sha256_file(destination)
        if before != after or copied != before:
            destination.unlink(missing_ok=True)
            raise WorkspacePolicyError("analysis input changed while it was copied")
        return destination

    def write_analysis_bytes(self, relative_path: str, data: bytes) -> Path:
        """Write derived parsing/report bytes only; candidate/build namespaces are unavailable."""
        if not isinstance(data, bytes):
            raise TypeError("analysis data must be bytes")
        destination = self._destination(relative_path, _WRITABLE_NAMESPACES)
        atomic_write_bytes(destination, data)
        return destination

    def _members(self) -> list[dict[str, Any]]:
        members: list[dict[str, Any]] = []
        if not self.root.exists():
            return members
        for directory, names, files in os.walk(self.root, topdown=True, followlinks=False):
            names.sort()
            files.sort()
            base = Path(directory)
            for name in files:
                path = base / name
                relative = path.relative_to(self.root).as_posix()
                if path.is_symlink():
                    members.append(
                        {
                            "relative_path": relative,
                            "kind": "symbolic_link",
                            "sha256": None,
                            "bytes": 0,
                        }
                    )
                else:
                    members.append(
                        {
                            "relative_path": relative,
                            "kind": "file",
                            "sha256": sha256_file(path),
                            "bytes": path.stat().st_size,
                        }
                    )
            for name in tuple(names):
                path = base / name
                if path.is_symlink():
                    relative = path.relative_to(self.root).as_posix()
                    members.append(
                        {
                            "relative_path": relative,
                            "kind": "symbolic_link",
                            "sha256": None,
                            "bytes": 0,
                        }
                    )
                    names.remove(name)
        members.sort(key=lambda item: item["relative_path"])
        return members

    def cleanup(self) -> dict[str, Any]:
        """Remove exactly this workspace and return the same receipt on repeated calls."""
        if self._cleanup_receipt is not None:
            return copy.deepcopy(self._cleanup_receipt)
        if not self._entered:
            raise WorkspacePolicyError("workspace was never entered")

        members = self._members()
        errors: list[str] = []
        try:
            shutil.rmtree(self.root)
        except OSError as error:
            errors.append(f"{type(error).__name__}: {error}")
        exists_after = self.root.exists()
        state = "CLEANED" if not errors and not exists_after else "CLEANUP_FAILED"
        receipt = self.identity.bind_receipt(
            {
                "schema_version": "kcd2.ephemeral-workspace-cleanup.v1",
                "receipt_id": self.cleanup_receipt_id,
                "workspace_classification": "EPHEMERAL_READ_ONLY_ANALYSIS",
                "operation_id": self.operation_id,
                "workspace_name": self.workspace_name,
                "source_access": "READ_ONLY_COPY",
                "candidate_build_mutation": False,
                "allowed_namespaces": sorted(_COPY_NAMESPACES | _WRITABLE_NAMESPACES),
                "members_removed": members,
                "cleanup_state": state,
                "cleanup_errors": errors,
                "workspace_exists_after_cleanup": exists_after,
            }
        )
        self._cleanup_receipt = receipt
        if state != "CLEANED":
            raise WorkspaceCleanupError("ephemeral analysis workspace cleanup failed")
        return copy.deepcopy(receipt)
