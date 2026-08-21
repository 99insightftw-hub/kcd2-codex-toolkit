"""Bounded content-addressed cache for immutable PAK member bytes."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import threading
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


class ArchiveMemberCacheError(ValueError):
    """The archive or its private cache entry is unsafe or invalid."""


@dataclass(frozen=True, slots=True)
class ArchiveMemberCacheResult:
    members: Mapping[str, bytes]
    cache_status: str
    manifest_sha256: str


def read_archive_members_cached(
    archive_path: Path | str,
    *,
    archive_sha256: str,
    cache_root: Path | str,
    max_members: int,
    max_member_bytes: int,
    max_total_bytes: int,
) -> ArchiveMemberCacheResult:
    """Return verified member bytes, populating an explicit private cache on a miss."""
    digest = _digest(archive_sha256)
    root = Path(cache_root)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    if _is_reparse(root):
        raise ArchiveMemberCacheError("archive cache root must not be a reparse point")
    entry = root / digest
    if entry.exists():
        try:
            members, manifest_sha = _load_entry(
                entry,
                digest,
                max_members=max_members,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes,
            )
            return ArchiveMemberCacheResult(members, "HIT_VERIFIED", manifest_sha)
        except ArchiveMemberCacheError:
            if _is_reparse(entry):
                raise
            quarantine = root / f"{digest}.invalid-{uuid.uuid4().hex}"
            entry.replace(quarantine)

    members = _read_archive(
        Path(archive_path),
        max_members=max_members,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
    )
    temporary = root / f".{digest}.tmp-{os.getpid()}-{threading.get_ident()}-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        objects = temporary / "objects"
        objects.mkdir()
        entries: list[dict[str, Any]] = []
        for logical_path, data in sorted(members.items(), key=lambda item: item[0].encode("utf-8")):
            member_sha = hashlib.sha256(data).hexdigest()
            object_path = objects / f"{member_sha}.bin"
            if not object_path.exists():
                object_path.write_bytes(data)
            entries.append(
                {"logical_path": logical_path, "sha256": member_sha, "bytes": len(data)}
            )
        manifest = {
            "schema_version": "kcd2.archive-member-cache.v1",
            "archive_sha256": digest,
            "member_count": len(entries),
            "total_bytes": sum(item["bytes"] for item in entries),
            "members": entries,
        }
        manifest_bytes = _canonical_bytes(manifest)
        (temporary / "manifest.json").write_bytes(manifest_bytes)
        try:
            temporary.replace(entry)
        except FileExistsError:
            shutil.rmtree(temporary)
        verified, manifest_sha = _load_entry(
            entry,
            digest,
            max_members=max_members,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
        return ArchiveMemberCacheResult(verified, "MISS_POPULATED", manifest_sha)
    except Exception:
        if temporary.exists() and not _is_reparse(temporary):
            shutil.rmtree(temporary)
        raise


def _load_entry(
    entry: Path,
    archive_sha256: str,
    *,
    max_members: int,
    max_member_bytes: int,
    max_total_bytes: int,
) -> tuple[dict[str, bytes], str]:
    if not entry.is_dir() or _is_reparse(entry):
        raise ArchiveMemberCacheError("archive cache entry must be a regular directory")
    manifest_path = entry / "manifest.json"
    try:
        manifest_bytes = manifest_path.read_bytes()
        if len(manifest_bytes) > 16 * 1024 * 1024:
            raise ArchiveMemberCacheError("archive cache manifest exceeds its bound")
        manifest = json.loads(manifest_bytes)
    except (OSError, ValueError) as exc:
        raise ArchiveMemberCacheError("archive cache manifest is unreadable") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "kcd2.archive-member-cache.v1"
        or manifest.get("archive_sha256") != archive_sha256
        or not isinstance(manifest.get("members"), list)
        or manifest.get("member_count") != len(manifest["members"])
        or len(manifest["members"]) > max_members
    ):
        raise ArchiveMemberCacheError("archive cache manifest identity is invalid")
    members: dict[str, bytes] = {}
    total = 0
    folded: set[str] = set()
    for item in manifest["members"]:
        if not isinstance(item, dict) or set(item) != {"logical_path", "sha256", "bytes"}:
            raise ArchiveMemberCacheError("archive cache member ledger is invalid")
        logical = _member_path(item["logical_path"])
        key = logical.casefold()
        if key in folded:
            raise ArchiveMemberCacheError("archive cache has colliding member paths")
        folded.add(key)
        member_sha = _digest(item["sha256"])
        size = item["bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or not 0 <= size <= max_member_bytes:
            raise ArchiveMemberCacheError("archive cache member size is invalid")
        object_path = entry / "objects" / f"{member_sha}.bin"
        if _is_reparse(object_path):
            raise ArchiveMemberCacheError("archive cache objects must not be reparse points")
        try:
            data = object_path.read_bytes()
        except OSError as exc:
            raise ArchiveMemberCacheError("archive cache object is unreadable") from exc
        if len(data) != size or hashlib.sha256(data).hexdigest() != member_sha:
            raise ArchiveMemberCacheError("archive cache object identity mismatch")
        total += size
        if total > max_total_bytes:
            raise ArchiveMemberCacheError("archive cache exceeds its total byte bound")
        members[logical] = data
    if manifest.get("total_bytes") != total:
        raise ArchiveMemberCacheError("archive cache total byte ledger is invalid")
    return members, hashlib.sha256(manifest_bytes).hexdigest()


def _read_archive(
    path: Path, *, max_members: int, max_member_bytes: int, max_total_bytes: int
) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            items = [item for item in archive.infolist() if not item.is_dir()]
            if len(items) > max_members:
                raise ArchiveMemberCacheError("archive exceeds its member bound")
            folded: set[str] = set()
            for item in items:
                logical = _member_path(item.filename)
                if logical.casefold() in folded:
                    raise ArchiveMemberCacheError("archive has colliding member paths")
                folded.add(logical.casefold())
                if item.flag_bits & 0x1 or item.compress_type not in {
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                }:
                    raise ArchiveMemberCacheError("archive member encoding is unsupported")
                if item.file_size > max_member_bytes:
                    raise ArchiveMemberCacheError("archive member exceeds its byte bound")
                total += item.file_size
                if total > max_total_bytes:
                    raise ArchiveMemberCacheError("archive exceeds its total byte bound")
                data = archive.read(item)
                if len(data) != item.file_size:
                    raise ArchiveMemberCacheError("archive member size changed while reading")
                members[logical] = data
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ArchiveMemberCacheError(f"could not read archive: {exc}") from exc
    return members


def _member_path(value: object) -> str:
    if not isinstance(value, str):
        raise ArchiveMemberCacheError("archive member path must be text")
    path = PurePosixPath(value)
    if (
        not value
        or len(value) > 4096
        or "\\" in value
        or "\x00" in value
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or (len(value) > 1 and value[1] == ":")
    ):
        raise ArchiveMemberCacheError("archive member path is noncanonical")
    return value


def _digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        raise ArchiveMemberCacheError("SHA-256 identity must be 64 hexadecimal characters")
    return value.lower()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _is_reparse(path: Path) -> bool:
    try:
        return bool(path.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, FileNotFoundError):
        return path.is_symlink()

