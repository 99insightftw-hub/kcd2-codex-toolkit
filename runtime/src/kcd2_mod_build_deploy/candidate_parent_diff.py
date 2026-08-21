"""Bounded, deterministic comparison of a candidate PAK with its declared parent."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping
from xml.etree import ElementTree as ET

from .archive_member_cache import ArchiveMemberCacheError, read_archive_members_cached
from .build_spec import parse_build_spec


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBERS = 16_384
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_XML_BYTES = 32 * 1024 * 1024

Comparison = Literal["clean_parent_to_declared_parent", "declared_parent_to_candidate"]


class CandidateParentDiffError(ValueError):
    """The requested comparison is invalid or exceeds a hard safety bound."""


@dataclass(frozen=True, slots=True)
class DiffLedgerEntry:
    comparison: Comparison
    member_path: str
    kind: str
    declared: bool
    selector: str | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison": self.comparison,
            "member_path": self.member_path,
            "kind": self.kind,
            "declared": self.declared,
            "selector": self.selector,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class CandidateParentDiffReport:
    status: Literal["PASS", "FAIL"]
    spec_id: str
    parent_sha256: str
    candidate_sha256: str
    clean_parent_sha256: str | None
    parent_contamination_detected: bool
    ledger: tuple[DiffLedgerEntry, ...]
    human_report: str
    ledger_path: Path | None = None
    report_path: Path | None = None
    archive_cache: tuple[Mapping[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.candidate-parent-diff-ledger.v1",
            "status": self.status,
            "spec_id": self.spec_id,
            "parent_sha256": self.parent_sha256,
            "candidate_sha256": self.candidate_sha256,
            "clean_parent_sha256": self.clean_parent_sha256,
            "parent_contamination_detected": self.parent_contamination_detected,
            "summary": {
                "entry_count": len(self.ledger),
                "undeclared_change_count": sum(
                    entry.kind != "byte_identical" and not entry.declared
                    for entry in self.ledger
                ),
                "identical_member_count": sum(
                    entry.kind == "byte_identical"
                    and entry.comparison == "declared_parent_to_candidate"
                    for entry in self.ledger
                ),
            },
            "entries": [entry.to_dict() for entry in self.ledger],
            "archive_cache": [dict(item) for item in self.archive_cache],
        }


@dataclass(frozen=True, slots=True)
class _Member:
    data: bytes
    sha256: str


def candidate_parent_diff(
    build_spec: Mapping[str, Any],
    parent_pak: Path | str,
    candidate_pak: Path | str,
    *,
    clean_parent_pak: Path | str | None = None,
    expected_clean_parent_sha256: str | None = None,
    output_directory: Path | str | None = None,
    archive_cache_root: Path | str | None = None,
    max_members: int = MAX_MEMBERS,
    max_member_bytes: int = MAX_MEMBER_BYTES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
) -> CandidateParentDiffReport:
    """Compare immutable archives and fail closed on every undeclared child change.

    When ``clean_parent_pak`` is supplied, its comparison with the declared parent is
    retained as a separate ledger layer. A valid child patch therefore cannot hide
    inherited parent contamination.
    """
    _bound("max_members", max_members, MAX_MEMBERS)
    _bound("max_member_bytes", max_member_bytes, MAX_MEMBER_BYTES)
    _bound(
        "max_total_uncompressed_bytes",
        max_total_uncompressed_bytes,
        MAX_TOTAL_UNCOMPRESSED_BYTES,
    )
    if not isinstance(build_spec, Mapping):
        raise CandidateParentDiffError("build_spec must be a declarative JSON mapping")
    try:
        detached_spec = json.loads(
            json.dumps(build_spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        )
    except (TypeError, ValueError) as exc:
        raise CandidateParentDiffError("build_spec must contain JSON values only") from exc
    parsed = parse_build_spec(detached_spec)
    if not parsed.valid or parsed.spec is None:
        codes = ", ".join(item.code for item in parsed.diagnostics)
        raise CandidateParentDiffError(f"build specification is invalid: {codes}")
    if parsed.spec.parent.mode != "derived_candidate":
        raise CandidateParentDiffError("candidate parent diff requires a derived_candidate spec")

    parent_path = Path(parent_pak)
    candidate_path = Path(candidate_pak)
    parent_hash = _hash_file_bounded(parent_path)
    candidate_hash = _hash_file_bounded(candidate_path)
    expected_parent = parsed.spec.parent.artifact_sha256
    if expected_parent is None or parent_hash.lower() != expected_parent.lower():
        raise CandidateParentDiffError(
            "declared parent artifact SHA-256 does not match the supplied parent PAK"
        )
    cache_events: list[Mapping[str, str]] = []
    parent_members = _read_parent_archive(
        parent_path,
        parent_hash,
        archive_cache_root,
        "declared_parent",
        cache_events,
        max_members,
        max_member_bytes,
        max_total_uncompressed_bytes,
    )
    candidate_members = _read_archive(
        candidate_path, max_members, max_member_bytes, max_total_uncompressed_bytes
    )

    declarations = _declarations(detached_spec)
    ledger: list[DiffLedgerEntry] = []
    contamination = False
    clean_hash: str | None = None
    if clean_parent_pak is not None:
        clean_path = Path(clean_parent_pak)
        clean_hash = _hash_file_bounded(clean_path)
        if expected_clean_parent_sha256 is None:
            raise CandidateParentDiffError(
                "expected_clean_parent_sha256 is required with clean_parent_pak"
            )
        if clean_hash.lower() != expected_clean_parent_sha256.lower():
            raise CandidateParentDiffError("clean parent SHA-256 does not match its declaration")
        clean_members = _read_parent_archive(
            clean_path,
            clean_hash,
            archive_cache_root,
            "clean_parent",
            cache_events,
            max_members,
            max_member_bytes,
            max_total_uncompressed_bytes,
        )
        baseline_entries = _compare_members(
            clean_members,
            parent_members,
            "clean_parent_to_declared_parent",
            {},
        )
        ledger.extend(baseline_entries)
        contamination = any(entry.kind != "byte_identical" for entry in baseline_entries)
    elif expected_clean_parent_sha256 is not None:
        raise CandidateParentDiffError(
            "clean_parent_pak is required with expected_clean_parent_sha256"
        )

    ledger.extend(
        _compare_members(
            parent_members,
            candidate_members,
            "declared_parent_to_candidate",
            declarations,
        )
    )
    ledger.sort(key=_entry_sort_key)
    undeclared = [
        entry for entry in ledger if entry.kind != "byte_identical" and not entry.declared
    ]
    status: Literal["PASS", "FAIL"] = "FAIL" if undeclared or contamination else "PASS"
    human = _render_human_report(
        status, parsed.spec.spec_id, ledger, contamination, parent_hash, candidate_hash
    )
    report = CandidateParentDiffReport(
        status,
        parsed.spec.spec_id,
        parent_hash,
        candidate_hash,
        clean_hash,
        contamination,
        tuple(ledger),
        human,
        archive_cache=tuple(cache_events),
    )
    if output_directory is None:
        return report
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    ledger_path = output / "candidate-parent-diff-ledger.json"
    report_path = output / "candidate-parent-diff-report.md"
    _atomic_text(
        ledger_path,
        json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")) + "\n",
    )
    _atomic_text(report_path, human)
    return CandidateParentDiffReport(
        report.status,
        report.spec_id,
        report.parent_sha256,
        report.candidate_sha256,
        report.clean_parent_sha256,
        report.parent_contamination_detected,
        report.ledger,
        report.human_report,
        ledger_path,
        report_path,
        report.archive_cache,
    )


def _declarations(spec: Mapping[str, Any]) -> dict[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for change in spec["allowed_changes"]:
        kind = change["change_kind"]
        if kind == "add_external_component" or kind == "remove_external_component":
            continue
        grouped.setdefault(change["logical_path"], []).append(change)
    return {path: tuple(items) for path, items in grouped.items()}


def _compare_members(
    before: Mapping[str, _Member],
    after: Mapping[str, _Member],
    comparison: Comparison,
    declarations: Mapping[str, tuple[Mapping[str, Any], ...]],
) -> list[DiffLedgerEntry]:
    entries: list[DiffLedgerEntry] = []
    for path in sorted(set(before) | set(after), key=lambda value: value.encode("utf-8")):
        old = before.get(path)
        new = after.get(path)
        declared_items = (
            declarations.get(path, ())
            if comparison == "declared_parent_to_candidate"
            else ()
        )
        if old is None and new is not None:
            declared = any(item["change_kind"] == "add_member" for item in declared_items)
            entries.append(
                DiffLedgerEntry(comparison, path, "member_added", declared, after_sha256=new.sha256)
            )
        elif new is None and old is not None:
            declared = any(
                item["change_kind"] == "remove_member"
                and _parent_hash_matches(item, old.sha256)
                for item in declared_items
            )
            entries.append(
                DiffLedgerEntry(
                    comparison, path, "member_removed", declared, before_sha256=old.sha256
                )
            )
        elif old is not None and new is not None and old.sha256 == new.sha256:
            entries.append(
                DiffLedgerEntry(
                    comparison,
                    path,
                    "byte_identical",
                    True,
                    before_sha256=old.sha256,
                    after_sha256=new.sha256,
                    detail="member bytes are SHA-256 identical",
                )
            )
        elif old is not None and new is not None:
            entries.extend(_changed_member(comparison, path, old, new, declared_items))
    return entries


def _changed_member(
    comparison: Comparison,
    path: str,
    old: _Member,
    new: _Member,
    declarations: tuple[Mapping[str, Any], ...],
) -> list[DiffLedgerEntry]:
    replacement = any(
        item["change_kind"] == "replace_member" and _parent_hash_matches(item, old.sha256)
        for item in declarations
    )
    patches = tuple(
        item
        for item in declarations
        if item["change_kind"] == "patch_record" and _parent_hash_matches(item, old.sha256)
    )
    semantic: list[DiffLedgerEntry] = []
    patch_authorized = False
    if len(old.data) <= MAX_XML_BYTES and len(new.data) <= MAX_XML_BYTES:
        semantic, patch_authorized = _xml_changes(comparison, path, old.data, new.data, patches)
    declared = comparison == "declared_parent_to_candidate" and (replacement or patch_authorized)
    byte_entry = DiffLedgerEntry(
        comparison,
        path,
        "byte_changed",
        declared,
        before_sha256=old.sha256,
        after_sha256=new.sha256,
        detail="member content SHA-256 changed",
    )
    if replacement:
        semantic = [
            DiffLedgerEntry(
                item.comparison,
                item.member_path,
                item.kind,
                True,
                item.selector,
                item.before_sha256,
                item.after_sha256,
                item.detail,
            )
            for item in semantic
        ]
    return [byte_entry, *semantic]


def _xml_changes(
    comparison: Comparison,
    path: str,
    before: bytes,
    after: bytes,
    patches: tuple[Mapping[str, Any], ...],
) -> tuple[list[DiffLedgerEntry], bool]:
    try:
        old_root = ET.fromstring(before)
        new_root = ET.fromstring(after)
    except ET.ParseError:
        return [], False
    if not patches:
        return (
            _semantic_fragment_changes(comparison, path, "$", old_root, new_root),
            False,
        )
    entries: list[DiffLedgerEntry] = []
    old_masked = copy.deepcopy(old_root)
    new_masked = copy.deepcopy(new_root)
    selectors_valid = bool(patches)
    changed_selector = False
    for patch in patches:
        selector = patch["record_selector"]
        assert isinstance(selector, str)
        try:
            old_nodes = old_root.findall(selector)
            new_nodes = new_root.findall(selector)
            old_masked_nodes = old_masked.findall(selector)
            new_masked_nodes = new_masked.findall(selector)
        except (KeyError, SyntaxError):
            selectors_valid = False
            continue
        if not old_nodes or len(old_nodes) != len(new_nodes):
            selectors_valid = False
            continue
        for index, (old_node, new_node) in enumerate(zip(old_nodes, new_nodes, strict=True)):
            if _canonical_xml(old_node) != _canonical_xml(new_node):
                changed_selector = True
                entries.extend(
                    _semantic_fragment_changes(comparison, path, selector, old_node, new_node)
                )
            _mask_node(old_masked, old_masked_nodes[index], selector, index)
            _mask_node(new_masked, new_masked_nodes[index], selector, index)
    residual_equal = _canonical_xml(old_masked) == _canonical_xml(new_masked)
    authorized = selectors_valid and changed_selector and residual_equal
    if patches and not authorized:
        entries.append(
            DiffLedgerEntry(
                comparison,
                path,
                "xml_change_outside_declared_selector",
                False,
                detail="XML changes were not completely covered by valid record selectors",
            )
        )
    return entries, authorized


def _semantic_fragment_changes(
    comparison: Comparison,
    path: str,
    selector: str,
    old: ET.Element,
    new: ET.Element,
) -> list[DiffLedgerEntry]:
    declared = comparison == "declared_parent_to_candidate"
    entries: list[DiffLedgerEntry] = []
    extension = PurePosixPath(path).suffix.casefold()
    local_tag = str(old.tag).rsplit("}", 1)[-1].casefold()
    if extension == ".adb":
        kind = "adb_fragment_changed"
    elif local_tag == "row":
        kind = "xml_row_changed"
    else:
        kind = "xml_fragment_changed"
    entries.append(DiffLedgerEntry(comparison, path, kind, declared, selector=selector))
    for key in sorted(set(old.attrib) | set(new.attrib)):
        if old.attrib.get(key) != new.attrib.get(key):
            entries.append(
                DiffLedgerEntry(
                    comparison,
                    path,
                    "xml_attribute_changed",
                    declared,
                    selector=selector,
                    detail=f"attribute {key!r} changed",
                )
            )
    old_children = Counter(_child_identity(child) for child in old)
    new_children = Counter(_child_identity(child) for child in new)
    for identity in sorted((old_children - new_children).elements()):
        entries.append(
            DiffLedgerEntry(
                comparison, path, "xml_child_removed", declared, selector, detail=identity
            )
        )
    for identity in sorted((new_children - old_children).elements()):
        entries.append(
            DiffLedgerEntry(
                comparison, path, "xml_child_added", declared, selector, detail=identity
            )
        )
    old_clips = _clip_references(old)
    new_clips = _clip_references(new)
    for clip in sorted(old_clips - new_clips):
        entries.append(
            DiffLedgerEntry(
                comparison, path, "clip_reference_removed", declared, selector, detail=clip
            )
        )
    for clip in sorted(new_clips - old_clips):
        entries.append(
            DiffLedgerEntry(
                comparison, path, "clip_reference_added", declared, selector, detail=clip
            )
        )
    for old_child, new_child in zip(old, new):
        if (
            _child_identity(old_child) == _child_identity(new_child)
            and _canonical_xml(old_child) != _canonical_xml(new_child)
        ):
            entries.append(
                DiffLedgerEntry(
                    comparison,
                    path,
                    "xml_child_changed",
                    declared,
                    selector,
                    detail=_child_identity(old_child),
                )
            )
    return entries


def _mask_node(root: ET.Element, target: ET.Element, selector: str, index: int) -> None:
    if root is target:
        root.clear()
        root.tag = "__declared_patch__"
        root.attrib.update({"selector": selector, "index": str(index)})
        return
    for parent in root.iter():
        for child_index, child in enumerate(parent):
            if child is target:
                marker = ET.Element(
                    "__declared_patch__", {"selector": selector, "index": str(index)}
                )
                marker.tail = child.tail
                parent.remove(child)
                parent.insert(child_index, marker)
                return


def _canonical_xml(element: ET.Element) -> tuple[Any, ...]:
    return (
        element.tag,
        tuple(sorted(element.attrib.items())),
        (element.text or "").strip(),
        tuple(_canonical_xml(child) + ((child.tail or "").strip(),) for child in element),
    )


def _child_identity(element: ET.Element) -> str:
    identity = element.attrib.get("id") or element.attrib.get("name") or ""
    return f"{element.tag}[{identity}]"


def _clip_references(element: ET.Element) -> set[str]:
    references: set[str] = set()
    for node in element.iter():
        tag_is_clip = "clip" in str(node.tag).casefold()
        for key, value in node.attrib.items():
            key_folded = key.casefold()
            if "clip" in key_folded or (tag_is_clip and key_folded in {"ref", "reference"}):
                references.add(f"{key}={value}")
    return references


def _parent_hash_matches(declaration: Mapping[str, Any], digest: str) -> bool:
    expected = declaration.get("expected_parent_sha256")
    return isinstance(expected, str) and expected.lower() == digest.lower()


def _read_archive(
    path: Path, max_members: int, max_member_bytes: int, max_total_bytes: int
) -> dict[str, _Member]:
    members: dict[str, _Member] = {}
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            items = [item for item in archive.infolist() if not item.is_dir()]
            if len(items) > max_members:
                raise CandidateParentDiffError(f"archive exceeds {max_members} members")
            folded: set[str] = set()
            for item in items:
                path_name = _member_path(item.filename)
                key = path_name.casefold()
                if key in folded:
                    raise CandidateParentDiffError(
                        "archive has duplicate or case-colliding members"
                    )
                folded.add(key)
                if item.flag_bits & 0x1:
                    raise CandidateParentDiffError("encrypted archive members are unsupported")
                if item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise CandidateParentDiffError(
                        f"unsupported compression method for member: {path_name}"
                    )
                if item.file_size > max_member_bytes:
                    raise CandidateParentDiffError(
                        f"member {path_name} exceeds {max_member_bytes} bytes"
                    )
                total += item.file_size
                if total > max_total_bytes:
                    raise CandidateParentDiffError(
                        f"archive exceeds {max_total_bytes} uncompressed bytes"
                    )
                chunks: list[bytes] = []
                actual_size = 0
                with archive.open(item) as stream:
                    while chunk := stream.read(min(1024 * 1024, max_member_bytes + 1)):
                        actual_size += len(chunk)
                        if actual_size > item.file_size or actual_size > max_member_bytes:
                            raise CandidateParentDiffError(
                                f"member expanded beyond its declared bound: {path_name}"
                            )
                        chunks.append(chunk)
                if actual_size != item.file_size:
                    raise CandidateParentDiffError(
                        f"member size changed while reading: {path_name}"
                    )
                data = b"".join(chunks)
                members[path_name] = _Member(data, hashlib.sha256(data).hexdigest())
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise CandidateParentDiffError(f"could not read PAK {path}: {exc}") from exc
    return members


def _read_parent_archive(
    path: Path,
    archive_sha256: str,
    cache_root: Path | str | None,
    role: str,
    cache_events: list[Mapping[str, str]],
    max_members: int,
    max_member_bytes: int,
    max_total_bytes: int,
) -> dict[str, _Member]:
    if cache_root is None:
        return _read_archive(path, max_members, max_member_bytes, max_total_bytes)
    try:
        result = read_archive_members_cached(
            path,
            archive_sha256=archive_sha256,
            cache_root=cache_root,
            max_members=max_members,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
        )
    except ArchiveMemberCacheError as exc:
        raise CandidateParentDiffError(f"parent archive cache failed closed: {exc}") from exc
    cache_events.append(
        {
            "role": role,
            "archive_sha256": archive_sha256,
            "status": result.cache_status,
            "manifest_sha256": result.manifest_sha256,
        }
    )
    return {
        logical: _Member(data, hashlib.sha256(data).hexdigest())
        for logical, data in result.members.items()
    }


def _member_path(value: str) -> str:
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
        raise CandidateParentDiffError(f"noncanonical archive member path: {value!r}")
    return value


def _hash_file_bounded(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CandidateParentDiffError(f"could not stat PAK {path}: {exc}") from exc
    if not path.is_file() or size > MAX_ARCHIVE_BYTES:
        raise CandidateParentDiffError(
            f"PAK must be a file no larger than {MAX_ARCHIVE_BYTES} bytes"
        )
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _render_human_report(
    status: str,
    spec_id: str,
    ledger: list[DiffLedgerEntry],
    contamination: bool,
    parent_hash: str,
    candidate_hash: str,
) -> str:
    changed = [item for item in ledger if item.kind != "byte_identical"]
    undeclared = [item for item in changed if not item.declared]
    identical = sum(
        item.kind == "byte_identical"
        and item.comparison == "declared_parent_to_candidate"
        for item in ledger
    )
    lines = [
        "# Candidate parent diff",
        "",
        f"Status: **{status}**",
        f"Build spec: `{spec_id}`",
        f"Declared parent SHA-256: `{parent_hash}`",
        f"Candidate SHA-256: `{candidate_hash}`",
        f"Parent contamination detected: **{'yes' if contamination else 'no'}**",
        f"Unrelated byte-identical candidate members: **{identical}**",
        f"Undeclared ledger entries: **{len(undeclared)}**",
        "",
        "## Change ledger",
        "",
    ]
    if not changed:
        lines.append("No byte or membership changes were found.")
    else:
        for item in changed:
            declaration = "declared" if item.declared else "UNDECLARED"
            selector = f" ({item.selector})" if item.selector else ""
            lines.append(
                f"- `{item.comparison}` `{item.member_path}`: {item.kind}{selector} [{declaration}]"
            )
    return "\n".join(lines) + "\n"


def _entry_sort_key(entry: DiffLedgerEntry) -> tuple[bytes, bytes, bytes, bytes]:
    return (
        entry.comparison.encode("utf-8"),
        entry.member_path.encode("utf-8"),
        entry.kind.encode("utf-8"),
        (entry.selector or "").encode("utf-8"),
    )


def _bound(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise CandidateParentDiffError(f"{name} must be between 1 and {maximum}")


def _atomic_text(path: Path, data: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(data, encoding="utf-8", newline="\n")
    os.replace(temporary, path)
