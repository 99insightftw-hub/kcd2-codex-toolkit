"""Bounded release validation for mutually exclusive physical PAK topology."""

from __future__ import annotations

import copy
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path
from .variant_selection import VariantSelectionReceipt, validate_variant_selection


_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TOPOLOGIES = 1024
_MAX_PAKS = 8192
_MAX_MEMBERS = 65536
_MUTUALLY_EXCLUSIVE_RULES = frozenset(
    {"EXACTLY_ONE", "ZERO_OR_ONE", "LANGUAGE", "PLATFORM", "PRESET"}
)


class VariantTopologyError(ValueError):
    """Topology evidence is malformed or exceeds a fixed analysis bound."""


def _sequence(value: Any, field: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise VariantTopologyError(f"{field} must be an array")
    if len(value) > maximum:
        raise VariantTopologyError(f"{field} exceeds the hard bound of {maximum}")
    return value


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise VariantTopologyError(f"{field} must be a mapping with string keys")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise VariantTopologyError(
            f"{field} must be a non-empty string of at most 1024 characters"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise VariantTopologyError(f"{field} must be a SHA-256 hex digest")
    return value.lower()


def _complete(topology: Mapping[str, Any]) -> bool:
    direct = topology.get("scan_complete")
    if isinstance(direct, bool):
        complete = direct
    else:
        receipt = topology.get("scope_receipt")
        if not isinstance(receipt, Mapping):
            return False
        access = receipt.get("actual_access", receipt.get("access", receipt))
        complete = access.get("scan_complete") if isinstance(access, Mapping) else None
        if not isinstance(complete, bool):
            return False
    return (
        complete
        and topology.get("pak_records_truncated", False) is False
        and topology.get("payload_override_paths_truncated", False) is False
    )


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class VariantTopologyReport:
    """Deeply immutable, deterministic variant-topology validation report."""

    _value: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def detect_simultaneously_deployable_variants(
    selection: Mapping[str, Any] | VariantSelectionReceipt,
    topologies: Sequence[Mapping[str, Any]],
) -> VariantTopologyReport:
    """Compare exact physical PAKs and their members against one approved selection.

    The function consumes caller-supplied exact inspection results and performs no discovery or
    filesystem reads. Duplicate copies of one physical artifact are diagnosed independently from
    multiple distinct members of a mutually exclusive group. Any partial topology makes the
    release verdict ``capture_inconclusive`` and forbids an absence claim.
    """

    receipt = validate_variant_selection(selection)
    selection_value = receipt.to_dict()
    topology_values = _sequence(topologies, "topologies", _MAX_TOPOLOGIES)

    packages_by_digest: dict[str, list[dict[str, Any]]] = defaultdict(list)
    member_count = 0
    topology_count = len(topology_values)
    partial_topologies: list[str] = []

    for topology_index, raw_topology in enumerate(topology_values):
        field = f"topologies[{topology_index}]"
        topology = _mapping(raw_topology, field)
        topology_id = _text(
            topology.get("topology_id", f"topology-{topology_index}"),
            f"{field}.topology_id",
        )
        if not _complete(topology):
            partial_topologies.append(topology_id)
        paks = _sequence(topology.get("paks"), f"{field}.paks", _MAX_PAKS)
        if sum(len(items) for items in packages_by_digest.values()) + len(paks) > _MAX_PAKS:
            raise VariantTopologyError(f"all PAK records exceed the hard bound of {_MAX_PAKS}")
        for pak_index, raw_pak in enumerate(paks):
            pak_field = f"{field}.paks[{pak_index}]"
            pak = _mapping(raw_pak, pak_field)
            path = canonical_relative_path(_text(pak.get("path"), f"{pak_field}.path"))
            digest = _digest(pak.get("sha256"), f"{pak_field}.sha256")
            members = _sequence(pak.get("members"), f"{pak_field}.members", _MAX_MEMBERS)
            member_count += len(members)
            if member_count > _MAX_MEMBERS:
                raise VariantTopologyError(
                    f"all PAK members exceed the hard bound of {_MAX_MEMBERS}"
                )
            canonical_members: dict[str, str] = {}
            for member_index, raw_member in enumerate(members):
                member = _mapping(raw_member, f"{pak_field}.members[{member_index}]")
                member_path = canonical_relative_path(
                    _text(member.get("path"), f"{pak_field}.members[{member_index}].path")
                )
                canonical_members.setdefault(canonical_path_key(member_path), member_path)
            if len(canonical_members) != len(members):
                raise VariantTopologyError(f"{pak_field}.members contains duplicate paths")
            if pak.get("structure_valid", True) is not True:
                if topology_id not in partial_topologies:
                    partial_topologies.append(topology_id)
            packages_by_digest[digest].append(
                {
                    "topology_id": topology_id,
                    "path": path,
                    "member_paths": canonical_members,
                }
            )

    duplicate_packages = []
    for digest, packages in sorted(packages_by_digest.items()):
        if len(packages) > 1:
            duplicate_packages.append(
                {
                    "reason_code": "DUPLICATE_PHYSICAL_PACKAGING",
                    "artifact_sha256": digest,
                    "locations": sorted(
                        [
                            {
                                "topology_id": package["topology_id"],
                                "pak_path": package["path"],
                            }
                            for package in packages
                        ],
                        key=lambda item: (
                            item["topology_id"].casefold(),
                            canonical_path_key(item["pak_path"]),
                        ),
                    ),
                }
            )

    collisions = []
    analyzed_member_ids: set[str] = set()
    for group in selection_value["groups"]:
        if group["rule"] not in _MUTUALLY_EXCLUSIVE_RULES:
            continue
        present: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for member in group["members"]:
            packages = packages_by_digest.get(member["artifact_sha256"], [])
            if packages:
                analyzed_member_ids.add(member["member_id"])
                # Multiple locations of identical bytes remain one member; duplicate physical
                # packaging is already represented by its own diagnostic above.
                present.append((member, packages[0]))
        if len(present) < 2:
            continue
        shared_keys = set(present[0][1]["member_paths"])
        for _, package in present[1:]:
            shared_keys &= set(package["member_paths"])
        shared_members = [
            min(
                package["member_paths"][key] for _, package in present
            )
            for key in shared_keys
        ]
        selected = set(group["selected_member_ids"])
        present_ids = sorted(member["member_id"] for member, _ in present)
        collisions.append(
            {
                "reason_code": "MUTUALLY_EXCLUSIVE_VARIANTS_SIMULTANEOUSLY_DEPLOYABLE",
                "group_id": group["group_id"],
                "rule": group["rule"],
                "present_member_ids": present_ids,
                "selected_member_ids": sorted(selected),
                "all_members_approved": set(present_ids) <= selected,
                "pak_locations": sorted(
                    [
                        {
                            "member_id": member["member_id"],
                            "topology_id": package["topology_id"],
                            "pak_path": package["path"],
                        }
                        for member, package in present
                    ],
                    key=lambda item: item["member_id"],
                ),
                "shared_pak_members": sorted(
                    shared_members, key=lambda item: (canonical_path_key(item), item)
                ),
            }
        )

    collisions.sort(key=lambda item: item["group_id"])
    reason_codes: set[str] = set()
    if collisions:
        reason_codes.add("MUTUALLY_EXCLUSIVE_VARIANTS_SIMULTANEOUSLY_DEPLOYABLE")
    if duplicate_packages:
        reason_codes.add("DUPLICATE_PHYSICAL_PACKAGING")
    if partial_topologies or not topology_values:
        reason_codes.add("PARTIAL_TOPOLOGY_SCOPE")

    if "PARTIAL_TOPOLOGY_SCOPE" in reason_codes:
        status = "capture_inconclusive"
    elif collisions or duplicate_packages:
        status = "FAIL"
    else:
        status = "PASS"
    material = {
        "schema_version": "kcd2.variant-topology-report.v1",
        "selection_id": receipt.selection_id,
        "topology_count": topology_count,
        "pak_count": sum(len(packages) for packages in packages_by_digest.values()),
        "pak_member_count": member_count,
        "analyzed_member_ids": sorted(analyzed_member_ids),
        "variant_collisions": collisions,
        "duplicate_physical_packages": duplicate_packages,
        "partial_topology_ids": sorted(set(partial_topologies), key=str.casefold),
        "status": status,
        "release_allowed": status == "PASS",
        "absence_claim_valid": status != "capture_inconclusive",
        "reason_codes": sorted(reason_codes),
    }
    report = {
        **material,
        "report_id": f"variant-topology-report:sha256:{sha256_json(material)}",
    }
    return VariantTopologyReport(_freeze(report))
