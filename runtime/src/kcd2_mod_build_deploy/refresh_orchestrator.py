"""Fail-closed coordination for refreshing one changed active Index target.

The coordinator is transport-neutral and performs no write itself.  It emits one bounded
``refresh_mod_exact`` request and validates the caller-supplied receipt.  Broad refresh remains a
different operation and stale conclusions remain quarantined until they are recomputed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal


MAX_OBSERVATIONS = 4096
MAX_CONCLUSIONS = 4096
MAX_IDENTIFIER_LENGTH = 512
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
Freshness = Literal["fresh", "stale", "partial", "unknown"]


class RefreshOrchestratorError(ValueError):
    """Refresh evidence or a hard bound is invalid."""


def _identifier(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_IDENTIFIER_LENGTH
        or "\x00" in value
    ):
        raise RefreshOrchestratorError(
            f"{field} must be a non-empty NUL-free string of at most "
            f"{MAX_IDENTIFIER_LENGTH} characters"
        )
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RefreshOrchestratorError(f"{field} must be a SHA-256 digest")
    return value.casefold()


def _unique_ids(values: Sequence[str], field: str, maximum: int) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise RefreshOrchestratorError(f"{field} must be an array")
    checked = tuple(_identifier(value, f"{field} item") for value in values)
    if len(checked) > maximum:
        raise RefreshOrchestratorError(f"{field} exceeds its hard bound of {maximum}")
    if len(set(checked)) != len(checked):
        raise RefreshOrchestratorError(f"{field} must contain unique IDs")
    return tuple(sorted(checked))


@dataclass(frozen=True, slots=True)
class ActiveRefreshTarget:
    target_id: str
    mod_id: str
    provider_id: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        for field in ("target_id", "mod_id", "provider_id"):
            object.__setattr__(self, field, _identifier(getattr(self, field), field))
        object.__setattr__(
            self,
            "artifact_sha256",
            _digest(self.artifact_sha256, "artifact_sha256"),
        )


@dataclass(frozen=True, slots=True)
class FreshnessObservation:
    observation_id: str
    target_id: str
    target_sha256: str
    freshness: Freshness
    conclusion_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observation_id", _identifier(self.observation_id, "observation_id")
        )
        object.__setattr__(self, "target_id", _identifier(self.target_id, "target_id"))
        object.__setattr__(
            self, "target_sha256", _digest(self.target_sha256, "target_sha256")
        )
        if self.freshness not in {"fresh", "stale", "partial", "unknown"}:
            raise RefreshOrchestratorError("freshness is not a supported state")
        object.__setattr__(
            self,
            "conclusion_ids",
            _unique_ids(self.conclusion_ids, "conclusion_ids", MAX_CONCLUSIONS),
        )


@dataclass(frozen=True, slots=True)
class BoundedRefreshRequest:
    operation: Literal["refresh_mod_exact"]
    target_id: str
    mod_id: str
    provider_id: str
    expected_target_sha256: str
    stale_ids: tuple[str, ...]
    max_stale_ids: int


@dataclass(frozen=True, slots=True)
class RefreshReceipt:
    operation: str
    target_id: str
    target_sha256: str
    refreshed_stale_ids: tuple[str, ...]
    scope_status: str
    other_provider_records_touched: int
    complete_for_requested_scope: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", _identifier(self.operation, "operation"))
        object.__setattr__(self, "target_id", _identifier(self.target_id, "target_id"))
        object.__setattr__(
            self, "target_sha256", _digest(self.target_sha256, "target_sha256")
        )
        object.__setattr__(
            self,
            "refreshed_stale_ids",
            _unique_ids(
                self.refreshed_stale_ids,
                "refreshed_stale_ids",
                MAX_OBSERVATIONS,
            ),
        )
        _identifier(self.scope_status, "scope_status")
        if (
            not isinstance(self.other_provider_records_touched, int)
            or isinstance(self.other_provider_records_touched, bool)
            or self.other_provider_records_touched < 0
        ):
            raise RefreshOrchestratorError(
                "other_provider_records_touched must be a non-negative integer"
            )
        if not isinstance(self.complete_for_requested_scope, bool):
            raise RefreshOrchestratorError(
                "complete_for_requested_scope must be a boolean"
            )


@dataclass(frozen=True, slots=True)
class StalenessReport:
    status: str
    target_id: str
    target_sha256: str
    stale_ids: tuple[str, ...]
    target_stale_ids: tuple[str, ...]
    deferred_stale_ids: tuple[str, ...]
    quarantined_conclusion_ids: tuple[str, ...]
    conclusions_allowed: bool
    request: BoundedRefreshRequest | None
    reason_codes: tuple[str, ...]


RefreshExecutor = Callable[[BoundedRefreshRequest], RefreshReceipt]


def _is_stale(target: ActiveRefreshTarget, observation: FreshnessObservation) -> bool:
    if observation.target_id == target.target_id:
        return (
            observation.freshness != "fresh"
            or observation.target_sha256 != target.artifact_sha256
        )
    return observation.freshness != "fresh"


def _receipt_reasons(
    target: ActiveRefreshTarget,
    request: BoundedRefreshRequest,
    receipt: RefreshReceipt,
) -> tuple[str, ...]:
    reasons = []
    if receipt.operation != request.operation:
        if receipt.operation in {"refresh_all", "refresh_broad", "refresh_snapshot"}:
            reasons.append("BROAD_REFRESH_REQUIRES_SEPARATE_ACTION")
        else:
            reasons.append("REFRESH_OPERATION_MISMATCH")
    if receipt.target_id != target.target_id:
        reasons.append("REFRESH_TARGET_ID_MISMATCH")
    if receipt.target_sha256 != target.artifact_sha256:
        reasons.append("REFRESH_TARGET_HASH_MISMATCH")
    if receipt.refreshed_stale_ids != request.stale_ids:
        reasons.append("REFRESH_STALE_ID_SET_MISMATCH")
    if receipt.scope_status != "TARGET_SCOPE_OK":
        reasons.append("REFRESH_TARGET_SCOPE_INVALID")
    if receipt.other_provider_records_touched != 0:
        reasons.append("REFRESH_TOUCHED_OTHER_PROVIDER")
    if not receipt.complete_for_requested_scope:
        reasons.append("REFRESH_PARTIAL_COVERAGE")
    return tuple(sorted(reasons))


def orchestrate_active_target_refresh(
    target: ActiveRefreshTarget,
    observations: Sequence[FreshnessObservation],
    refresh_exact: RefreshExecutor | None = None,
) -> StalenessReport:
    """Plan and validate one exact refresh without broad substitution.

    Stale observations owned by other targets are reported and deferred.  A successful refresh
    confirms only that the requested target was refreshed; conclusions derived from stale input
    remain quarantined until separately recomputed from fresh evidence.
    """

    if not isinstance(target, ActiveRefreshTarget):
        raise RefreshOrchestratorError("target must be an ActiveRefreshTarget")
    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise RefreshOrchestratorError("observations must be an array")
    checked = tuple(observations)
    if len(checked) > MAX_OBSERVATIONS:
        raise RefreshOrchestratorError(
            f"observations exceeds its hard bound of {MAX_OBSERVATIONS}"
        )
    if any(not isinstance(item, FreshnessObservation) for item in checked):
        raise RefreshOrchestratorError(
            "observations must contain FreshnessObservation values"
        )
    identifiers = [item.observation_id for item in checked]
    if len(set(identifiers)) != len(identifiers):
        raise RefreshOrchestratorError("observation IDs must be globally unique")

    stale = tuple(sorted(item.observation_id for item in checked if _is_stale(target, item)))
    target_observations = tuple(item for item in checked if item.target_id == target.target_id)
    target_stale = tuple(
        sorted(item.observation_id for item in target_observations if _is_stale(target, item))
    )
    target_stale_set = set(target_stale)
    deferred = tuple(item for item in stale if item not in target_stale_set)
    quarantined = tuple(
        sorted(
            {
                conclusion
                for item in target_observations
                if item.observation_id in target_stale_set
                for conclusion in item.conclusion_ids
            }
        )
    )

    if not target_observations:
        return StalenessReport(
            status="capture_inconclusive",
            target_id=target.target_id,
            target_sha256=target.artifact_sha256,
            stale_ids=stale,
            target_stale_ids=(),
            deferred_stale_ids=deferred,
            quarantined_conclusion_ids=(),
            conclusions_allowed=False,
            request=None,
            reason_codes=("MISSING_ACTIVE_TARGET_FRESHNESS",),
        )

    if not target_stale:
        return StalenessReport(
            status="fresh",
            target_id=target.target_id,
            target_sha256=target.artifact_sha256,
            stale_ids=stale,
            target_stale_ids=(),
            deferred_stale_ids=deferred,
            quarantined_conclusion_ids=(),
            conclusions_allowed=True,
            request=None,
            reason_codes=(),
        )

    request = BoundedRefreshRequest(
        operation="refresh_mod_exact",
        target_id=target.target_id,
        mod_id=target.mod_id,
        provider_id=target.provider_id,
        expected_target_sha256=target.artifact_sha256,
        stale_ids=target_stale,
        max_stale_ids=len(target_stale),
    )
    if refresh_exact is None:
        return StalenessReport(
            status="refresh_required",
            target_id=target.target_id,
            target_sha256=target.artifact_sha256,
            stale_ids=stale,
            target_stale_ids=target_stale,
            deferred_stale_ids=deferred,
            quarantined_conclusion_ids=quarantined,
            conclusions_allowed=False,
            request=request,
            reason_codes=("STALE_CONCLUSIONS_QUARANTINED",),
        )

    receipt = refresh_exact(request)
    if not isinstance(receipt, RefreshReceipt):
        raise RefreshOrchestratorError("refresh executor must return a RefreshReceipt")
    reasons = _receipt_reasons(target, request, receipt)
    status = "capture_inconclusive" if reasons else "refresh_confirmed_reanalysis_required"
    if not reasons:
        reasons = ("STALE_CONCLUSIONS_REQUIRE_REANALYSIS",)
    return StalenessReport(
        status=status,
        target_id=target.target_id,
        target_sha256=target.artifact_sha256,
        stale_ids=stale,
        target_stale_ids=target_stale,
        deferred_stale_ids=deferred,
        quarantined_conclusion_ids=quarantined,
        conclusions_allowed=False,
        request=request,
        reason_codes=reasons,
    )


__all__ = [
    "ActiveRefreshTarget",
    "BoundedRefreshRequest",
    "FreshnessObservation",
    "MAX_CONCLUSIONS",
    "MAX_OBSERVATIONS",
    "RefreshOrchestratorError",
    "RefreshReceipt",
    "StalenessReport",
    "orchestrate_active_target_refresh",
]
