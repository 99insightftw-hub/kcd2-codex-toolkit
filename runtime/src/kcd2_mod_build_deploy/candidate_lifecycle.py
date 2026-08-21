"""Typed, append-only candidate lifecycle events and deterministic state reduction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable, TypeVar

from .deployment_registry import DeploymentOperation, SnapshotGateDecision


MAX_EVENTS = 10_000
MAX_EVIDENCE_REFS = 256
MAX_RUNTIME_SESSION_IDS = 256
_DEPLOYMENT_ID = re.compile(r"^deploy:sha256:[A-Fa-f0-9]{64}$")
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class LifecycleError(ValueError):
    """Base error for invalid lifecycle input."""


class LifecycleAuthorityError(LifecycleError):
    """Raised when a producer attempts to emit an event outside its authority."""


class LifecycleHistoryError(LifecycleError):
    """Raised when an event sequence violates append-only history invariants."""


class BuildState(StrEnum):
    NOT_BUILT = "NOT_BUILT"
    BUILD_FAILED = "BUILD_FAILED"
    BUILD_STATIC_VALIDATED = "BUILD_STATIC_VALIDATED"


class PackageState(StrEnum):
    NOT_VALIDATED = "NOT_VALIDATED"
    PACKAGE_FAILED = "PACKAGE_FAILED"
    PACKAGE_VALIDATED = "PACKAGE_VALIDATED"
    PACKAGE_VALIDATED_WITH_SCOPED_WAIVER = "PACKAGE_VALIDATED_WITH_SCOPED_WAIVER"


class InstallationState(StrEnum):
    NOT_INSTALLED = "NOT_INSTALLED"
    INSTALL_PREPARED = "INSTALL_PREPARED"
    INSTALL_VALIDATED = "INSTALL_VALIDATED"
    ROLLED_BACK = "ROLLED_BACK"


class RuntimeValidationRequirement(StrEnum):
    UNKNOWN = "UNKNOWN"
    REQUIRED = "REQUIRED"
    NOT_REQUIRED_WITH_EVIDENCE = "NOT_REQUIRED_WITH_EVIDENCE"


class RuntimeState(StrEnum):
    RUNTIME_UNTESTED = "RUNTIME_UNTESTED"
    RUNTIME_OBSERVED_PASS = "RUNTIME_OBSERVED_PASS"
    RUNTIME_OBSERVED_FAIL = "RUNTIME_OBSERVED_FAIL"
    RUNTIME_INCONCLUSIVE = "RUNTIME_INCONCLUSIVE"


class CausalState(StrEnum):
    NOT_ASSESSED = "NOT_ASSESSED"
    CAUSALLY_ISOLATED = "CAUSALLY_ISOLATED"
    CAUSALLY_CONFOUNDED = "CAUSALLY_CONFOUNDED"
    CAUSALITY_INCONCLUSIVE = "CAUSALITY_INCONCLUSIVE"


class DispositionState(StrEnum):
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


class EventType(StrEnum):
    BUILD_FAILED = "BUILD_FAILED"
    BUILD_STATIC_VALIDATED = "BUILD_STATIC_VALIDATED"
    PACKAGE_FAILED = "PACKAGE_FAILED"
    PACKAGE_VALIDATED = "PACKAGE_VALIDATED"
    PACKAGE_VALIDATED_WITH_SCOPED_WAIVER = "PACKAGE_VALIDATED_WITH_SCOPED_WAIVER"
    INSTALL_PREPARED = "INSTALL_PREPARED"
    INSTALL_VALIDATED = "INSTALL_VALIDATED"
    ROLLED_BACK = "ROLLED_BACK"
    RUNTIME_UNTESTED = "RUNTIME_UNTESTED"
    RUNTIME_OBSERVED_PASS = "RUNTIME_OBSERVED_PASS"
    RUNTIME_OBSERVED_FAIL = "RUNTIME_OBSERVED_FAIL"
    RUNTIME_INCONCLUSIVE = "RUNTIME_INCONCLUSIVE"
    CAUSALLY_ISOLATED = "CAUSALLY_ISOLATED"
    CAUSALLY_CONFOUNDED = "CAUSALLY_CONFOUNDED"
    CAUSALITY_INCONCLUSIVE = "CAUSALITY_INCONCLUSIVE"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


class EventProducer(StrEnum):
    BUILDER = "builder"
    PACKAGE_VALIDATOR = "package_validator"
    INSTALLER = "installer"
    RUNTIME_IMPORTER = "runtime_importer"
    USER_CONFIRMATION = "user_confirmation"
    CAUSAL_ANALYSIS = "causal_analysis"
    MIGRATION = "migration"
    OPERATOR = "operator"


class DeploymentBindingState(StrEnum):
    EXACT = "EXACT"
    DEPLOYMENT_UNBOUND_LEGACY = "DEPLOYMENT_UNBOUND_LEGACY"


class XmlTblGate(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CLEAR = "CLEAR"
    UNKNOWN_WITH_SCOPED_WAIVER = "UNKNOWN_WITH_SCOPED_WAIVER"


BUILD_EVENT_TYPES = frozenset(
    {EventType.BUILD_FAILED, EventType.BUILD_STATIC_VALIDATED}
)
PACKAGE_EVENT_TYPES = frozenset(
    {
        EventType.PACKAGE_FAILED,
        EventType.PACKAGE_VALIDATED,
        EventType.PACKAGE_VALIDATED_WITH_SCOPED_WAIVER,
    }
)
INSTALLATION_EVENT_TYPES = frozenset(
    {EventType.INSTALL_PREPARED, EventType.INSTALL_VALIDATED, EventType.ROLLED_BACK}
)
RUNTIME_EVENT_TYPES = frozenset(
    {
        EventType.RUNTIME_UNTESTED,
        EventType.RUNTIME_OBSERVED_PASS,
        EventType.RUNTIME_OBSERVED_FAIL,
        EventType.RUNTIME_INCONCLUSIVE,
    }
)
CAUSAL_EVENT_TYPES = frozenset(
    {
        EventType.CAUSALLY_ISOLATED,
        EventType.CAUSALLY_CONFOUNDED,
        EventType.CAUSALITY_INCONCLUSIVE,
    }
)
DISPOSITION_EVENT_TYPES = frozenset(
    {EventType.REJECTED, EventType.SUPERSEDED, EventType.ARCHIVED}
)

_PRODUCER_AUTHORITY = {
    EventProducer.BUILDER: BUILD_EVENT_TYPES,
    EventProducer.PACKAGE_VALIDATOR: PACKAGE_EVENT_TYPES,
    EventProducer.INSTALLER: INSTALLATION_EVENT_TYPES,
    EventProducer.RUNTIME_IMPORTER: RUNTIME_EVENT_TYPES,
    EventProducer.USER_CONFIRMATION: RUNTIME_EVENT_TYPES,
    EventProducer.CAUSAL_ANALYSIS: CAUSAL_EVENT_TYPES,
    EventProducer.MIGRATION: frozenset(EventType),
    EventProducer.OPERATOR: DISPOSITION_EVENT_TYPES | {EventType.RUNTIME_UNTESTED},
}


def _as_enum(value: _EnumT | str, enum_type: type[_EnumT], field: str) -> _EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise LifecycleError(f"{field} has an unsupported value: {value!r}") from exc


def _bounded_unique_strings(
    values: Iterable[str],
    *,
    field: str,
    maximum: int,
    item_maximum: int,
    allow_empty: bool,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise LifecycleError(f"{field} must be a collection of strings")
    result = tuple(values)
    if not allow_empty and not result:
        raise LifecycleError(f"{field} must contain at least one value")
    if len(result) > maximum:
        raise LifecycleError(f"{field} exceeds the limit of {maximum}")
    if any(
        not isinstance(value, str) or not 1 <= len(value) <= item_maximum
        for value in result
    ):
        raise LifecycleError(
            f"{field} values must contain between 1 and {item_maximum} characters"
        )
    if len(set(result)) != len(result):
        raise LifecycleError(f"{field} must not contain duplicate values")
    return result


def _parse_occurred_at(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LifecycleError("occurred_at must be a non-empty date-time string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LifecycleError("occurred_at must be an ISO-8601 date-time") from exc
    if parsed.tzinfo is None:
        raise LifecycleError("occurred_at must include a UTC offset")
    return parsed


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_id: str
    event_type: EventType
    occurred_at: str
    producer: EventProducer
    evidence_refs: tuple[str, ...]
    deployment_id: str | None = None
    deployment_binding_state: DeploymentBindingState | None = None
    xml_tbl_gate: XmlTblGate | None = None
    xml_tbl_verdict_refs: tuple[str, ...] = ()
    runtime_session_ids: tuple[str, ...] = ()
    superseding_candidate_id: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not 1 <= len(self.event_id) <= 128:
            raise LifecycleError("event_id must contain between 1 and 128 characters")
        event_type = _as_enum(self.event_type, EventType, "event_type")
        producer = _as_enum(self.producer, EventProducer, "producer")
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "producer", producer)
        _parse_occurred_at(self.occurred_at)

        evidence_refs = _bounded_unique_strings(
            self.evidence_refs,
            field="evidence_refs",
            maximum=MAX_EVIDENCE_REFS,
            item_maximum=512,
            allow_empty=False,
        )
        verdict_refs = _bounded_unique_strings(
            self.xml_tbl_verdict_refs,
            field="xml_tbl_verdict_refs",
            maximum=MAX_EVIDENCE_REFS,
            item_maximum=512,
            allow_empty=True,
        )
        session_ids = _bounded_unique_strings(
            self.runtime_session_ids,
            field="runtime_session_ids",
            maximum=MAX_RUNTIME_SESSION_IDS,
            item_maximum=128,
            allow_empty=True,
        )
        object.__setattr__(self, "evidence_refs", evidence_refs)
        object.__setattr__(self, "xml_tbl_verdict_refs", verdict_refs)
        object.__setattr__(self, "runtime_session_ids", session_ids)

        if event_type not in _PRODUCER_AUTHORITY[producer]:
            raise LifecycleAuthorityError(
                f"producer {producer.value} cannot emit {event_type.value}"
            )
        if self.deployment_id is not None and not _DEPLOYMENT_ID.fullmatch(
            self.deployment_id
        ):
            raise LifecycleError("deployment_id must be a content-addressed deployment ID")
        if self.deployment_binding_state is not None:
            object.__setattr__(
                self,
                "deployment_binding_state",
                _as_enum(
                    self.deployment_binding_state,
                    DeploymentBindingState,
                    "deployment_binding_state",
                ),
            )
        if self.xml_tbl_gate is not None:
            object.__setattr__(
                self,
                "xml_tbl_gate",
                _as_enum(self.xml_tbl_gate, XmlTblGate, "xml_tbl_gate"),
            )
        if self.notes is not None and (
            not isinstance(self.notes, str) or len(self.notes) > 4_000
        ):
            raise LifecycleError("notes must be null or at most 4000 characters")
        if self.superseding_candidate_id is not None and not re.fullmatch(
            r"cand:sha256:[A-Fa-f0-9]{64}", self.superseding_candidate_id
        ):
            raise LifecycleError(
                "superseding_candidate_id must be a content-addressed candidate ID"
            )
        if (
            event_type is EventType.SUPERSEDED
            and self.superseding_candidate_id is None
        ):
            raise LifecycleError("SUPERSEDED requires a superseding candidate identity")

        self._validate_promotion_fields()

    def _validate_promotion_fields(self) -> None:
        if self.event_type is EventType.INSTALL_VALIDATED:
            if self.deployment_id is None:
                raise LifecycleError("INSTALL_VALIDATED requires an exact deployment ID")
            if self.deployment_binding_state is not DeploymentBindingState.EXACT:
                raise LifecycleError(
                    "INSTALL_VALIDATED requires deployment_binding_state EXACT"
                )

        if self.event_type in {
            EventType.RUNTIME_OBSERVED_PASS,
            EventType.RUNTIME_OBSERVED_FAIL,
        }:
            if self.deployment_id is None:
                raise LifecycleError(
                    f"{self.event_type.value} requires an exact deployment ID"
                )
            if self.deployment_binding_state is not DeploymentBindingState.EXACT:
                raise LifecycleError(
                    f"{self.event_type.value} requires deployment_binding_state EXACT"
                )
            if not self.runtime_session_ids:
                raise LifecycleError(
                    f"{self.event_type.value} requires at least one runtime session ID"
                )

        if self.event_type is EventType.PACKAGE_VALIDATED:
            if self.xml_tbl_gate not in {XmlTblGate.NOT_APPLICABLE, XmlTblGate.CLEAR}:
                raise LifecycleError(
                    "PACKAGE_VALIDATED requires an explicit NOT_APPLICABLE or "
                    "CLEAR XML/TBL gate"
                )
        if self.event_type is EventType.PACKAGE_VALIDATED_WITH_SCOPED_WAIVER:
            if self.xml_tbl_gate is not XmlTblGate.UNKNOWN_WITH_SCOPED_WAIVER:
                raise LifecycleError(
                    "scoped-waiver package validation requires UNKNOWN_WITH_SCOPED_WAIVER"
                )
            if not self.xml_tbl_verdict_refs:
                raise LifecycleError(
                    "scoped-waiver package validation requires an XML/TBL verdict reference"
                )


@dataclass(frozen=True, slots=True)
class DerivedCandidateState:
    build: BuildState = BuildState.NOT_BUILT
    package: PackageState = PackageState.NOT_VALIDATED
    installation: InstallationState = InstallationState.NOT_INSTALLED
    runtime_validation_requirement: RuntimeValidationRequirement = (
        RuntimeValidationRequirement.UNKNOWN
    )
    runtime: RuntimeState = RuntimeState.RUNTIME_UNTESTED
    causal: CausalState = CausalState.NOT_ASSESSED
    disposition: DispositionState = DispositionState.ACTIVE
    computed_from_event_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return the schema-shaped deterministic dimensions without inventing computed time."""
        return {
            "build": self.build.value,
            "package": self.package.value,
            "installation": self.installation.value,
            "runtime_validation_requirement": self.runtime_validation_requirement.value,
            "runtime": self.runtime.value,
            "causal": self.causal.value,
            "disposition": self.disposition.value,
            "computed_from_event_ids": list(self.computed_from_event_ids),
        }


@dataclass(frozen=True, slots=True)
class CandidateLifecycle:
    events: tuple[LifecycleEvent, ...] = ()

    def __post_init__(self) -> None:
        events = tuple(self.events)
        object.__setattr__(self, "events", events)
        if len(events) > MAX_EVENTS:
            raise LifecycleHistoryError(f"event history exceeds the limit of {MAX_EVENTS}")
        if any(not isinstance(event, LifecycleEvent) for event in events):
            raise LifecycleHistoryError("event history accepts LifecycleEvent values only")

        identifiers = [event.event_id for event in events]
        if len(set(identifiers)) != len(identifiers):
            raise LifecycleHistoryError("event history contains duplicate event IDs")
        timestamps = [_parse_occurred_at(event.occurred_at) for event in events]
        pairs = zip(timestamps, timestamps[1:], strict=False)
        if any(current < previous for previous, current in pairs):
            raise LifecycleHistoryError("event history must be ordered by occurred_at")

    def append(
        self,
        event: LifecycleEvent,
        *,
        snapshot_gate: SnapshotGateDecision | None = None,
    ) -> CandidateLifecycle:
        """Return a new history; the existing lifecycle and its events remain unchanged."""
        if not isinstance(event, LifecycleEvent):
            raise LifecycleHistoryError("append accepts a LifecycleEvent value only")
        if event.event_type is EventType.INSTALL_VALIDATED:
            if (
                snapshot_gate is None
                or not snapshot_gate.authorizes(DeploymentOperation.INSTALL_VALIDATION)
                or snapshot_gate.deployment_id != event.deployment_id
            ):
                raise LifecycleError(
                    "INSTALL_VALIDATED requires a matching fresh exact snapshot gate"
                )
        return CandidateLifecycle(self.events + (event,))

    @property
    def derived_state(self) -> DerivedCandidateState:
        return reduce_lifecycle(self.events)


def reduce_lifecycle(events: Iterable[LifecycleEvent]) -> DerivedCandidateState:
    """Reduce independent dimensions in event order without collapsing them to PASS/FAIL."""
    history = CandidateLifecycle(tuple(events))
    build = BuildState.NOT_BUILT
    package = PackageState.NOT_VALIDATED
    installation = InstallationState.NOT_INSTALLED
    runtime = RuntimeState.RUNTIME_UNTESTED
    causal = CausalState.NOT_ASSESSED
    disposition = DispositionState.ACTIVE

    for event in history.events:
        if event.event_type in BUILD_EVENT_TYPES:
            build = BuildState(event.event_type.value)
        elif event.event_type in PACKAGE_EVENT_TYPES:
            package = PackageState(event.event_type.value)
        elif event.event_type in INSTALLATION_EVENT_TYPES:
            installation = InstallationState(event.event_type.value)
        elif event.event_type in RUNTIME_EVENT_TYPES:
            runtime = RuntimeState(event.event_type.value)
        elif event.event_type in CAUSAL_EVENT_TYPES:
            causal = CausalState(event.event_type.value)
        elif event.event_type in DISPOSITION_EVENT_TYPES:
            disposition = DispositionState(event.event_type.value)

    return DerivedCandidateState(
        build=build,
        package=package,
        installation=installation,
        runtime=runtime,
        causal=causal,
        disposition=disposition,
        computed_from_event_ids=tuple(event.event_id for event in history.events),
    )


def render_derived_status(state: DerivedCandidateState) -> str:
    """Render every qualified dimension in a fixed order; never emit an overall PASS."""
    if not isinstance(state, DerivedCandidateState):
        raise TypeError("state must be a DerivedCandidateState")
    return "; ".join(
        (
            f"build={state.build.value}",
            f"package={state.package.value}",
            f"installation={state.installation.value}",
            "runtime_validation_requirement="
            f"{state.runtime_validation_requirement.value}",
            f"runtime={state.runtime.value}",
            f"causal={state.causal.value}",
            f"disposition={state.disposition.value}",
        )
    )
