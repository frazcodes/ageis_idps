"""The canonical Aegis IDPS event schema.

Every observation in the platform - a process starting on a Windows endpoint, a flow
summary from the network sensor, an anomaly score from the ML engine - is expressed as a
:class:`SecurityEvent`. Downstream components (backend ingestion, correlation engine,
dashboards, SIEM export) therefore only ever need to understand one envelope.

Layout
------
``SecurityEvent`` is a flat envelope of *identity* (who/what/when) plus optional,
typed **context blocks**:

* :class:`SourceRef`     - the component that observed the event
* :class:`HostRef`       - the host the event happened on/at
* :class:`ActorRef`      - the user/process responsible, when known
* :class:`NetworkContext`- 5-tuple and volume details for network activity
* :class:`ProcessContext`- process identity, command line and hashes
* :class:`FileContext`   - file path, hashes and the file operation
* :class:`RiskAssessment`- output of the detection/ML layer
* :class:`CorrelationRef`- links to an incident and sibling events

Rules
-----
1. Events are **immutable** (``frozen=True``). A correction is a new event.
2. The envelope is **closed** (``extra="forbid"``): unknown top-level keys are rejected so
   schema drift fails loudly at the boundary instead of being silently dropped.
   Sensor-specific detail belongs in ``raw``, and extensible tags in ``labels``.
3. Timestamps must be **timezone-aware UTC**. A security timeline built from naive local
   timestamps is worse than useless.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import (
    AddressFamily,
    EventCategory,
    EventType,
    FileType,
    HashStatus,
    NetworkDirection,
    Platform,
    RiskBand,
    Severity,
    SourceKind,
    TransportProtocol,
)
from .version import EVENT_SCHEMA_VERSION

# ---------------------------------------------------------------------------
# Base model configuration
# ---------------------------------------------------------------------------


class _FrozenModel(BaseModel):
    """Immutable, closed base model used by every event component."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=False,
        use_enum_values=False,
    )


def _utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(tz=UTC)


def _require_aware(value: datetime, field_name: str) -> datetime:
    """Normalise a datetime to UTC, rejecting naive (timezone-less) values."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware (use datetime.now(timezone.utc))")
    return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Identity blocks
# ---------------------------------------------------------------------------


class SourceRef(_FrozenModel):
    """The component that produced the event."""

    kind: SourceKind
    #: Stable identifier of the emitter, e.g. ``agent-7f3a91`` or ``sensor-eth0-01``.
    id: str = Field(min_length=1, max_length=128)
    #: Emitter build version, used to spot stale agents in the field.
    version: str | None = Field(default=None, max_length=32)


class HostRef(_FrozenModel):
    """The host an event relates to.

    ``host_id`` is a stable, agent-assigned identifier; ``hostname`` and IPs are
    attributes that may legitimately change over time, so they never act as the key.
    """

    host_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    platform: Platform = Platform.UNKNOWN
    os_version: str | None = Field(default=None, max_length=128)
    ip_addresses: tuple[str, ...] = ()
    #: Hosts may be labelled by role or asset criticality, e.g. {"role": "domain-controller"}.
    tags: dict[str, str] = Field(default_factory=dict)


class ActorRef(_FrozenModel):
    """The principal responsible for an action, when the sensor can attribute it."""

    user: str | None = Field(default=None, max_length=255)
    user_id: str | None = Field(default=None, max_length=255)
    #: ``True`` when the action was performed with elevated privileges.
    privileged: bool = False
    #: Session / logon identifier, useful for correlating multi-step activity.
    session_id: str | None = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# Context blocks
# ---------------------------------------------------------------------------


class NetworkContext(_FrozenModel):
    """Connection or flow details.

    ``src_*`` always refers to the initiator of the observed traffic, so the semantics are
    identical for a host-local connection event and a sensor-side flow record.
    """

    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: TransportProtocol = TransportProtocol.OTHER
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    #: Capture interface the observation came from, when known.
    interface: str | None = Field(default=None, max_length=64)
    #: IP version (ipv4/ipv6), reusing the shared address-family vocabulary.
    ip_version: AddressFamily = AddressFamily.UNKNOWN
    #: Observed frame/packet length in bytes.
    packet_length: int | None = Field(default=None, ge=0)
    #: Deterministic identifier of the directional flow this packet belongs to.
    flow_id: str | None = Field(default=None, max_length=256)
    #: Bytes/packets transferred, when the sensor aggregates a flow.
    bytes_sent: int | None = Field(default=None, ge=0)
    bytes_received: int | None = Field(default=None, ge=0)
    packets_sent: int | None = Field(default=None, ge=0)
    packets_received: int | None = Field(default=None, ge=0)
    duration_ms: int | None = Field(default=None, ge=0)
    #: Domain name observed for the connection (DNS/TLS SNI), if resolvable.
    domain: str | None = Field(default=None, max_length=253)


class SocketContext(_FrozenModel):
    """A local socket endpoint, such as a listening port.

    Describes the **local** side only. Remote peers are the concern of
    :class:`NetworkContext`, which models connections and flows; a listening
    socket has no peer, so no remote address is recorded here.
    """

    local_address: str | None = Field(default=None, max_length=64)
    local_port: int | None = Field(default=None, ge=0, le=65535)
    address_family: AddressFamily = AddressFamily.UNKNOWN
    #: Transport protocol of the socket, reusing the shared vocabulary.
    protocol: TransportProtocol = TransportProtocol.OTHER
    #: OS-reported socket state (e.g. ``"LISTEN"``). ``None`` when not applicable,
    #: which is always the case for UDP - UDP has no connection state.
    status: str | None = Field(default=None, max_length=32)


class ProcessContext(_FrozenModel):
    """Process identity, including lineage for parent/child attack-chain analysis."""

    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, max_length=255)
    executable_path: str | None = Field(default=None, max_length=1024)
    command_line: str | None = Field(default=None, max_length=8192)
    #: Lowercase hex digests, keyed by algorithm, e.g. {"sha256": "..."}.
    hashes: dict[str, str] = Field(default_factory=dict)


class FileContext(_FrozenModel):
    """File identity, the operation that touched it, and hash provenance."""

    path: str = Field(min_length=1, max_length=4096)
    #: ``created`` / ``modified`` / ``deleted`` / ``scanned`` / ``quarantined``.
    operation: str | None = Field(default=None, max_length=32)
    file_type: FileType = FileType.OTHER
    size_bytes: int | None = Field(default=None, ge=0)
    #: Last modification time in UTC, when the filesystem reports it.
    modified_at: datetime | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    #: Why ``hashes`` is empty/partial; ``None`` when the producer did not say.
    hash_status: HashStatus | None = None
    #: YARA rule identifiers when the file matched a signature.
    yara_rules: tuple[str, ...] = ()

    @field_validator("modified_at")
    @classmethod
    def _modified_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _require_aware(value, info.field_name)


class RiskAssessment(_FrozenModel):
    """Output of the detection layer.

    A risk score is *advice*, never authorisation. The response engine independently
    consults policy before acting on any value in this block.
    """

    score: float = Field(ge=0.0, le=1.0)
    #: Model or rule pack that produced the score, e.g. ``isolation_forest@2026-09-01``.
    model: str | None = Field(default=None, max_length=128)
    #: Human-readable contributions, e.g. {"rare_destination_port": 0.31}.
    factors: dict[str, float] = Field(default_factory=dict)
    #: Convenience label derived from ``score``; computed automatically.
    band: RiskBand | None = None

    @model_validator(mode="after")
    def _derive_band(self) -> Self:
        if self.band is None:
            object.__setattr__(self, "band", band_for_score(self.score))
        return self


class CorrelationRef(_FrozenModel):
    """Links an event to correlated context."""

    incident_id: str | None = Field(default=None, max_length=64)
    #: Other events that contributed to the same correlation decision.
    related_event_ids: tuple[str, ...] = ()
    #: Free-form correlation keys (e.g. ``src_ip``, ``user``) used for grouping.
    keys: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


class SecurityEvent(_FrozenModel):
    """The single event envelope used across Aegis IDPS.

    Example
    -------
    >>> from aegis_shared.enums import EventType, Severity
    >>> event = SecurityEvent.create(
    ...     event_type=EventType.PROCESS_STARTED,
    ...     severity=Severity.INFO,
    ...     source=SourceRef(kind=SourceKind.AGENT, id="agent-01"),
    ...     host=HostRef(host_id="host-01", hostname="ws-01", platform=Platform.WINDOWS),
    ... )
    >>> event.category
    <EventCategory.HOST: 'host'>
    """

    # --- Identity ---------------------------------------------------------
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), max_length=64)
    schema_version: str = EVENT_SCHEMA_VERSION
    event_type: EventType
    #: Derived from ``event_type``; kept explicit so it can be indexed and filtered in SQL.
    category: EventCategory
    severity: Severity = Severity.INFO

    # --- Time -------------------------------------------------------------
    #: When the observation happened at the source.
    timestamp: datetime = Field(default_factory=_utc_now)
    #: When the backend accepted the event. ``None`` for events that have not been ingested.
    ingested_at: datetime | None = None

    # --- Provenance -------------------------------------------------------
    source: SourceRef
    host: HostRef | None = None
    actor: ActorRef | None = None

    # --- Context ----------------------------------------------------------
    network: NetworkContext | None = None
    socket: SocketContext | None = None
    process: ProcessContext | None = None
    file: FileContext | None = None
    risk: RiskAssessment | None = None
    correlation: CorrelationRef | None = None

    # --- Extensibility ----------------------------------------------------
    #: Short human-readable summary shown in alert lists.
    message: str | None = Field(default=None, max_length=1024)
    #: Queryable tags, e.g. {"mitre_technique": "T1059"}.
    labels: dict[str, str] = Field(default_factory=dict)
    #: Untouched sensor payload. Kept for forensics and for fields that have not yet
    #: earned a first-class place in the schema.
    raw: dict[str, Any] = Field(default_factory=dict)

    # -- Validators --------------------------------------------------------

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _aware_timestamps(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _require_aware(value, info.field_name)

    @model_validator(mode="after")
    def _category_matches_event_type(self) -> Self:
        """Guarantee ``category`` is never inconsistent with ``event_type``."""
        expected = EventCategory(self.event_type.value.split(".", 1)[0])
        if self.category is not expected:
            raise ValueError(
                f"category {self.category.value!r} does not match event_type "
                f"{self.event_type.value!r} (expected {expected.value!r})"
            )
        return self

    # -- Factories ---------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        event_type: EventType,
        source: SourceRef,
        severity: Severity = Severity.INFO,
        **context: Any,
    ) -> Self:
        """Build an event, deriving ``category`` from ``event_type``.

        Sensors should prefer this over constructing the model directly: it removes the
        one field that is trivially derivable and therefore trivially wrong.
        """
        category = EventCategory(event_type.value.split(".", 1)[0])
        return cls(
            event_type=event_type,
            category=category,
            severity=severity,
            source=source,
            **context,
        )

    # -- Convenience -------------------------------------------------------

    @property
    def is_high_severity(self) -> bool:
        """Whether the event is at least ``HIGH`` severity."""
        return self.severity.rank >= Severity.HIGH.rank


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

#: Inclusive lower bounds for each risk band, evaluated from most to least severe.
_RISK_BAND_THRESHOLDS: tuple[tuple[float, RiskBand], ...] = (
    (0.9, RiskBand.SEVERE),
    (0.7, RiskBand.HIGH),
    (0.4, RiskBand.ELEVATED),
    (0.2, RiskBand.LOW),
    (0.0, RiskBand.NEGLIGIBLE),
)


def band_for_score(score: float) -> RiskBand:
    """Map a 0-1 risk score onto a :class:`RiskBand`.

    Raises:
        ValueError: if ``score`` is outside ``[0.0, 1.0]``.
    """
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"risk score must be within [0.0, 1.0], got {score!r}")
    for lower_bound, band in _RISK_BAND_THRESHOLDS:
        if score >= lower_bound:
            return band
    return RiskBand.NEGLIGIBLE  # pragma: no cover - unreachable, kept for exhaustiveness


def severity_for_score(score: float) -> Severity:
    """Suggest a severity for a risk score.

    Deterministic default mapping used when a detector does not supply its own severity.
    Policy - not this helper - decides what happens next.
    """
    return _BAND_TO_SEVERITY[band_for_score(score)]


_BAND_TO_SEVERITY: dict[RiskBand, Severity] = {
    RiskBand.NEGLIGIBLE: Severity.INFO,
    RiskBand.LOW: Severity.LOW,
    RiskBand.ELEVATED: Severity.MEDIUM,
    RiskBand.HIGH: Severity.HIGH,
    RiskBand.SEVERE: Severity.CRITICAL,
}


__all__ = [
    "ActorRef",
    "CorrelationRef",
    "FileContext",
    "HostRef",
    "NetworkContext",
    "ProcessContext",
    "RiskAssessment",
    "SecurityEvent",
    "SocketContext",
    "SourceRef",
    "band_for_score",
    "severity_for_score",
]
