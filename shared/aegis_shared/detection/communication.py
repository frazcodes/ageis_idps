"""Deterministic multi-signal suspicious-communication analysis.

Combines several **factual** signals already produced by Aegis - a new
relationship/destination/port from the bounded baseline, a network AI anomaly,
existing host evidence, existing network behavioral findings and IOC context -
into a single explainable finding (``AEGIS-NET-007``).

Design
------
* **Pure and stateless.** :meth:`SuspiciousCommunicationAnalyzer.analyze` is a
  pure function of the supplied observations; it keeps no state between calls.
* **Multi-signal only.** A single weak signal (a new IP, port or relationship
  alone) never produces a finding. At least ``min_signals`` independent signals
  are required.
* **No duplicate IOC.** When an IOC match is present the existing
  ``AEGIS-IOC-001`` finding remains primary evidence; no ``AEGIS-NET-007`` is
  emitted for that relationship.
* **Neutral language.** Findings describe observed patterns, never a verdict.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from aegis_shared.detection.config import DetectionSettings
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.detection.rules import RULE_NETWORK_COMMUNICATION
from aegis_shared.enums import (
    EventCategory,
    EventType,
    NetworkDirection,
    Severity,
    TransportProtocol,
)

_RULE_NAME = "Suspicious communication pattern observed"
_RULE_DESCRIPTION = (
    "Multiple independent network or host signals were observed for a "
    "communication relationship."
)


class CommunicationSignalType(StrEnum):
    """The factual signals the analyzer can combine."""

    NEW_RELATIONSHIP = "new_relationship"
    NEW_DESTINATION = "new_destination"
    NEW_DESTINATION_PORT = "new_destination_port"
    NETWORK_ANOMALY = "network_anomaly"
    HOST_EVIDENCE = "host_evidence"
    BEHAVIORAL = "behavioral"
    IOC_MATCH = "ioc_match"


@dataclass(frozen=True)
class CommunicationSignal:
    """One observed signal supporting a communication relationship."""

    signal_type: CommunicationSignalType
    source: str
    observed: bool
    description: str


@dataclass(frozen=True)
class CommunicationObservation:
    """One communication relationship with its observed signals."""

    host_id: str
    event_id: str
    event_type: EventType
    category: EventCategory
    timestamp: datetime
    local_ip: str | None
    remote_ip: str
    remote_port: int | None
    protocol: TransportProtocol
    direction: NetworkDirection
    signals: tuple[CommunicationSignal, ...] = ()
    related_finding_ids: tuple[str, ...] = ()

    @property
    def relationship(self) -> str:
        """A short factual description of the relationship."""
        local = self.local_ip or "-"
        port = self.remote_port if self.remote_port is not None else "-"
        return f"{local} -> {self.remote_ip}:{port}"

    @property
    def observed_signals(self) -> tuple[CommunicationSignal, ...]:
        """The signals that were actually observed."""
        return tuple(signal for signal in self.signals if signal.observed)


def _relationship_id(observation: CommunicationObservation) -> str:
    payload = (
        f"{observation.host_id}|{observation.local_ip or '-'}|{observation.remote_ip}|"
        f"{observation.remote_port}|{observation.protocol.value}"
    )
    return hashlib.sha1(payload.encode(), usedforsecurity=False).hexdigest()[:16]


def _severity(types: set[CommunicationSignalType]) -> Severity:
    """Deterministic severity from the signal combination (no new scoring model)."""
    has_anomaly = CommunicationSignalType.NETWORK_ANOMALY in types
    has_host = CommunicationSignalType.HOST_EVIDENCE in types
    if has_anomaly and has_host:
        return Severity.HIGH
    if has_anomaly or has_host:
        return Severity.MEDIUM
    if CommunicationSignalType.BEHAVIORAL in types:
        return Severity.MEDIUM
    return Severity.LOW


class SuspiciousCommunicationAnalyzer:
    """Combine factual signals into explainable suspicious-communication findings."""

    def __init__(self, *, min_signals: int = 2, max_findings: int = 256) -> None:
        self._min_signals = max(2, min_signals)
        self._max_findings = max(1, max_findings)

    @property
    def min_signals(self) -> int:
        """Minimum independent signals required."""
        return self._min_signals

    @property
    def max_findings(self) -> int:
        """Maximum findings produced per analysis."""
        return self._max_findings

    def analyze(
        self, observations: Iterable[CommunicationObservation]
    ) -> tuple[DetectionFinding, ...]:
        """Return suspicious-communication findings, deduplicated and deterministic."""
        by_id: dict[str, DetectionFinding] = {}
        for observation in observations:
            finding = self._evaluate(observation)
            if finding is not None:
                by_id.setdefault(finding.finding_id, finding)
        findings = sorted(by_id.values(), key=lambda finding: finding.finding_id)
        return tuple(findings[: self._max_findings])

    def _evaluate(self, observation: CommunicationObservation) -> DetectionFinding | None:
        present = observation.observed_signals
        types = {signal.signal_type for signal in present}
        # The existing IOC finding is primary evidence; never duplicate it.
        if CommunicationSignalType.IOC_MATCH in types:
            return None
        if len(present) < self._min_signals:
            return None
        return _build_finding(observation, present, _severity(types))


def _build_finding(
    observation: CommunicationObservation,
    present: Sequence[CommunicationSignal],
    severity: Severity,
) -> DetectionFinding:
    types = {signal.signal_type for signal in present}
    baseline_state = (
        "new" if CommunicationSignalType.NEW_RELATIONSHIP in types else "known"
    )
    evidence = {
        "relationship": observation.relationship,
        "local_ip": observation.local_ip or "-",
        "remote_ip": observation.remote_ip,
        "remote_port": (
            str(observation.remote_port) if observation.remote_port is not None else "-"
        ),
        "protocol": observation.protocol.value,
        "direction": observation.direction.value,
        "signals": ",".join(sorted(signal.signal_type.value for signal in present)),
        "signal_count": str(len(present)),
        "baseline_state": baseline_state,
        "related_finding_ids": ",".join(observation.related_finding_ids),
    }
    return DetectionFinding(
        finding_id=f"{RULE_NETWORK_COMMUNICATION}:{_relationship_id(observation)}",
        rule_id=RULE_NETWORK_COMMUNICATION,
        rule_name=_RULE_NAME,
        severity=severity,
        title=_RULE_NAME,
        description=_RULE_DESCRIPTION,
        event_id=observation.event_id,
        event_type=observation.event_type,
        category=observation.category,
        timestamp=observation.timestamp,
        host_id=observation.host_id,
        evidence=evidence,
        tags=("network", "communication", "multi_signal"),
    )


def build_communication_analyzer(settings: DetectionSettings) -> SuspiciousCommunicationAnalyzer:
    """Build the analyzer from the existing detection settings."""
    return SuspiciousCommunicationAnalyzer(
        min_signals=settings.network_communication_min_signals,
        max_findings=settings.network_communication_max_findings,
    )


def communication_rule_info(rule_id: str) -> dict[str, str]:
    """Return static metadata for the communication rule, or ``{}`` when unknown."""
    if rule_id != RULE_NETWORK_COMMUNICATION:
        return {}
    return {
        "rule_id": RULE_NETWORK_COMMUNICATION,
        "name": _RULE_NAME,
        "description": _RULE_DESCRIPTION,
        "tags": "network, communication, multi_signal",
    }


__all__ = [
    "CommunicationObservation",
    "CommunicationSignal",
    "CommunicationSignalType",
    "SuspiciousCommunicationAnalyzer",
    "build_communication_analyzer",
    "communication_rule_info",
]
