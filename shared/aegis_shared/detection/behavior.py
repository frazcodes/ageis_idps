"""Deterministic behavioral network detection over bounded flow telemetry.

The per-event :class:`~aegis_shared.detection.rules.DetectionRule` contract
evaluates one event at a time. Some useful network behaviors are only visible
across a *window* of flows (a burst, repeated communication, fan-out, broad
destination ports). :class:`NetworkBehaviorAnalyzer` evaluates those patterns
deterministically over the network flow-summary events already produced by the
runtime.

Design
------
* **Pure and stateless.** ``evaluate(events)`` is a pure function of the supplied
  events; the same batch always yields the same findings. The bounded event
  pipeline buffer is the only window state, so there is no unbounded history and
  nothing to persist.
* **Configuration-driven.** Every threshold defaults to ``0`` = disabled, so
  normal low-volume traffic never produces findings.
* **Evidence-based language.** Findings describe the observed pattern and counts
  ("connection/flow burst observed", "multiple destination ports observed"),
  never a cause. Exceeding a behavioral threshold is not proof of an attack.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from aegis_shared.detection.config import DetectionSettings
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.detection.rules import (
    RULE_NETWORK_DEST_FANOUT,
    RULE_NETWORK_FLOW_BURST,
    RULE_NETWORK_PORT_BREADTH,
    RULE_NETWORK_REPEATED_COMM,
)
from aegis_shared.enums import EventCategory, EventType, Severity
from aegis_shared.events import SecurityEvent

#: Stable identity/severity metadata for the behavioral rules (for the UI).
BEHAVIOR_RULE_INFO: dict[str, dict[str, str]] = {
    RULE_NETWORK_FLOW_BURST: {
        "rule_id": RULE_NETWORK_FLOW_BURST,
        "name": "Connection/flow burst observed",
        "description": (
            "A high number of distinct network flows was observed within the "
            "configured window."
        ),
        "tags": "network, flow, burst",
    },
    RULE_NETWORK_REPEATED_COMM: {
        "rule_id": RULE_NETWORK_REPEATED_COMM,
        "name": "Repeated communication observed",
        "description": (
            "Repeated flows between the same source and destination were observed "
            "within the configured window."
        ),
        "tags": "network, flow, repeated",
    },
    RULE_NETWORK_DEST_FANOUT: {
        "rule_id": RULE_NETWORK_DEST_FANOUT,
        "name": "Destination fan-out observed",
        "description": (
            "One source communicated with an unusually high number of distinct "
            "destinations within the configured window."
        ),
        "tags": "network, flow, fanout",
    },
    RULE_NETWORK_PORT_BREADTH: {
        "rule_id": RULE_NETWORK_PORT_BREADTH,
        "name": "Multiple destination ports observed",
        "description": (
            "One source communicated with an unusually broad range of destination "
            "ports within the configured window."
        ),
        "tags": "network, flow, ports",
    },
}


@dataclass(frozen=True)
class _Observation:
    """One network flow-summary observation (metadata only, no payload)."""

    timestamp: datetime
    event_id: str
    flow_id: str
    host_id: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str


@dataclass(frozen=True)
class _RuleSpec:
    rule_id: str
    name: str
    description: str
    severity: Severity
    tags: tuple[str, ...]
    window_seconds: int
    threshold: int
    kind: str


def _observation_from_event(event: SecurityEvent) -> _Observation | None:
    if not isinstance(event, SecurityEvent):
        return None
    if event.event_type is not EventType.FLOW_SUMMARY:
        return None
    net = event.network
    if net is None:
        return None
    flow_id = net.flow_id or (
        f"{net.src_ip or '-'}|{net.protocol.value}|{net.dst_ip or '-'}:{net.dst_port}"
    )
    return _Observation(
        timestamp=event.timestamp,
        event_id=event.event_id,
        flow_id=flow_id,
        host_id=event.host.host_id if event.host is not None else None,
        src_ip=net.src_ip,
        dst_ip=net.dst_ip,
        dst_port=net.dst_port,
        protocol=net.protocol.value,
    )


class NetworkBehaviorAnalyzer:
    """Evaluate deterministic behavioral network patterns over flow events."""

    def __init__(
        self,
        *,
        flow_burst_threshold: int = 0,
        flow_burst_window_seconds: int = 60,
        repeated_comm_threshold: int = 0,
        repeated_comm_window_seconds: int = 60,
        dest_fanout_threshold: int = 0,
        dest_fanout_window_seconds: int = 60,
        port_breadth_threshold: int = 0,
        port_breadth_window_seconds: int = 60,
        disabled_rules: Iterable[str] = (),
    ) -> None:
        self._disabled = frozenset(disabled_rules)
        self._specs: tuple[_RuleSpec, ...] = (
            _RuleSpec(
                RULE_NETWORK_FLOW_BURST,
                "Connection/flow burst observed",
                "A high number of distinct network flows was observed within the "
                "configured window. This describes observed connection volume, not "
                "an attack.",
                Severity.MEDIUM,
                ("network", "flow", "burst"),
                max(1, flow_burst_window_seconds),
                max(0, flow_burst_threshold),
                "burst",
            ),
            _RuleSpec(
                RULE_NETWORK_REPEATED_COMM,
                "Repeated communication observed",
                "Repeated flows between the same source and destination were observed "
                "within the configured window. Repeated communication is not "
                "inherently malicious.",
                Severity.LOW,
                ("network", "flow", "repeated"),
                max(1, repeated_comm_window_seconds),
                max(0, repeated_comm_threshold),
                "repeated",
            ),
            _RuleSpec(
                RULE_NETWORK_DEST_FANOUT,
                "Destination fan-out observed",
                "One source communicated with an unusually high number of distinct "
                "destinations within the configured window.",
                Severity.MEDIUM,
                ("network", "flow", "fanout"),
                max(1, dest_fanout_window_seconds),
                max(0, dest_fanout_threshold),
                "fanout",
            ),
            _RuleSpec(
                RULE_NETWORK_PORT_BREADTH,
                "Multiple destination ports observed",
                "One source communicated with an unusually broad range of destination "
                "ports within the configured window. This is an observation, not a "
                "confirmed port scan.",
                Severity.MEDIUM,
                ("network", "flow", "ports"),
                max(1, port_breadth_window_seconds),
                max(0, port_breadth_threshold),
                "port_breadth",
            ),
        )

    @property
    def configured(self) -> bool:
        """Whether any behavioral rule has a threshold and is enabled."""
        return any(
            spec.threshold > 0 and spec.rule_id not in self._disabled for spec in self._specs
        )

    def evaluate(self, events: Iterable[SecurityEvent]) -> tuple[DetectionFinding, ...]:
        """Return behavioral findings for the supplied flow events (pure)."""
        observations = [
            obs for event in events if (obs := _observation_from_event(event)) is not None
        ]
        if not observations:
            return ()

        # Anchor every finding at the newest observation so findings reference a
        # real, current event (usable by risk assessment and correlation).
        anchor = max(observations, key=lambda obs: (obs.timestamp, obs.event_id))

        findings: list[DetectionFinding] = []
        for spec in self._specs:
            if spec.threshold <= 0 or spec.rule_id in self._disabled:
                continue
            window = [
                obs
                for obs in observations
                if 0.0 <= (anchor.timestamp - obs.timestamp).total_seconds() <= spec.window_seconds
            ]
            if not window:
                continue
            metric, detail = self._measure(spec.kind, window)
            if metric < spec.threshold:
                continue
            findings.append(self._build(spec, metric, detail, window, anchor))

        return tuple(sorted(findings, key=lambda finding: finding.finding_id))

    # ------------------------------------------------------------------
    # Pattern measurement
    # ------------------------------------------------------------------

    @staticmethod
    def _measure(kind: str, window: list[_Observation]) -> tuple[int, dict[str, str]]:
        if kind == "burst":
            return len({obs.flow_id for obs in window}), {}

        if kind == "repeated":
            groups: dict[tuple[str, str], set[str]] = {}
            for obs in window:
                key = (obs.src_ip or "-", obs.dst_ip or "-")
                groups.setdefault(key, set()).add(obs.flow_id)
            (src, dst), flows = max(groups.items(), key=lambda item: (len(item[1]), item[0]))
            return len(flows), {"src_ip": src, "dst_ip": dst, "repeated_flows": str(len(flows))}

        if kind == "fanout":
            groups = {}
            for obs in window:
                if obs.dst_ip is None:
                    continue
                groups.setdefault(obs.src_ip or "-", set()).add(obs.dst_ip)
            if not groups:
                return 0, {}
            src, destinations = max(groups.items(), key=lambda item: (len(item[1]), item[0]))
            return len(destinations), {
                "src_ip": src,
                "distinct_destinations": str(len(destinations)),
            }

        # port_breadth
        groups = {}
        for obs in window:
            if obs.dst_port is None:
                continue
            groups.setdefault(obs.src_ip or "-", set()).add(obs.dst_port)
        if not groups:
            return 0, {}
        src, ports = max(groups.items(), key=lambda item: (len(item[1]), item[0]))
        return len(ports), {
            "src_ip": src,
            "distinct_destination_ports": str(len(ports)),
        }

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build(
        spec: _RuleSpec,
        metric: int,
        detail: dict[str, str],
        window: list[_Observation],
        anchor: _Observation,
    ) -> DetectionFinding:
        evidence: dict[str, str] = {
            "observed_count": str(metric),
            "threshold": str(spec.threshold),
            "window_seconds": str(spec.window_seconds),
            "distinct_flows_in_window": str(len({obs.flow_id for obs in window})),
        }
        evidence.update(detail)
        protocols = sorted({obs.protocol for obs in window})
        if protocols:
            evidence["protocols"] = ",".join(protocols)
        if anchor.src_ip:
            evidence.setdefault("anchor_src_ip", anchor.src_ip)
        if anchor.dst_ip:
            evidence.setdefault("anchor_dst_ip", anchor.dst_ip)

        return DetectionFinding(
            finding_id=f"{spec.rule_id}:{anchor.event_id}",
            rule_id=spec.rule_id,
            rule_name=spec.name,
            severity=spec.severity,
            title=spec.name,
            description=spec.description,
            event_id=anchor.event_id,
            event_type=EventType.FLOW_SUMMARY,
            category=EventCategory.NETWORK,
            timestamp=anchor.timestamp,
            host_id=anchor.host_id,
            evidence=evidence,
            tags=spec.tags,
        )


def build_behavior_analyzer(settings: DetectionSettings) -> NetworkBehaviorAnalyzer:
    """Build the behavioral analyzer from configuration."""
    return NetworkBehaviorAnalyzer(
        flow_burst_threshold=settings.network_flow_burst_threshold,
        flow_burst_window_seconds=settings.network_flow_burst_window_seconds,
        repeated_comm_threshold=settings.network_repeated_comm_threshold,
        repeated_comm_window_seconds=settings.network_repeated_comm_window_seconds,
        dest_fanout_threshold=settings.network_destination_fanout_threshold,
        dest_fanout_window_seconds=settings.network_destination_fanout_window_seconds,
        port_breadth_threshold=settings.network_destination_port_breadth_threshold,
        port_breadth_window_seconds=settings.network_destination_port_breadth_window_seconds,
        disabled_rules=settings.disabled_rules,
    )


def behavior_rule_info(rule_id: str) -> dict[str, str]:
    """Return static metadata for a behavioral rule, or ``{}`` when unknown."""
    return dict(BEHAVIOR_RULE_INFO.get(rule_id, {}))


__all__ = [
    "BEHAVIOR_RULE_INFO",
    "NetworkBehaviorAnalyzer",
    "behavior_rule_info",
    "build_behavior_analyzer",
]
