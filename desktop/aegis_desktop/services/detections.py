"""Detections adapter: existing Step 8 detection engine -> UI-friendly data.

Strictly read-only. It locates the existing :class:`DetectionEngine` through the
small process-wide registry, evaluates the events currently buffered in the
existing event pipeline (a one-shot, read-only ``peek``) and translates the
resulting :class:`DetectionFinding` objects for the Qt table model.

The detection engine remains the single source of truth: no rules are duplicated
in the GUI, no findings are fabricated, and no independent event store exists. It
never starts a producer, never runs a detection loop and never performs a
response. Sensitive evidence is redacted at the presentation layer.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_desktop.services.assets import AssetContext, asset_context_for_host
from aegis_desktop.services.correlation import (
    CorrelationEvidence,
    correlation_for_finding,
)
from aegis_desktop.services.processes import MISSING
from aegis_desktop.services.response_policy import (
    ResponsePolicyView,
    collect_response_policy_view,
)
from aegis_desktop.services.threat_intel import ThreatIntelView, threat_intel_for_event
from aegis_shared.logging import get_logger, redact

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.detection import DetectionEngine, DetectionFinding
    from aegis_shared.events import SecurityEvent
    from aegis_shared.risk import AnomalySignal

logger = get_logger(__name__)

#: Non-sensitive message shown when findings cannot be read.
DETECTION_ERROR = "Unable to read detection findings"
#: Non-sensitive message shown when no detection engine is published.
ENGINE_NOT_RUNNING = "Detection Engine: Not running"

#: Evidence keys whose values are command lines and must be re-sanitized.
_COMMAND_LINE_KEYS = ("command_line", "cmdline", "cmd")


@dataclass(frozen=True)
class FindingRow:
    """One detection finding, flattened for display and sorting."""

    timestamp: datetime
    finding_id: str
    rule_id: str
    severity: str
    title: str
    event_id: str
    event_type: str
    category: str
    host_id: str | None
    description: str
    evidence_summary: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class DetectionPosture:
    """Read-only view of the detection engine's configuration/state."""

    running: bool
    enabled: bool
    rule_count: int
    findings: int


@dataclass(frozen=True)
class FindingSnapshotView:
    """Read-only view of detection findings plus engine posture."""

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: DetectionPosture
    rows: tuple[FindingRow, ...]
    findings: tuple[DetectionFinding, ...] = ()

    @property
    def count(self) -> int:
        """Number of findings in the view."""
        return len(self.rows)

    def finding_by_id(self, finding_id: str) -> DetectionFinding | None:
        """Return the finding with ``finding_id``, if present."""
        for finding in self.findings:
            if finding.finding_id == finding_id:
                return finding
        return None


def _sanitize_command_line(command_line: str) -> str | None:
    """Re-sanitize a command line at presentation time (lazy import).

    Imported lazily so importing the desktop application does not load
    ``aegis_agent.monitors`` (startup-safety requirement).
    """
    from aegis_agent.monitors.process.commandline import sanitize_command_line

    return sanitize_command_line(command_line)


def _safe_value(key: str, value: object) -> str:
    """Render one evidence value safely, re-sanitizing command lines."""
    text = str(value)
    if key.lower() in _COMMAND_LINE_KEYS:
        sanitized = _sanitize_command_line(text)
        return sanitized if sanitized is not None else MISSING
    return text


def _redacted_evidence(evidence: dict[str, str]) -> dict[str, str]:
    """Return evidence safe for display: redacted keys + sanitized command lines."""
    redacted = redact(dict(evidence))
    return {key: _safe_value(key, value) for key, value in redacted.items()}


def evidence_summary(evidence: dict[str, str]) -> str:
    """Build a concise, deterministic, safe summary of finding evidence."""
    if not evidence:
        return MISSING
    safe = _redacted_evidence(evidence)
    parts = [f"{key}={safe[key]}" for key in sorted(safe)]
    return " ".join(parts)


def _default_engine() -> DetectionEngine | None:
    """Return the published detection engine, or ``None`` when none is running."""
    from aegis_shared.detection import get_active_engine

    return get_active_engine()


def _default_events() -> list[SecurityEvent]:
    """Return the events currently buffered in the existing pipeline (read-only)."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return []
    return [envelope.event for envelope in pipeline.peek()]


def _merge_findings(
    findings: tuple[DetectionFinding, ...],
    events: Iterable[SecurityEvent],
) -> tuple[DetectionFinding, ...]:
    """Merge per-event engine findings with deterministic behavioral findings.

    The behavioral analyzer is pure over the same bounded event buffer, so the
    GUI shows exactly the findings the runtime produces - no GUI-only detection.
    """
    try:
        from aegis_shared.detection import build_behavior_analyzer, get_detection_settings

        analyzer = build_behavior_analyzer(get_detection_settings())
        behavior = analyzer.evaluate(events) if analyzer.configured else ()
    except Exception as exc:
        logger.warning("Behavioral detection failed: %s", exc)
        behavior = ()

    seen: set[str] = set()
    merged: list[DetectionFinding] = []
    for finding in (*findings, *behavior):
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        merged.append(finding)
    return tuple(merged)


def _posture(engine: DetectionEngine | None, findings: int) -> DetectionPosture:
    if engine is None:
        return DetectionPosture(running=False, enabled=False, rule_count=0, findings=findings)
    return DetectionPosture(
        running=True,
        enabled=engine.enabled,
        rule_count=len(engine.rules),
        findings=findings,
    )


def _to_row(finding: DetectionFinding) -> FindingRow:
    return FindingRow(
        timestamp=finding.timestamp,
        finding_id=finding.finding_id,
        rule_id=finding.rule_id,
        severity=finding.severity.value,
        title=finding.title,
        event_id=finding.event_id,
        event_type=finding.event_type.value,
        category=finding.category.value,
        host_id=finding.host_id,
        description=finding.description,
        evidence_summary=evidence_summary(dict(finding.evidence)),
        tags=tuple(finding.tags),
    )


def collect_finding_view(
    *,
    engine: DetectionEngine | None = None,
    engine_provider: Callable[[], DetectionEngine | None] | None = None,
    events_provider: Callable[[], Iterable[SecurityEvent]] | None = None,
) -> FindingSnapshotView:
    """Read findings by evaluating the existing engine over buffered events.

    Args:
        engine: An engine to use directly (tests inject one).
        engine_provider: Overrides how the active engine is resolved.
        events_provider: Overrides the event source (defaults to the existing
            event pipeline's read-only ``peek``).

    The engine is only evaluated; it is never started, and no producer is
    triggered. With no engine published, an honest "not running" state is shown.
    """
    resolved = engine
    if resolved is None:
        provider = engine_provider or _default_engine
        try:
            resolved = provider()
        except Exception as exc:
            logger.warning("Resolving the detection engine failed: %s", exc)
            resolved = None

    try:
        findings: tuple[DetectionFinding, ...]
        if resolved is None:
            findings = ()
        else:
            events = (events_provider or _default_events)()
            findings = _merge_findings(resolved.evaluate_many(events), events)
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Reading detection findings failed: %s", exc)
        return FindingSnapshotView(
            available=False,
            error=DETECTION_ERROR,
            collected_at=None,
            posture=DetectionPosture(False, False, 0, 0),
            rows=(),
        )

    rows = tuple(_to_row(finding) for finding in findings)
    return FindingSnapshotView(
        available=True,
        error=None,
        collected_at=rows[-1].timestamp if rows else None,
        posture=_posture(resolved, len(rows)),
        rows=rows,
        findings=findings,
    )


def describe_finding(finding: DetectionFinding) -> dict[str, str]:
    """Return a structured, safe, read-only view of one finding for the detail panel.

    Only known fields are included; evidence is redacted and command lines are
    re-sanitized. No ``repr()`` is used.
    """
    details: dict[str, str] = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "event_id": finding.event_id,
        "event_type": finding.event_type.value,
        "category": finding.category.value,
        "timestamp": finding.timestamp.isoformat(),
    }
    if finding.host_id:
        details["host_id"] = finding.host_id

    safe_evidence = _redacted_evidence(dict(finding.evidence))
    for key in sorted(safe_evidence):
        details[f"evidence.{key}"] = safe_evidence[key]

    if finding.tags:
        details["tags"] = ", ".join(finding.tags)

    return details


# ---------------------------------------------------------------------------
# Investigation view
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnomalyView:
    """Read-only view of an existing ML anomaly signal on a risk assessment."""

    detected: bool
    score: float
    confidence: float
    model_version: str
    source: str
    reason: str | None


@dataclass(frozen=True)
class RiskView:
    """Read-only risk assessment summary for one finding's event."""

    risk_score: int
    risk_level: str
    severity: str
    reasons: tuple[str, ...]
    contributors: tuple[str, ...]
    anomaly: AnomalyView | None = None


@dataclass(frozen=True)
class ResponsePosture:
    """Read-only response engine posture."""

    mode: str
    dry_run: bool
    require_approval: bool


@dataclass(frozen=True)
class CommunicationView:
    """Read-only view of a multi-signal suspicious-communication finding."""

    relationship: str
    local_ip: str | None
    remote_ip: str
    remote_port: str | None
    protocol: str
    signals: tuple[str, ...]
    signal_count: int
    related_finding_ids: tuple[str, ...]
    assessment: str


@dataclass(frozen=True)
class InvestigationView:
    """Full read-only investigation context for one detection finding."""

    finding: dict[str, str]
    rule_info: dict[str, str]
    evidence: dict[str, str]
    risk: RiskView | None
    response: ResponsePosture
    event_details: dict[str, str] | None
    correlation: CorrelationEvidence | None = None
    threat_intel: ThreatIntelView | None = None
    asset_context: AssetContext | None = None
    communication: CommunicationView | None = None
    response_policy: ResponsePolicyView | None = None


def _response_posture() -> ResponsePosture:
    """Read response posture from existing env config (lazy import)."""
    try:
        from aegis_response_engine.config import get_response_settings

        settings = get_response_settings()
        return ResponsePosture(
            mode=settings.mode.value,
            dry_run=settings.dry_run,
            require_approval=settings.require_approval,
        )
    except Exception:
        return ResponsePosture(mode="monitor", dry_run=True, require_approval=True)


def _rule_info_for(rule_id: str) -> dict[str, str]:
    """Look up static rule metadata from the detection engine (lazy import)."""
    from aegis_shared.detection import behavior_rule_info, get_active_engine

    engine = get_active_engine()
    if engine is not None:
        for rule in engine.rules:
            if rule.rule_id == rule_id:
                return {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "tags": ", ".join(rule.tags) if rule.tags else "",
                }
    # Behavioral network rules are evaluated over a window, not per-event, so they
    # are not part of the engine's rule set; fall back to their static metadata.
    behavior_info = behavior_rule_info(rule_id)
    if behavior_info:
        return behavior_info
    # Threat-intelligence matching is likewise evaluated outside the engine.
    from aegis_shared.threat_intel import ioc_rule_info

    threat_info = ioc_rule_info(rule_id)
    if threat_info:
        return threat_info
    # Multi-signal communication analysis is evaluated outside the engine too.
    from aegis_shared.detection import communication_rule_info

    return communication_rule_info(rule_id)


def _event_for(event_id: str) -> SecurityEvent | None:
    """Resolve an event from the active pipeline by event_id."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return None
    for envelope in pipeline.peek():
        if envelope.event.event_id == event_id:
            return envelope.event
    return None


def _anomaly_for(event: SecurityEvent | None) -> AnomalySignal | None:
    """Resolve an ML anomaly signal for an event from the published registry.

    Read-only: it never runs a model. Returns ``None`` when no signal was
    published (e.g. no fitted model or ML disabled), so the panel shows the
    honest empty state.
    """
    if event is None:
        return None
    from aegis_shared.risk import get_active_anomaly_signals

    return get_active_anomaly_signals().get(event.event_id)


def _anomaly_view(signal: AnomalySignal | None) -> AnomalyView | None:
    """Map an existing :class:`AnomalySignal` to a read-only display view.

    Returns ``None`` when no signal exists so the UI can show an honest empty
    state. No value is invented: every field comes from the signal.
    """
    if signal is None:
        return None
    return AnomalyView(
        detected=True,
        score=signal.score,
        confidence=signal.confidence,
        model_version=signal.model_version,
        source=signal.source,
        reason=signal.reason,
    )


def _risk_for(
    event: SecurityEvent,
    finding: DetectionFinding,
    anomaly_signal: AnomalySignal | None = None,
) -> RiskView | None:
    """Run a one-shot risk assessment for one event + finding (lazy import).

    When an existing anomaly signal is supplied it is passed through to the
    engine so the returned assessment carries it in ``RiskAssessment.anomaly``.
    The signal never changes the deterministic risk score.
    """
    from aegis_shared.risk import get_active_risk_engine

    engine = get_active_risk_engine()
    if engine is None:
        return None
    try:
        assessment = engine.assess(event, [finding], anomaly_signal=anomaly_signal)
    except Exception:
        return None
    contributors = tuple(
        f"{c.finding_id} ({c.severity.value}) +{c.contribution}"
        for c in assessment.contributors
    )
    return RiskView(
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level.value,
        severity=assessment.severity.value,
        reasons=assessment.reasons,
        contributors=contributors,
        anomaly=_anomaly_view(assessment.anomaly),
    )


def _communication_for(finding: DetectionFinding) -> CommunicationView | None:
    """Build a communication view from a multi-signal finding's evidence."""
    from aegis_shared.detection.rules import RULE_NETWORK_COMMUNICATION

    if finding.rule_id != RULE_NETWORK_COMMUNICATION:
        return None
    evidence = dict(finding.evidence)

    def _split(key: str) -> tuple[str, ...]:
        return tuple(item for item in evidence.get(key, "").split(",") if item)

    try:
        count = int(evidence.get("signal_count", "0") or 0)
    except ValueError:
        count = 0
    return CommunicationView(
        relationship=evidence.get("relationship", ""),
        local_ip=evidence.get("local_ip"),
        remote_ip=evidence.get("remote_ip", ""),
        remote_port=evidence.get("remote_port"),
        protocol=evidence.get("protocol", ""),
        signals=_split("signals"),
        signal_count=count,
        related_finding_ids=_split("related_finding_ids"),
        assessment=finding.title,
    )


def collect_investigation_view(
    finding: DetectionFinding,
    *,
    finding_lookup: Callable[[str], DetectionFinding | None] | None = None,
    event_lookup: Callable[[str], SecurityEvent | None] | None = None,
    event_details_lookup: Callable[[str], dict[str, str] | None] | None = None,
    risk_lookup: Callable[[SecurityEvent, DetectionFinding], RiskView | None] | None = None,
    rule_lookup: Callable[[str], dict[str, str]] | None = None,
    anomaly_lookup: Callable[[SecurityEvent, DetectionFinding], AnomalySignal | None] | None = None,
    correlation_lookup: Callable[[DetectionFinding], CorrelationEvidence | None] | None = None,
    threat_intel_lookup: Callable[[SecurityEvent | None], ThreatIntelView | None] | None = None,
    asset_context_lookup: Callable[[str | None], AssetContext | None] | None = None,
    response_policy_lookup: Callable[[DetectionFinding], ResponsePolicyView | None] | None = None,
) -> InvestigationView:
    """Build a read-only investigation context for one finding.

    Args:
        finding: The finding to investigate.
        finding_lookup: Override for the snapshot-level finding lookup.
        event_lookup: Override for event resolution (defaults to pipeline).
        event_details_lookup: Override for event detail dict resolution. When
            supplied it takes precedence over ``event_lookup`` + ``describe_event``.
        risk_lookup: Override for risk resolution (defaults to risk engine).
        rule_lookup: Override for rule metadata resolution (defaults to engine).
        anomaly_lookup: Optional override returning the existing ML anomaly signal
            for an event/finding. When omitted no signal is used and the panel
            shows an honest empty state.
        correlation_lookup: Optional override returning the host/network
            correlation for a finding. When omitted the published runtime
            correlation is used, or ``None`` (honest empty state).
        threat_intel_lookup: Optional override returning the IOC context for the
            finding's event. When omitted the shared matcher is run over the
            resolved event, or ``None`` (honest empty state).
        asset_context_lookup: Optional override returning the observed asset
            context for the finding's host. When omitted the published asset
            snapshot is used, or ``None``.
        response_policy_lookup: Optional override returning the response-policy
            decision for a finding. When omitted the deterministic policy engine
            is evaluated (read-only; nothing executes).
    """
    finding_dict = describe_finding(finding)
    lookup_rule = rule_lookup or _rule_info_for
    rule_info = lookup_rule(finding.rule_id)
    safe_evidence = _redacted_evidence(dict(finding.evidence))

    # Event details: use the direct lookup when supplied, otherwise resolve
    # through the pipeline + describe_event path.
    event: SecurityEvent | None = None
    if event_details_lookup is not None:
        event_details = event_details_lookup(finding.event_id)
    else:
        lookup_event = event_lookup or _event_for
        event = lookup_event(finding.event_id)
        if event is not None:
            from aegis_desktop.services.events import describe_event

            event_details = describe_event(event)
        else:
            event_details = None

    anomaly_signal: AnomalySignal | None = None
    if anomaly_lookup is not None:
        try:
            anomaly_signal = anomaly_lookup(event, finding)  # type: ignore[arg-type]
        except Exception:
            anomaly_signal = None
    else:
        # Default: read the latest signal published by the running runtime.
        anomaly_signal = _anomaly_for(event)

    if risk_lookup is not None:
        risk = risk_lookup(event, finding)  # type: ignore[arg-type]
    elif event is not None:
        risk = _risk_for(event, finding, anomaly_signal)
    else:
        risk = None
    response = _response_posture()

    correlation: CorrelationEvidence | None = None
    if correlation_lookup is not None:
        try:
            correlation = correlation_lookup(finding)
        except Exception:
            correlation = None
    else:
        correlation = correlation_for_finding(finding.finding_id)

    threat_intel: ThreatIntelView | None = None
    if threat_intel_lookup is not None:
        try:
            threat_intel = threat_intel_lookup(event)
        except Exception:
            threat_intel = None
    else:
        threat_intel = threat_intel_for_event(event)

    asset_context: AssetContext | None = None
    if asset_context_lookup is not None:
        try:
            asset_context = asset_context_lookup(finding.host_id)
        except Exception:
            asset_context = None
    else:
        asset_context = asset_context_for_host(finding.host_id)

    communication = _communication_for(finding)

    response_policy: ResponsePolicyView | None = None
    if response_policy_lookup is not None:
        try:
            response_policy = response_policy_lookup(finding)
        except Exception:
            response_policy = None
    else:
        response_policy = collect_response_policy_view(
            finding,
            risk_level=risk.risk_level if risk is not None else None,
            risk_score=risk.risk_score if risk is not None else None,
        )

    return InvestigationView(
        finding=finding_dict,
        rule_info=rule_info,
        evidence=safe_evidence,
        risk=risk,
        response=response,
        event_details=event_details,
        correlation=correlation,
        threat_intel=threat_intel,
        asset_context=asset_context,
        communication=communication,
        response_policy=response_policy,
    )


__all__ = [
    "DETECTION_ERROR",
    "ENGINE_NOT_RUNNING",
    "AnomalyView",
    "DetectionPosture",
    "FindingRow",
    "FindingSnapshotView",
    "InvestigationView",
    "ResponsePosture",
    "RiskView",
    "collect_finding_view",
    "collect_investigation_view",
    "describe_finding",
    "evidence_summary",
]
