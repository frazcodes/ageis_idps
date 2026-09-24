"""Risk adapter: existing Step 9 risk engine -> UI-friendly data.

Strictly read-only. It locates the existing :class:`RiskEngine` through the small
process-wide registry and, when one is published, produces assessments one-shot
by invoking the existing engine over the events already buffered in the existing
event pipeline (read-only ``peek``) and the findings produced by the existing
detection engine. The risk engine remains the single source of truth: no scoring,
weights, thresholds or contribution logic is duplicated in the GUI.

It never starts a producer, never runs a scoring loop, never drains shared state
and never performs a response. Sensitive reason/evidence text is redacted at the
presentation layer.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_desktop.services.processes import MISSING
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.detection import DetectionEngine, DetectionFinding
    from aegis_shared.events import SecurityEvent
    from aegis_shared.risk import AnomalySignal, RiskAssessment, RiskEngine

logger = get_logger(__name__)

#: Non-sensitive message shown when risk assessments cannot be read.
RISK_ERROR = "Unable to read risk assessments"
#: Non-sensitive message shown when no risk engine is published.
RISK_ENGINE_NOT_RUNNING = "Risk Engine: Not running"


@dataclass(frozen=True)
class RiskRow:
    """One risk assessment, flattened for display and sorting."""

    timestamp: datetime
    assessment_id: str
    event_id: str
    host_id: str | None
    risk_score: int
    risk_level: str
    severity: str
    reasons_summary: str
    finding_ids: tuple[str, ...]
    scoring_version: str
    has_anomaly: bool


@dataclass(frozen=True)
class RiskPosture:
    """Read-only view of the risk engine's configuration/state."""

    running: bool
    assessments: int
    scoring_version: str | None


@dataclass(frozen=True)
class RiskSnapshotView:
    """Read-only view of risk assessments plus engine posture."""

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: RiskPosture
    rows: tuple[RiskRow, ...]
    assessments: tuple[RiskAssessment, ...] = ()

    @property
    def count(self) -> int:
        """Number of assessments in the view."""
        return len(self.rows)

    def assessment_by_id(self, assessment_id: str) -> RiskAssessment | None:
        """Return the assessment with ``assessment_id``, if present."""
        for assessment in self.assessments:
            if assessment.assessment_id == assessment_id:
                return assessment
        return None


def _redact_text(value: str) -> str:
    """Redact a free-text value at presentation time.

    The shared :func:`aegis_shared.logging.redact` scrubs mapping *keys*; free
    text has no keys, so the existing command-line sanitizer (the established
    presentation-time scrubber) is applied instead. Imported lazily so importing
    the desktop application does not load ``aegis_agent.monitors``.
    """
    from aegis_agent.monitors.process.commandline import sanitize_command_line

    sanitized = sanitize_command_line(value)
    return sanitized if sanitized is not None else value


def reasons_summary(reasons: tuple[str, ...]) -> str:
    """Build a concise, deterministic, safe summary of an assessment's reasons."""
    if not reasons:
        return MISSING
    return " | ".join(_redact_text(reason) for reason in reasons)


def _default_engine() -> RiskEngine | None:
    """Return the published risk engine, or ``None`` when none is running."""
    from aegis_shared.risk import get_active_risk_engine

    return get_active_risk_engine()


def _default_events() -> list[SecurityEvent]:
    """Return the events currently buffered in the existing pipeline (read-only)."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return []
    return [envelope.event for envelope in pipeline.peek()]


def _default_detection_engine() -> DetectionEngine | None:
    """Return the published detection engine, or ``None`` when none is running."""
    from aegis_shared.detection import get_active_engine

    return get_active_engine()


def _build_items(
    events: Iterable[SecurityEvent],
    detection_engine: DetectionEngine | None,
) -> list[tuple[SecurityEvent, tuple[DetectionFinding, ...]]]:
    """Pair each event with the findings the existing detection engine produces."""
    items: list[tuple[SecurityEvent, tuple[DetectionFinding, ...]]] = []
    for event in events:
        findings = detection_engine.evaluate(event) if detection_engine is not None else ()
        items.append((event, tuple(findings)))
    return items


def _posture(engine: RiskEngine | None, assessments: int) -> RiskPosture:
    if engine is None:
        return RiskPosture(running=False, assessments=assessments, scoring_version=None)
    return RiskPosture(
        running=True,
        assessments=assessments,
        scoring_version=engine.settings.scoring_version,
    )


def _to_row(assessment: RiskAssessment) -> RiskRow:
    return RiskRow(
        timestamp=assessment.timestamp,
        assessment_id=assessment.assessment_id,
        event_id=assessment.event_id,
        host_id=assessment.host_id,
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level.value,
        severity=assessment.severity.value,
        reasons_summary=reasons_summary(tuple(assessment.reasons)),
        finding_ids=tuple(assessment.finding_ids),
        scoring_version=assessment.scoring_version,
        has_anomaly=assessment.anomaly is not None,
    )


def collect_risk_view(
    *,
    engine: RiskEngine | None = None,
    engine_provider: Callable[[], RiskEngine | None] | None = None,
    events_provider: Callable[[], Iterable[SecurityEvent]] | None = None,
    detection_engine_provider: Callable[[], DetectionEngine | None] | None = None,
) -> RiskSnapshotView:
    """Read risk assessments produced by the existing risk engine.

    Args:
        engine: An engine to use directly (tests inject one).
        engine_provider: Overrides how the active risk engine is resolved.
        events_provider: Overrides the event source (defaults to the existing
            event pipeline's read-only ``peek``).
        detection_engine_provider: Overrides how the active detection engine is
            resolved (used only to produce findings for assessment).

    The engines are only invoked one-shot; nothing is started. With no risk
    engine published, an honest "not running" state is shown and no assessment is
    produced.
    """
    resolved = engine
    if resolved is None:
        provider = engine_provider or _default_engine
        try:
            resolved = provider()
        except Exception as exc:
            logger.warning("Resolving the risk engine failed: %s", exc)
            resolved = None

    if resolved is None:
        return RiskSnapshotView(
            available=True,
            error=None,
            collected_at=None,
            posture=_posture(None, 0),
            rows=(),
            assessments=(),
        )

    try:
        events = (events_provider or _default_events)()
        detection_engine = (detection_engine_provider or _default_detection_engine)()
        items = _build_items(events, detection_engine)
        assessments = resolved.assess_many(items)
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Reading risk assessments failed: %s", exc)
        return RiskSnapshotView(
            available=False,
            error=RISK_ERROR,
            collected_at=None,
            posture=_posture(None, 0),
            rows=(),
        )

    rows = tuple(_to_row(assessment) for assessment in assessments)
    return RiskSnapshotView(
        available=True,
        error=None,
        collected_at=rows[-1].timestamp if rows else None,
        posture=_posture(resolved, len(rows)),
        rows=rows,
        assessments=assessments,
    )


def _anomaly_details(anomaly: AnomalySignal) -> dict[str, str]:
    details = {
        "anomaly.source": anomaly.source,
        "anomaly.score": f"{anomaly.score:.2f}",
        "anomaly.confidence": f"{anomaly.confidence:.2f}",
        "anomaly.model_version": anomaly.model_version,
    }
    details["anomaly.reason"] = _redact_text(anomaly.reason) if anomaly.reason else MISSING
    return details


def describe_assessment(assessment: RiskAssessment) -> dict[str, str]:
    """Return a structured, safe, read-only view of one assessment for the detail panel.

    Only known fields are included; reasons and anomaly text are redacted. No
    ``repr()`` is used.
    """
    details: dict[str, str] = {
        "assessment_id": assessment.assessment_id,
        "event_id": assessment.event_id,
        "host_id": assessment.host_id or MISSING,
        "risk_score": str(assessment.risk_score),
        "risk_level": assessment.risk_level.value,
        "severity": assessment.severity.value,
        "scoring_version": assessment.scoring_version,
        "timestamp": assessment.timestamp.isoformat(),
    }

    if assessment.reasons:
        for index, reason in enumerate(assessment.reasons, start=1):
            details[f"reason.{index}"] = _redact_text(reason)
    else:
        details["reasons"] = MISSING

    details["finding_ids"] = (
        ", ".join(assessment.finding_ids) if assessment.finding_ids else MISSING
    )

    for index, contributor in enumerate(assessment.contributors, start=1):
        prefix = f"contributor.{index}"
        details[f"{prefix}.finding_id"] = contributor.finding_id
        details[f"{prefix}.rule_id"] = contributor.rule_id
        details[f"{prefix}.severity"] = contributor.severity.value
        details[f"{prefix}.contribution"] = str(contributor.contribution)
        details[f"{prefix}.reason"] = _redact_text(contributor.reason)

    if assessment.anomaly is not None:
        details.update(_anomaly_details(assessment.anomaly))
    else:
        details["anomaly"] = "None"

    return details


__all__ = [
    "RISK_ENGINE_NOT_RUNNING",
    "RISK_ERROR",
    "RiskPosture",
    "RiskRow",
    "RiskSnapshotView",
    "collect_risk_view",
    "describe_assessment",
    "reasons_summary",
]
