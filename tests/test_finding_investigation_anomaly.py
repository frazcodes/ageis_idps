"""Focused tests for exposing the ML anomaly signal in investigation (Step 18).

Verifies that an existing :class:`RiskAssessment.anomaly` (:class:`AnomalySignal`)
is surfaced read-only in the Finding Investigation view, that the honest empty
state is shown when no signal exists, and that no anomaly values are fabricated.
No ML model, runtime, or engine scoring is modified or started.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.pages.detections import DetectionsPage
from aegis_desktop.services.detections import (
    DetectionPosture,
    FindingRow,
    FindingSnapshotView,
    InvestigationView,
    RiskView,
    collect_investigation_view,
    evidence_summary,
)
from aegis_shared.detection import DetectionFinding
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    NetworkDirection,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import NetworkContext, SecurityEvent, SourceRef
from aegis_shared.risk import (
    AnomalySignal,
    RiskEngine,
    clear_active_risk_engine,
    set_active_risk_engine,
)

_TS = datetime(2026, 3, 15, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


@pytest.fixture(autouse=True)
def _clean_risk_registry() -> object:
    clear_active_risk_engine()
    yield
    clear_active_risk_engine()


def _finding() -> DetectionFinding:
    return DetectionFinding(
        finding_id="AEGIS-FLOW-001:evt-1",
        rule_id="AEGIS-FLOW-001",
        rule_name="Unexpected flow volume",
        severity=Severity.MEDIUM,
        title="Unexpected flow volume",
        description="A flow exceeded the learned volume baseline.",
        event_id="evt-1",
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        host_id="host-1",
        evidence={"flow_id": "f|1", "bytes_sent": "900000"},
        tags=("network", "flow"),
    )


def _event() -> SecurityEvent:
    return SecurityEvent.create(
        event_id="evt-1",
        event_type=EventType.FLOW_SUMMARY,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor"),
        timestamp=_TS,
        network=NetworkContext(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol=TransportProtocol.TCP,
            direction=NetworkDirection.OUTBOUND,
            ip_version=AddressFamily.IPV4,
            flow_id="f|1",
            packets_sent=5000,
            bytes_sent=900000,
            duration_ms=10000,
        ),
    )


def _signal(score: float = 0.82) -> AnomalySignal:
    return AnomalySignal(
        source="network_anomaly",
        score=score,
        confidence=1.0,
        model_version="1.0.0",
        reason="behavior differs from the learned baseline",
    )


def _investigation(anomaly: AnomalySignal | None) -> InvestigationView:
    set_active_risk_engine(RiskEngine())
    event = _event()
    finding = _finding()
    return collect_investigation_view(
        finding,
        event_lookup=lambda _eid: event,
        rule_lookup=lambda _rid: {"name": "Unexpected flow volume"},
        anomaly_lookup=lambda _ev, _f: anomaly,
    )


# --- 1. Real anomaly signal is surfaced ------------------------------------


def test_investigation_shows_real_anomaly_signal() -> None:
    view = _investigation(_signal())

    assert view.risk is not None
    assert view.risk.anomaly is not None
    assert view.risk.anomaly.detected is True
    assert view.risk.anomaly.source == "network_anomaly"


# --- 2. Score / model version displayed correctly ---------------------------


def test_anomaly_score_and_model_version_are_correct() -> None:
    view = _investigation(_signal(score=0.82))

    assert view.risk is not None
    anomaly = view.risk.anomaly
    assert anomaly is not None
    assert anomaly.score == pytest.approx(0.82)
    assert anomaly.model_version == "1.0.0"


def test_page_renders_anomaly_fields(app: QApplication) -> None:
    view = _investigation(_signal(score=0.82))
    page = DetectionsPage(
        provider=lambda: _snapshot_with(_finding()),
        investigation_provider=lambda _f: view,
    )
    page.refresh()
    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    values = page.detail_values()
    assert "Anomaly Detected" in keys
    assert "Anomaly Score" in keys
    assert "Model Version" in keys
    assert "Source" in keys
    assert "Yes" in values
    assert "0.820" in values
    assert "1.0.0" in values
    assert "network_anomaly" in values


# --- 3. Honest empty state --------------------------------------------------


def test_investigation_without_anomaly_shows_empty_state(app: QApplication) -> None:
    view = _investigation(None)

    assert view.risk is not None
    assert view.risk.anomaly is None

    page = DetectionsPage(
        provider=lambda: _snapshot_with(_finding()),
        investigation_provider=lambda _f: view,
    )
    page.refresh()
    page.show_detail_for(page.row_at(0))

    assert "ML Anomaly" in page.detail_keys()
    assert "No ML anomaly signal available" in page.detail_values()


# --- 4. Existing risk fields remain unchanged -------------------------------


def test_existing_risk_fields_unchanged_by_anomaly() -> None:
    with_anomaly = _investigation(_signal(score=0.99))
    without_anomaly = _investigation(None)

    assert with_anomaly.risk is not None
    assert without_anomaly.risk is not None
    assert with_anomaly.risk.risk_score == without_anomaly.risk.risk_score
    assert with_anomaly.risk.risk_level == without_anomaly.risk.risk_level
    assert with_anomaly.risk.severity == without_anomaly.risk.severity
    assert with_anomaly.risk.reasons == without_anomaly.risk.reasons
    assert with_anomaly.risk.contributors == without_anomaly.risk.contributors
    # The anomaly is carried alongside, not in place of, the risk fields.
    assert with_anomaly.risk.anomaly is not None
    assert without_anomaly.risk.anomaly is None


# --- 5. No fake anomaly data ------------------------------------------------


def test_anomaly_view_defaults_to_none_and_is_never_fabricated() -> None:
    # A RiskView built without an anomaly must not invent one.
    risk = RiskView(
        risk_score=45,
        risk_level="medium",
        severity="medium",
        reasons=("r",),
        contributors=("c",),
    )
    assert risk.anomaly is None

    # And the service maps a missing signal to None rather than a zero-value view.
    from aegis_desktop.services.detections import _anomaly_view

    assert _anomaly_view(None) is None


def test_anomaly_lookup_failure_is_ignored() -> None:
    set_active_risk_engine(RiskEngine())
    event = _event()

    def boom(_ev: object, _f: object) -> AnomalySignal:
        raise RuntimeError("lookup failed")

    view = collect_investigation_view(
        _finding(),
        event_lookup=lambda _eid: event,
        rule_lookup=lambda _rid: {},
        anomaly_lookup=boom,
    )

    assert view.risk is not None
    assert view.risk.anomaly is None


# --- Helpers ----------------------------------------------------------------


def _snapshot_with(finding: DetectionFinding) -> FindingSnapshotView:
    return FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(running=True, enabled=True, rule_count=6, findings=1),
        rows=(
            FindingRow(
                timestamp=_TS,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity="medium",
                title=finding.title,
                event_id=finding.event_id,
                event_type="flow.summary",
                category="network",
                host_id="host-1",
                description=finding.description,
                evidence_summary=evidence_summary(dict(finding.evidence)),
                tags=("network", "flow"),
            ),
        ),
        findings=(finding,),
    )
