"""Deterministic tests for the explainable risk-scoring engine.

Events and findings are constructed locally; no test needs ML, the network or
elevated privileges.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aegis_shared.detection import DetectionFinding
from aegis_shared.enums import (
    EventCategory,
    EventType,
    Platform,
    RiskLevel,
    Severity,
    SourceKind,
)
from aegis_shared.events import HostRef, ProcessContext, SecurityEvent, SourceRef
from aegis_shared.risk import (
    AnomalySignal,
    RiskAssessment,
    RiskEngine,
    RiskSettings,
    combine_contributions,
    risk_level_for_score,
    severity_contribution,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _event(event_id: str = "evt-1") -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        source=SourceRef(kind=SourceKind.AGENT, id="agent-test"),
        host=HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS),
        timestamp=_TS,
        process=ProcessContext(pid=1, name="demo"),
    )


def _finding(
    event_id: str = "evt-1",
    *,
    finding_id: str | None = None,
    rule_id: str = "AEGIS-TEST-001",
    severity: Severity = Severity.MEDIUM,
    title: str = "Test finding",
) -> DetectionFinding:
    return DetectionFinding(
        finding_id=finding_id or f"{rule_id}:{event_id}",
        rule_id=rule_id,
        rule_name="Test rule",
        severity=severity,
        title=title,
        description="Test finding.",
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )


def _base_kwargs() -> dict[str, Any]:
    return {
        "assessment_id": "1:evt-1",
        "event_id": "evt-1",
        "host_id": "host-1",
        "risk_score": 0,
        "risk_level": RiskLevel.INFORMATIONAL,
        "severity": Severity.INFO,
        "scoring_version": "1",
        "timestamp": _TS,
    }


# --- Model -----------------------------------------------------------------


def test_valid_assessment() -> None:
    assessment = RiskEngine().assess(_event(), [_finding()])

    assert isinstance(assessment, RiskAssessment)
    assert assessment.event_id == "evt-1"
    assert assessment.host_id == "host-1"
    assert assessment.scoring_version == "1"


def test_score_bounds_are_enforced() -> None:
    assert RiskAssessment(**{**_base_kwargs(), "risk_score": 0}).risk_score == 0
    assert RiskAssessment(**{**_base_kwargs(), "risk_score": 100}).risk_score == 100

    many = [
        _finding("evt-1", rule_id=f"R{index}", severity=Severity.CRITICAL) for index in range(5)
    ]
    assert RiskEngine().assess(_event(), many).risk_score == 100


@pytest.mark.parametrize("score", [-1, 101])
def test_invalid_score_is_rejected(score: int) -> None:
    with pytest.raises(ValidationError):
        RiskAssessment(**{**_base_kwargs(), "risk_score": score})


def test_timestamp_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        RiskAssessment(**{**_base_kwargs(), "timestamp": datetime(2026, 1, 1)})


def test_assessment_id_is_deterministic() -> None:
    engine = RiskEngine()
    first = engine.assess(_event("evt-9"), [_finding("evt-9")])
    second = engine.assess(_event("evt-9"), [_finding("evt-9")])

    assert first.assessment_id == second.assessment_id
    assert first.assessment_id == "1:evt-9"
    assert (
        RiskEngine(RiskSettings(scoring_version="2")).assess(_event("evt-9"), []).assessment_id
        == "2:evt-9"
    )


def test_assessment_is_frozen() -> None:
    assessment = RiskEngine().assess(_event(), [])
    with pytest.raises(ValidationError):
        assessment.risk_score = 50


# --- Scoring ---------------------------------------------------------------


def test_zero_findings_produce_informational_zero() -> None:
    assessment = RiskEngine().assess(_event(), [])

    assert assessment.risk_score == 0
    assert assessment.risk_level is RiskLevel.INFORMATIONAL
    assert assessment.severity is Severity.INFO
    assert assessment.reasons == ()
    assert assessment.contributors == ()
    assert assessment.finding_ids == ()
    assert assessment.event_id == "evt-1"


@pytest.mark.parametrize(
    ("severity", "expected_score", "expected_level"),
    [
        (Severity.INFO, 0, RiskLevel.INFORMATIONAL),
        (Severity.LOW, 10, RiskLevel.LOW),
        (Severity.MEDIUM, 25, RiskLevel.MEDIUM),
        (Severity.HIGH, 40, RiskLevel.HIGH),
        (Severity.CRITICAL, 60, RiskLevel.CRITICAL),
    ],
)
def test_severity_maps_to_contribution(
    severity: Severity, expected_score: int, expected_level: RiskLevel
) -> None:
    assessment = RiskEngine().assess(_event(), [_finding(severity=severity)])

    assert assessment.risk_score == expected_score
    assert assessment.risk_level is expected_level
    assert assessment.contributors[0].contribution == expected_score


def test_multiple_findings_combine() -> None:
    findings = [
        _finding("evt-1", rule_id="R-MED", severity=Severity.MEDIUM),
        _finding("evt-1", rule_id="R-HIGH", severity=Severity.HIGH),
    ]

    assessment = RiskEngine().assess(_event(), findings)

    assert assessment.risk_score == 65
    assert assessment.risk_level is RiskLevel.CRITICAL
    assert assessment.severity is Severity.HIGH
    assert len(assessment.contributors) == 2


def test_score_is_capped_at_100() -> None:
    findings = [
        _finding("evt-1", rule_id=f"R{index}", severity=Severity.CRITICAL) for index in range(4)
    ]

    assessment = RiskEngine().assess(_event(), findings)

    assert assessment.risk_score == 100
    assert assessment.risk_level is RiskLevel.CRITICAL


def test_duplicate_finding_ids_are_rejected() -> None:
    finding = _finding("evt-1", finding_id="dup")
    with pytest.raises(ValueError, match="duplicate finding id"):
        RiskEngine().assess(_event(), [finding, finding])


def test_contributor_ordering_is_deterministic() -> None:
    first = _finding("evt-1", rule_id="B-RULE", severity=Severity.LOW)
    second = _finding("evt-1", rule_id="A-RULE", severity=Severity.HIGH)

    assessment = RiskEngine().assess(_event(), [first, second])

    assert [contributor.rule_id for contributor in assessment.contributors] == [
        "A-RULE",
        "B-RULE",
    ]
    assert list(assessment.finding_ids) == ["A-RULE:evt-1", "B-RULE:evt-1"]


def test_reasons_are_deterministic() -> None:
    engine = RiskEngine()
    findings = [_finding("evt-1", rule_id="R1", severity=Severity.HIGH)]

    first = engine.assess(_event(), findings)
    second = engine.assess(_event(), findings)

    assert first.reasons == second.reasons
    assert "R1" in first.reasons[0]
    assert "contributed 40" in first.reasons[0]


def test_same_input_produces_same_output() -> None:
    engine = RiskEngine()
    findings = [_finding("evt-1", rule_id="R1"), _finding("evt-1", rule_id="R2")]

    assert engine.assess(_event(), findings) == engine.assess(_event(), findings)


def test_per_finding_cap_is_applied() -> None:
    settings = RiskSettings(max_contribution_per_finding=10)
    assessment = RiskEngine(settings).assess(_event(), [_finding(severity=Severity.CRITICAL)])

    assert assessment.contributors[0].contribution == 10
    assert assessment.risk_score == 10


def test_custom_thresholds_are_respected() -> None:
    settings = RiskSettings(
        threshold_low=5, threshold_medium=15, threshold_high=35, threshold_critical=55
    )
    assessment = RiskEngine(settings).assess(_event(), [_finding(severity=Severity.MEDIUM)])

    assert assessment.risk_score == 25
    assert assessment.risk_level is RiskLevel.MEDIUM


# --- Batch -----------------------------------------------------------------


def test_assess_many_produces_one_assessment_per_item() -> None:
    items = [
        (_event("e1"), []),
        (_event("e2"), [_finding("e2")]),
        (_event("e3"), []),
    ]

    assessments = RiskEngine().assess_many(items)

    assert len(assessments) == 3
    assert [assessment.event_id for assessment in assessments] == ["e1", "e2", "e3"]


def test_assess_many_preserves_input_order() -> None:
    items = [
        (_event("z"), [_finding("z", severity=Severity.CRITICAL)]),
        (_event("a"), []),
        (_event("m"), [_finding("m", severity=Severity.LOW)]),
    ]

    assessments = RiskEngine().assess_many(items)

    assert [assessment.event_id for assessment in assessments] == ["z", "a", "m"]


def test_finding_for_wrong_event_is_rejected() -> None:
    wrong = _finding("other-event")
    with pytest.raises(ValueError, match="does not belong"):
        RiskEngine().assess(_event("evt-1"), [wrong])


def test_empty_batch_returns_empty_tuple() -> None:
    assert RiskEngine().assess_many([]) == ()


# --- Configuration ---------------------------------------------------------


def test_valid_configuration_defaults() -> None:
    settings = RiskSettings()

    assert settings.scoring_version == "1"
    assert settings.severity_weights[Severity.MEDIUM] == 25
    assert settings.threshold_low < settings.threshold_medium < settings.threshold_high
    assert settings.threshold_high < settings.threshold_critical


@pytest.mark.parametrize("weight", [-1, 101])
def test_invalid_weights_are_rejected(weight: int) -> None:
    with pytest.raises(ValidationError):
        RiskSettings(weight_high=weight)


def test_invalid_thresholds_are_rejected() -> None:
    with pytest.raises(ValidationError, match="low < medium < high < critical"):
        RiskSettings(threshold_low=50)
    with pytest.raises(ValidationError):
        RiskSettings(threshold_critical=0)


def test_scoring_version_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        RiskSettings(scoring_version="")


# --- Future ML interface ---------------------------------------------------


def test_anomaly_signal_none_is_deterministic() -> None:
    engine = RiskEngine()
    findings = [_finding(severity=Severity.HIGH)]

    with_none = engine.assess(_event(), findings, anomaly_signal=None)
    without = engine.assess(_event(), findings)

    assert with_none.anomaly is None
    assert with_none.risk_score == without.risk_score == 40


def test_future_anomaly_signal_can_be_represented() -> None:
    signal = AnomalySignal(
        source="isolation_forest",
        score=0.82,
        confidence=0.9,
        model_version="2026-01-01",
        reason="demo signal",
    )

    assessment = RiskEngine().assess(_event(), [_finding()], anomaly_signal=signal)

    assert assessment.anomaly == signal
    # A supplied signal does not affect the deterministic finding-based score yet.
    assert assessment.risk_score == 25


# --- Safety / data integrity ----------------------------------------------


def test_inputs_are_not_mutated() -> None:
    event = _event()
    finding = _finding()
    event_before = event.model_dump()
    finding_before = finding.model_dump()

    RiskEngine().assess(event, [finding])

    assert event.model_dump() == event_before
    assert finding.model_dump() == finding_before


def test_json_serialization_is_deterministic() -> None:
    assessment = RiskEngine().assess(_event(), [_finding(severity=Severity.HIGH)])

    first = json.dumps(assessment.to_json_dict(), sort_keys=True)
    second = json.dumps(assessment.to_json_dict(), sort_keys=True)

    assert first == second
    assert json.loads(first)["risk_score"] == 40


# --- Pure scoring functions ------------------------------------------------


def test_pure_scoring_helpers() -> None:
    weights = {Severity.HIGH: 40, Severity.CRITICAL: 60}

    assert severity_contribution(Severity.HIGH, weights=weights, max_contribution=100) == 40
    assert severity_contribution(Severity.CRITICAL, weights=weights, max_contribution=30) == 30
    assert severity_contribution(Severity.INFO, weights=weights, max_contribution=100) == 0

    assert combine_contributions([40, 40, 40]) == 100
    assert combine_contributions([]) == 0
    assert combine_contributions([-10, 5]) == 5

    assert risk_level_for_score(0, low=10, medium=25, high=40, critical=60) is (
        RiskLevel.INFORMATIONAL
    )
    assert risk_level_for_score(10, low=10, medium=25, high=40, critical=60) is RiskLevel.LOW
    assert risk_level_for_score(100, low=10, medium=25, high=40, critical=60) is (
        RiskLevel.CRITICAL
    )


# --- CLI -------------------------------------------------------------------


def test_cli_risk_text(capsys: pytest.CaptureFixture[str]) -> None:
    from aegis_agent.__main__ import main

    exit_code = main(["risk"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis risk assessment demonstration" in out
    assert "level=informational" in out
    assert "level=medium" in out
    assert "level=high" in out


def test_cli_risk_json(capsys: pytest.CaptureFixture[str]) -> None:
    from aegis_agent.__main__ import main

    exit_code = main(["risk", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["count"] == 4
    scores = [assessment["risk_score"] for assessment in payload["assessments"]]
    assert scores == [0, 25, 40, 65]
    assert payload["assessments"][3]["risk_level"] == "critical"
    assert len(payload["assessments"][3]["contributors"]) == 2
