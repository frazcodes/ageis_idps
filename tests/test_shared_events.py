"""Tests for the canonical shared event schema."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis_shared.enums import (
    EventCategory,
    EventType,
    Platform,
    RiskBand,
    Severity,
    SourceKind,
)
from aegis_shared.events import (
    HostRef,
    SecurityEvent,
    SourceRef,
    band_for_score,
    severity_for_score,
)


def _make_event(**overrides: object) -> SecurityEvent:
    defaults: dict[str, object] = {
        "event_type": EventType.PROCESS_STARTED,
        "source": SourceRef(kind=SourceKind.AGENT, id="agent-01"),
        "host": HostRef(host_id="host-01", platform=Platform.WINDOWS),
    }
    defaults.update(overrides)
    return SecurityEvent.create(**defaults)  # type: ignore[arg-type]


def test_category_is_derived_from_event_type() -> None:
    event = _make_event()
    assert event.category is EventCategory.HOST


def test_category_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_type=EventType.PROCESS_STARTED,
            category=EventCategory.NETWORK,
            source=SourceRef(kind=SourceKind.AGENT, id="agent-01"),
        )


def test_events_are_immutable() -> None:
    event = _make_event()
    with pytest.raises(ValidationError):
        event.message = "tampered"


def test_unknown_top_level_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_event(unexpected_field="boom")


def test_naive_timestamps_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _make_event(timestamp=datetime(2026, 1, 1, 12, 0, 0))


def test_timezone_aware_timestamps_are_normalised() -> None:

    event = _make_event(timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC))
    assert event.timestamp.tzinfo is not None


def test_is_high_severity() -> None:
    assert _make_event(severity=Severity.HIGH).is_high_severity
    assert not _make_event(severity=Severity.MEDIUM).is_high_severity


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, RiskBand.NEGLIGIBLE),
        (0.2, RiskBand.LOW),
        (0.4, RiskBand.ELEVATED),
        (0.7, RiskBand.HIGH),
        (0.9, RiskBand.SEVERE),
        (1.0, RiskBand.SEVERE),
    ],
)
def test_band_for_score(score: float, expected: RiskBand) -> None:
    assert band_for_score(score) is expected


def test_band_for_score_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="risk score"):
        band_for_score(1.5)


def test_severity_for_score_mapping() -> None:
    assert severity_for_score(0.95) is Severity.CRITICAL
    assert severity_for_score(0.0) is Severity.INFO
