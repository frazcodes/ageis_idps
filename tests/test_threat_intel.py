"""Focused tests for the threat-intelligence / IOC context layer (Step 25).

Exercises the deterministic :class:`IOCMatcher`, the runtime integration into the
existing finding/risk/correlation path, and the desktop views. Only reserved /
synthetic indicator values are used; no external service is contacted.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from aegis_shared.correlation import HostNetworkCorrelator, clear_active_host_network_correlations
from aegis_shared.enums import (
    EventCategory,
    EventType,
    IndicatorType,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import (
    FileContext,
    HostRef,
    NetworkContext,
    SecurityEvent,
    SourceRef,
)
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine
from aegis_shared.threat_intel import (
    IOCMatcher,
    ThreatIndicator,
    ThreatIntelSettings,
    clear_active_ioc_matches,
    get_active_ioc_matches,
    matches_to_findings,
    normalize_value,
    parse_indicators,
)

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)
_IP = "203.0.113.30"  # RFC 5737 documentation range
_SHA = "a" * 64


def _matcher(*indicators: str) -> IOCMatcher:
    return IOCMatcher.from_settings(ThreatIntelSettings(indicators=list(indicators)))


def _network_event(
    event_id: str = "n1",
    *,
    src_ip: str | None = "10.0.0.1",
    dst_ip: str | None = None,
    domain: str | None = None,
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FLOW_SUMMARY,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor"),
        timestamp=_TS,
        host=HostRef(host_id="host-1"),
        network=NetworkContext(
            src_ip=src_ip,
            dst_ip=dst_ip,
            domain=domain,
            protocol=TransportProtocol.TCP,
        ),
    )


def _file_event(event_id: str = "f1", *, sha256: str = _SHA) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FILE_MODIFIED,
        source=SourceRef(kind=SourceKind.AGENT, id="agent"),
        timestamp=_TS,
        host=HostRef(host_id="host-1"),
        file=FileContext(path="C:\\tmp\\sample.bin", hashes={"sha256": sha256}),
    )


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_host_network_correlations()
    clear_active_ioc_matches()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_host_network_correlations()
    clear_active_ioc_matches()


# --- 1. IP exact match ------------------------------------------------------


def test_ip_exact_match() -> None:
    matcher = _matcher(f"ip:{_IP}")

    matches = matcher.match_event(_network_event(dst_ip=_IP))

    assert len(matches) == 1
    match = matches[0]
    assert match.indicator_type is IndicatorType.IP
    assert match.observed_value == _IP
    assert match.source == "configured"
    assert match.severity is Severity.MEDIUM
    assert match.confidence == pytest.approx(0.5)


# --- 2. Domain normalization / match ----------------------------------------


def test_domain_normalization_match() -> None:
    matcher = _matcher("domain:Example.TEST.")

    assert matcher.match_event(_network_event(domain="example.test"))
    assert matcher.match_event(_network_event(domain="EXAMPLE.TEST"))


# --- 3. File hash match -----------------------------------------------------


def test_file_hash_match() -> None:
    matcher = _matcher(f"file_hash:{_SHA.upper()}")

    matches = matcher.match_event(_file_event(sha256=_SHA))

    assert len(matches) == 1
    assert matches[0].indicator_type is IndicatorType.FILE_HASH
    assert matches[0].observed_value == _SHA


# --- 4. Non-match -----------------------------------------------------------


def test_non_match() -> None:
    matcher = _matcher(f"ip:{_IP}")

    assert matcher.match_event(_network_event(dst_ip="10.0.0.99")) == ()


# --- 5. Disabled indicator does not match -----------------------------------


def test_disabled_indicator_does_not_match() -> None:
    disabled = ThreatIndicator(
        indicator_id="IOC-disabled",
        indicator_type=IndicatorType.IP,
        value=_IP,
        source="configured",
        confidence=0.5,
        severity=Severity.MEDIUM,
        enabled=False,
    )
    matcher = IOCMatcher([disabled])

    assert matcher.enabled is False
    assert matcher.match_event(_network_event(dst_ip=_IP)) == ()


# --- 6. Multiple indicators match deterministically -------------------------


def test_multiple_indicators_deterministic() -> None:
    matcher = _matcher(f"ip:{_IP}", "domain:example.test")
    event = _network_event(dst_ip=_IP, domain="example.test")

    first = matcher.match_event(event)
    second = matcher.match_event(event)

    assert len(first) == 2
    assert [m.match_id for m in first] == [m.match_id for m in second]
    assert {m.indicator_type for m in first} == {IndicatorType.IP, IndicatorType.DOMAIN}


# --- 7. Duplicate definitions / observables do not duplicate matches --------


def test_duplicate_definitions_no_duplicate_matches() -> None:
    matcher = _matcher(f"ip:{_IP}", f"ip:{_IP}")

    assert matcher.indicator_count == 1
    # The same value observed as both source and destination still yields one match.
    matches = matcher.match_event(_network_event(src_ip=_IP, dst_ip=_IP))
    assert len(matches) == 1


# --- 8. Empty / invalid values are handled safely ---------------------------


def test_empty_and_invalid_values_are_safe() -> None:
    settings = ThreatIntelSettings(
        indicators=["ip:not-an-ip", "domain:", "file_hash:zzz", "garbage", ":", "url:http://x"]
    )
    matcher = IOCMatcher.from_settings(settings)

    assert parse_indicators(settings) == ()
    assert matcher.enabled is False
    assert matcher.match_event(_network_event(dst_ip=_IP)) == ()
    assert normalize_value(IndicatorType.IP, "not-an-ip") is None
    assert normalize_value(IndicatorType.DOMAIN, "  ") is None


# --- 9. Runtime produces IOC evidence through the existing pipeline ---------


def test_runtime_produces_ioc_finding() -> None:
    from aegis_network_sensor.config import SensorSettings
    from aegis_runtime import AegisRuntime
    from tests.test_runtime import FakeNetworkSensor, _agent

    event = _network_event("n1", dst_ip=_IP)
    runtime = AegisRuntime(
        agent_settings=_agent(),
        sensor_settings=SensorSettings(capture_enabled=True, interface="eth0"),
        network_sensor=FakeNetworkSensor([event]),
        ioc_matcher=_matcher(f"ip:{_IP}"),
    )
    runtime.start()
    result = runtime.poll_once()

    assert result.findings >= 1
    assert "AEGIS-IOC-001" in {f.rule_id for f in runtime._cycle_findings}
    assert get_active_ioc_matches()
    assert get_active_ioc_matches()[0].observed_value == _IP

    runtime.stop()
    assert get_active_ioc_matches() == ()


# --- 10. IOC finding reaches the existing RiskEngine ------------------------


def test_ioc_finding_reaches_risk_engine() -> None:
    from aegis_network_sensor.config import SensorSettings
    from aegis_runtime import AegisRuntime
    from tests.test_runtime import FakeNetworkSensor, _agent

    runtime = AegisRuntime(
        agent_settings=_agent(),
        sensor_settings=SensorSettings(capture_enabled=True, interface="eth0"),
        network_sensor=FakeNetworkSensor([_network_event("n1", dst_ip=_IP)]),
        ioc_matcher=_matcher(f"ip:{_IP}"),
    )
    runtime.start()
    result = runtime.poll_once()

    assert result.assessments >= 1
    contributor_rules = {
        c.rule_id for a in runtime._cycle_assessments for c in a.contributors
    }
    assert "AEGIS-IOC-001" in contributor_rules
    runtime.stop()


# --- 11. IOC evidence coexists with Host <-> Network correlation ------------


def test_ioc_evidence_coexists_with_host_network_correlation() -> None:
    from aegis_shared.detection import DetectionFinding

    host_finding = DetectionFinding(
        finding_id="AEGIS-PROC-001:h1",
        rule_id="AEGIS-PROC-001",
        rule_name="Process launched from configured path",
        severity=Severity.HIGH,
        title="Process finding",
        description="A process finding.",
        event_id="h1",
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )
    ioc_matches = _matcher(f"ip:{_IP}").match_event(_network_event("n1", dst_ip=_IP))
    ioc_findings = matches_to_findings(ioc_matches)
    assert ioc_findings[0].rule_id == "AEGIS-IOC-001"

    correlations = HostNetworkCorrelator().correlate([host_finding, *ioc_findings])

    assert len(correlations) == 1
    assert ioc_findings[0].finding_id in correlations[0].network_finding_ids


# --- 12. Desktop investigation exposes IOC context --------------------------


def test_desktop_investigation_exposes_ioc_context() -> None:
    from aegis_desktop.services.detections import collect_investigation_view
    from aegis_desktop.services.threat_intel import threat_intel_for_event

    matcher = _matcher(f"ip:{_IP}")
    event = _network_event("n1", dst_ip=_IP)
    finding = matches_to_findings(matcher.match_event(event))[0]

    view = collect_investigation_view(
        finding,
        event_lookup=lambda _eid: event,
        threat_intel_lookup=lambda ev: threat_intel_for_event(
            ev, matcher_provider=lambda: matcher
        ),
    )

    assert view.threat_intel is not None
    assert view.threat_intel.matched is True
    assert view.threat_intel.count == 1
    assert view.threat_intel.matches[0].observed_value == _IP
    assert view.threat_intel.types == ("ip",)

    # Honest empty state for an event with no match.
    other = _network_event("n2", dst_ip="10.0.0.99")
    no_match = collect_investigation_view(
        finding,
        event_lookup=lambda _eid: other,
        threat_intel_lookup=lambda ev: threat_intel_for_event(
            ev, matcher_provider=lambda: matcher
        ),
    )
    assert no_match.threat_intel is None


# --- 13. Desktop incident view exposes IOC context --------------------------


def test_desktop_incident_view_exposes_ioc_context() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.incidents import IncidentsPage
    from aegis_desktop.services.incidents import collect_incident_view
    from aegis_shared.correlation import IncidentCorrelator

    app = create_application([])
    assert app is not None

    matcher = _matcher(f"ip:{_IP}")
    event = _network_event("n1", dst_ip=_IP)
    ioc_finding = matches_to_findings(matcher.match_event(event))[0]

    # An incident requires >= 2 findings; pair the IOC finding with a host finding.
    from aegis_shared.detection import DetectionFinding

    host_finding = DetectionFinding(
        finding_id="AEGIS-PROC-001:h1",
        rule_id="AEGIS-PROC-001",
        rule_name="Process launched from configured path",
        severity=Severity.HIGH,
        title="Process finding",
        description="A process finding.",
        event_id="h1",
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )
    incident = IncidentCorrelator().correlate((), [host_finding, ioc_finding])[0]

    view = collect_incident_view(
        incidents_provider=lambda: (incident,),
        findings_provider=lambda: {
            host_finding.finding_id: host_finding,
            ioc_finding.finding_id: ioc_finding,
        },
        events_provider=lambda: (event,),
        anomalies_provider=lambda: {},
        correlations_provider=lambda: (),
        ioc_matcher_provider=lambda: matcher,
    )
    assert view.ioc_matches

    page = IncidentsPage(provider=lambda: view)
    page.refresh()
    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    values = page.detail_values()
    assert "IOC Matches" in keys
    assert "1" in values
    assert "ip" in values
