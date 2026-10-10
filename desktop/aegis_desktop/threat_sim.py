"""Threat simulation playbooks (demo mode) for the SOC console.

Two canned scenarios inject **synthetic** findings into the services the console
already uses - the dashboard :class:`AlertService`, the published incident
registry and the existing correlation engines - so the Threat Feed, Security
Posture row and alert list react exactly as they would to real telemetry.

Nothing here touches the network: no scapy capture runs, no packet is read, no
process is executed and no malware runs.  Every injected object is tagged
``simulated`` and built from documentation-safe indicators (RFC 5737 test-net
addresses and a lab host name).  Each playbook additionally opens one *draft*
``BLOCK_IP`` request against the simulated attacker IP in the response
workflow, so the Action Center and the Response Center's Dry Run → Approve →
Execute pipeline can be exercised end-to-end; the request is never approved or
executed automatically.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.services.alerts import AlertService, SecurityAlert
from aegis_desktop.services.dashboard import ActivityItem, DashboardSnapshot
from aegis_shared.enums import EventCategory, EventType, Severity
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.correlation.models import HostNetworkCorrelation, SecurityIncident
    from aegis_shared.detection.models import DetectionFinding

logger = get_logger(__name__)

# --- Playbook contract ------------------------------------------------------

#: Dialog headline.
TITLE = "Threat Simulation Playbooks"
#: Honest scope statement shown under the title.
SUBTITLE = (
    "Demo mode: injects synthetic telemetry into this console only. "
    "No packet is captured, no malware runs and no response is executed."
)

PORT_SCAN_KEY = "port_scan"
C2_BEACON_KEY = "c2_beacon"

#: Local lab host every synthetic finding belongs to (keeps correlation valid).
DEMO_HOST_ID = "DESKTOP-LAB01"
#: Documentation-safe external address (RFC 5737 TEST-NET-3 range: 185.15.x.x).
ATTACKER_IP = "185.15.44.17"
#: Monitored host address used in the synthetic evidence.
LOCAL_IP = "10.10.4.25"
#: Tag attached to every injected finding so demo data stays identifiable.
SIMULATED_TAG = "simulated"

#: Upper bound on simulated findings retained for the dashboard overlay.
MAX_SIMULATED = 30


@dataclass(frozen=True)
class SimulationScenario:
    """One demo playbook shown in the simulation dialog."""

    key: str
    title: str
    domain: str
    severity: str
    description: str
    injection: str


PORT_SCAN = SimulationScenario(
    key=PORT_SCAN_KEY,
    title="External Port Scan",
    domain="Network only",
    severity="high",
    description=(
        "Sequential SYN probes from an external host sweep 1,024 ports on the "
        "monitored workstation in under five seconds."
    ),
    injection=(
        "Injects 1 HIGH network finding (AEGIS-NET-002) into the alert feed and "
        "opens a draft Block IP request against 185.15.44.17."
    ),
)

C2_BEACON = SimulationScenario(
    key=C2_BEACON_KEY,
    title="C2 Beaconing & Host Compromise",
    domain="Host \u2194 Network correlation",
    severity="critical",
    description=(
        "A weaponised document drops powershell.exe, which then beacons to a "
        "command-and-control endpoint every 60 seconds."
    ),
    injection=(
        "Injects 1 CRITICAL host finding (AEGIS-EXEC-001) + 1 network finding, "
        "correlates them into an OPEN incident and opens a draft Block IP "
        "request against 185.15.44.17."
    ),
)

#: Every playbook, in the order the dialog shows them.
SCENARIOS: tuple[SimulationScenario, ...] = (PORT_SCAN, C2_BEACON)
_SCENARIOS_BY_KEY: dict[str, SimulationScenario] = {s.key: s for s in SCENARIOS}

_run_counter = itertools.count(1)


def scenario_for(key: str) -> SimulationScenario | None:
    """Return the playbook for *key*, or ``None`` when it is unknown."""
    return _SCENARIOS_BY_KEY.get(key)


# --- Synthetic telemetry ----------------------------------------------------


def _now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.now(UTC)


def build_port_scan_findings(now: datetime | None = None) -> tuple[DetectionFinding, ...]:
    """Synthetic HIGH network finding describing an external port scan."""
    from aegis_shared.detection.models import DetectionFinding

    ts = _now(now)
    run = next(_run_counter)
    event_id = f"SIM-NET-SCAN-{run:04d}"
    return (
        DetectionFinding(
            finding_id=f"AEGIS-NET-002:{event_id}",
            rule_id="AEGIS-NET-002",
            rule_name="Unusually high network traffic volume",
            severity=Severity.HIGH,
            title=f"External port scan from {ATTACKER_IP}",
            description=(
                f"1024 sequential SYN probes hit {DEMO_HOST_ID} ({LOCAL_IP}) in 4.2s; "
                "22/tcp, 80/tcp, 443/tcp and 3389/tcp responded before the sweep continued."
            ),
            event_id=event_id,
            event_type=EventType.PORT_SCAN_SUSPECTED,
            category=EventCategory.NETWORK,
            timestamp=ts,
            host_id=DEMO_HOST_ID,
            evidence={
                "src_ip": ATTACKER_IP,
                "dst_ip": LOCAL_IP,
                "scan_type": "SYN",
                "ports_probed": "1024",
                "window_seconds": "4.2",
                "synthetic": "true",
            },
            tags=("network", "scan", SIMULATED_TAG),
        ),
    )


def build_c2_findings(now: datetime | None = None) -> tuple[DetectionFinding, ...]:
    """Synthetic CRITICAL host finding plus its matching network beacon."""
    from aegis_shared.detection.models import DetectionFinding

    ts = _now(now)
    run = next(_run_counter)
    host_event = f"SIM-HOST-EXEC-{run:04d}"
    net_event = f"SIM-NET-C2-{run:04d}"
    host_finding = DetectionFinding(
        finding_id=f"AEGIS-EXEC-001:{host_event}",
        rule_id="AEGIS-EXEC-001",
        rule_name="Executable file created in monitored location",
        severity=Severity.CRITICAL,
        title="Suspicious Process: powershell.exe launched with encoded command",
        description=(
            "WINWORD.EXE wrote an executable to the user temp directory and started "
            "powershell.exe with a base64-encoded command line (lab simulation)."
        ),
        event_id=host_event,
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=ts,
        host_id=DEMO_HOST_ID,
        evidence={
            "process": "powershell.exe",
            "parent_process": "WINWORD.EXE",
            "path": r"C:\Users\labuser\AppData\Local\Temp\update.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "user": "labuser",
            "synthetic": "true",
        },
        tags=("host", "process", "execution", SIMULATED_TAG),
    )
    network_finding = DetectionFinding(
        finding_id=f"AEGIS-NET-001:{net_event}",
        rule_id="AEGIS-NET-001",
        rule_name="Configured suspicious endpoint observed",
        severity=Severity.HIGH,
        title=f"C2 beaconing to {ATTACKER_IP}:443",
        description=(
            f"{DEMO_HOST_ID} contacted {ATTACKER_IP}:443 five times at a steady 60s "
            "interval with 512-byte keep-alive payloads (lab simulation)."
        ),
        event_id=net_event,
        event_type=EventType.SUSPICIOUS_EGRESS,
        category=EventCategory.NETWORK,
        timestamp=ts,
        host_id=DEMO_HOST_ID,
        evidence={
            "src_ip": LOCAL_IP,
            "dst_ip": ATTACKER_IP,
            "dst_port": "443",
            "protocol": "tcp",
            "beacon_interval_seconds": "60",
            "beacons_observed": "5",
            "synthetic": "true",
        },
        tags=("network", "c2", "beacon", SIMULATED_TAG),
    )
    return (host_finding, network_finding)


_BUILDERS: dict[str, Callable[..., tuple[DetectionFinding, ...]]] = {
    PORT_SCAN_KEY: build_port_scan_findings,
    C2_BEACON_KEY: build_c2_findings,
}


# --- Demo overlay registries ------------------------------------------------

#: Findings injected during this session (dashboard posture/feed overlay).
_simulated_findings: list[DetectionFinding] = []
#: Incidents correlated from those findings (posture "open incident" count).
_simulated_incidents: list[SecurityIncident] = []


def simulated_findings() -> tuple[DetectionFinding, ...]:
    """Findings injected so far, oldest first."""
    return tuple(_simulated_findings)


def simulated_incidents() -> tuple[SecurityIncident, ...]:
    """Incidents correlated from injected findings, oldest first."""
    return tuple(_simulated_incidents)


def clear_simulated() -> None:
    """Forget every injected finding/incident (used by tests and reset paths)."""
    _simulated_findings.clear()
    _simulated_incidents.clear()


def augment_snapshot(snapshot: DashboardSnapshot) -> DashboardSnapshot:
    """Overlay simulated findings/incidents onto a dashboard snapshot.

    The dashboard's own findings view already carries the demo findings once the
    detections adapter overlays them, so this pass only adds what the snapshot is
    missing: a finding already present is neither re-listed nor re-counted, which
    keeps posture numbers exact and the overlay idempotent. Returns *snapshot*
    unchanged when nothing has been simulated, so the normal read-only path is
    untouched outside demo runs.
    """
    findings = simulated_findings()
    incidents = simulated_incidents()
    if not findings and not incidents:
        return snapshot

    activity = list(snapshot.activity)
    high_risk = list(snapshot.high_risk_findings)
    known_activity = {item.description for item in activity}
    known_high = {item.description for item in high_risk}
    counted = 0
    changed = False

    for finding in findings:
        severity = finding.severity.value
        high_description = f"{finding.rule_id}: {finding.title}"
        already_listed = high_description in known_high or finding.title in known_activity
        if not already_listed:
            # The shared activity feed carries the bare title (services.dashboard).
            known_activity.add(finding.title)
            activity.append(
                ActivityItem(
                    timestamp=finding.timestamp,
                    kind="finding",
                    severity=severity,
                    description=finding.title,
                )
            )
            counted += 1
            changed = True
        if severity in ("high", "critical") and high_description not in known_high:
            known_high.add(high_description)
            high_risk.append(
                ActivityItem(
                    timestamp=finding.timestamp,
                    kind="finding",
                    severity=severity,
                    description=high_description,
                )
            )
            changed = True

    for incident in incidents:
        if incident.summary in known_activity:
            continue
        known_activity.add(incident.summary)
        activity.append(
            ActivityItem(
                timestamp=incident.updated_at,
                kind="incident",
                severity=incident.risk_level.value,
                description=incident.summary,
            )
        )
        changed = True

    if not changed:
        return snapshot

    activity.sort(key=lambda item: item.timestamp, reverse=True)
    high_risk.sort(key=lambda item: item.timestamp, reverse=True)
    detection = replace(
        snapshot.detection,
        finding_count=snapshot.detection.finding_count + counted,
    )
    return replace(
        snapshot,
        activity=tuple(activity),
        high_risk_findings=tuple(high_risk),
        detection=detection,
    )


# --- Injection --------------------------------------------------------------


@dataclass(frozen=True)
class SimulationOutcome:
    """What one playbook run injected."""

    scenario: str
    findings: tuple[DetectionFinding, ...]
    incident: SecurityIncident | None
    alerts: tuple[SecurityAlert, ...]
    timestamp: datetime
    response_request_id: str | None = None


def _correlate(
    findings: tuple[DetectionFinding, ...], ts: datetime
) -> tuple[SecurityIncident | None, tuple[HostNetworkCorrelation, ...]]:
    """Link the synthetic host + network findings with the existing correlators."""
    from aegis_shared.correlation import HostNetworkCorrelator, IncidentCorrelator
    from aegis_shared.enums import RiskLevel
    from aegis_shared.risk.models import RiskAssessment

    # Risk advice the correlator copies onto the incident: without it the
    # incident would carry 0/informational and the alert feed would understate it.
    assessments = (
        RiskAssessment(
            assessment_id=f"SIM-DEMO:{findings[0].event_id}",
            event_id=findings[0].event_id,
            host_id=DEMO_HOST_ID,
            risk_score=91,
            risk_level=RiskLevel.CRITICAL,
            severity=Severity.CRITICAL,
            reasons=("critical host execution combined with matching C2 egress",),
            finding_ids=tuple(f.finding_id for f in findings),
            scoring_version="sim-demo",
            timestamp=ts,
        ),
    )
    incidents = IncidentCorrelator().correlate((), findings, assessments)
    correlations = HostNetworkCorrelator().correlate(findings, reference_time=ts)
    return (incidents[0] if incidents else None), tuple(correlations)


def _demo_response_engine() -> object:
    """Policy engine used for *simulated* response requests only.

    The product default is fail-closed (``response_enabled=False``), which
    would deny a demo request outright and dead-end the Response Center at a
    BLOCKED dry run.  Simulated requests therefore run under a demo policy
    that keeps every human gate — dry run required, administrator approval
    required, no automatic execution — while still letting an operator click
    through Dry Run → Approve → Execute against a documentation-safe
    TEST-NET address.
    """
    from aegis_response_engine.policy import ResponsePolicyEngine, ResponsePolicySettings

    settings = ResponsePolicySettings(
        response_enabled=True,
        automatic_execution=False,
        approval_required=True,
        dry_run_required=True,
    )
    return ResponsePolicyEngine(settings)


def _open_response_request(
    findings: tuple[DetectionFinding, ...],
    incident: SecurityIncident | None,
) -> str | None:
    """Open a *draft* ``BLOCK_IP`` workflow entry for the simulated attacker IP.

    Returns the new request id, or ``None`` when the workflow registry is
    unavailable.  Nothing is approved or executed here: the request only makes
    the Action Center report pending work and gives the Response Center a
    request to dry-run, approve and execute.
    """
    from aegis_desktop.services.response_workflow import get_workflow_manager

    if incident is not None:
        incident_id = incident.incident_id
        risk_level = incident.risk_level.value
        risk_score = incident.risk_score
    else:
        incident_id = ""
        risk_level = "high"
        risk_score = 75
    try:
        view = get_workflow_manager().create_request_from_incident(
            incident_id,
            action_label="block_ip",
            target_value=ATTACKER_IP,
            target_kind="ip",
            risk_level=risk_level,
            risk_score=risk_score,
            finding_ids=tuple(f.finding_id for f in findings),
            engine=_demo_response_engine(),
        )
    except Exception as exc:
        logger.warning("Threat simulation could not open a response request: %s", exc)
        return None
    if view is None:
        return None
    logger.info(
        "Threat simulation opened response request %s (%s -> %s)",
        view.request_id,
        view.action_label,
        view.target,
    )
    return view.request_id


def run_scenario(key: str, *, alert_service: AlertService) -> SimulationOutcome:
    """Execute one playbook: inject synthetic data, then raise real alerts.

    Scenario ``port_scan`` injects a single HIGH network finding.  Scenario
    ``c2_beacon`` injects a CRITICAL host finding plus a network finding, runs
    the existing :class:`IncidentCorrelator` over them to form an OPEN incident
    and publishes that incident (and the host/network correlation) through the
    normal registries the console reads.

    Every run also opens one draft ``BLOCK_IP`` request against
    :data:`ATTACKER_IP` in the response workflow; the request id is returned
    as :attr:`SimulationOutcome.response_request_id`.
    """
    if key not in _SCENARIOS_BY_KEY:
        raise KeyError(f"Unknown threat simulation scenario: {key}")
    ts = datetime.now(UTC)
    findings = _BUILDERS[key](ts)

    incident: SecurityIncident | None = None
    correlations: tuple[HostNetworkCorrelation, ...] = ()
    if key == C2_BEACON_KEY:
        incident, correlations = _correlate(findings, ts)

    _remember(findings, incident)
    if incident is not None:
        _publish(incident, correlations)

    request_id = _open_response_request(findings, incident)

    alerts = alert_service.detect(
        findings=findings,
        incidents=((incident,) if incident is not None else ()),
        now=ts,
    )
    return SimulationOutcome(
        scenario=key,
        findings=findings,
        incident=incident,
        alerts=alerts,
        timestamp=ts,
        response_request_id=request_id,
    )


def _remember(
    findings: tuple[DetectionFinding, ...], incident: SecurityIncident | None
) -> None:
    _simulated_findings.extend(findings)
    if len(_simulated_findings) > MAX_SIMULATED:
        del _simulated_findings[: -MAX_SIMULATED]
    if incident is not None:
        _simulated_incidents.append(incident)
        if len(_simulated_incidents) > MAX_SIMULATED:
            del _simulated_incidents[: -MAX_SIMULATED]


def _publish(
    incident: SecurityIncident, correlations: tuple[HostNetworkCorrelation, ...]
) -> None:
    from aegis_shared.correlation import (
        get_active_incidents,
        set_active_host_network_correlations,
        set_active_incidents,
    )

    existing = tuple(get_active_incidents())
    if not any(item.incident_id == incident.incident_id for item in existing):
        set_active_incidents((*existing, incident))
    if correlations:
        set_active_host_network_correlations(correlations)


# --- Dialog -----------------------------------------------------------------


def _restyle(widget: QWidget) -> None:
    """Re-evaluate QSS dynamic-property rules after a property change."""
    style = widget.style()
    if style is None:
        return
    style.unpolish(widget)
    style.polish(widget)


class ThreatSimulationDialog(QDialog):
    """Frameless playbook picker: choose a scenario, then run it."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ThreatSimDialog")
        self.setWindowTitle(TITLE)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setFixedWidth(560)

        self._selected_key = SCENARIOS[0].key
        self._cards: dict[str, QFrame] = {}

        self._build()

    # -- Layout ------------------------------------------------------------

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 20)
        root.setSpacing(14)

        title = QLabel(TITLE)
        title.setObjectName("ThreatSimTitle")
        subtitle = QLabel(SUBTITLE)
        subtitle.setObjectName("ThreatSimSubtitle")
        subtitle.setWordWrap(True)
        root.addWidget(title)
        root.addWidget(subtitle)

        for scenario in SCENARIOS:
            root.addWidget(self._build_card(scenario))

        self.run_button = QPushButton("Run Simulation")
        self.run_button.setObjectName("WarningButton")
        self.run_button.clicked.connect(self.accept)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("DangerButton")
        self.cancel_button.setFixedWidth(96)
        self.cancel_button.clicked.connect(self.reject)

        note = QLabel("Synthetic demo data \u2014 never touches the live network.")
        note.setObjectName("ThreatSimNote")
        note.setWordWrap(True)

        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(10)
        footer.addWidget(self.run_button)
        footer.addWidget(self.cancel_button)
        root.addWidget(note)
        root.addLayout(footer)

    def _build_card(self, scenario: SimulationScenario) -> QFrame:
        card = QFrame()
        card.setObjectName("ScenarioCard")
        card.setProperty("selected", scenario.key == self._selected_key)
        card.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(12)
        name = QLabel(scenario.title)
        name.setObjectName("ScenarioTitle")
        severity = QLabel(scenario.severity.upper())
        severity.setObjectName("ScenarioSeverity")
        severity.setProperty("state", scenario.severity)
        header.addWidget(name, 1)
        header.addWidget(severity, 0, Qt.AlignmentFlag.AlignRight)

        domain = QLabel(scenario.domain)
        domain.setObjectName("ScenarioDomain")
        description = QLabel(scenario.description)
        description.setObjectName("ScenarioDesc")
        description.setWordWrap(True)
        injection = QLabel(scenario.injection)
        injection.setObjectName("ScenarioHint")
        injection.setWordWrap(True)

        layout.addLayout(header)
        layout.addWidget(domain)
        layout.addWidget(description)
        layout.addWidget(injection)

        key = scenario.key
        card.mousePressEvent = lambda _event, k=key: self.select(k)
        self._cards[scenario.key] = card
        return card

    # -- Introspection -----------------------------------------------------

    def scenario_keys(self) -> tuple[str, ...]:
        """Every selectable playbook key, in display order."""
        return tuple(scenario.key for scenario in SCENARIOS)

    def selected_key(self) -> str:
        """The playbook that will run when *Run Simulation* is pressed."""
        return self._selected_key

    def is_selected(self, key: str) -> bool:
        """Whether *key* is the currently selected playbook."""
        return key == self._selected_key

    def select(self, key: str) -> None:
        """Select the playbook identified by *key*."""
        if key not in self._cards:
            raise KeyError(key)
        self._selected_key = key
        for candidate, card in self._cards.items():
            card.setProperty("selected", candidate == key)
            _restyle(card)


__all__ = [
    "C2_BEACON",
    "C2_BEACON_KEY",
    "PORT_SCAN",
    "PORT_SCAN_KEY",
    "SCENARIOS",
    "TITLE",
    "SimulationOutcome",
    "SimulationScenario",
    "ThreatSimulationDialog",
    "augment_snapshot",
    "build_c2_findings",
    "build_port_scan_findings",
    "clear_simulated",
    "run_scenario",
    "scenario_for",
    "simulated_findings",
    "simulated_incidents",
]
