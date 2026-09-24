"""Real-time security alert service for the SOC dashboard.

Detects newly observed HIGH/CRITICAL findings and new OPEN incidents from
the existing runtime state.  Uses deterministic object IDs for deduplication
so the same finding or incident never generates a duplicate alert.

The service is stateless between calls: it receives the current findings and
incidents, compares them against the set of already-alerted IDs, and emits
new alerts.  It stores a bounded history of emitted alerts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: Maximum number of alerts retained in history.
MAX_ALERTS: int = 100


@dataclass(frozen=True)
class SecurityAlert:
    """One real-time security alert."""

    alert_id: str
    alert_type: str  # "finding" | "incident"
    severity: str  # "high" | "critical" | risk_level
    title: str
    description: str
    source_id: str  # finding_id or incident_id
    host_id: str
    timestamp: datetime


class AlertService:
    """Detects and tracks new security alerts from runtime state.

    Maintains the set of already-alerted IDs for deduplication and a bounded
    history of emitted alerts.
    """

    def __init__(self, max_alerts: int = MAX_ALERTS) -> None:
        self._max = max_alerts
        self._alerted_finding_ids: set[str] = set()
        self._alerted_incident_ids: set[str] = set()
        self._alerts: list[SecurityAlert] = []

    @property
    def count(self) -> int:
        """Number of alerts in history."""
        return len(self._alerts)

    @property
    def alerted_finding_ids(self) -> frozenset[str]:
        """Set of finding IDs that have already been alerted."""
        return frozenset(self._alerted_finding_ids)

    @property
    def alerted_incident_ids(self) -> frozenset[str]:
        """Set of incident IDs that have already been alerted."""
        return frozenset(self._alerted_incident_ids)

    def detect(
        self,
        *,
        findings: tuple[object, ...] = (),
        incidents: tuple[object, ...] = (),
        now: datetime | None = None,
    ) -> tuple[SecurityAlert, ...]:
        """Compare current findings/incidents against alerted set.

        Returns only newly detected alerts.  High/critical findings and
        open incidents generate alerts; the same object never alerts twice.
        """
        ts = now or datetime.now()
        new_alerts: list[SecurityAlert] = []

        for finding in findings:
            severity = str(getattr(finding, "severity", "")).lower()
            if severity not in ("high", "critical"):
                continue
            fid = str(getattr(finding, "finding_id", ""))
            if not fid or fid in self._alerted_finding_ids:
                continue
            self._alerted_finding_ids.add(fid)

            rule_id = str(getattr(finding, "rule_id", ""))
            title_text = str(getattr(finding, "title", ""))
            host_id = str(getattr(finding, "host_id", ""))

            alert = SecurityAlert(
                alert_id=f"ALRT-F-{fid}",
                alert_type="finding",
                severity=severity,
                title=f"{severity.upper()} severity finding detected",
                description=f"Rule: {rule_id} | {title_text}",
                source_id=fid,
                host_id=host_id,
                timestamp=ts,
            )
            new_alerts.append(alert)

        for incident in incidents:
            status = str(getattr(incident, "status", "")).lower()
            if status not in ("open",):
                continue
            inc_id = str(getattr(incident, "incident_id", ""))
            if not inc_id or inc_id in self._alerted_incident_ids:
                continue
            self._alerted_incident_ids.add(inc_id)

            risk_level = str(getattr(incident, "risk_level", "")).lower()
            host_id = str(getattr(incident, "host_id", ""))
            finding_ids = getattr(incident, "finding_ids", ())
            summary = str(getattr(incident, "summary", ""))
            finding_count = len(finding_ids)

            desc = (
                f"Incident: {inc_id} | Risk: {risk_level.upper()}"
                f" | Findings: {finding_count} | {summary[:80]}"
            )
            alert = SecurityAlert(
                alert_id=f"ALRT-I-{inc_id}",
                alert_type="incident",
                severity=risk_level,
                title="New incident opened",
                description=desc,
                source_id=inc_id,
                host_id=host_id,
                timestamp=ts,
            )
            new_alerts.append(alert)

        for alert in new_alerts:
            self._alerts.append(alert)
        if len(self._alerts) > self._max:
            self._alerts = self._alerts[-self._max :]

        return tuple(new_alerts)

    def all_alerts(self) -> tuple[SecurityAlert, ...]:
        """Return all alerts, newest first."""
        return tuple(reversed(self._alerts))

    def clear(self) -> None:
        """Clear all alerts and dedup state."""
        self._alerted_finding_ids.clear()
        self._alerted_incident_ids.clear()
        self._alerts.clear()


__all__ = ["MAX_ALERTS", "AlertService", "SecurityAlert"]
