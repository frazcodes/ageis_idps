"""Deterministic host <-> network evidence correlation.

Groups existing findings that belong to the **same host** within a bounded time
window into a :class:`~aegis_shared.correlation.models.HostNetworkCorrelation`:
a statement that host-side and network-side security findings were observed on
the same host in a compatible window.

It is stateless, passive and performs no I/O: the same findings and configuration
always produce identical correlations. It reuses the existing
:class:`~aegis_shared.detection.models.DetectionFinding` contract and classifies
evidence by the finding's existing ``category`` (``host`` / ``network``), so no
new detection, event store or scoring system is introduced.

Language is deliberately evidence-based: it never claims that a process caused
network activity, that the host is compromised, or any attack attribution.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime, timedelta

from aegis_shared.correlation.config import CorrelationSettings
from aegis_shared.correlation.models import HostNetworkCorrelation
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.enums import EventCategory


class HostNetworkCorrelator:
    """Correlate related host-side and network-side findings on the same host."""

    def __init__(self, settings: CorrelationSettings | None = None) -> None:
        self._settings = settings or CorrelationSettings()

    @property
    def settings(self) -> CorrelationSettings:
        """The settings this correlator groups with."""
        return self._settings

    @property
    def window_seconds(self) -> int:
        """The configured host/network correlation window (seconds)."""
        return self._settings.host_network_correlation_window_seconds

    def correlate(
        self,
        findings: Iterable[DetectionFinding],
        *,
        reference_time: datetime | None = None,
    ) -> tuple[HostNetworkCorrelation, ...]:
        """Return host/network correlations, in deterministic order.

        A correlation requires the same non-empty ``host_id``, at least one
        host-side finding, at least one network-side finding, and a compatible
        timestamp inside the configured window.
        """
        all_findings = list(findings)
        correlations: list[HostNetworkCorrelation] = []

        for host_id in sorted(self._hosts(all_findings)):
            group = [f for f in all_findings if f.host_id == host_id]
            host_side = [f for f in group if f.category is EventCategory.HOST]
            network_side = [f for f in group if f.category is EventCategory.NETWORK]
            if not host_side or not network_side:
                continue

            reference = reference_time or max(f.timestamp for f in group)
            low = reference - timedelta(seconds=self.window_seconds)
            host_window = [f for f in host_side if low <= f.timestamp <= reference]
            network_window = [f for f in network_side if low <= f.timestamp <= reference]
            if not host_window or not network_window:
                continue

            correlations.append(
                self._build(host_id, host_window, network_window)
            )

        return tuple(sorted(correlations, key=lambda c: c.correlation_id))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hosts(findings: list[DetectionFinding]) -> set[str]:
        return {
            finding.host_id
            for finding in findings
            if finding.host_id is not None and finding.host_id != ""
        }

    def _build(
        self,
        host_id: str,
        host_findings: list[DetectionFinding],
        network_findings: list[DetectionFinding],
    ) -> HostNetworkCorrelation:
        host_ids = tuple(sorted(f.finding_id for f in host_findings))
        network_ids = tuple(sorted(f.finding_id for f in network_findings))
        event_ids = tuple(
            sorted({f.event_id for f in (*host_findings, *network_findings)})
        )
        created_at = min(f.timestamp for f in (*host_findings, *network_findings))
        window = self.window_seconds

        return HostNetworkCorrelation(
            correlation_id=self._correlation_id(host_id, host_ids, network_ids),
            host_id=host_id,
            created_at=created_at,
            host_finding_ids=host_ids,
            network_finding_ids=network_ids,
            event_ids=event_ids,
            window_seconds=window,
            summary=(
                f"{len(host_ids)} host and {len(network_ids)} network findings were "
                f"correlated on host {host_id}."
            ),
            reason=(
                "Host and network findings were observed on the same host within "
                f"the configured correlation window ({window}s)."
            ),
        )

    @staticmethod
    def _correlation_id(
        host_id: str, host_ids: tuple[str, ...], network_ids: tuple[str, ...]
    ) -> str:
        payload = f"{host_id}|{'|'.join(host_ids)}|{'|'.join(network_ids)}".encode()
        digest = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        return f"HNC-{digest[:16]}"


__all__ = ["HostNetworkCorrelator"]
