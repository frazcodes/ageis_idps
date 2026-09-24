"""Correlation adapter: host <-> network evidence -> UI-friendly data.

Strictly read-only. It reads the current host/network correlations published by
the running runtime through the process-wide registry and shapes them for the
investigation/incident detail views. No correlation is fabricated in the GUI and
no model, engine or pipeline is run here.

Imports of the shared correlation layer are lazy so opening the application loads
no security engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.correlation import HostNetworkCorrelation

logger = get_logger(__name__)


@dataclass(frozen=True)
class CorrelationEvidence:
    """Read-only view of a host <-> network evidence correlation."""

    correlated: bool
    host_id: str
    host_finding_count: int
    network_finding_count: int
    window_seconds: int
    host_finding_ids: tuple[str, ...]
    network_finding_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    reason: str

    @property
    def finding_ids(self) -> tuple[str, ...]:
        """Every related finding ID (host + network)."""
        return (*self.host_finding_ids, *self.network_finding_ids)


def _default_correlations() -> tuple[HostNetworkCorrelation, ...]:
    """Return the host/network correlations published by the runtime (read-only)."""
    from aegis_shared.correlation import get_active_host_network_correlations

    return get_active_host_network_correlations()


def _to_evidence(correlation: HostNetworkCorrelation) -> CorrelationEvidence:
    return CorrelationEvidence(
        correlated=True,
        host_id=correlation.host_id,
        host_finding_count=len(correlation.host_finding_ids),
        network_finding_count=len(correlation.network_finding_ids),
        window_seconds=correlation.window_seconds,
        host_finding_ids=tuple(correlation.host_finding_ids),
        network_finding_ids=tuple(correlation.network_finding_ids),
        event_ids=tuple(correlation.event_ids),
        reason=correlation.reason,
    )


def correlation_for_finding(
    finding_id: str,
    *,
    provider: Callable[[], tuple[HostNetworkCorrelation, ...]] | None = None,
) -> CorrelationEvidence | None:
    """Return the host/network correlation containing ``finding_id``, if any."""
    for correlation in _safe_correlations(provider):
        related = (*correlation.host_finding_ids, *correlation.network_finding_ids)
        if finding_id in related:
            return _to_evidence(correlation)
    return None


def correlation_for_incident(
    host_id: str,
    finding_ids: tuple[str, ...],
    *,
    provider: Callable[[], tuple[HostNetworkCorrelation, ...]] | None = None,
) -> CorrelationEvidence | None:
    """Return the host/network correlation related to an incident, if any.

    Matches on the same host and an overlapping related finding.
    """
    wanted = set(finding_ids)
    for correlation in _safe_correlations(provider):
        if correlation.host_id != host_id:
            continue
        related = set(correlation.host_finding_ids) | set(correlation.network_finding_ids)
        if wanted & related:
            return _to_evidence(correlation)
    return None


def _safe_correlations(
    provider: Callable[[], tuple[HostNetworkCorrelation, ...]] | None,
) -> tuple[HostNetworkCorrelation, ...]:
    try:
        return tuple((provider or _default_correlations)())
    except Exception as exc:
        logger.warning("Reading host/network correlations failed: %s", exc)
        return ()


def collect_correlations(
    *,
    provider: Callable[[], tuple[HostNetworkCorrelation, ...]] | None = None,
) -> tuple[CorrelationEvidence, ...]:
    """Return every published host/network correlation as a read-only view."""
    return tuple(_to_evidence(c) for c in _safe_correlations(provider))


__all__ = [
    "CorrelationEvidence",
    "collect_correlations",
    "correlation_for_finding",
    "correlation_for_incident",
]
