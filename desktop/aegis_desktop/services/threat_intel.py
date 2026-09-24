"""Threat-intelligence adapter: IOC matches -> UI-friendly data.

Strictly read-only. It runs the shared, deterministic :class:`IOCMatcher` over
the events already buffered in the existing pipeline (no I/O, no network request,
no external provider) and shapes the matches for the investigation/incident
detail views. No match is fabricated in the GUI.

Imports of the shared threat-intelligence layer are lazy so opening the
application loads no security engine.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.events import SecurityEvent
    from aegis_shared.threat_intel import IOCMatch, IOCMatcher

logger = get_logger(__name__)


@dataclass(frozen=True)
class IOCMatchView:
    """Read-only view of one IOC match (context, not a verdict)."""

    event_id: str
    indicator_type: str
    observed_value: str
    source: str
    confidence: float
    severity: str
    description: str | None


@dataclass(frozen=True)
class ThreatIntelView:
    """Read-only view of the IOC context for one event or an incident."""

    matched: bool
    matches: tuple[IOCMatchView, ...]

    @property
    def count(self) -> int:
        """Number of IOC matches."""
        return len(self.matches)

    @property
    def types(self) -> tuple[str, ...]:
        """Distinct matched indicator types, sorted."""
        return tuple(sorted({match.indicator_type for match in self.matches}))

    @property
    def sources(self) -> tuple[str, ...]:
        """Distinct indicator sources, sorted."""
        return tuple(sorted({match.source for match in self.matches}))


def _default_matcher() -> IOCMatcher:
    from aegis_shared.threat_intel import IOCMatcher, get_threat_intel_settings

    return IOCMatcher.from_settings(get_threat_intel_settings())


def _to_match_view(match: IOCMatch) -> IOCMatchView:
    return IOCMatchView(
        event_id=match.event_id,
        indicator_type=match.indicator_type.value,
        observed_value=match.observed_value,
        source=match.source,
        confidence=match.confidence,
        severity=match.severity.value,
        description=match.description,
    )


def threat_intel_for_event(
    event: SecurityEvent | None,
    *,
    matcher_provider: Callable[[], IOCMatcher] | None = None,
) -> ThreatIntelView | None:
    """Return the IOC context for one event, or ``None`` when there is no match."""
    if event is None:
        return None
    try:
        matches = (matcher_provider or _default_matcher)().match_event(event)
    except Exception as exc:
        logger.warning("IOC matching failed: %s", exc)
        return None
    if not matches:
        return None
    return ThreatIntelView(matched=True, matches=tuple(_to_match_view(m) for m in matches))


def threat_intel_for_events(
    events: Iterable[SecurityEvent],
    *,
    matcher_provider: Callable[[], IOCMatcher] | None = None,
) -> tuple[IOCMatchView, ...]:
    """Return de-duplicated IOC match views across many events."""
    try:
        matcher = (matcher_provider or _default_matcher)()
    except Exception as exc:
        logger.warning("IOC matcher unavailable: %s", exc)
        return ()
    seen: set[str] = set()
    views: list[IOCMatchView] = []
    for event in events:
        try:
            matches = matcher.match_event(event)
        except Exception as exc:
            logger.warning("IOC matching failed: %s", exc)
            continue
        for match in matches:
            if match.match_id in seen:
                continue
            seen.add(match.match_id)
            views.append(_to_match_view(match))
    return tuple(views)


__all__ = [
    "IOCMatchView",
    "ThreatIntelView",
    "threat_intel_for_event",
    "threat_intel_for_events",
]
