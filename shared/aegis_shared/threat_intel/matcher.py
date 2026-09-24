"""Deterministic, offline IOC matching over existing Aegis observables.

The matcher normalizes values already present in telemetry and looks them up in a
locally configured indicator index. It is pure: no I/O, no network requests, no
telemetry mutation, no external provider. The same event and indicators always
produce the same matches.

Observables actually available today:

* **IP** - ``NetworkContext.src_ip`` / ``dst_ip``
* **Domain** - ``NetworkContext.domain`` (DNS/TLS SNI, when resolvable)
* **File hash** - ``FileContext.hashes`` / ``ProcessContext.hashes`` values

URLs are not present in telemetry and are deliberately not matched. Matching an
IOC is **context**, never proof of malicious activity or attribution.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable

from aegis_shared.detection.models import DetectionFinding
from aegis_shared.detection.rules import RULE_IOC_MATCH
from aegis_shared.enums import IndicatorType
from aegis_shared.events import SecurityEvent
from aegis_shared.threat_intel.config import ThreatIntelSettings
from aegis_shared.threat_intel.models import IOCMatch, ThreatIndicator

_TYPE_ALIASES: dict[str, IndicatorType] = {
    "ip": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "file_hash": IndicatorType.FILE_HASH,
    "hash": IndicatorType.FILE_HASH,
}

_HASH_LENGTHS = frozenset({32, 40, 64})  # md5 / sha1 / sha256
_HEX_DIGITS = frozenset("0123456789abcdef")

_IOC_RULE_NAME = "Configured threat-intelligence indicator matched observed telemetry"
_IOC_RULE_DESCRIPTION = (
    "A configured threat-intelligence indicator matched an observed value in "
    "telemetry. This is context for investigation, not proof of malicious activity."
)


def normalize_value(indicator_type: IndicatorType, value: str | None) -> str | None:
    """Normalize an observable value, or return ``None`` when unusable.

    IPs are canonicalised; domains and file hashes are lowercased (and domains
    have a trailing dot removed). Case-sensitive duplicates therefore cannot
    occur.
    """
    text = (value or "").strip()
    if not text:
        return None
    if indicator_type is IndicatorType.IP:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    if indicator_type is IndicatorType.DOMAIN:
        domain = text.lower().rstrip(".")
        return domain or None
    if indicator_type is IndicatorType.FILE_HASH:
        digest = text.lower()
        if len(digest) in _HASH_LENGTHS and all(ch in _HEX_DIGITS for ch in digest):
            return digest
        return None
    return None


def _indicator_id(indicator_type: IndicatorType, value: str) -> str:
    payload = f"{indicator_type.value}|{value}".encode()
    return f"IOC-{hashlib.sha1(payload, usedforsecurity=False).hexdigest()[:16]}"


def _parse_indicator(raw: str, settings: ThreatIntelSettings) -> ThreatIndicator | None:
    if ":" not in raw:
        return None
    type_text, _, value_text = raw.partition(":")
    indicator_type = _TYPE_ALIASES.get(type_text.strip().lower())
    if indicator_type is None:
        return None
    normalized = normalize_value(indicator_type, value_text)
    if normalized is None:
        return None
    return ThreatIndicator(
        indicator_id=_indicator_id(indicator_type, normalized),
        indicator_type=indicator_type,
        value=normalized,
        source=settings.source,
        confidence=settings.default_confidence,
        severity=settings.default_severity,
        enabled=True,
    )


def parse_indicators(settings: ThreatIntelSettings) -> tuple[ThreatIndicator, ...]:
    """Parse and de-duplicate configured indicators deterministically."""
    seen: set[tuple[IndicatorType, str]] = set()
    indicators: list[ThreatIndicator] = []
    for raw in settings.indicators:
        indicator = _parse_indicator(raw, settings)
        if indicator is None:
            continue
        key = (indicator.indicator_type, indicator.value)
        if key in seen:
            continue
        seen.add(key)
        indicators.append(indicator)
    return tuple(indicators)


def _observables(event: SecurityEvent) -> list[tuple[IndicatorType, str]]:
    """Extract candidate (type, value) observables from an event's context."""
    observables: list[tuple[IndicatorType, str]] = []
    network = event.network
    if network is not None:
        if network.src_ip:
            observables.append((IndicatorType.IP, network.src_ip))
        if network.dst_ip:
            observables.append((IndicatorType.IP, network.dst_ip))
        if network.domain:
            observables.append((IndicatorType.DOMAIN, network.domain))
    for context in (event.file, event.process):
        if context is None:
            continue
        for digest in context.hashes.values():
            if digest:
                observables.append((IndicatorType.FILE_HASH, digest))
    return observables


def _build_match(
    indicator: ThreatIndicator, observed_value: str, event: SecurityEvent
) -> IOCMatch:
    payload = f"{indicator.indicator_id}|{observed_value}|{event.event_id}".encode()
    match_id = f"IOCM-{hashlib.sha1(payload, usedforsecurity=False).hexdigest()[:16]}"
    return IOCMatch(
        match_id=match_id,
        indicator_id=indicator.indicator_id,
        indicator_type=indicator.indicator_type,
        observed_value=observed_value,
        source=indicator.source,
        confidence=indicator.confidence,
        severity=indicator.severity,
        matched_at=event.timestamp,
        event_id=event.event_id,
        event_type=event.event_type,
        category=event.category,
        host_id=event.host.host_id if event.host is not None else None,
        description=indicator.description,
    )


class IOCMatcher:
    """Match observables in events against a local indicator index."""

    def __init__(self, indicators: Iterable[ThreatIndicator]) -> None:
        self._index: dict[IndicatorType, dict[str, ThreatIndicator]] = {}
        for indicator in indicators:
            if not indicator.enabled:
                continue
            bucket = self._index.setdefault(indicator.indicator_type, {})
            bucket.setdefault(indicator.value, indicator)

    @classmethod
    def from_settings(cls, settings: ThreatIntelSettings) -> IOCMatcher:
        """Build a matcher from configured indicators."""
        return cls(parse_indicators(settings))

    @property
    def enabled(self) -> bool:
        """Whether any enabled indicator is loaded."""
        return bool(self._index)

    @property
    def indicator_count(self) -> int:
        """Number of enabled indicators loaded."""
        return sum(len(bucket) for bucket in self._index.values())

    def match_event(self, event: SecurityEvent) -> tuple[IOCMatch, ...]:
        """Return the deterministic IOC matches for one event (deduplicated)."""
        if not self._index or not isinstance(event, SecurityEvent):
            return ()
        matches: dict[tuple[str, str], IOCMatch] = {}
        for indicator_type, raw_value in _observables(event):
            normalized = normalize_value(indicator_type, raw_value)
            if normalized is None:
                continue
            indicator = self._index.get(indicator_type, {}).get(normalized)
            if indicator is None:
                continue
            key = (indicator.indicator_id, normalized)
            if key in matches:
                continue
            matches[key] = _build_match(indicator, normalized, event)
        return tuple(sorted(matches.values(), key=lambda match: match.match_id))

    def match_events(self, events: Iterable[SecurityEvent]) -> tuple[IOCMatch, ...]:
        """Match many events in order, preserving event order."""
        collected: list[IOCMatch] = []
        for event in events:
            collected.extend(self.match_event(event))
        return tuple(collected)


def to_finding(match: IOCMatch) -> DetectionFinding:
    """Convert an :class:`IOCMatch` into a detection finding (severity from IOC)."""
    return DetectionFinding(
        finding_id=f"{RULE_IOC_MATCH}:{match.event_id}:{match.indicator_id}",
        rule_id=RULE_IOC_MATCH,
        rule_name=_IOC_RULE_NAME,
        severity=match.severity,
        title="Threat-intelligence indicator matched observed telemetry",
        description=_IOC_RULE_DESCRIPTION,
        event_id=match.event_id,
        event_type=match.event_type,
        category=match.category,
        timestamp=match.matched_at,
        host_id=match.host_id,
        evidence={
            "indicator_type": match.indicator_type.value,
            "observed_value": match.observed_value,
            "source": match.source,
            "confidence": f"{match.confidence:.2f}",
            "indicator_id": match.indicator_id,
        },
        tags=("threat_intel", "ioc"),
    )


def matches_to_findings(matches: Iterable[IOCMatch]) -> tuple[DetectionFinding, ...]:
    """Convert many matches to findings, deduplicated by ``finding_id``."""
    seen: set[str] = set()
    findings: list[DetectionFinding] = []
    for match in matches:
        finding = to_finding(match)
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        findings.append(finding)
    return tuple(findings)


def ioc_rule_info(rule_id: str) -> dict[str, str]:
    """Return static metadata for the IOC rule, or ``{}`` when unknown."""
    if rule_id != RULE_IOC_MATCH:
        return {}
    return {
        "rule_id": RULE_IOC_MATCH,
        "name": _IOC_RULE_NAME,
        "description": _IOC_RULE_DESCRIPTION,
        "tags": "threat_intel, ioc",
    }


__all__ = [
    "IOCMatcher",
    "ioc_rule_info",
    "matches_to_findings",
    "normalize_value",
    "parse_indicators",
    "to_finding",
]
