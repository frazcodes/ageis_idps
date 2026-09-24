"""Deterministic rule-based detection engine.

The engine applies a set of :class:`~aegis_shared.detection.rules.DetectionRule`
objects to canonical events. It is **stateless**, **passive** and independently
callable::

    engine = DetectionEngine.from_settings(settings)
    findings = engine.evaluate(event)
    findings = engine.evaluate_many(events)

It never performs a response, never mutates events, and never touches the
network, filesystem or process table. Findings are returned in deterministic
order: by event order for :meth:`evaluate_many`, and by sorted ``rule_id`` within
each event.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from aegis_shared.detection.config import DetectionSettings
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.detection.rules import DetectionRule, build_default_rules
from aegis_shared.events import SecurityEvent
from aegis_shared.logging import get_logger

logger = get_logger(__name__)


class DetectionEngine:
    """Apply deterministic rules to events and produce findings."""

    def __init__(self, rules: Iterable[DetectionRule], *, enabled: bool = True) -> None:
        rule_list = list(rules)
        self._validate_rule_ids(rule_list)
        # Deterministic evaluation order regardless of construction order.
        self._rules = tuple(sorted(rule_list, key=lambda rule: rule.rule_id))
        self._enabled = enabled

    @classmethod
    def from_settings(cls, settings: DetectionSettings) -> DetectionEngine:
        """Build the standard engine from configuration."""
        return cls(build_default_rules(settings), enabled=settings.enabled)

    @property
    def enabled(self) -> bool:
        """Whether the engine evaluates at all."""
        return self._enabled

    @property
    def rules(self) -> tuple[DetectionRule, ...]:
        """The configured rules, in deterministic ``rule_id`` order."""
        return self._rules

    def evaluate(self, event: SecurityEvent) -> tuple[DetectionFinding, ...]:
        """Evaluate all enabled rules against one event.

        Returns every match (a single event may match multiple rules). A rule
        that raises on incomplete telemetry is skipped rather than crashing the
        engine.
        """
        if not self._enabled or not isinstance(event, SecurityEvent):
            return ()

        findings: list[DetectionFinding] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if rule.matches(event):
                    findings.append(rule.build_finding(event))
            except Exception as exc:
                # Incomplete/malformed telemetry must never crash detection.
                logger.debug(
                    "Rule %s skipped event %s: %s",
                    rule.rule_id,
                    getattr(event, "event_id", "<unknown>"),
                    exc,
                )
        return tuple(findings)

    def evaluate_many(self, events: Iterable[SecurityEvent]) -> tuple[DetectionFinding, ...]:
        """Evaluate many events, concatenating findings in event order."""
        findings: list[DetectionFinding] = []
        for event in events:
            findings.extend(self.evaluate(event))
        return tuple(findings)

    @staticmethod
    def _validate_rule_ids(rules: list[DetectionRule]) -> None:
        for rule in rules:
            if not rule.rule_id or not rule.rule_id.strip():
                raise ValueError("rule_id must be a non-empty string")
        duplicates = [
            rule_id for rule_id, count in Counter(r.rule_id for r in rules).items() if count > 1
        ]
        if duplicates:
            raise ValueError(f"duplicate rule id(s): {sorted(duplicates)}")


__all__ = ["DetectionEngine"]
