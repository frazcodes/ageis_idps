"""Local threat-intelligence / IOC context.

Matches observables already present in Aegis telemetry (IP addresses, domains,
file hashes) against locally configured indicators and exposes the match as
explainable evidence. This is **context enrichment**, not prevention: it performs
no external requests, no blocking and no attribution.

**IOC match != confirmed attack.**
"""

from __future__ import annotations

from aegis_shared.threat_intel.config import (
    ThreatIntelSettings,
    get_threat_intel_settings,
)
from aegis_shared.threat_intel.matcher import (
    IOCMatcher,
    ioc_rule_info,
    matches_to_findings,
    normalize_value,
    parse_indicators,
    to_finding,
)
from aegis_shared.threat_intel.models import IOCMatch, ThreatIndicator
from aegis_shared.threat_intel.runtime import (
    clear_active_ioc_matches,
    get_active_ioc_matches,
    set_active_ioc_matches,
)

__all__ = [
    "IOCMatch",
    "IOCMatcher",
    "ThreatIndicator",
    "ThreatIntelSettings",
    "clear_active_ioc_matches",
    "get_active_ioc_matches",
    "get_threat_intel_settings",
    "ioc_rule_info",
    "matches_to_findings",
    "normalize_value",
    "parse_indicators",
    "set_active_ioc_matches",
    "to_finding",
]
