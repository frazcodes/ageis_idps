"""Deterministic, rule-based detection over canonical Aegis telemetry.

Transforms normalized :class:`aegis_shared.events.SecurityEvent` records into
:class:`~aegis_shared.detection.models.DetectionFinding` objects with evidence.

Design
------
* **Rule definition** - :class:`DetectionRule` and the concrete rules.
* **Rule evaluation** - deterministic ``matches``/``evidence`` on each rule.
* **Finding representation** - :class:`DetectionFinding`.
* **Engine orchestration** - :class:`DetectionEngine`.

This is **detection, not confirmation**: a finding records that an event matched
a configured criterion, not that the system is compromised. All suspicious
criteria are configuration-driven (``AEGIS_DETECTION_*``) and default to empty.
The engine is passive and stateless - it never blocks, kills, deletes or
quarantines anything.
"""

from __future__ import annotations

from aegis_shared.detection.behavior import (
    BEHAVIOR_RULE_INFO,
    NetworkBehaviorAnalyzer,
    behavior_rule_info,
    build_behavior_analyzer,
)
from aegis_shared.detection.communication import (
    CommunicationObservation,
    CommunicationSignal,
    CommunicationSignalType,
    SuspiciousCommunicationAnalyzer,
    build_communication_analyzer,
    communication_rule_info,
)
from aegis_shared.detection.config import (
    DEFAULT_EXECUTABLE_EXTENSIONS,
    DetectionSettings,
    get_detection_settings,
    normalize_endpoint,
    parse_endpoint,
)
from aegis_shared.detection.engine import DetectionEngine
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.detection.rules import (
    ALL_RULE_IDS,
    BEHAVIOR_RULE_IDS,
    COMMUNICATION_RULE_IDS,
    KNOWN_RULE_IDS,
    RULE_EXECUTABLE_CREATION,
    RULE_IOC_MATCH,
    RULE_LISTEN_PORT,
    RULE_NETWORK_COMMUNICATION,
    RULE_NETWORK_DEST_FANOUT,
    RULE_NETWORK_ENDPOINT,
    RULE_NETWORK_FLOW_BURST,
    RULE_NETWORK_PORT_BREADTH,
    RULE_NETWORK_REPEATED_COMM,
    RULE_NETWORK_VOLUME,
    RULE_PROCESS_PATH,
    RULE_SENSITIVE_FILE,
    THREAT_INTEL_RULE_IDS,
    DetectionRule,
    ExecutableCreationRule,
    HighNetworkVolumeRule,
    SensitiveFileModificationRule,
    SuspiciousListeningPortRule,
    SuspiciousNetworkEndpointRule,
    SuspiciousProcessPathRule,
    build_default_rules,
)
from aegis_shared.detection.runtime import (
    clear_active_engine,
    get_active_engine,
    set_active_engine,
)

__all__ = [
    "ALL_RULE_IDS",
    "BEHAVIOR_RULE_IDS",
    "BEHAVIOR_RULE_INFO",
    "COMMUNICATION_RULE_IDS",
    "DEFAULT_EXECUTABLE_EXTENSIONS",
    "KNOWN_RULE_IDS",
    "RULE_EXECUTABLE_CREATION",
    "RULE_IOC_MATCH",
    "RULE_LISTEN_PORT",
    "RULE_NETWORK_COMMUNICATION",
    "RULE_NETWORK_DEST_FANOUT",
    "RULE_NETWORK_ENDPOINT",
    "RULE_NETWORK_FLOW_BURST",
    "RULE_NETWORK_PORT_BREADTH",
    "RULE_NETWORK_REPEATED_COMM",
    "RULE_NETWORK_VOLUME",
    "RULE_PROCESS_PATH",
    "RULE_SENSITIVE_FILE",
    "THREAT_INTEL_RULE_IDS",
    "CommunicationObservation",
    "CommunicationSignal",
    "CommunicationSignalType",
    "DetectionEngine",
    "DetectionFinding",
    "DetectionRule",
    "DetectionSettings",
    "ExecutableCreationRule",
    "HighNetworkVolumeRule",
    "NetworkBehaviorAnalyzer",
    "SensitiveFileModificationRule",
    "SuspiciousCommunicationAnalyzer",
    "SuspiciousListeningPortRule",
    "SuspiciousNetworkEndpointRule",
    "SuspiciousProcessPathRule",
    "behavior_rule_info",
    "build_behavior_analyzer",
    "build_communication_analyzer",
    "build_default_rules",
    "clear_active_engine",
    "communication_rule_info",
    "get_active_engine",
    "get_detection_settings",
    "normalize_endpoint",
    "parse_endpoint",
    "set_active_engine",
]
