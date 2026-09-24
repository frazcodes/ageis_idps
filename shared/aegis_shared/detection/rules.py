"""Deterministic, side-effect-free detection rules.

A rule inspects one canonical :class:`~aegis_shared.events.SecurityEvent` and
decides whether it matches. Rules never modify the event, never touch the system
and never perform I/O. All "suspicious" criteria come from configuration; a rule
with empty criteria never matches.

Language note: findings describe **observable facts** ("configured sensitive file
modified"), never conclusions ("malware confirmed"). These are rules, not proof
of compromise.
"""

from __future__ import annotations

import fnmatch
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar

from aegis_shared.detection.config import DetectionSettings, parse_endpoint
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.enums import EventType, FileType, Severity, TransportProtocol
from aegis_shared.events import SecurityEvent

# Stable rule identifiers (sorted order defines deterministic evaluation order).
RULE_LISTEN_PORT = "AEGIS-LISTEN-001"
RULE_SENSITIVE_FILE = "AEGIS-FILE-001"
RULE_EXECUTABLE_CREATION = "AEGIS-EXEC-001"
RULE_PROCESS_PATH = "AEGIS-PROC-001"
RULE_NETWORK_ENDPOINT = "AEGIS-NET-001"
RULE_NETWORK_VOLUME = "AEGIS-NET-002"
# Behavioral network rules are evaluated over a bounded window of flow events by
# :class:`~aegis_shared.detection.behavior.NetworkBehaviorAnalyzer`, not per-event.
RULE_NETWORK_FLOW_BURST = "AEGIS-NET-003"
RULE_NETWORK_REPEATED_COMM = "AEGIS-NET-004"
RULE_NETWORK_DEST_FANOUT = "AEGIS-NET-005"
RULE_NETWORK_PORT_BREADTH = "AEGIS-NET-006"
# Threat-intelligence matching is evaluated by the IOC layer, not per-event.
RULE_IOC_MATCH = "AEGIS-IOC-001"
# Multi-signal suspicious-communication analysis is evaluated by its analyzer.
RULE_NETWORK_COMMUNICATION = "AEGIS-NET-007"

#: Every rule ID the per-event engine can build.
ALL_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_LISTEN_PORT,
        RULE_SENSITIVE_FILE,
        RULE_EXECUTABLE_CREATION,
        RULE_PROCESS_PATH,
        RULE_NETWORK_ENDPOINT,
        RULE_NETWORK_VOLUME,
    }
)

#: Behavioral rule IDs evaluated over a bounded flow window (not per-event).
BEHAVIOR_RULE_IDS: frozenset[str] = frozenset(
    {
        RULE_NETWORK_FLOW_BURST,
        RULE_NETWORK_REPEATED_COMM,
        RULE_NETWORK_DEST_FANOUT,
        RULE_NETWORK_PORT_BREADTH,
    }
)

#: Threat-intelligence rule IDs evaluated by the IOC layer (not per-event).
THREAT_INTEL_RULE_IDS: frozenset[str] = frozenset({RULE_IOC_MATCH})

#: Multi-signal communication rule IDs evaluated by the communication analyzer.
COMMUNICATION_RULE_IDS: frozenset[str] = frozenset({RULE_NETWORK_COMMUNICATION})

#: Every rule ID the detection layer understands (engine + behavioral + IOC + comms).
KNOWN_RULE_IDS: frozenset[str] = (
    ALL_RULE_IDS | BEHAVIOR_RULE_IDS | THREAT_INTEL_RULE_IDS | COMMUNICATION_RULE_IDS
)


class DetectionRule(ABC):
    """Base class for a deterministic detection rule."""

    rule_id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    default_severity: ClassVar[Severity] = Severity.INFO
    tags: ClassVar[tuple[str, ...]] = ()

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        """Whether the engine should evaluate this rule."""
        return self._enabled

    @abstractmethod
    def matches(self, event: SecurityEvent) -> bool:
        """Return whether ``event`` satisfies this rule. Must not mutate anything."""

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        """Return the observed facts supporting the match (deterministic)."""
        return {}

    def title(self, event: SecurityEvent) -> str:
        """Return the finding title; defaults to the rule name."""
        return self.name

    def build_finding(self, event: SecurityEvent) -> DetectionFinding:
        """Construct the finding for a matched event."""
        return DetectionFinding(
            finding_id=f"{self.rule_id}:{event.event_id}",
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.default_severity,
            title=self.title(event),
            description=self.description,
            event_id=event.event_id,
            event_type=event.event_type,
            category=event.category,
            timestamp=event.timestamp,
            host_id=event.host.host_id if event.host is not None else None,
            evidence=self.evidence(event),
            tags=self.tags,
        )


class SuspiciousListeningPortRule(DetectionRule):
    """Rule A - a listening TCP endpoint on a configured port."""

    rule_id = RULE_LISTEN_PORT
    name = "Unexpected listening port"
    description = (
        "A listening TCP endpoint was observed on a port in the configured suspicious-port set."
    )
    default_severity = Severity.MEDIUM
    tags = ("host", "port")

    def __init__(self, *, ports: Iterable[int], enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self._ports = frozenset(ports)

    def matches(self, event: SecurityEvent) -> bool:
        if not self._ports or event.event_type is not EventType.PORT_LISTENING:
            return False
        socket = event.socket
        if socket is None or socket.protocol is not TransportProtocol.TCP:
            return False
        return socket.local_port is not None and socket.local_port in self._ports

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        socket = event.socket
        if socket is None:
            return {}
        evidence = {
            "local_port": str(socket.local_port),
            "protocol": socket.protocol.value,
        }
        if socket.local_address:
            evidence["local_address"] = socket.local_address
        process = event.process
        if process is not None:
            if process.pid is not None:
                evidence["pid"] = str(process.pid)
            if process.name:
                evidence["process_name"] = process.name
        return evidence


class SensitiveFileModificationRule(DetectionRule):
    """Rule B - a modification to a configured sensitive path."""

    rule_id = RULE_SENSITIVE_FILE
    name = "Configured sensitive file modified"
    description = "A file matching a configured sensitive-path pattern was modified."
    default_severity = Severity.HIGH
    tags = ("host", "file")

    def __init__(self, *, patterns: Iterable[str], enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self._patterns = tuple(patterns)

    def _match(self, path: str) -> str | None:
        for pattern in self._patterns:
            if fnmatch.fnmatch(path, pattern):
                return pattern
        return None

    def matches(self, event: SecurityEvent) -> bool:
        if not self._patterns or event.event_type is not EventType.FILE_MODIFIED:
            return False
        file = event.file
        if file is None:
            return False
        return self._match(file.path) is not None

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        file = event.file
        if file is None:
            return {}
        evidence = {"path": file.path, "file_type": file.file_type.value}
        matched = self._match(file.path)
        if matched is not None:
            evidence["matched_pattern"] = matched
        if file.hash_status is not None:
            evidence["hash_status"] = file.hash_status.value
        return evidence


class ExecutableCreationRule(DetectionRule):
    """Rule C - an executable-like file created under a monitored directory."""

    rule_id = RULE_EXECUTABLE_CREATION
    name = "Executable file created in monitored location"
    description = (
        "A file with a configured executable-like extension was created under a "
        "configured monitored directory."
    )
    default_severity = Severity.MEDIUM
    tags = ("host", "file", "executable")

    def __init__(
        self,
        *,
        extensions: Iterable[str],
        watch_paths: Iterable[str],
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self._extensions = frozenset(extension.lower() for extension in extensions)
        self._watch_paths = tuple(watch_paths)

    @staticmethod
    def _normcase(path: str) -> str:
        return os.path.normcase(os.path.normpath(path))

    def _watch_root(self, path: str) -> str | None:
        normalized = self._normcase(path)
        for watch in self._watch_paths:
            root = self._normcase(watch)
            if normalized == root or normalized.startswith(root + os.sep):
                return watch
        return None

    def matches(self, event: SecurityEvent) -> bool:
        if not self._extensions or not self._watch_paths:
            return False
        if event.event_type is not EventType.FILE_CREATED:
            return False
        file = event.file
        if file is None or file.file_type is not FileType.REGULAR:
            return False
        extension = os.path.splitext(file.path)[1].lower()
        if extension not in self._extensions:
            return False
        return self._watch_root(file.path) is not None

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        file = event.file
        if file is None:
            return {}
        evidence = {
            "path": file.path,
            "extension": os.path.splitext(file.path)[1].lower(),
        }
        watch = self._watch_root(file.path)
        if watch is not None:
            evidence["watch_path"] = watch
        return evidence


class SuspiciousProcessPathRule(DetectionRule):
    """Rule D - a process started from a configured suspicious path."""

    rule_id = RULE_PROCESS_PATH
    name = "Process launched from configured path"
    description = (
        "A process start event referenced an executable path matching a configured "
        "suspicious-path pattern."
    )
    default_severity = Severity.HIGH
    tags = ("host", "process")

    def __init__(self, *, patterns: Iterable[str], enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self._patterns = tuple(patterns)

    def _match(self, path: str) -> str | None:
        for pattern in self._patterns:
            if fnmatch.fnmatch(path, pattern):
                return pattern
        return None

    def matches(self, event: SecurityEvent) -> bool:
        if not self._patterns or event.event_type is not EventType.PROCESS_STARTED:
            return False
        process = event.process
        if process is None or not process.executable_path:
            return False
        return self._match(process.executable_path) is not None

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        process = event.process
        if process is None or not process.executable_path:
            return {}
        evidence = {"executable_path": process.executable_path}
        matched = self._match(process.executable_path)
        if matched is not None:
            evidence["matched_pattern"] = matched
        if process.pid is not None:
            evidence["pid"] = str(process.pid)
        if process.name:
            evidence["process_name"] = process.name
        return evidence


class SuspiciousNetworkEndpointRule(DetectionRule):
    """Rule E - a network event whose destination is a configured endpoint."""

    rule_id = RULE_NETWORK_ENDPOINT
    name = "Configured suspicious endpoint observed"
    description = (
        "A network telemetry event referenced a destination matching a configured "
        "suspicious endpoint."
    )
    default_severity = Severity.HIGH
    tags = ("network", "endpoint")

    def __init__(
        self, *, endpoints: Iterable[tuple[str, int | None]], enabled: bool = True
    ) -> None:
        super().__init__(enabled=enabled)
        self._endpoints = tuple(endpoints)

    def _match(self, dst_ip: str, dst_port: int | None) -> tuple[str, int | None] | None:
        for ip, port in self._endpoints:
            if dst_ip == ip and (port is None or dst_port == port):
                return (ip, port)
        return None

    def matches(self, event: SecurityEvent) -> bool:
        if not self._endpoints:
            return False
        if event.event_type not in {
            EventType.NETWORK_PACKET_OBSERVED,
            EventType.FLOW_SUMMARY,
        }:
            return False
        network = event.network
        if network is None or not network.dst_ip:
            return False
        return self._match(network.dst_ip, network.dst_port) is not None

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        network = event.network
        if network is None or not network.dst_ip:
            return {}
        evidence = {
            "dst_ip": network.dst_ip,
            "protocol": network.protocol.value,
        }
        if network.dst_port is not None:
            evidence["dst_port"] = str(network.dst_port)
        if network.flow_id:
            evidence["flow_id"] = network.flow_id
        matched = self._match(network.dst_ip, network.dst_port)
        if matched is not None:
            ip, port = matched
            evidence["matched_endpoint"] = ip if port is None else f"{ip}:{port}"
        return evidence


class HighNetworkVolumeRule(DetectionRule):
    """Rule F - unusually high network flow volume within a flow's window.

    Evaluates a single ``NETWORK_FLOW_SUMMARY`` event against explicitly
    configured packet and/or byte thresholds. A flow whose counters are at or
    above a threshold matches. The rule never matches until at least one
    threshold is configured (both default to ``0`` = unconfigured).

    Wording deliberately describes the *observation* ("unusually high network
    traffic volume observed"), not a cause: exceeding a volume threshold is not
    evidence of DDoS, malware or an attack.
    """

    rule_id = RULE_NETWORK_VOLUME
    name = "Unusually high network traffic volume"
    description = (
        "A network flow summary reported packet or byte volume at or above a "
        "configured threshold within its observation window."
    )
    default_severity = Severity.MEDIUM
    tags = ("network", "flow", "volume")

    def __init__(
        self,
        *,
        packet_threshold: int = 0,
        byte_threshold: int = 0,
        enabled: bool = True,
    ) -> None:
        super().__init__(enabled=enabled)
        self._packet_threshold = max(0, packet_threshold)
        self._byte_threshold = max(0, byte_threshold)

    @property
    def configured(self) -> bool:
        """Whether at least one volume threshold has been supplied."""
        return self._packet_threshold > 0 or self._byte_threshold > 0

    def _breach(self, packets: int, byte_count: int) -> tuple[bool, bool]:
        """Return ``(packet_breached, byte_breached)`` for the counters."""
        packet_breached = self._packet_threshold > 0 and packets >= self._packet_threshold
        byte_breached = self._byte_threshold > 0 and byte_count >= self._byte_threshold
        return packet_breached, byte_breached

    def matches(self, event: SecurityEvent) -> bool:
        if not self.configured or event.event_type is not EventType.FLOW_SUMMARY:
            return False
        network = event.network
        if network is None:
            return False
        packet_breached, byte_breached = self._breach(
            network.packets_sent or 0, network.bytes_sent or 0
        )
        return packet_breached or byte_breached

    def evidence(self, event: SecurityEvent) -> dict[str, str]:
        network = event.network
        if network is None:
            return {}
        packets = network.packets_sent or 0
        byte_count = network.bytes_sent or 0
        packet_breached, byte_breached = self._breach(packets, byte_count)

        evidence = {
            "packets_sent": str(packets),
            "bytes_sent": str(byte_count),
        }
        if network.flow_id:
            evidence["flow_id"] = network.flow_id
        evidence["protocol"] = network.protocol.value
        if network.duration_ms is not None:
            evidence["duration_ms"] = str(network.duration_ms)
        if packet_breached:
            evidence["packet_threshold"] = str(self._packet_threshold)
        if byte_breached:
            evidence["byte_threshold"] = str(self._byte_threshold)
        return evidence


def build_default_rules(settings: DetectionSettings) -> tuple[DetectionRule, ...]:
    """Build the standard rule set from configuration.

    Raises:
        ValueError: if ``disabled_rules`` names an unknown rule ID.
    """
    disabled = set(settings.disabled_rules)
    unknown = disabled - KNOWN_RULE_IDS
    if unknown:
        raise ValueError(f"unknown rule id(s) in disabled_rules: {sorted(unknown)}")

    return (
        SuspiciousListeningPortRule(
            ports=settings.suspicious_listen_ports,
            enabled=RULE_LISTEN_PORT not in disabled,
        ),
        SensitiveFileModificationRule(
            patterns=settings.sensitive_file_patterns,
            enabled=RULE_SENSITIVE_FILE not in disabled,
        ),
        ExecutableCreationRule(
            extensions=settings.executable_extensions,
            watch_paths=settings.executable_watch_paths,
            enabled=RULE_EXECUTABLE_CREATION not in disabled,
        ),
        SuspiciousProcessPathRule(
            patterns=settings.suspicious_process_path_patterns,
            enabled=RULE_PROCESS_PATH not in disabled,
        ),
        SuspiciousNetworkEndpointRule(
            endpoints=[parse_endpoint(item) for item in settings.suspicious_network_endpoints],
            enabled=RULE_NETWORK_ENDPOINT not in disabled,
        ),
        HighNetworkVolumeRule(
            packet_threshold=settings.network_volume_packet_threshold,
            byte_threshold=settings.network_volume_byte_threshold,
            enabled=RULE_NETWORK_VOLUME not in disabled,
        ),
    )


__all__ = [
    "ALL_RULE_IDS",
    "BEHAVIOR_RULE_IDS",
    "COMMUNICATION_RULE_IDS",
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
    "DetectionRule",
    "ExecutableCreationRule",
    "HighNetworkVolumeRule",
    "SensitiveFileModificationRule",
    "SuspiciousListeningPortRule",
    "SuspiciousNetworkEndpointRule",
    "SuspiciousProcessPathRule",
    "build_default_rules",
]
