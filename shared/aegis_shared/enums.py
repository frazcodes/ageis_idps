"""Closed vocabularies shared by every Aegis IDPS component.

Enums are `str`-valued so they serialise to stable, human-readable tokens in JSON,
PostgreSQL and the SOC dashboard. Values are part of the public contract: **append,
never rename**, and bump ``EVENT_SCHEMA_VERSION`` when the meaning of a value changes.
"""

from __future__ import annotations

from enum import StrEnum


class EventCategory(StrEnum):
    """Which subsystem produced the observation."""

    HOST = "host"
    NETWORK = "network"
    DETECTION = "detection"
    CORRELATION = "correlation"
    RESPONSE = "response"
    SYSTEM = "system"


class EventType(StrEnum):
    """Fine-grained event type.

    Naming convention: ``<DOMAIN>_<OBSERVATION>``. The domain prefix mirrors
    :class:`EventCategory` so the two can be cross-validated cheaply.
    """

    # --- Host / endpoint agent -------------------------------------------
    PROCESS_STARTED = "host.process.started"
    PROCESS_STOPPED = "host.process.stopped"
    PORT_LISTENING = "host.port.listening"
    PORT_CLOSED = "host.port.closed"
    CONNECTION_OPENED = "host.connection.opened"
    CONNECTION_CLOSED = "host.connection.closed"
    FILE_CREATED = "host.file.created"
    FILE_MODIFIED = "host.file.modified"
    FILE_DELETED = "host.file.deleted"
    INTEGRITY_VIOLATION = "host.integrity.violation"
    YARA_MATCH = "host.yara.match"
    SYSTEM_INVENTORY = "host.system.inventory"

    # --- Network sensor ---------------------------------------------------
    #: A single passively observed packet, normalized for later analysis.
    NETWORK_PACKET_OBSERVED = "network.packet.observed"
    FLOW_SUMMARY = "network.flow.summary"
    PORT_SCAN_SUSPECTED = "network.scan.suspected"
    BRUTE_FORCE_SUSPECTED = "network.bruteforce.suspected"
    DOS_SUSPECTED = "network.dos.suspected"
    SUSPICIOUS_EGRESS = "network.egress.suspicious"
    DNS_ANOMALY = "network.dns.anomaly"

    # --- Detection / ML engine -------------------------------------------
    ANOMALY_DETECTED = "detection.anomaly"
    RISK_SCORED = "detection.risk.scored"
    THREAT_INTEL_MATCH = "detection.threatintel.match"

    # --- Correlation engine ----------------------------------------------
    INCIDENT_OPENED = "correlation.incident.opened"
    INCIDENT_UPDATED = "correlation.incident.updated"
    INCIDENT_CLOSED = "correlation.incident.closed"

    # --- Response / IPS engine -------------------------------------------
    RESPONSE_PROPOSED = "response.action.proposed"
    RESPONSE_APPROVED = "response.action.approved"
    RESPONSE_DENIED = "response.action.denied"
    RESPONSE_EXECUTED = "response.action.executed"
    RESPONSE_FAILED = "response.action.failed"
    RESPONSE_ROLLED_BACK = "response.action.rolled_back"

    # --- Platform ---------------------------------------------------------
    AGENT_HEARTBEAT = "system.agent.heartbeat"
    SENSOR_HEARTBEAT = "system.sensor.heartbeat"
    AUDIT_RECORD = "system.audit.record"


class Severity(StrEnum):
    """Normalised severity. Ordered from least to most urgent."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for comparisons and thresholding (``INFO`` = 0)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class SourceKind(StrEnum):
    """What kind of component emitted the event."""

    AGENT = "agent"
    SENSOR = "sensor"
    BACKEND = "backend"
    ML_ENGINE = "ml_engine"
    RESPONSE_ENGINE = "response_engine"
    CORRELATOR = "correlator"


class Platform(StrEnum):
    """Host operating system family. Keeps Windows and Linux agents on one schema."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class NetworkDirection(StrEnum):
    """Direction of a flow relative to the monitored host."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"
    UNKNOWN = "unknown"


class TransportProtocol(StrEnum):
    """Transport protocol of an observed connection or flow."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class AddressFamily(StrEnum):
    """Network address family of a socket endpoint.

    Kept separate from the OS ``AF_*`` constants so the value is portable and
    stable in JSON, PostgreSQL and the dashboard.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    UNIX = "unix"
    OTHER = "other"
    UNKNOWN = "unknown"


class FileType(StrEnum):
    """Kind of filesystem object observed at a path."""

    REGULAR = "regular"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


class HashStatus(StrEnum):
    """Why a content hash is (or is not) available for a file.

    A missing hash is never treated as "unchanged": the reason is recorded so
    downstream consumers can decide how much to trust the observation.
    """

    HASHED = "hashed"
    #: File exceeded the configured maximum size and was not hashed.
    SKIPPED_SIZE = "skipped_size"
    PERMISSION_DENIED = "permission_denied"
    #: Object kind that cannot be hashed (e.g. a device or FIFO).
    UNSUPPORTED = "unsupported"
    #: Transient filesystem/read error.
    ERROR = "error"
    #: Hashing does not apply (e.g. a directory or a reported symlink).
    NOT_APPLICABLE = "not_applicable"


class AlertStatus(StrEnum):
    """Lifecycle of an alert."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class IncidentStatus(StrEnum):
    """Lifecycle of an incident (a correlated group of alerts)."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IndicatorType(StrEnum):
    """Observable indicator types the threat-intelligence layer can match.

    Only types Aegis telemetry can actually provide are listed: IP addresses
    (``NetworkContext`` src/dst), domains (``NetworkContext.domain``) and file
    hashes (``FileContext``/``ProcessContext.hashes``). URLs are not present in
    telemetry today and are deliberately omitted; add a value here when a
    producer can supply them.
    """

    IP = "ip"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"


class ResponseMode(StrEnum):
    """Operating mode of the response engine.

    ``MONITOR`` is the only mode enabled by default; nothing on a host is modified.
    """

    MONITOR = "monitor"
    DRY_RUN = "dry_run"
    ENFORCE = "enforce"


class ActionType(StrEnum):
    """Response actions the IPS layer may perform.

    Ordered from least to most invasive. ``HOST_ISOLATE`` is intentionally the last
    resort and must always be gated by an explicit policy rule.
    """

    LOG_ONLY = "log_only"
    NOTIFY = "notify"
    RATE_LIMIT = "rate_limit"
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    BLOCK_PORT = "block_port"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    HOST_ISOLATE = "host_isolate"
    HOST_RESTORE = "host_restore"


class ActionStatus(StrEnum):
    """Lifecycle of a single response action."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class RiskBand(StrEnum):
    """Bucketed interpretation of a 0-1 risk score, used for UI colouring and routing."""

    NEGLIGIBLE = "negligible"
    LOW = "low"
    ELEVATED = "elevated"
    HIGH = "high"
    SEVERE = "severe"


class RiskLevel(StrEnum):
    """Risk level of a deterministic 0-100 assessment.

    This is the standalone assessment vocabulary produced by the risk engine. It
    is distinct from :class:`RiskBand`, which buckets the 0-1 score embedded in a
    :class:`aegis_shared.events.RiskAssessment` context block. A level describes
    the configured assessment, never a confirmed compromise.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


__all__ = [
    "ActionStatus",
    "ActionType",
    "AddressFamily",
    "AlertStatus",
    "EventCategory",
    "EventType",
    "FileType",
    "HashStatus",
    "IncidentStatus",
    "IndicatorType",
    "NetworkDirection",
    "Platform",
    "ResponseMode",
    "RiskBand",
    "RiskLevel",
    "Severity",
    "SourceKind",
    "TransportProtocol",
]
