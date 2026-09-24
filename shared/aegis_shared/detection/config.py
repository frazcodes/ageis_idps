"""Typed configuration for the deterministic detection engine.

Every "suspicious" criterion is **configuration-driven** and defaults to empty:
Aegis never ships hard-coded malicious ports, IPs, paths or extensions, and never
scans the system by itself. A rule with empty criteria simply never matches.

Environment prefix: ``AEGIS_DETECTION_`` (list fields accept comma-separated
values).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings

#: Small, configurable default set of executable-like extensions (Rule C).
DEFAULT_EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
)

_LIST_FIELDS = (
    "disabled_rules",
    "suspicious_listen_ports",
    "sensitive_file_patterns",
    "executable_extensions",
    "executable_watch_paths",
    "suspicious_process_path_patterns",
    "suspicious_network_endpoints",
)


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid port {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range (1-65535): {port}")
    return port


def normalize_endpoint(value: str) -> str:
    """Normalize an ``ip`` or ``ip:port`` endpoint, validating the IP.

    Accepts IPv4 (``203.0.113.9``, ``203.0.113.9:4444``) and IPv6
    (``2001:db8::1``, ``[2001:db8::1]:4444``). Raises ``ValueError`` otherwise.
    """
    raw = value.strip()
    if not raw:
        raise ValueError("endpoint must be non-empty")

    host = raw
    port: int | None = None

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"invalid endpoint {value!r}: missing ']'")
        host = raw[1:end]
        remainder = raw[end + 1 :]
        if remainder.startswith(":"):
            port = _parse_port(remainder[1:])
        elif remainder:
            raise ValueError(f"invalid endpoint {value!r}")
    elif raw.count(":") == 1:
        left, right = raw.split(":", 1)
        if _is_ipv4(left):
            host = left
            port = _parse_port(right)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"invalid endpoint {value!r}: {exc}") from exc

    if port is None:
        return str(ip)
    return f"{ip}:{port}" if ip.version == 4 else f"[{ip}]:{port}"


def parse_endpoint(value: str) -> tuple[str, int | None]:
    """Split a normalized endpoint back into ``(ip, port | None)``."""
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end]
        remainder = value[end + 1 :]
        port = int(remainder[1:]) if remainder.startswith(":") else None
        return host, port
    if value.count(":") == 1:
        host, port_text = value.split(":", 1)
        return host, int(port_text)
    return value, None


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


class DetectionSettings(AegisSettings):
    """Criteria and switches for the detection engine."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_DETECTION_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(default=True, description="Master switch for rule evaluation.")

    disabled_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs to disable. Unknown IDs are rejected when rules are built.",
    )

    # --- Rule A: unexpected listening port -------------------------------
    suspicious_listen_ports: list[int] = Field(
        default_factory=list,
        description="TCP listening ports to flag. Empty = rule never matches.",
    )

    # --- Rule B: sensitive file modification -----------------------------
    sensitive_file_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns for sensitive paths. Empty = rule never matches.",
    )

    # --- Rule C: executable creation -------------------------------------
    executable_extensions: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXECUTABLE_EXTENSIONS),
        description="Executable-like extensions for created-file detection.",
    )
    executable_watch_paths: list[str] = Field(
        default_factory=list,
        description="Directories to watch for executable creation. Empty = rule never matches.",
    )

    # --- Rule D: process launched from configured path -------------------
    suspicious_process_path_patterns: list[str] = Field(
        default_factory=list,
        description="Glob patterns for process executable paths. Empty = rule never matches.",
    )

    # --- Rule E: configured suspicious endpoint --------------------------
    suspicious_network_endpoints: list[str] = Field(
        default_factory=list,
        description="Destination IPs or ip:port endpoints to flag. Empty = rule never matches.",
    )

    # --- Rule F: unusually high network flow volume ----------------------
    # Both default to 0, meaning "not configured": the rule never matches until
    # an operator supplies an explicit threshold.
    network_volume_packet_threshold: int = Field(
        default=0,
        ge=0,
        description="Flow packet count at or above which to flag. 0 disables the check.",
    )
    network_volume_byte_threshold: int = Field(
        default=0,
        ge=0,
        description="Flow byte count at or above which to flag. 0 disables the check.",
    )

    # --- Behavioral network rules (AEGIS-NET-003 .. AEGIS-NET-006) --------
    # Thresholds default to 0 = disabled, so normal low-volume traffic never
    # produces findings. Windows are in seconds and bounded.
    network_flow_burst_threshold: int = Field(
        default=0,
        ge=0,
        description="Distinct flows within the window at or above which to flag. 0 disables.",
    )
    network_flow_burst_window_seconds: int = Field(
        default=60, ge=1, le=86400, description="Flow-burst observation window."
    )
    network_repeated_comm_threshold: int = Field(
        default=0,
        ge=0,
        description="Repeated flows between one src/dst pair at/above which to flag. 0 disables.",
    )
    network_repeated_comm_window_seconds: int = Field(
        default=60, ge=1, le=86400, description="Repeated-communication observation window."
    )
    network_destination_fanout_threshold: int = Field(
        default=0,
        ge=0,
        description="Distinct destinations from one source at or above which to flag. 0 disables.",
    )
    network_destination_fanout_window_seconds: int = Field(
        default=60, ge=1, le=86400, description="Destination-fan-out observation window."
    )
    network_destination_port_breadth_threshold: int = Field(
        default=0,
        ge=0,
        description="Distinct destination ports from one source at/above which to flag. 0=off.",
    )
    network_destination_port_breadth_window_seconds: int = Field(
        default=60, ge=1, le=86400, description="Destination-port-breadth observation window."
    )

    # --- Multi-signal suspicious-communication analysis (AEGIS-NET-007) ----
    network_communication_min_signals: int = Field(
        default=2,
        ge=2,
        le=7,
        description=(
            "Minimum number of independent signals required before a suspicious-"
            "communication finding is produced."
        ),
    )
    network_communication_max_findings: int = Field(
        default=256,
        ge=1,
        le=100_000,
        description="Maximum suspicious-communication findings produced per analysis.",
    )

    @field_validator(*_LIST_FIELDS, mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept a comma-separated string from the environment as well as a list."""
        if isinstance(value, str):
            raw = value.strip()
            if not raw or raw.startswith("["):
                return value if raw else []
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value

    @field_validator("suspicious_listen_ports")
    @classmethod
    def _valid_ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range (1-65535): {port}")
        return sorted(set(value))

    @field_validator("executable_extensions")
    @classmethod
    def _normalize_extensions(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        for extension in value:
            text = extension.strip().lower()
            if not text:
                continue
            normalized.append(text if text.startswith(".") else f".{text}")
        return sorted(set(normalized))

    @field_validator("suspicious_network_endpoints")
    @classmethod
    def _normalize_endpoints(cls, value: list[str]) -> list[str]:
        return sorted({normalize_endpoint(item) for item in value})

    @field_validator(
        "sensitive_file_patterns",
        "executable_watch_paths",
        "suspicious_process_path_patterns",
    )
    @classmethod
    def _clean_patterns(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item.strip()]

    @field_validator("disabled_rules")
    @classmethod
    def _clean_disabled(cls, value: list[str]) -> list[str]:
        return sorted({item.strip() for item in value if item.strip()})


@lru_cache(maxsize=1)
def get_detection_settings() -> DetectionSettings:
    """Return the process-wide detection settings (loaded once)."""
    return DetectionSettings()


__all__ = [
    "DEFAULT_EXECUTABLE_EXTENSIONS",
    "DetectionSettings",
    "get_detection_settings",
    "normalize_endpoint",
    "parse_endpoint",
]
