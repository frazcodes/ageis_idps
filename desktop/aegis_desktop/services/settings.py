"""Settings adapter: existing Aegis configuration -> read-only UI data.

Strictly read-only. It reads the real configuration objects that already exist in
the project and shapes selected, safe fields into label/value rows for display.

It never writes configuration, never starts a monitor, capture, detection, risk
evaluation, ML or response, and never exposes secrets (only explicitly chosen,
non-sensitive fields are surfaced - no ``repr``/``vars``/``__dict__`` dumps).

Runtime status is read from the existing registries (event pipeline, detection,
risk) only; no new runtime infrastructure is created. All imports are lazy so
that constructing the page (or importing the application) loads no security
runtime modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Non-sensitive message shown when configuration cannot be read.
SETTINGS_ERROR = "Unable to read configuration"
#: Placeholder for an unavailable/empty value.
MISSING = "—"
#: Runtime state when a component is not published/running.
NOT_RUNNING = "Not running"


@dataclass(frozen=True)
class ConfigField:
    """One read-only configuration row."""

    label: str
    value: str


@dataclass(frozen=True)
class ConfigSection:
    """A titled group of read-only configuration rows."""

    title: str
    fields: tuple[ConfigField, ...] = ()


@dataclass(frozen=True)
class SettingsView:
    """Read-only snapshot of configuration and security posture."""

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: tuple[ConfigField, ...] = field(default_factory=tuple)
    sections: tuple[ConfigSection, ...] = field(default_factory=tuple)

    def value_for(self, section: str, label: str) -> str | None:
        """Return the value of ``label`` within the named section, if present."""
        for entry in self.sections:
            if entry.title == section:
                for config_field in entry.fields:
                    if config_field.label == label:
                        return config_field.value
        return None

    def posture_value(self, label: str) -> str | None:
        """Return the value of a security-posture ``label``, if present."""
        for config_field in self.posture:
            if config_field.label == label:
                return config_field.value
        return None

    def section_titles(self) -> tuple[str, ...]:
        """Return the titles of the configuration sections."""
        return tuple(entry.title for entry in self.sections)


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _enabled_disabled(value: bool) -> str:
    return "Enabled" if value else "Disabled"


def _text(value: str | None) -> str:
    if value is None:
        return MISSING
    stripped = value.strip()
    return stripped or MISSING


def _items(values: list[str]) -> str:
    cleaned = [item for item in values if item and item.strip()]
    return ", ".join(cleaned) if cleaned else MISSING


def _ports(values: list[int]) -> str:
    return ", ".join(str(port) for port in values) if values else MISSING


def _runtime_state(getter: Any) -> str:
    """Safely call a registry getter, returning a runtime state string."""
    try:
        return NOT_RUNNING if getter() is None else "Running"
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Runtime registry read failed: %s", exc)
        return "Unknown"


def _posture(
    agent: Any,
    sensor: Any,
    detection: Any,
    risk: Any,
    response: Any,
) -> tuple[ConfigField, ...]:
    enabled = agent.enabled_monitors
    return (
        ConfigField("Agent Monitoring", _enabled_disabled(bool(enabled))),
        ConfigField("Network Capture", _enabled_disabled(sensor.capture_enabled)),
        ConfigField(
            "File Integrity Monitoring",
            _enabled_disabled(agent.enable_file_integrity),
        ),
        ConfigField(
            "Detection Engine",
            _enabled_disabled(detection.enabled),
        ),
        ConfigField("Detection Runtime", _runtime_state(_detection_running)),
        ConfigField("Risk Engine", _runtime_state(_risk_running)),
        ConfigField("Response Mode", response.mode.value),
        ConfigField("Dry Run", _enabled_disabled(response.dry_run)),
        ConfigField("Approval Required", _yes_no(response.require_approval)),
    )


def _detection_running() -> Any:
    from aegis_shared.detection import get_active_engine

    return get_active_engine()


def _risk_running() -> Any:
    from aegis_shared.risk import get_active_risk_engine

    return get_active_risk_engine()


def _pipeline_running() -> Any:
    from aegis_shared.pipeline import get_active_pipeline

    return get_active_pipeline()


def _agent_sections(agent: Any) -> tuple[ConfigSection, ...]:
    monitors = ConfigSection(
        "Monitors (configuration)",
        (
            ConfigField("Process Monitoring", _enabled_disabled(agent.enable_process_monitor)),
            ConfigField("Port Monitoring", _enabled_disabled(agent.enable_port_monitor)),
            ConfigField(
                "Connection Monitoring", _enabled_disabled(agent.enable_connection_monitor)
            ),
            ConfigField(
                "File Integrity Monitoring", _enabled_disabled(agent.enable_file_integrity)
            ),
            ConfigField("YARA Scanning", _enabled_disabled(agent.enable_yara)),
        ),
    )
    agent_section = ConfigSection(
        "Agent",
        (
            ConfigField("Agent ID", _text(agent.agent_id)),
            ConfigField("Backend URL", _text(agent.backend_url)),
            ConfigField("Heartbeat Interval", f"{agent.heartbeat_interval}s"),
            ConfigField("Event Buffer Capacity", str(agent.event_buffer_max_events)),
        ),
    )
    return (agent_section, monitors)


def _file_integrity_section(agent: Any) -> ConfigSection:
    paths = agent.file_integrity_paths
    return ConfigSection(
        "File Integrity",
        (
            ConfigField("Enabled", _enabled_disabled(agent.enable_file_integrity)),
            ConfigField("Configured Paths", str(len(paths))),
            ConfigField("Paths", _items(paths)),
            ConfigField("Poll Interval", f"{agent.file_integrity_interval}s"),
            ConfigField("Maximum Hash Bytes", str(agent.file_integrity_max_hash_bytes)),
            ConfigField("Symlink Policy", agent.file_integrity_symlink_policy.value),
        ),
    )


def _network_section(sensor: Any) -> ConfigSection:
    return ConfigSection(
        "Network Sensor",
        (
            ConfigField("Capture Enabled", _enabled_disabled(sensor.capture_enabled)),
            ConfigField("Interface", _text(sensor.interface)),
            ConfigField("Promiscuous", _yes_no(sensor.promiscuous)),
            ConfigField("Capture Filter", _text(sensor.capture_filter)),
            ConfigField("Max Packets / Run", str(sensor.max_packets_per_run)),
            ConfigField("Max Packet Bytes", str(sensor.max_packet_bytes)),
            ConfigField("Local Addresses", _items(sensor.local_addresses)),
            ConfigField("Flow Window", f"{sensor.flow_window_seconds}s"),
        ),
    )


def _detection_section(detection: Any) -> ConfigSection:
    engine_running = _detection_running() is not None
    rule_count = str(len(_detection_rules())) if engine_running else "Not connected"
    return ConfigSection(
        "Detection",
        (
            ConfigField("Enabled", _enabled_disabled(detection.enabled)),
            ConfigField("Rule Count", rule_count),
            ConfigField("Disabled Rules", _items(detection.disabled_rules)),
            ConfigField("Suspicious Listen Ports", _ports(detection.suspicious_listen_ports)),
            ConfigField("Sensitive File Patterns", _items(detection.sensitive_file_patterns)),
            ConfigField("Executable Extensions", _items(detection.executable_extensions)),
            ConfigField("Executable Watch Paths", _items(detection.executable_watch_paths)),
            ConfigField(
                "Suspicious Process Paths",
                _items(detection.suspicious_process_path_patterns),
            ),
            ConfigField(
                "Suspicious Endpoints",
                _items(detection.suspicious_network_endpoints),
            ),
        ),
    )


def _detection_rules() -> tuple[Any, ...]:
    from aegis_shared.detection import get_active_engine

    engine = get_active_engine()
    return engine.rules if engine is not None else ()


def _risk_section(risk: Any) -> ConfigSection:
    weights = risk.severity_weights
    return ConfigSection(
        "Risk",
        (
            ConfigField("Scoring Version", _text(risk.scoring_version)),
            ConfigField(
                "Severity Weights (info/low/med/high/crit)",
                "/".join(str(weights[level]) for level in _severity_order()),
            ),
            ConfigField(
                "Thresholds (low/med/high/crit)",
                f"{risk.threshold_low}/{risk.threshold_medium}/"
                f"{risk.threshold_high}/{risk.threshold_critical}",
            ),
            ConfigField(
                "Max Contribution / Finding",
                str(risk.max_contribution_per_finding),
            ),
        ),
    )


def _severity_order() -> tuple[Any, ...]:
    from aegis_shared.enums import Severity

    return (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def _response_section(response: Any) -> ConfigSection:
    return ConfigSection(
        "Response Safety",
        (
            ConfigField("Mode", response.mode.value),
            ConfigField("Dry Run", _enabled_disabled(response.dry_run)),
            ConfigField("Approval Required", _yes_no(response.require_approval)),
            ConfigField("Enforcement Enabled", _yes_no(response.enforcement_enabled)),
        ),
    )


def _ml_section(ml: Any) -> ConfigSection:
    return ConfigSection(
        "ML / Anomaly",
        (
            ConfigField("Model Directory", _text(ml.model_dir)),
            ConfigField("Contamination", str(ml.contamination)),
            ConfigField("Risk Threshold", str(ml.risk_threshold)),
        ),
    )


def _runtime_section() -> ConfigSection:
    return ConfigSection(
        "Runtime Status",
        (
            ConfigField("Event Pipeline", _runtime_state(_pipeline_running)),
            ConfigField("Detection Engine", _runtime_state(_detection_running)),
            ConfigField("Risk Engine", _runtime_state(_risk_running)),
        ),
    )


def collect_settings_view(
    *,
    agent_settings: Any | None = None,
    sensor_settings: Any | None = None,
    detection_settings: Any | None = None,
    risk_settings: Any | None = None,
    response_settings: Any | None = None,
    ml_settings: Any | None = None,
    collected_at: datetime | None = None,
) -> SettingsView:
    """Read the existing configuration and build a read-only view.

    Every settings object defaults to the project's real settings loaded lazily;
    tests may inject overrides. Nothing is started or modified.
    """
    try:
        if agent_settings is None:
            from aegis_agent.config import get_agent_settings

            agent_settings = get_agent_settings()
        if sensor_settings is None:
            from aegis_network_sensor.config import get_sensor_settings

            sensor_settings = get_sensor_settings()
        if detection_settings is None:
            from aegis_shared.detection import get_detection_settings

            detection_settings = get_detection_settings()
        if risk_settings is None:
            from aegis_shared.risk import get_risk_settings

            risk_settings = get_risk_settings()
        if response_settings is None:
            from aegis_response_engine.config import get_response_settings

            response_settings = get_response_settings()
        if ml_settings is None:
            from aegis_ml_engine.config import get_ml_settings

            ml_settings = get_ml_settings()

        posture = _posture(
            agent_settings,
            sensor_settings,
            detection_settings,
            risk_settings,
            response_settings,
        )
        sections = (
            *_agent_sections(agent_settings),
            _file_integrity_section(agent_settings),
            _network_section(sensor_settings),
            _detection_section(detection_settings),
            _risk_section(risk_settings),
            _response_section(response_settings),
            _ml_section(ml_settings),
            _runtime_section(),
        )
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Reading configuration failed: %s", exc)
        return SettingsView(available=False, error=SETTINGS_ERROR, collected_at=None)

    return SettingsView(
        available=True,
        error=None,
        collected_at=collected_at or datetime.now(UTC),
        posture=posture,
        sections=sections,
    )


__all__ = [
    "MISSING",
    "NOT_RUNNING",
    "SETTINGS_ERROR",
    "ConfigField",
    "ConfigSection",
    "SettingsView",
    "collect_settings_view",
]
