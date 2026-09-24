"""Tests for component configuration safety defaults."""

from __future__ import annotations

from aegis_agent.config import AgentSettings
from aegis_ml_engine.config import MLEngineSettings
from aegis_network_sensor.config import SensorSettings
from aegis_response_engine.config import ResponseEngineSettings
from aegis_shared.enums import ResponseMode


def test_agent_monitors_are_disabled_by_default() -> None:
    settings = AgentSettings()
    assert settings.enabled_monitors == ()


def test_sensor_capture_is_disabled_by_default() -> None:
    settings = SensorSettings(capture_enabled=False, interface="")
    assert settings.capture_enabled is False


def test_ml_defaults_are_within_valid_ranges() -> None:
    settings = MLEngineSettings()
    assert 0.0 < settings.contamination < 0.5
    assert 0.0 <= settings.risk_threshold <= 1.0


def test_response_engine_is_safe_by_default() -> None:
    settings = ResponseEngineSettings()
    assert settings.mode is ResponseMode.MONITOR
    assert settings.dry_run is True
    assert settings.require_approval is True
    assert settings.enforcement_enabled is False


def test_enforcement_requires_enforce_mode_without_dry_run() -> None:
    settings = ResponseEngineSettings(
        mode=ResponseMode.ENFORCE, dry_run=False, require_approval=True
    )
    assert settings.enforcement_enabled is True
