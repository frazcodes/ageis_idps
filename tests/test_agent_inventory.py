"""Tests for the endpoint agent's system inventory and host identity.

Skipped automatically when the optional agent dependencies (psutil) are absent.
No test touches the network or the real user state directory.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("psutil", reason="agent extra not installed")

from aegis_agent.inventory import (
    HOST_ID_FILENAME,
    HostIdentityProvider,
    HostIdSource,
    SystemInventory,
    collect_system_inventory,
    default_state_dir,
)
from aegis_agent.inventory import collector as collector_module
from aegis_shared.enums import Platform

_EXPECTED_FIELDS = {
    "schema_version",
    "host_id",
    "hostname",
    "platform",
    "os_name",
    "os_version",
    "architecture",
    "python_version",
    "agent_version",
    "boot_time",
    "cpu_count",
    "total_memory_bytes",
    "collected_at",
}


def _provider(tmp_path: Path) -> HostIdentityProvider:
    return HostIdentityProvider(state_dir=tmp_path / "state")


def test_collect_returns_required_fields(tmp_path: Path) -> None:
    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))
    assert inventory.host_id
    assert inventory.hostname
    assert inventory.os_name
    assert inventory.architecture
    assert inventory.python_version
    assert inventory.agent_version
    assert isinstance(inventory.platform, Platform)


def test_inventory_exposes_only_expected_fields(tmp_path: Path) -> None:
    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))
    assert set(inventory.to_json_dict()) == _EXPECTED_FIELDS


def test_collected_at_is_timezone_aware_utc(tmp_path: Path) -> None:
    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))
    assert inventory.collected_at.tzinfo is not None
    assert inventory.collected_at.utcoffset() == timedelta(0)


def test_injected_timestamp_is_normalised_to_utc(tmp_path: Path) -> None:
    plus_two = timezone(timedelta(hours=2))
    inventory = collect_system_inventory(
        identity_provider=_provider(tmp_path),
        collected_at=datetime(2026, 1, 1, 12, 0, tzinfo=plus_two),
    )
    assert inventory.collected_at.utcoffset() == timedelta(0)
    assert inventory.collected_at.hour == 10


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        SystemInventory(
            host_id="host-1",
            hostname="ws-01",
            os_name="Windows",
            architecture="AMD64",
            python_version="3.14.3",
            agent_version="0.1.0",
            collected_at=datetime(2026, 1, 1, 12, 0),
        )


def test_json_serialization_round_trip(tmp_path: Path) -> None:
    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))

    text = json.dumps(inventory.to_json_dict())
    restored = SystemInventory.model_validate(json.loads(text))

    assert restored == inventory
    assert restored.collected_at == inventory.collected_at


def test_host_id_is_stable_across_collections(tmp_path: Path) -> None:
    provider = _provider(tmp_path)
    first = collect_system_inventory(identity_provider=provider)
    second = collect_system_inventory(identity_provider=provider)
    assert first.host_id == second.host_id


def test_host_id_is_persisted_to_state_file(tmp_path: Path) -> None:
    provider = _provider(tmp_path)
    inventory = collect_system_inventory(identity_provider=provider)

    assert provider.state_path.exists()
    assert provider.state_path.read_text(encoding="utf-8").strip() == inventory.host_id


def test_second_resolution_uses_persisted_identity(tmp_path: Path) -> None:
    provider = _provider(tmp_path)
    assert provider.resolve().source is HostIdSource.GENERATED
    assert provider.resolve().source is HostIdSource.PERSISTED


def test_configured_id_is_used_without_persistence(tmp_path: Path) -> None:
    provider = HostIdentityProvider(state_dir=tmp_path / "state", configured_id="host-configured")

    identity = provider.resolve()

    assert identity.host_id == "host-configured"
    assert identity.source is HostIdSource.CONFIGURED
    assert not provider.state_path.exists()


def test_blank_configured_id_falls_back_to_persistence(tmp_path: Path) -> None:
    provider = HostIdentityProvider(state_dir=tmp_path / "state", configured_id="   ")
    assert provider.resolve().source is HostIdSource.GENERATED


@pytest.mark.parametrize("corrupt_content", ["   \n", "x" * 200])
def test_corrupt_state_file_is_regenerated(tmp_path: Path, corrupt_content: str) -> None:
    provider = _provider(tmp_path)
    provider.state_path.parent.mkdir(parents=True, exist_ok=True)
    provider.state_path.write_text(corrupt_content, encoding="utf-8")

    identity = provider.resolve()

    assert identity.source is HostIdSource.GENERATED
    assert identity.host_id


def test_unavailable_psutil_fields_degrade_to_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module, "_boot_time", lambda: None)
    monkeypatch.setattr(collector_module, "_cpu_count", lambda: None)
    monkeypatch.setattr(collector_module, "_total_memory_bytes", lambda: None)

    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))

    assert inventory.boot_time is None
    assert inventory.cpu_count is None
    assert inventory.total_memory_bytes is None


def test_unavailable_platform_fields_degrade_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module, "_hostname", lambda: "unknown-host")
    monkeypatch.setattr(collector_module, "_os_name", lambda: "unknown")
    monkeypatch.setattr(collector_module, "_os_version", lambda: None)
    monkeypatch.setattr(collector_module, "_architecture", lambda: "unknown")

    inventory = collect_system_inventory(identity_provider=_provider(tmp_path))

    assert inventory.hostname == "unknown-host"
    assert inventory.os_name == "unknown"
    assert inventory.os_version is None
    assert inventory.architecture == "unknown"


@pytest.mark.parametrize(
    ("sys_platform", "expected"),
    [
        ("win32", Platform.WINDOWS),
        ("linux", Platform.LINUX),
        ("darwin", Platform.MACOS),
        ("aix", Platform.UNKNOWN),
    ],
)
def test_platform_detection(
    sys_platform: str, expected: Platform, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(collector_module.sys, "platform", sys_platform)
    assert collector_module._detect_platform() is expected


def test_default_state_dir_is_absolute_and_namespaced() -> None:
    state_dir = default_state_dir()
    assert state_dir.is_absolute()
    assert any(part.lower() in {"aegis", "agent"} for part in state_dir.parts)


def test_state_path_uses_expected_filename(tmp_path: Path) -> None:
    assert _provider(tmp_path).state_path.name == HOST_ID_FILENAME
