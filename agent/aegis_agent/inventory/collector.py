"""Collect a :class:`SystemInventory` from the local machine.

Collection is read-only and best-effort: any single platform probe that fails
(restricted container, unusual OS, denied API) degrades to ``None`` rather than
aborting the whole inventory. This keeps the agent useful on heterogeneous
fleets.

Only non-sensitive technical facts are read. See
:mod:`aegis_agent.inventory.models` for the exact field set.
"""

from __future__ import annotations

import platform as platform_module
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import psutil

from aegis_agent.config import get_agent_settings
from aegis_agent.inventory.identity import HostIdentityProvider
from aegis_agent.inventory.models import SystemInventory
from aegis_shared.enums import Platform
from aegis_shared.logging import get_logger
from aegis_shared.version import __version__

logger = get_logger(__name__)

#: Mapping from :data:`sys.platform` values to the shared :class:`Platform` enum.
_PLATFORM_BY_SYS: dict[str, Platform] = {
    "win32": Platform.WINDOWS,
    "linux": Platform.LINUX,
    "darwin": Platform.MACOS,
}


def _detect_platform() -> Platform:
    """Map the running interpreter's platform onto the shared vocabulary."""
    return _PLATFORM_BY_SYS.get(sys.platform, Platform.UNKNOWN)


def _hostname() -> str:
    try:
        name = socket.gethostname().strip()
    except OSError as exc:
        logger.debug("Hostname unavailable: %s", exc)
        name = ""
    return name or "unknown-host"


def _os_name() -> str:
    try:
        name = platform_module.system().strip()
    except Exception as exc:
        logger.debug("OS name unavailable: %s", exc)
        name = ""
    return name or "unknown"


def _os_version() -> str | None:
    try:
        version = (platform_module.version() or platform_module.release() or "").strip()
    except Exception as exc:
        logger.debug("OS version unavailable: %s", exc)
        return None
    return version or None


def _architecture() -> str:
    try:
        machine = platform_module.machine().strip()
    except Exception as exc:
        logger.debug("Architecture unavailable: %s", exc)
        machine = ""
    return machine or "unknown"


def _python_version() -> str:
    try:
        return platform_module.python_version()
    except Exception as exc:
        logger.debug("Python version unavailable: %s", exc)
        return "unknown"


def _boot_time() -> datetime | None:
    try:
        return datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
    except Exception as exc:
        logger.debug("Boot time unavailable: %s", exc)
        return None


def _cpu_count() -> int | None:
    try:
        return psutil.cpu_count(logical=True)
    except Exception as exc:
        logger.debug("CPU count unavailable: %s", exc)
        return None


def _total_memory_bytes() -> int | None:
    try:
        return int(psutil.virtual_memory().total)
    except Exception as exc:
        logger.debug("Total memory unavailable: %s", exc)
        return None


def _default_identity_provider() -> HostIdentityProvider:
    """Build the identity provider from agent configuration."""
    settings = get_agent_settings()
    state_dir = Path(settings.state_dir) if settings.state_dir else None
    return HostIdentityProvider(state_dir=state_dir, configured_id=settings.agent_id)


def collect_system_inventory(
    *,
    identity_provider: HostIdentityProvider | None = None,
    collected_at: datetime | None = None,
) -> SystemInventory:
    """Collect the local system inventory.

    Args:
        identity_provider: Overrides identity resolution. Defaults to the
            configured/persisted provider; tests inject a temporary one.
        collected_at: Overrides the collection timestamp (must be timezone-aware).
            Defaults to the current UTC time.

    Returns:
        A validated, immutable :class:`SystemInventory`.
    """
    provider = identity_provider or _default_identity_provider()
    identity = provider.resolve()

    inventory = SystemInventory(
        host_id=identity.host_id,
        hostname=_hostname(),
        platform=_detect_platform(),
        os_name=_os_name(),
        os_version=_os_version(),
        architecture=_architecture(),
        python_version=_python_version(),
        agent_version=__version__,
        boot_time=_boot_time(),
        cpu_count=_cpu_count(),
        total_memory_bytes=_total_memory_bytes(),
        collected_at=collected_at or datetime.now(UTC),
    )
    logger.debug("Collected system inventory for host %s", inventory.host_id)
    return inventory


__all__ = ["collect_system_inventory"]
