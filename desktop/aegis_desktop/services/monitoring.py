"""Monitoring controller: drives the single :class:`AegisRuntime` from the GUI.

The desktop console owns exactly one runtime and drives it from a single Qt
timer. This controller is the thin adapter between the window's Start/Stop
control and the existing :class:`~aegis_runtime.AegisRuntime`: it constructs the
runtime lazily (so opening the application loads no security engine), starts and
stops it, runs one bounded ``poll_once`` per tick, and reports the real network
capture state.

It never captures packets itself, never duplicates the runtime loop, never
fabricates telemetry and never performs a response.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_runtime import AegisRuntime

logger = get_logger(__name__)

#: Non-sensitive message shown when monitoring could not be started.
MONITORING_START_ERROR = "Monitoring could not be started"

#: Capture state vocabulary (mirrors the runtime's honest reporting).
CAPTURE_INACTIVE = "inactive"
CAPTURE_ACTIVE = "active"
CAPTURE_ERROR = "error"

#: Default UI poll interval (ms). Small but not busy.
DEFAULT_POLL_INTERVAL_MS = 2000


@dataclass(frozen=True)
class NetworkCounters:
    """Real network counters, or ``None`` when the metric is unavailable."""

    packets: int | None
    bytes: int | None
    flows: int | None
    active_flows: int | None


@dataclass(frozen=True)
class MonitoringStatus:
    """Read-only snapshot of the runtime and network capture state."""

    running: bool
    capture_state: str
    capture_error: str | None
    interface: str | None
    counters: NetworkCounters
    start_error: str | None = None


def _empty_counters() -> NetworkCounters:
    return NetworkCounters(packets=None, bytes=None, flows=None, active_flows=None)


def _counters_from_runtime(runtime: AegisRuntime) -> NetworkCounters:
    """Derive counters from real flow telemetry; ``None`` when unavailable."""
    if getattr(runtime, "network_sensor", None) is None:
        return _empty_counters()
    flows = runtime.network_flows
    packets = sum(flow.packet_count for flow in flows)
    byte_total = sum(flow.byte_count for flow in flows)
    return NetworkCounters(
        packets=packets,
        bytes=byte_total,
        flows=len(flows),
        active_flows=runtime.network_flow_count,
    )


class MonitoringController:
    """Own and drive the single runtime from the desktop lifecycle."""

    def __init__(
        self,
        *,
        runtime_factory: Callable[[], AegisRuntime] | None = None,
        poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS,
    ) -> None:
        self._runtime_factory = runtime_factory
        self._poll_interval_ms = poll_interval_ms
        self._runtime: AegisRuntime | None = None
        self._start_error: str | None = None

    @property
    def poll_interval_ms(self) -> int:
        """The interval the window should poll at."""
        return self._poll_interval_ms

    @property
    def runtime(self) -> AegisRuntime | None:
        """The current runtime, or ``None`` when not started."""
        return self._runtime

    @property
    def is_running(self) -> bool:
        """Whether the runtime is currently running."""
        return self._runtime is not None and self._runtime.is_running

    def _build_runtime(self) -> AegisRuntime:
        if self._runtime_factory is not None:
            return self._runtime_factory()
        # Imported lazily: opening the application must not load the runtime.
        from aegis_runtime import AegisRuntime

        return AegisRuntime()

    def start(self) -> bool:
        """Start the runtime. Returns ``True`` on success, ``False`` on failure.

        Never raises: a failure is recorded as an honest ``start_error`` state so
        the GUI can display it rather than pretending monitoring is running.
        """
        if self.is_running:
            return True
        try:
            runtime = self._build_runtime()
            runtime.start()
        except Exception as exc:
            self._start_error = f"{type(exc).__name__}: {exc}"
            logger.warning("Starting monitoring failed: %s", exc)
            self._runtime = None
            return False
        self._runtime = runtime
        self._start_error = None
        return True

    def poll(self) -> None:
        """Run one bounded runtime cycle. Never raises."""
        runtime = self._runtime
        if runtime is None or not runtime.is_running:
            return
        try:
            runtime.poll_once()
        except Exception as exc:
            logger.warning("Monitoring poll failed: %s", exc)

    def stop(self) -> None:
        """Stop the runtime and clear active state. Never raises."""
        runtime = self._runtime
        if runtime is None:
            return
        try:
            runtime.stop()
        except Exception as exc:
            logger.warning("Stopping monitoring failed: %s", exc)
        finally:
            self._runtime = None

    def status(self) -> MonitoringStatus:
        """Return the current runtime + capture status (read-only)."""
        runtime = self._runtime
        if runtime is None or not runtime.is_running:
            return MonitoringStatus(
                running=False,
                capture_state=CAPTURE_INACTIVE,
                capture_error=None,
                interface=None,
                counters=_empty_counters(),
                start_error=self._start_error,
            )
        return MonitoringStatus(
            running=True,
            capture_state=getattr(runtime, "network_capture_state", CAPTURE_INACTIVE),
            capture_error=getattr(runtime, "network_capture_error", None),
            interface=getattr(runtime, "network_interface", None),
            counters=_counters_from_runtime(runtime),
            start_error=None,
        )

    def network_flows(self) -> tuple[Any, ...]:
        """Return the real flows tracked by the runtime's network sensor."""
        runtime = self._runtime
        if runtime is None:
            return ()
        return tuple(getattr(runtime, "network_flows", ()) or ())


# ---------------------------------------------------------------------------
# Process-wide registry (mirrors the existing registry pattern)
# ---------------------------------------------------------------------------

_active: MonitoringController | None = None


def set_active_monitoring_controller(controller: MonitoringController | None) -> None:
    """Publish (or clear) the desktop monitoring controller for observers."""
    global _active
    _active = controller


def get_active_monitoring_controller() -> MonitoringController | None:
    """Return the published controller, or ``None`` when none is running."""
    return _active


def clear_active_monitoring_controller() -> None:
    """Clear the published controller."""
    global _active
    _active = None


__all__ = [
    "CAPTURE_ACTIVE",
    "CAPTURE_ERROR",
    "CAPTURE_INACTIVE",
    "DEFAULT_POLL_INTERVAL_MS",
    "MONITORING_START_ERROR",
    "MonitoringController",
    "MonitoringStatus",
    "NetworkCounters",
    "clear_active_monitoring_controller",
    "get_active_monitoring_controller",
    "set_active_monitoring_controller",
]
