"""Passive, read-only packet capture (scapy, imported lazily).

Safety
------
This module only *observes* frames. It never injects, forges, modifies or
redirects traffic, never changes firewall/routing/DNS state and never shells out
to network tools. Capture is always a single bounded run (``count`` packets,
``store=False`` so scapy retains nothing) - never an unbounded loop.

Scapy is imported lazily so that configuration, models and the CLI can run
without the ``sensor`` extra installed. Actual capture requires scapy and, on
most platforms, elevated privileges (Npcap on Windows, CAP_NET_RAW/root on
Linux).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from aegis_shared.logging import get_logger

logger = get_logger(__name__)


class CaptureUnavailableError(RuntimeError):
    """Raised when packet capture support (scapy) is not installed."""


def _import_scapy() -> Any:
    try:
        import scapy.all as scapy_all
    except ImportError as exc:  # pragma: no cover - exercised only without scapy
        raise CaptureUnavailableError(
            "scapy is required for packet capture; install the 'sensor' extra"
        ) from exc
    return scapy_all


def list_interfaces() -> tuple[str, ...]:
    """Return available interface names. Read-only; requires no privileges."""
    scapy_all = _import_scapy()
    try:
        interfaces = scapy_all.get_if_list()
    except Exception as exc:
        logger.warning("Could not list interfaces: %s", exc)
        return ()
    return tuple(sorted(str(name) for name in interfaces))


class PacketCapture:
    """A bounded passive capture session over one interface.

    An optional BPF (Berkeley Packet Filter) expression can be supplied via
    ``packet_filter``.  When set, the kernel/Npcap driver drops matching frames
    *before* they cross into Python, dramatically reducing per-packet CPU cost.
    The filter syntax is the standard pcap-filter(7) language; common examples::

        "(ip or ip6) and not multicast and not broadcast"
        "tcp port 443"
        "icmp"

    If ``packet_filter`` is empty, all frames on the interface are delivered.
    """

    def __init__(
        self,
        *,
        interface: str,
        packet_filter: str = "",
        promiscuous: bool = False,
    ) -> None:
        if not interface.strip():
            raise ValueError("interface is required for capture")
        self._interface = interface
        self._filter = packet_filter.strip()
        self._promiscuous = promiscuous

    @property
    def interface(self) -> str:
        """The interface this session captures from."""
        return self._interface

    def capture(
        self,
        *,
        count: int,
        on_packet: Callable[[Any], None],
        timeout: float | None = None,
    ) -> int:
        """Capture at most ``count`` packets, invoking ``on_packet`` for each.

        Args:
            count: Maximum packets to capture.
            on_packet: Callback invoked for each observed packet.
            timeout: Maximum seconds to wait.  ``None`` waits indefinitely
                until *count* packets are seen.  A finite timeout ensures the
                call never blocks the caller for too long (returns early with
                whatever packets were seen so far).

        Returns the number of packets observed. ``store=False`` ensures scapy
        does not accumulate packets in memory.
        """
        if count < 1:
            raise ValueError("count must be at least 1")

        scapy_all = _import_scapy()
        observed = 0

        def _handle(packet: Any) -> None:
            nonlocal observed
            observed += 1
            on_packet(packet)

        kwargs: dict[str, Any] = {
            "iface": self._interface,
            "filter": self._filter or None,
            "prn": _handle,
            "store": False,
            "count": count,
            "promisc": self._promiscuous,
        }
        if timeout is not None:
            kwargs["timeout"] = timeout

        scapy_all.sniff(**kwargs)
        return observed


__all__ = ["CaptureUnavailableError", "PacketCapture", "list_interfaces"]
