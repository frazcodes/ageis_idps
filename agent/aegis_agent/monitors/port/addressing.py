"""Deterministic address and socket-type handling for the port monitor.

Keeping this logic in one place makes the mapping from OS primitives to the
shared vocabulary explicit and testable, and guarantees that an endpoint is
rendered unambiguously (``[::1]:8000`` can never be confused with ``::1:8000``).
"""

from __future__ import annotations

import socket
from typing import Any

from aegis_shared.enums import AddressFamily, TransportProtocol

_SOCKET_TYPE_TO_PROTOCOL: dict[int, TransportProtocol] = {
    socket.SOCK_STREAM: TransportProtocol.TCP,
    socket.SOCK_DGRAM: TransportProtocol.UDP,
}

_ADDRESS_FAMILY: dict[int, AddressFamily] = {
    socket.AF_INET: AddressFamily.IPV4,
    socket.AF_INET6: AddressFamily.IPV6,
}
if hasattr(socket, "AF_UNIX"):
    _ADDRESS_FAMILY[socket.AF_UNIX] = AddressFamily.UNIX


def protocol_for_socket_type(socket_type: int | None) -> TransportProtocol:
    """Map a ``socket.SOCK_*`` value onto the shared transport vocabulary."""
    if socket_type is None:
        return TransportProtocol.OTHER
    return _SOCKET_TYPE_TO_PROTOCOL.get(socket_type, TransportProtocol.OTHER)


def address_family_for(raw_family: int | None) -> AddressFamily:
    """Map a ``socket.AF_*`` value onto the shared address-family vocabulary."""
    if raw_family is None:
        return AddressFamily.UNKNOWN
    return _ADDRESS_FAMILY.get(raw_family, AddressFamily.OTHER)


def normalize_address(address: str | None, family: AddressFamily) -> str | None:
    """Return a bare host string without IPv6 brackets or surrounding whitespace."""
    if not address:
        return None
    text = address.strip()
    if family is AddressFamily.IPV6 and text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    return text or None


def split_local_address(laddr: Any) -> tuple[str | None, int | None]:
    """Extract ``(host, port)`` from a psutil ``laddr`` value.

    IPv4 laddrs are ``(host, port)`` and IPv6 laddrs are ``(host, port, flow,
    scope)``; only the first two elements are meaningful here.
    """
    if not laddr:
        return None, None
    try:
        host = laddr[0]
        port = laddr[1]
    except (TypeError, IndexError, KeyError):
        return None, None
    address = host if isinstance(host, str) else None
    port_number = port if isinstance(port, int) and not isinstance(port, bool) else None
    return address, port_number


def format_endpoint(address: str | None, port: int | None, family: AddressFamily) -> str:
    """Render an endpoint, bracketing IPv6 hosts to avoid port ambiguity."""
    if port is None:
        return address or "?"
    host = address or "*"
    if family is AddressFamily.IPV6:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


__all__ = [
    "address_family_for",
    "format_endpoint",
    "normalize_address",
    "protocol_for_socket_type",
    "split_local_address",
]
