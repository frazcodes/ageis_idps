"""Normalize captured packets into typed telemetry (scapy-dependent).

Only the packet header is read. Payload bytes are never copied into a
:class:`~aegis_network_sensor.models.PacketRecord`, so no application content,
credentials or sensitive data is retained.

Robustness
----------
Packet parsing is an untrusted-input boundary: malformed or unsupported frames
are returned as ``None`` (and logged at debug level) instead of raising. No
direction is invented - without configured local addresses the direction stays
``unknown``.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from aegis_network_sensor.models import PacketRecord, format_ip_endpoint
from aegis_network_sensor.tls_parser import extract_tls_sni
from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: IPv6 next-header value for ICMPv6.
_ICMPV6_NEXT_HEADER = 58


def compute_flow_id(
    *,
    ip_version: AddressFamily,
    protocol: TransportProtocol,
    src_ip: str | None,
    src_port: int | None,
    dst_ip: str | None,
    dst_port: int | None,
) -> str:
    """Return a deterministic, directional flow identifier.

    The key is ``ip_version | protocol | src -> dst``; IPv6 endpoints are
    bracketed so they are never ambiguous. It is stateless - the same packet
    always yields the same id - and does not imply flow aggregation.
    """
    source = format_ip_endpoint(src_ip, src_port, ip_version)
    destination = format_ip_endpoint(dst_ip, dst_port, ip_version)
    return f"{ip_version.value}|{protocol.value}|{source}->{destination}"


def detect_direction(
    src_ip: str | None, dst_ip: str | None, local_addresses: Iterable[str]
) -> NetworkDirection:
    """Classify direction only when configured local addresses prove it."""
    local = set(local_addresses)
    if not local:
        return NetworkDirection.UNKNOWN
    src_local = src_ip is not None and src_ip in local
    dst_local = dst_ip is not None and dst_ip in local
    if src_local and not dst_local:
        return NetworkDirection.OUTBOUND
    if dst_local and not src_local:
        return NetworkDirection.INBOUND
    return NetworkDirection.UNKNOWN


def _packet_timestamp(packet: Any) -> datetime:
    raw = getattr(packet, "time", None)
    if raw is not None:
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except (TypeError, ValueError, OSError, OverflowError):
            pass
    return datetime.now(UTC)


def _safe_port(raw: Any) -> int:
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _transport(
    packet: Packet, ip_version: AddressFamily
) -> tuple[TransportProtocol, bool, int | None, int | None]:
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        return TransportProtocol.TCP, True, _safe_port(tcp.sport), _safe_port(tcp.dport)
    if packet.haslayer(UDP):
        udp = packet[UDP]
        return TransportProtocol.UDP, True, _safe_port(udp.sport), _safe_port(udp.dport)
    if ip_version is AddressFamily.IPV4 and packet.haslayer(ICMP):
        return TransportProtocol.ICMP, False, None, None
    if ip_version is AddressFamily.IPV6:
        next_header = getattr(packet[IPv6], "nh", 0)
        if next_header == _ICMPV6_NEXT_HEADER:
            return TransportProtocol.ICMP, False, None, None
    return TransportProtocol.OTHER, False, None, None


def normalize_packet(
    packet: Any,
    *,
    interface: str | None = None,
    local_addresses: Iterable[str] = (),
    timestamp: datetime | None = None,
) -> PacketRecord | None:
    """Normalize one scapy packet, or return ``None`` if unsupported/malformed."""
    try:
        return _normalize_packet(
            packet,
            interface=interface,
            local_addresses=local_addresses,
            timestamp=timestamp,
        )
    except Exception as exc:
        # Parsing untrusted frames must never crash the sensor.
        logger.debug("Skipping unparsable packet: %s", exc)
        return None


def _normalize_packet(
    packet: Any,
    *,
    interface: str | None,
    local_addresses: Iterable[str],
    timestamp: datetime | None,
) -> PacketRecord | None:
    if not isinstance(packet, Packet):
        return None

    if packet.haslayer(IP):
        ip_version = AddressFamily.IPV4
        ip_layer = packet[IP]
    elif packet.haslayer(IPv6):
        ip_version = AddressFamily.IPV6
        ip_layer = packet[IPv6]
    else:
        return None

    src_ip = str(ip_layer.src) if getattr(ip_layer, "src", None) else None
    dst_ip = str(ip_layer.dst) if getattr(ip_layer, "dst", None) else None
    protocol, ports_applicable, src_port, dst_port = _transport(packet, ip_version)

    try:
        packet_length: int | None = len(packet)
    except Exception:
        packet_length = None

    # Passive TLS SNI extraction (RFC 6066). Operates on single TCP packet payloads.
    # TCP stream reassembly is not implemented in this step; fragmented ClientHello
    # messages split across multiple TCP segments evaluate safely to None.
    sni: str | None = None
    if protocol is TransportProtocol.TCP and packet.haslayer(TCP):
        try:
            raw_payload = bytes(packet[TCP].payload)
            if raw_payload:
                sni = extract_tls_sni(raw_payload)
        except Exception:
            sni = None

    return PacketRecord(
        timestamp=timestamp or _packet_timestamp(packet),
        interface=interface,
        ip_version=ip_version,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        ports_applicable=ports_applicable,
        src_port=src_port,
        dst_port=dst_port,
        packet_length=packet_length,
        direction=detect_direction(src_ip, dst_ip, local_addresses),
        flow_id=compute_flow_id(
            ip_version=ip_version,
            protocol=protocol,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        ),
        sni=sni,
    )


__all__ = ["compute_flow_id", "detect_direction", "normalize_packet"]
