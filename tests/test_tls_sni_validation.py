"""Comprehensive end-to-end validation tests for TLS/SNI extraction & threat intelligence.

Validates the full pipeline:
Phase 3 — Valid, missing, ECH, malformed, and segmented TLS ClientHello scenarios.
Phase 4 — IOC matching (exact match, case/dot normalization, subdomain policy,
           substring rejection, safe missing IOC handling, unusual TLD behavior).
Phase 5 — Multi-connection flow isolation, SNI retention, event propagation, backward compatibility.
Phase 6 — Desktop UI display formatting, tooltip behavior, port extraction, and table model roles.
"""

from __future__ import annotations

import os
import struct
from datetime import UTC, datetime
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from aegis_desktop.app import create_application
from aegis_desktop.services.live_network import (
    LiveActivityRow,
    LiveNetworkTableModel,
    analyze_packet_threat,
)
from aegis_desktop.services.network import (
    _to_event_row,
    _to_flow_row,
)
from aegis_network_sensor.events import build_network_event
from aegis_network_sensor.flows import FlowAggregator, FlowRecord
from aegis_network_sensor.flows.events import build_flow_event
from aegis_network_sensor.models import PacketRecord
from aegis_network_sensor.normalization import normalize_packet
from aegis_network_sensor.tls_parser import extract_tls_sni
from aegis_shared.enums import (
    AddressFamily,
    IndicatorType,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import SourceRef
from aegis_shared.threat_intel.matcher import IOCMatcher
from aegis_shared.threat_intel.models import ThreatIndicator

_TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _build_raw_client_hello(
    sni: str | None = "service.example.test",
    *,
    client_version: tuple[int, int] = (3, 3),  # TLS 1.2
    record_version: tuple[int, int] = (3, 1),  # TLS 1.0 record layer
    session_id: bytes = b"",
    ciphers: tuple[int, ...] = (0x1301, 0x1302),
    include_extensions: bool = True,
    extra_extensions: bytes = b"",
) -> bytes:
    """Helper to synthesize deterministic, valid TLS ClientHello records."""
    extensions_bytes = b""
    if include_extensions:
        ext_entries = bytearray()
        if sni is not None:
            sni_raw = sni.encode("ascii")
            server_name_entry = b"\x00" + struct.pack(">H", len(sni_raw)) + sni_raw
            server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
            sni_extension = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list
            ext_entries.extend(sni_extension)

        if extra_extensions:
            ext_entries.extend(extra_extensions)

        extensions_bytes = struct.pack(">H", len(ext_entries)) + bytes(ext_entries)

    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    ch_body = (
        struct.pack("BB", *client_version)
        + (b"\x55" * 32)  # Random
        + struct.pack("B", len(session_id))
        + session_id
        + struct.pack(">H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"  # Compression method: null
        + extensions_bytes
    )

    handshake_msg = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    record_hdr = (
        b"\x16"
        + struct.pack("BB", *record_version)
        + struct.pack(">H", len(handshake_msg))
    )
    return record_hdr + handshake_msg


# ===========================================================================
# Phase 3 — Validate TLS/SNI Extraction
# ===========================================================================


def test_phase3_1_valid_client_hello_sni_extraction() -> None:
    """3.1 Valid ClientHello with SNI extraction and full model propagation."""
    raw_payload = _build_raw_client_hello("service.example.test")
    extracted = extract_tls_sni(raw_payload)
    assert extracted == "service.example.test"

    # Packet normalization
    scapy_pkt = (
        IP(src="192.168.1.10", dst="198.51.100.10")
        / TCP(sport=51234, dport=443)
        / Raw(raw_payload)
    )
    rec = normalize_packet(scapy_pkt, timestamp=_TS)
    assert rec is not None
    assert rec.protocol is TransportProtocol.TCP
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "198.51.100.10"
    assert rec.dst_port == 443
    assert rec.sni == "service.example.test"

    # Flow aggregation
    agg = FlowAggregator()
    flow = agg.observe(rec)
    assert flow.sni == "service.example.test"

    # Event generation
    src = SourceRef(kind=SourceKind.SENSOR, id="sensor-test")
    pkt_event = build_network_event(rec, source=src)
    assert pkt_event.network is not None
    assert pkt_event.network.domain == "service.example.test"

    flow_event = build_flow_event(flow, source=src)
    assert flow_event.network is not None
    assert flow_event.network.domain == "service.example.test"


def test_phase3_2_tls_without_sni() -> None:
    """3.2 Valid TLS ClientHello with extensions but missing SNI extension."""
    # ALPN dummy extension (ext_type 0x0010)
    alpn_ext = struct.pack(">HH", 0x0010, 4) + b"\x03h2\x00"
    raw_payload = _build_raw_client_hello(sni=None, extra_extensions=alpn_ext)

    assert extract_tls_sni(raw_payload) is None

    scapy_pkt = (
        IP(src="192.168.1.10", dst="198.51.100.10")
        / TCP(sport=51234, dport=443)
        / Raw(raw_payload)
    )
    rec = normalize_packet(scapy_pkt, timestamp=_TS)
    assert rec is not None
    assert rec.dst_ip == "198.51.100.10"
    assert rec.dst_port == 443
    assert rec.sni is None

    # Missing SNI must not trigger domain IOC threat alert
    is_threat, tag, _ = analyze_packet_threat(
        destination=f"{rec.dst_ip}:{rec.dst_port}",
        port="443",
        protocol="TCP",
        domain=rec.sni or "",
    )
    assert is_threat is False
    assert tag == ""


def test_phase3_3_encrypted_client_hello_ech() -> None:
    """3.3 Encrypted ClientHello (ECH) distinguishes outer vs inner hostname."""
    # Outer SNI in cleartext, ECH extension (0xfe0d) containing encrypted inner ClientHello
    ech_data = b"\x00\x20" + (b"\xcc" * 32)  # Dummy encrypted inner payload
    ech_ext = struct.pack(">HH", 0xFE0D, len(ech_data)) + ech_data
    raw_payload = _build_raw_client_hello(
        sni="public.cloudflare-ech.com",
        extra_extensions=ech_ext,
    )

    # Observable outer hostname is extracted
    extracted = extract_tls_sni(raw_payload)
    assert extracted == "public.cloudflare-ech.com"

    # Implementation does not falsely claim inner encrypted hostname was recovered
    assert "secret" not in (extracted or "")

    # Outer SNI without IOC match is not classified as malicious
    is_threat, _, _ = analyze_packet_threat(
        destination="104.16.1.1:443",
        port="443",
        protocol="TCP",
        domain=extracted or "",
    )
    assert is_threat is False


def test_phase3_4_malformed_and_truncated_packets() -> None:
    """3.4 Malformed records, invalid lengths, and truncations never crash."""
    valid_payload = _build_raw_client_hello("test.example.org")

    # 1. Truncated record header (< 5 bytes)
    assert extract_tls_sni(valid_payload[:3]) is None

    # 2. Corrupt handshake length claiming 16MB
    corrupt_handshake = valid_payload[:6] + b"\xff\xff\xff" + valid_payload[9:]
    assert extract_tls_sni(corrupt_handshake) is None

    # 3. Corrupt extension length claiming 65535 bytes
    corrupt_ext_hdr = valid_payload[:70] + b"\xff\xff" + valid_payload[72:]
    assert extract_tls_sni(corrupt_ext_hdr) is None

    # 4. Truncated inside hostname
    assert extract_tls_sni(valid_payload[:-3]) is None


def test_phase3_5_tcp_segmentation_limitation() -> None:
    """3.5 TCP segmentation: fragmented ClientHello evaluates safely to None."""
    full_payload = _build_raw_client_hello("segmented.service.net")

    # Segment 1 contains TLS record header and handshake header, but cuts off
    # before cipher suites and extensions
    segment_1 = full_payload[:40]
    # Single-packet parser does not speculate or fail catastrophically
    assert extract_tls_sni(segment_1) is None

    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443) / Raw(segment_1)
    rec1 = normalize_packet(pkt1)
    assert rec1 is not None
    assert rec1.sni is None


# ===========================================================================
# Phase 4 — Validate IOC Matching
# ===========================================================================


@pytest.fixture
def test_ioc_matcher() -> IOCMatcher:
    """In-memory deterministic IOC fixture using reserved RFC 2606/6761 domains."""
    indicators = [
        ThreatIndicator(
            indicator_id="IOC-TEST-MALICIOUS-001",
            indicator_type=IndicatorType.DOMAIN,
            value="malicious.example.test",
            source="test-fixture",
            confidence=0.99,
            severity=Severity.CRITICAL,
            description="Known C2 test indicator",
        ),
        ThreatIndicator(
            indicator_id="IOC-TEST-EXPLOIT-002",
            indicator_type=IndicatorType.DOMAIN,
            value="exploit-beacon.example.test",
            source="test-fixture",
            confidence=0.90,
            severity=Severity.HIGH,
            description="Exploit staging domain",
        ),
    ]
    return IOCMatcher(indicators)


def test_phase4_1_exact_ioc_match(test_ioc_matcher: IOCMatcher) -> None:
    """4.1 Configured exact domain IOC matches with MALICIOUS IOC DOMAIN tag."""
    is_threat, tag, detail = analyze_packet_threat(
        source="10.0.0.5:51234",
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="malicious.example.test",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is True
    assert tag == "MALICIOUS IOC DOMAIN"
    assert "malicious.example.test" in detail
    assert "Known C2 test indicator" in detail


def test_phase4_2_benign_unmatched_domain(test_ioc_matcher: IOCMatcher) -> None:
    """4.2 Benign unmatched hostname produces no IOC threat alert."""
    is_threat, tag, _ = analyze_packet_threat(
        source="10.0.0.5:51234",
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="service.example.test",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is False
    assert tag == ""


def test_phase4_3_case_normalization(test_ioc_matcher: IOCMatcher) -> None:
    """4.3 Domain matching is case-insensitive."""
    is_threat, tag, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="MALICIOUS.EXAMPLE.TEST",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is True
    assert tag == "MALICIOUS IOC DOMAIN"


def test_phase4_4_trailing_dot_normalization(test_ioc_matcher: IOCMatcher) -> None:
    """4.4 Trailing-dot DNS FQDN syntax is normalized for matching."""
    is_threat, tag, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="malicious.example.test.",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is True
    assert tag == "MALICIOUS IOC DOMAIN"


def test_phase4_5_subdomain_matching_policy(test_ioc_matcher: IOCMatcher) -> None:
    """4.5 Subdomains do not accidentally match exact IOC domain unless configured."""
    # Policy: Aegis IOC matching is exact-observable matching.
    is_threat, tag, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="sub.malicious.example.test",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is False
    assert tag == ""


def test_phase4_6_substring_non_matching(test_ioc_matcher: IOCMatcher) -> None:
    """4.6 A hostname containing an IOC as a substring must NOT match."""
    # "notmalicious.example.test" contains "malicious.example.test" as substring
    is_threat, tag, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="notmalicious.example.test",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat is False
    assert tag == ""

    # Prefix substring
    is_threat_prefix, _, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="attacker-malicious.example.test",
        ioc_matcher=test_ioc_matcher,
    )
    assert is_threat_prefix is False


def test_phase4_7_missing_threat_intel_safe() -> None:
    """4.7 Empty/missing IOC index safely returns no match without error."""
    empty_matcher = IOCMatcher([])
    is_threat, tag, _ = analyze_packet_threat(
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        domain="malicious.example.test",
        ioc_matcher=empty_matcher,
    )
    assert is_threat is False
    assert tag == ""


def test_phase4_8_unusual_tlds_contextual_only() -> None:
    """4.8 Benign domains with .xyz, .top are NOT classified as malicious."""
    for tld_domain in ("developer-blog.xyz", "enterprise-service.top", "secure-gateway.click"):
        is_threat, tag, _ = analyze_packet_threat(
            destination="104.21.5.10:443",
            port="443",
            protocol="TCP",
            domain=tld_domain,
        )
        assert is_threat is False
        assert tag == ""


# ===========================================================================
# Phase 5 — Validate Flow and Event Association
# ===========================================================================


def test_phase5_1_multi_connection_flow_isolation() -> None:
    """5.1 Multiple concurrent connections maintain distinct SNI hostnames."""
    agg = FlowAggregator()

    # Connection 1: Client to 198.51.100.1:443 -> service.example.test
    rec1 = PacketRecord(
        flow_id="ipv4|tcp|192.168.1.10:49152->198.51.100.1:443",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="192.168.1.10",
        src_port=49152,
        dst_ip="198.51.100.1",
        dst_port=443,
        ports_applicable=True,
        timestamp=_TS,
        sni="service.example.test",
    )
    flow1 = agg.observe(rec1)
    assert flow1.sni == "service.example.test"

    # Connection 2: Client to 203.0.113.2:443 -> analytics.example.test
    rec2 = PacketRecord(
        flow_id="ipv4|tcp|192.168.1.11:49153->203.0.113.2:443",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="192.168.1.11",
        src_port=49153,
        dst_ip="203.0.113.2",
        dst_port=443,
        ports_applicable=True,
        timestamp=_TS,
        sni="analytics.example.test",
    )
    flow2 = agg.observe(rec2)
    assert flow2.sni == "analytics.example.test"

    # Connection 3: Plain HTTP connection without SNI
    rec3 = PacketRecord(
        flow_id="ipv4|tcp|192.168.1.12:49154->198.51.100.3:80",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="192.168.1.12",
        src_port=49154,
        dst_ip="198.51.100.3",
        dst_port=80,
        ports_applicable=True,
        timestamp=_TS,
        sni=None,
    )
    flow3 = agg.observe(rec3)
    assert flow3.sni is None

    # Verify flow 1 and flow 2 remain isolated and unchanged
    flows = {f.flow_id: f for f in agg.snapshot()}
    assert rec1.flow_id is not None and rec2.flow_id is not None and rec3.flow_id is not None
    assert flows[rec1.flow_id].sni == "service.example.test"
    assert flows[rec2.flow_id].sni == "analytics.example.test"
    assert flows[rec3.flow_id].sni is None


def test_phase5_2_repeated_packets_no_duplicate_hostname_formatting() -> None:
    """5.2 Successive packets in a flow do not duplicate hostname formatting."""
    agg = FlowAggregator()

    rec_hello = PacketRecord(
        flow_id="flow-repeat-1",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="198.51.100.10",
        dst_port=443,
        ports_applicable=True,
        timestamp=_TS,
        sni="service.example.test",
    )
    flow = agg.observe(rec_hello)

    # Subsequent ACK / data packets without SNI
    for i in range(5):
        ack_rec = PacketRecord(
            flow_id="flow-repeat-1",
            ip_version=AddressFamily.IPV4,
            protocol=TransportProtocol.TCP,
            src_ip="10.0.0.1",
            src_port=50000,
            dst_ip="198.51.100.10",
            dst_port=443,
            ports_applicable=True,
            timestamp=datetime(2026, 1, 1, 12, 0, i + 1, tzinfo=UTC),
            sni=None,
        )
        flow = agg.observe(ack_rec)

    assert flow.packet_count == 6
    assert flow.sni == "service.example.test"

    # Convert to FlowRow repeatedly
    row = _to_flow_row(flow)
    assert row.destination == "198.51.100.10:443 (service.example.test)"
    # Ensure no repetitive nesting occurred
    assert row.destination.count("service.example.test") == 1
    assert row.destination.count("(") == 1


# ===========================================================================
# Phase 6 — Validate Desktop UI Integration
# ===========================================================================


def test_phase6_1_destination_column_formatting(app: Any) -> None:
    """6.1 Table model displays IP:port (domain) when SNI is present."""
    from PySide6.QtCore import Qt

    model = LiveNetworkTableModel()
    row_sni = LiveActivityRow(
        timestamp=_TS,
        source="10.0.0.1:50000",
        destination="192.0.2.10:443",
        port="443",
        protocol="TCP",
        packets=10,
        bytes=2048,
        direction="outbound",
        state="active",
        flow_id="f-ui-1",
        sni="service.example.test",
    )
    row_plain = LiveActivityRow(
        timestamp=_TS,
        source="10.0.0.1:50001",
        destination="192.0.2.10:80",
        port="80",
        protocol="TCP",
        packets=5,
        bytes=1024,
        direction="outbound",
        state="active",
        flow_id="f-ui-2",
        sni=None,
    )
    model.set_rows((row_sni, row_plain))

    # Row 0 with SNI
    dest_sni = model.data(model.index(0, 2), Qt.ItemDataRole.DisplayRole)
    assert dest_sni == "192.0.2.10:443 (service.example.test)"

    # Row 1 without SNI
    dest_plain = model.data(model.index(1, 2), Qt.ItemDataRole.DisplayRole)
    assert dest_plain == "192.0.2.10:80"
    assert "(" not in dest_plain


def test_phase6_2_no_duplicate_formatting_if_destination_already_contains_sni() -> None:
    """6.2 Display logic does not double-format if destination already has domain."""
    model = LiveNetworkTableModel()
    row_already_formatted = LiveActivityRow(
        timestamp=_TS,
        source="10.0.0.1:50000",
        destination="192.0.2.10:443 (service.example.test)",
        port="443",
        protocol="TCP",
        packets=10,
        bytes=2048,
        direction="outbound",
        state="active",
        flow_id="f-ui-3",
        sni="service.example.test",
    )
    model.set_rows((row_already_formatted,))

    dest_val = model.data(model.index(0, 2), Qt.ItemDataRole.DisplayRole)
    assert dest_val == "192.0.2.10:443 (service.example.test)"
    assert dest_val.count("(") == 1


def test_phase6_3_threat_and_hover_tooltips(app: Any) -> None:
    """6.3 Hover tooltips appear on destination and threat rows accurately."""
    from PySide6.QtCore import Qt

    model = LiveNetworkTableModel()
    row_threat = LiveActivityRow(
        timestamp=_TS,
        source="10.0.0.1:50000",
        destination="198.51.100.5:443",
        port="443",
        protocol="TCP",
        packets=10,
        bytes=2048,
        direction="outbound",
        state="active",
        flow_id="f-threat-ui",
        is_suspicious=True,
        threat_tag="MALICIOUS IOC DOMAIN",
        threat_detail=(
            "TLS SNI matches configured threat-intelligence indicator: "
            "malicious.example.test"
        ),
        sni="malicious.example.test",
    )
    row_benign = LiveActivityRow(
        timestamp=_TS,
        source="10.0.0.1:50001",
        destination="198.51.100.6:443",
        port="443",
        protocol="TCP",
        packets=10,
        bytes=2048,
        direction="outbound",
        state="active",
        flow_id="f-benign-ui",
        is_suspicious=False,
        sni="service.example.test",
    )
    model.set_rows((row_threat, row_benign))

    # Threat tooltip on suspicious row
    threat_tooltip = model.data(model.index(0, 0), Qt.ItemDataRole.ToolTipRole)
    assert threat_tooltip is not None
    assert "MALICIOUS IOC DOMAIN" in str(threat_tooltip)
    assert "malicious.example.test" in str(threat_tooltip)

    # Benign row general cell has no threat tooltip
    assert model.data(model.index(1, 0), Qt.ItemDataRole.ToolTipRole) is None

    # Destination column (col 2) tooltip shows resolved SNI
    dest_tooltip = model.data(model.index(1, 2), Qt.ItemDataRole.ToolTipRole)
    assert dest_tooltip == "Resolved TLS SNI Hostname: service.example.test"


def test_phase6_4_flow_row_and_network_event_row_builders() -> None:
    """6.4 Desktop network page flow and event row converters include SNI."""
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    # FlowRecord -> FlowRow
    flow_with_sni = FlowRecord(
        flow_id="f-100",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="192.0.2.10",
        dst_port=443,
        ports_applicable=True,
        first_seen=ts,
        last_seen=ts,
        sni="service.example.test",
    )
    flow_row = _to_flow_row(flow_with_sni)
    assert flow_row.destination == "192.0.2.10:443 (service.example.test)"
    assert flow_row.sni == "service.example.test"

    # SecurityEvent -> NetworkEventRow
    rec = PacketRecord(
        flow_id="f-101",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="192.0.2.10",
        dst_port=443,
        ports_applicable=True,
        timestamp=ts,
        sni="service.example.test",
    )
    src = SourceRef(kind=SourceKind.SENSOR, id="test-sensor")
    evt = build_network_event(rec, source=src)

    evt_row = _to_event_row(evt)
    assert evt_row.destination == "192.0.2.10:443 (service.example.test)"
    assert evt_row.sni == "service.example.test"
