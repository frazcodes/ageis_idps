"""Unit tests for binary TLS ClientHello SNI parser (extract_tls_sni).

Tests verify safe parsing, RFC 6066 compliance, memory safety, and strict bounds
validation across valid, malformed, truncated, and non-TLS payloads.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from aegis_network_sensor.events import build_network_event
from aegis_network_sensor.flows import FlowAggregator, FlowRecord
from aegis_network_sensor.flows.events import build_flow_event
from aegis_network_sensor.models import PacketRecord
from aegis_network_sensor.normalization import normalize_packet
from aegis_network_sensor.tls_parser import extract_tls_sni
from aegis_shared.enums import AddressFamily, SourceKind, TransportProtocol
from aegis_shared.events import SourceRef


def _build_client_hello(
    sni: str | None = "example.com",
    *,
    client_version: tuple[int, int] = (3, 3),  # TLS 1.2
    record_version: tuple[int, int] = (3, 1),  # TLS 1.0 record layer
    session_id: bytes = b"",
    ciphers: tuple[int, ...] = (0x1301, 0x1302),  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
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
        + (b"\x42" * 32)  # Random
        + struct.pack("B", len(session_id))
        + session_id
        + struct.pack(">H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"  # 1 compression method: null
        + extensions_bytes
    )

    handshake_msg = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    record_hdr = (
        b"\x16"
        + struct.pack("BB", *record_version)
        + struct.pack(">H", len(handshake_msg))
    )
    return record_hdr + handshake_msg


# ---------------------------------------------------------------------------
# Valid SNI Extraction Tests
# ---------------------------------------------------------------------------


def test_extract_valid_sni_standard_domain() -> None:
    payload = _build_client_hello("example.com")
    assert extract_tls_sni(payload) == "example.com"


def test_extract_valid_sni_subdomain() -> None:
    payload = _build_client_hello("c2.beacon.malicious-network.org")
    assert extract_tls_sni(payload) == "c2.beacon.malicious-network.org"


def test_extract_valid_sni_normalizes_case_and_trailing_dot() -> None:
    payload = _build_client_hello("API.CLOUD.GOOGLE.COM.")
    assert extract_tls_sni(payload) == "api.cloud.google.com"


def test_extract_valid_sni_with_session_id_and_multiple_extensions() -> None:
    # ALPN dummy extension (ext_type 0x0010)
    alpn_dummy = struct.pack(">HH", 0x0010, 4) + b"\x03h2\x00"
    payload = _build_client_hello(
        "secure.internal.corp",
        session_id=b"\x01\x02\x03\x04\x05\x06\x07\x08",
        extra_extensions=alpn_dummy,
    )
    assert extract_tls_sni(payload) == "secure.internal.corp"


# ---------------------------------------------------------------------------
# Missing SNI & Extension Scenarios
# ---------------------------------------------------------------------------


def test_client_hello_without_sni_returns_none() -> None:
    # ClientHello with an extension (e.g. dummy ALPN), but no SNI
    alpn_dummy = struct.pack(">HH", 0x0010, 2) + b"h2"
    payload = _build_client_hello(sni=None, extra_extensions=alpn_dummy)
    assert extract_tls_sni(payload) is None


def test_client_hello_without_extensions_block_returns_none() -> None:
    payload = _build_client_hello(sni=None, include_extensions=False)
    assert extract_tls_sni(payload) is None


# ---------------------------------------------------------------------------
# Non-TLS and Non-ClientHello Payloads
# ---------------------------------------------------------------------------


def test_empty_payload_returns_none() -> None:
    assert extract_tls_sni(b"") is None


def test_non_tls_plain_text_http_returns_none() -> None:
    http_get = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert extract_tls_sni(http_get) is None


def test_non_tls_ssh_banner_returns_none() -> None:
    ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    assert extract_tls_sni(ssh_banner) is None


def test_tls_record_not_handshake_returns_none() -> None:
    # ContentType 0x17 (Application Data)
    app_data = b"\x17\x03\x03\x00\x10" + (b"\x00" * 16)
    assert extract_tls_sni(app_data) is None


def test_tls_handshake_not_client_hello_returns_none() -> None:
    # ContentType 0x16 (Handshake), but Handshake Type 0x02 (ServerHello)
    server_hello = b"\x16\x03\x03\x00\x08\x02\x00\x00\x04\x03\x03\x00\x00"
    assert extract_tls_sni(server_hello) is None


# ---------------------------------------------------------------------------
# Malformed Lengths & Bounds Tests
# ---------------------------------------------------------------------------


def test_malformed_record_length_claimed_exceeds_payload() -> None:
    payload = _build_client_hello("example.com")
    # Tamper with record length header to claim 65000 bytes
    tampered = payload[:3] + struct.pack(">H", 65000) + payload[5:]
    # Should safely process within available limit or return None
    result = extract_tls_sni(tampered)
    # Available slice is intact, so it extracts without crash
    assert result == "example.com"


def test_malformed_record_length_smaller_than_handshake() -> None:
    payload = _build_client_hello("example.com")
    # Tamper record length to claim only 6 bytes (less than required handshake)
    tampered = payload[:3] + struct.pack(">H", 6) + payload[5:]
    assert extract_tls_sni(tampered) is None


def test_malformed_cipher_suites_length_overflow() -> None:
    valid = _build_client_hello("example.com")
    # Offset: 5 record + 4 handshake + 2 version + 32 random + 1 session_len
    offset = 5 + 4 + 2 + 32 + 1
    tampered = valid[:offset] + struct.pack(">H", 0xFF00) + valid[offset + 2 :]
    assert extract_tls_sni(tampered) is None


def test_malformed_extensions_length_overflow() -> None:
    valid = _build_client_hello("example.com")
    # Overwrite the extensions block length to overflow available handshake
    # To find extensions_len offset: right before the 0x0000 SNI extension header
    idx = valid.find(b"\x00\x00\x00")  # SNI extension header
    assert idx != -1
    ext_len_idx = idx - 2
    tampered = valid[:ext_len_idx] + struct.pack(">H", 0x7FFF) + valid[idx:]
    assert extract_tls_sni(tampered) is None


def test_malformed_sni_list_length_overflow() -> None:
    valid = _build_client_hello("example.com")
    idx = valid.find(b"example.com")
    assert idx != -1
    # 2 bytes name_len, 1 byte name_type, 2 bytes list_len before host
    list_len_idx = idx - 5
    tampered = valid[:list_len_idx] + struct.pack(">H", 0xFFFF) + valid[list_len_idx + 2 :]
    assert extract_tls_sni(tampered) is None


# ---------------------------------------------------------------------------
# Truncation Tests
# ---------------------------------------------------------------------------


def test_truncated_at_every_byte_never_crashes() -> None:
    full_packet = _build_client_hello("staging.auth.threat-intel.net")
    for cut in range(len(full_packet)):
        truncated_slice = full_packet[:cut]
        # Must return None or valid hostname without raising any exception
        res = extract_tls_sni(truncated_slice)
        if cut < len(full_packet):
            assert res is None


# ---------------------------------------------------------------------------
# Invalid / Hostile Hostnames
# ---------------------------------------------------------------------------


def test_non_ascii_hostname_returns_none() -> None:
    # Inject non-ASCII / binary payload as hostname
    bad_host = b"\xff\xfe\xfd\x00\x12"
    server_name_entry = b"\x00" + struct.pack(">H", len(bad_host)) + bad_host
    server_name_list = struct.pack(">H", len(server_name_entry)) + server_name_entry
    sni_ext = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list
    extensions = struct.pack(">H", len(sni_ext)) + sni_ext
    ch_body = (
        b"\x03\x03"
        + (b"\x00" * 32)
        + b"\x00"
        + struct.pack(">H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    assert extract_tls_sni(record) is None


def test_control_character_in_hostname_returns_none() -> None:
    payload = _build_client_hello("evil\x00injector.com")
    assert extract_tls_sni(payload) is None


def test_hostname_with_slash_returns_none() -> None:
    payload = _build_client_hello("evil.com/exploit")
    assert extract_tls_sni(payload) is None


# ---------------------------------------------------------------------------
# Step 2: Model & Pipeline Integration Tests
# ---------------------------------------------------------------------------


def test_packet_record_construction_backward_compatibility() -> None:
    # Constructing PacketRecord without sni defaults to None
    rec_default = PacketRecord()
    assert rec_default.sni is None

    # Constructing PacketRecord with sni
    rec_sni = PacketRecord(sni="api.example.com")
    assert rec_sni.sni == "api.example.com"


def test_flow_record_construction_backward_compatibility() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    flow_default = FlowRecord(
        flow_id="test-flow",
        first_seen=ts,
        last_seen=ts,
    )
    assert flow_default.sni is None

    flow_sni = FlowRecord(
        flow_id="test-flow-2",
        first_seen=ts,
        last_seen=ts,
        sni="login.service.net",
    )
    assert flow_sni.sni == "login.service.net"


def test_normalize_packet_extracts_and_propagates_sni() -> None:
    client_hello_bytes = _build_client_hello("portal.mybank.com")
    pkt = (
        IP(src="192.168.1.50", dst="104.21.5.10")
        / TCP(sport=54321, dport=443)
        / Raw(client_hello_bytes)
    )

    rec = normalize_packet(pkt)
    assert rec is not None
    assert rec.protocol is TransportProtocol.TCP
    assert rec.src_port == 54321
    assert rec.dst_port == 443
    assert rec.sni == "portal.mybank.com"


def test_normalize_packet_non_tls_tcp_payload_has_no_sni() -> None:
    http_payload = b"GET /api/v1/health HTTP/1.1\r\nHost: internal.service\r\n\r\n"
    pkt = (
        IP(src="192.168.1.50", dst="10.0.0.1")
        / TCP(sport=50000, dport=80)
        / Raw(http_payload)
    )

    rec = normalize_packet(pkt)
    assert rec is not None
    assert rec.sni is None


def test_normalize_packet_malformed_tls_payload_has_no_sni() -> None:
    corrupt_tls = b"\x16\x03\x01\x00\x10\x01\xff\xff\xff" + (b"\x00" * 7)
    pkt = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=49999, dport=443)
        / Raw(corrupt_tls)
    )

    rec = normalize_packet(pkt)
    assert rec is not None
    assert rec.sni is None


def test_flow_aggregator_retains_sni_across_packets() -> None:
    agg = FlowAggregator()
    ts1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    ts2 = datetime(2026, 1, 1, 10, 0, 1, tzinfo=UTC)

    # Packet 1: ClientHello carrying SNI
    rec1 = PacketRecord(
        flow_id="flow-tls-1",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.5",
        dst_ip="1.1.1.1",
        ports_applicable=True,
        src_port=40000,
        dst_port=443,
        timestamp=ts1,
        sni="cloudflare-dns.com",
    )
    flow1 = agg.observe(rec1)
    assert flow1.sni == "cloudflare-dns.com"
    assert flow1.packet_count == 1

    # Packet 2: Subsequent TCP ACK / data packet in same flow without SNI
    rec2 = PacketRecord(
        flow_id="flow-tls-1",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.5",
        dst_ip="1.1.1.1",
        ports_applicable=True,
        src_port=40000,
        dst_port=443,
        timestamp=ts2,
        sni=None,
    )
    flow2 = agg.observe(rec2)
    # Must NOT overwrite cloudflare-dns.com with None
    assert flow2.sni == "cloudflare-dns.com"
    assert flow2.packet_count == 2


def test_flow_aggregator_updates_sni_if_first_packet_had_none() -> None:
    agg = FlowAggregator()
    ts1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    ts2 = datetime(2026, 1, 1, 10, 0, 1, tzinfo=UTC)

    # Packet 1: TCP SYN packet (no SNI yet)
    rec1 = PacketRecord(
        flow_id="flow-tls-2",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.6",
        dst_ip="8.8.8.8",
        ports_applicable=True,
        src_port=40001,
        dst_port=443,
        timestamp=ts1,
        sni=None,
    )
    flow1 = agg.observe(rec1)
    assert flow1.sni is None

    # Packet 2: ClientHello arrived
    rec2 = PacketRecord(
        flow_id="flow-tls-2",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.6",
        dst_ip="8.8.8.8",
        ports_applicable=True,
        src_port=40001,
        dst_port=443,
        timestamp=ts2,
        sni="dns.google",
    )
    flow2 = agg.observe(rec2)
    assert flow2.sni == "dns.google"


def test_event_builders_propagate_sni_to_domain() -> None:
    src = SourceRef(kind=SourceKind.SENSOR, id="sensor-test")
    ts = datetime(2026, 1, 1, tzinfo=UTC)

    # 1. Packet event builder with SNI
    rec_sni = PacketRecord(
        flow_id="f1",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ports_applicable=True,
        src_port=1000,
        dst_port=443,
        timestamp=ts,
        sni="corp-intranet.local",
    )
    pkt_evt = build_network_event(rec_sni, source=src)
    assert pkt_evt.network is not None
    assert pkt_evt.network.domain == "corp-intranet.local"

    # 2. Packet event builder without SNI
    rec_no_sni = PacketRecord(
        flow_id="f2",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ports_applicable=True,
        src_port=1000,
        dst_port=80,
        timestamp=ts,
        sni=None,
    )
    pkt_evt_none = build_network_event(rec_no_sni, source=src)
    assert pkt_evt_none.network is not None
    assert pkt_evt_none.network.domain is None

    # 3. Flow event builder with SNI
    flow_sni = FlowRecord(
        flow_id="f1",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ports_applicable=True,
        src_port=1000,
        dst_port=443,
        first_seen=ts,
        last_seen=ts,
        sni="corp-intranet.local",
    )
    flow_evt = build_flow_event(flow_sni, source=src)
    assert flow_evt.network is not None
    assert flow_evt.network.domain == "corp-intranet.local"

    # 4. Flow event builder without SNI
    flow_no_sni = FlowRecord(
        flow_id="f2",
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ports_applicable=True,
        src_port=1000,
        dst_port=80,
        first_seen=ts,
        last_seen=ts,
        sni=None,
    )
    flow_evt_none = build_flow_event(flow_no_sni, source=src)
    assert flow_evt_none.network is not None
    assert flow_evt_none.network.domain is None

