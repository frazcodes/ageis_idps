"""Safe, memory-bounded TLS ClientHello SNI (Server Name Indication) parser.

Extracts the RFC 6066 Server Name Indication (SNI) extension from raw TCP
packet payload bytes without requiring TLS decryption or external dependencies.

Design & Limitations
--------------------
* **Pure & Stateless**: Operates strictly on bytes in memory; performs no I/O,
  no dynamic process creation, and has zero external dependencies.
* **Bounds-Checked**: Every offset and length field (TLS record layer, handshake
  header, session ID, cipher suites, compression methods, extensions list,
  SNI list, and hostname) is strictly validated against the available byte slice
  before indexing.
* **Safe Degradation**: Malformed, truncated, non-TLS, or non-ClientHello
  payloads evaluate to ``None`` without raising exceptions.
* **TCP Reassembly Limitation**: This parser operates on single-packet TCP
  payloads. In real networks, standard TLS ClientHello frames (typically 200-800
  bytes) fit comfortably within a standard MTU (1500 bytes) and are observed in
  the initial data segment after the 3-way handshake. However, TCP stream
  reassembly / multi-packet segment buffering is **not implemented in this step**.
  If a ClientHello is fragmented across multiple TCP segments such that the SNI
  extension is split or delayed, ``extract_tls_sni`` returns ``None`` rather than
  speculating or accumulating unbounded state.
"""

from __future__ import annotations

import struct

# TLS Record Layer constants (RFC 5246, RFC 8446)
_TLS_CONTENT_TYPE_HANDSHAKE = 0x16  # 22: Handshake record
_TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01  # 1: ClientHello message

# RFC 6066 (SNI extension) constants
_EXTENSION_SERVER_NAME = 0x0000  # 0: Server Name Indication
_NAME_TYPE_HOST_NAME = 0x00  # 0: host_name


def _is_valid_hostname(host: str) -> bool:
    """Validate extracted hostname conforms to RFC 1035 / RFC 6066 constraints."""
    if not host or len(host) > 253:
        return False
    # Hostnames must not contain control characters, whitespace, colons, or slashes
    for ch in host:
        code = ord(ch)
        if code <= 0x20 or code >= 0x7F or ch in "/:\\?#[]@":
            return False
    return True


def extract_tls_sni(payload: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello packet payload.

    Args:
        payload: Raw TCP packet payload bytes.

    Returns:
        The normalized lowercase SNI hostname if present and valid;
        otherwise ``None``.
    """
    if not payload or len(payload) < 9:  # Min record (5) + min handshake (4)
        return None

    try:
        # 1. TLS Record Header (5 bytes): [ContentType:1][Version:2][Length:2]
        content_type = payload[0]
        if content_type != _TLS_CONTENT_TYPE_HANDSHAKE:
            return None

        major_version = payload[1]
        if major_version != 3:  # SSL 3.0 / TLS 1.0 - 1.3 use major version 3
            return None

        record_len = struct.unpack_from(">H", payload, 3)[0]
        # Data available in this single packet frame
        available_limit = min(len(payload), 5 + record_len)
        if available_limit < 9:
            return None

        # 2. Handshake Header (4 bytes): [Type:1][Length:3]
        handshake_type = payload[5]
        if handshake_type != _TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            return None

        handshake_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
        # In single-packet capture without TCP reassembly, if handshake_len exceeds
        # available frame bytes, the message is fragmented or truncated.
        if 9 + handshake_len > available_limit:
            return None
        handshake_end = 9 + handshake_len

        # 3. ClientHello Body:
        # [ClientVersion:2][Random:32][SessionIDLen:1][SessionID:N]...
        curr = 9 + 2 + 32  # Skip client_version (2) and random (32)
        if curr >= handshake_end:
            return None

        # Session ID
        session_id_len = payload[curr]
        curr += 1 + session_id_len
        if curr + 2 > handshake_end:
            return None

        # Cipher Suites
        cipher_suites_len = struct.unpack_from(">H", payload, curr)[0]
        curr += 2 + cipher_suites_len
        if curr + 1 > handshake_end:
            return None

        # Compression Methods
        compression_methods_len = payload[curr]
        curr += 1 + compression_methods_len

        # If ClientHello ends without extensions block
        if curr == handshake_end:
            return None

        # 4. Extensions block: [ExtensionsLength:2][Extension...]
        if curr + 2 > handshake_end:
            return None

        extensions_len = struct.unpack_from(">H", payload, curr)[0]
        curr += 2
        extensions_end = curr + extensions_len
        if extensions_end > handshake_end:
            return None

        # 5. Walk extensions
        while curr + 4 <= extensions_end:
            ext_type, ext_len = struct.unpack_from(">HH", payload, curr)
            curr += 4
            ext_data_end = curr + ext_len
            if ext_data_end > extensions_end:
                return None

            if ext_type == _EXTENSION_SERVER_NAME:
                # SNI Extension Data:
                # [ServerNameListLength:2][NameType:1][NameLength:2][HostName:N]...
                if ext_len < 2:
                    return None

                list_len = struct.unpack_from(">H", payload, curr)[0]
                sni_ptr = curr + 2
                sni_list_end = sni_ptr + list_len
                if sni_list_end > ext_data_end:
                    return None

                while sni_ptr + 3 <= sni_list_end:
                    name_type = payload[sni_ptr]
                    name_len = struct.unpack_from(">H", payload, sni_ptr + 1)[0]
                    name_start = sni_ptr + 3
                    name_end = name_start + name_len
                    if name_end > sni_list_end:
                        return None

                    if name_type == _NAME_TYPE_HOST_NAME and name_len > 0:
                        raw_host = payload[name_start:name_end]
                        try:
                            host_str = raw_host.decode("ascii").strip().lower().rstrip(".")
                        except UnicodeDecodeError:
                            return None

                        if _is_valid_hostname(host_str):
                            return host_str
                        return None

                    sni_ptr = name_end

                return None

            curr = ext_data_end

        return None

    except Exception:
        # Untrusted binary packet payload must never crash the sensor
        return None


__all__ = ["extract_tls_sni"]
