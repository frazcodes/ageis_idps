"""ARP Radar: Subnet device discovery, MAC vendor resolution, and ARP spoofing detector.

Features:
1. Subnet & Wi-Fi Rogue Device Discovery: Discovers active hosts via ARP telemetry.
2. MAC Vendor (OUI) Identification: Translates hardware MAC addresses into manufacturer brands
   (e.g., Apple, Samsung, Intel, Cisco, Raspberry Pi, Espressif IoT, etc.).
3. ARP Cache Poisoning & MITM Attack Detection:
   - Detects conflicting MAC addresses claiming the same IP (cache poisoning).
   - Detects rogue devices impersonating the Default Gateway (gateway poisoning).
   - Detects Gratuitous ARP flooding / rapid spoof bursts.
4. Safe, non-crashing execution: Works offline and with live Scapy capture.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from aegis_shared.enums import Severity
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# MAC Vendor OUI Database (Extensive normalized prefixes)
# ---------------------------------------------------------------------------

_OUI_VENDORS: dict[str, str] = {
    # Apple
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0a:95": "Apple",
    "00:0d:93": "Apple",
    "00:10:fa": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:cb": "Apple",
    "00:17:f2": "Apple",
    "00:19:e3": "Apple",
    "00:1b:63": "Apple",
    "00:1c:b3": "Apple",
    "00:1d:4f": "Apple",
    "00:1e:52": "Apple",
    "00:1f:5b": "Apple",
    "00:1f:f3": "Apple",
    "00:21:e9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:df": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4b": "Apple",
    "00:26:08": "Apple",
    "00:26:b0": "Apple",
    "3c:07:54": "Apple",
    "3c:15:c2": "Apple",
    "3c:ab:8e": "Apple",
    "40:6c:8f": "Apple",
    "70:56:81": "Apple",
    "8c:85:90": "Apple",
    "a4:83:e7": "Apple",
    "ac:de:48": "Apple",
    "bc:d0:74": "Apple",
    "f0:18:98": "Apple",
    "f4:5c:89": "Apple",
    # Samsung
    "00:07:ab": "Samsung",
    "00:12:47": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:6b": "Samsung",
    "00:17:c9": "Samsung",
    "00:18:af": "Samsung",
    "00:1a:8a": "Samsung",
    "00:21:4c": "Samsung",
    "00:24:54": "Samsung",
    "00:26:37": "Samsung",
    "50:01:d9": "Samsung",
    "64:1c:67": "Samsung",
    "94:63:72": "Samsung",
    "a0:0b:ba": "Samsung",
    "d8:90:e8": "Samsung",
    # Intel
    "00:02:b3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:0e:35": "Intel",
    "00:11:11": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:15:00": "Intel",
    "00:16:76": "Intel",
    "00:19:d1": "Intel",
    "00:1b:21": "Intel",
    "00:1c:c0": "Intel",
    "00:1d:e0": "Intel",
    "00:1e:64": "Intel",
    "00:21:5c": "Intel",
    "00:22:fb": "Intel",
    "00:23:14": "Intel",
    "00:24:d7": "Intel",
    "34:13:e8": "Intel",
    "70:1c:e8": "Intel",
    "8c:ec:4b": "Intel",
    # Cisco
    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:01:63": "Cisco",
    "00:01:96": "Cisco",
    "00:02:16": "Cisco",
    "00:02:ba": "Cisco",
    "00:03:e3": "Cisco",
    "00:05:31": "Cisco",
    "00:0c:85": "Cisco",
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "28:cd:c1": "Raspberry Pi",
    # Espressif IoT (Smart Home / ESP32 / ESP8266)
    "18:fe:34": "Espressif IoT",
    "24:0a:c4": "Espressif IoT",
    "24:6f:28": "Espressif IoT",
    "30:ae:a4": "Espressif IoT",
    "84:0d:8e": "Espressif IoT",
    "84:f3:eb": "Espressif IoT",
    "a4:e5:7c": "Espressif IoT",
    "bc:dd:c2": "Espressif IoT",
    "d8:a0:1d": "Espressif IoT",
    # Microsoft
    "00:03:ff": "Microsoft",
    "00:0d:3a": "Microsoft",
    "00:15:5d": "Microsoft",
    "00:17:fa": "Microsoft",
    "00:50:f2": "Microsoft",
    "28:18:78": "Microsoft",
    "7c:ed:8d": "Microsoft",
    # Dell
    "00:06:5b": "Dell",
    "00:08:74": "Dell",
    "00:0b:db": "Dell",
    "00:11:43": "Dell",
    "00:14:22": "Dell",
    "00:18:8b": "Dell",
    "00:21:70": "Dell",
    "00:24:e8": "Dell",
    "14:fe:b5": "Dell",
    # HP
    "00:01:e6": "HP",
    "00:02:a5": "HP",
    "00:08:02": "HP",
    "00:0e:7f": "HP",
    "00:11:0a": "HP",
    "00:14:c2": "HP",
    "00:16:35": "HP",
    "00:1a:4b": "HP",
    "00:1e:0b": "HP",
    "00:23:7d": "HP",
    # TP-Link
    "00:19:e0": "TP-Link",
    "00:27:19": "TP-Link",
    "14:cc:20": "TP-Link",
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    # Google
    "00:1a:11": "Google",
    "3c:5a:37": "Google",
    "54:60:09": "Google",
    "f4:03:04": "Google",
    # Realtek
    "00:e0:4c": "Realtek",
    "52:54:00": "QEMU/Realtek",
    # Virtualization / Emulation
    "00:05:69": "VMware",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "02:42:ac": "Docker Container",
    # Networking gear
    "00:18:0a": "Cisco Meraki",
    "00:26:86": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",
    "00:0c:42": "MikroTik",
    "48:8f:5a": "MikroTik",
    "00:0f:66": "Huawei",
    "00:1e:10": "Huawei",
    "88:40:3b": "Huawei",
    "80:9d:65": "Realtek",
    "74:a7:8e": "Xiaomi",
    "00:9e:c8": "Xiaomi",
    "18:59:36": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "74:23:44": "Xiaomi",
    "ec:d0:9f": "Xiaomi",
    "90:cb:a3": "Vivo Mobile",
    "1c:77:f6": "Vivo Mobile",
    "24:e2:71": "Vivo Mobile",
    "54:44:8c": "Vivo Mobile",
    "04:79:70": "Oppo Mobile",
    "14:0c:76": "Oppo Mobile",
    "1c:1b:0d": "Oppo Mobile",
    "94:65:2d": "OnePlus",
    "a0:93:47": "OnePlus",
    "c0:ee:fb": "OnePlus",
}


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address string to lowercase colon-separated format."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac.strip().lower())
    if len(clean) == 12:
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return mac.strip().lower()


def lookup_mac_vendor(mac: str) -> str:
    """Resolve the manufacturer brand from a MAC address via OUI prefix lookup."""
    norm = normalize_mac(mac)
    if norm in ("ff:ff:ff:ff:ff:ff", "broadcast"):
        return "Broadcast"
    if norm.startswith("01:00:5e") or norm.startswith("33:33"):
        return "Multicast"

    prefix = norm[:8].lower()
    if prefix in _OUI_VENDORS:
        return _OUI_VENDORS[prefix]

    # Locally administered MACs (randomized MAC address on iOS/Android/Windows)
    # Bit 1 of first byte set to 1 indicates locally administered / private randomized MAC.
    try:
        first_byte = int(norm[:2], 16)
        if first_byte & 0x02:
            return "Private / Randomized MAC"
    except (ValueError, IndexError) as exc:
        logger.debug("Failed parsing MAC first byte: %s", exc)

    return "Unknown Vendor"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ArpDevice(BaseModel):
    """An active host endpoint discovered on the local subnet via ARP."""

    ip: str = Field(..., max_length=64)
    mac: str = Field(..., max_length=32)
    vendor: str = Field(default="Unknown Vendor", max_length=64)
    hostname: str | None = Field(default=None, max_length=128)
    is_gateway: bool = False
    is_local_host: bool = False
    is_suspicious: bool = False
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    packet_count: int = 1


class ArpAlert(BaseModel):
    """A security alert generated by suspicious ARP activity or MITM attempt."""

    alert_id: str
    alert_type: str  # GATEWAY_SPOOFING | ARP_CACHE_POISONING | GRATUITOUS_FLOOD | ROGUE_DEVICE
    ip: str
    claimed_mac: str
    original_mac: str
    severity: Severity = Severity.HIGH
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Stateful ARP Tracker & Spoofing Detector
# ---------------------------------------------------------------------------


class ArpTracker:
    """Tracks subnet hosts, detects cache poisoning, and flags rogue devices."""

    def __init__(
        self,
        *,
        known_gateway_ip: str | None = None,
        known_gateway_mac: str | None = None,
        local_host_ip: str | None = None,
        local_host_mac: str | None = None,
        gratuitous_window_seconds: float = 2.0,
        gratuitous_burst_limit: int = 4,
    ) -> None:
        self.known_gateway_ip = known_gateway_ip
        self.known_gateway_mac = (
            normalize_mac(known_gateway_mac) if known_gateway_mac else None
        )
        self.local_host_ip = local_host_ip
        self.local_host_mac = normalize_mac(local_host_mac) if local_host_mac else None
        self.gratuitous_window = gratuitous_window_seconds
        self.gratuitous_limit = gratuitous_burst_limit

        self._devices: dict[str, ArpDevice] = {}
        self._ip_to_mac: dict[str, str] = {}
        self._gratuitous_timestamps: dict[str, list[float]] = {}
        self._alerts: list[ArpAlert] = []

    def set_gateway(self, ip: str, mac: str | None = None) -> None:
        """Explicitly set or update the known default gateway IP and MAC."""
        self.known_gateway_ip = ip.strip()
        if mac:
            self.known_gateway_mac = normalize_mac(mac)
            if self.known_gateway_ip in self._devices:
                dev = self._devices[self.known_gateway_ip]
                self._devices[self.known_gateway_ip] = dev.model_copy(
                    update={"is_gateway": True, "mac": self.known_gateway_mac}
                )

    def observe_arp(
        self,
        *,
        src_ip: str,
        src_mac: str,
        dst_ip: str = "",
        dst_mac: str = "",
        op: int = 2,  # 1=request, 2=reply
        timestamp: datetime | None = None,
    ) -> list[ArpAlert]:
        """Process an observed ARP frame, update device state, and detect attacks."""
        src_ip = src_ip.strip()
        src_mac = normalize_mac(src_mac)
        dst_ip = dst_ip.strip()
        dst_mac = normalize_mac(dst_mac)
        ts = timestamp or datetime.now(UTC)
        now_epoch = time.time()

        if not src_ip or not src_mac or src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return []

        alerts: list[ArpAlert] = []

        # 1. Detect Gateway Spoofing / MITM
        if self.known_gateway_ip and src_ip == self.known_gateway_ip:
            if self.known_gateway_mac and src_mac != self.known_gateway_mac:
                alert = ArpAlert(
                    alert_id=f"ARP-GW-SPOOF-{int(now_epoch * 1000)}",
                    alert_type="GATEWAY_SPOOFING",
                    ip=src_ip,
                    claimed_mac=src_mac,
                    original_mac=self.known_gateway_mac,
                    severity=Severity.CRITICAL,
                    message=(
                        f"CRITICAL MITM DETECTED: Default Gateway ({src_ip}) is being "
                        f"impersonated by rogue MAC {src_mac} "
                        f"(Legitimate Gateway: {self.known_gateway_mac})."
                    ),
                    timestamp=ts,
                )
                alerts.append(alert)
                self._alerts.append(alert)
                logger.critical(alert.message)
            elif not self.known_gateway_mac:
                # First time seeing the gateway MAC
                self.known_gateway_mac = src_mac

        # 2. Detect IP Conflict / ARP Cache Poisoning for non-gateway hosts
        existing_mac = self._ip_to_mac.get(src_ip)
        if not alerts and existing_mac and existing_mac != src_mac:
            # IP was previously mapped to a different MAC!
            alert = ArpAlert(
                alert_id=f"ARP-POISON-{int(now_epoch * 1000)}",
                alert_type="ARP_CACHE_POISONING",
                ip=src_ip,
                claimed_mac=src_mac,
                original_mac=existing_mac,
                severity=Severity.HIGH,
                message=(
                    f"ARP CACHE POISONING: IP {src_ip} conflict detected. Originally bound "
                    f"to {existing_mac}, now claimed by rogue MAC {src_mac}."
                ),
                timestamp=ts,
            )
            alerts.append(alert)
            self._alerts.append(alert)
            logger.warning(alert.message)

        # 3. Detect Gratuitous ARP Flooding (Unsolicited Announcements)
        # In a Gratuitous ARP, src_ip == dst_ip or dst_mac == broadcast
        is_gratuitous = (src_ip == dst_ip) or (dst_mac in ("ff:ff:ff:ff:ff:ff", "broadcast"))
        if is_gratuitous and op == 2:
            burst_list = self._gratuitous_timestamps.setdefault(src_mac, [])
            burst_list.append(now_epoch)
            # Retain only timestamps within the sliding window
            self._gratuitous_timestamps[src_mac] = [
                t for t in burst_list if now_epoch - t <= self.gratuitous_window
            ]
            if len(self._gratuitous_timestamps[src_mac]) > self.gratuitous_limit:
                alert = ArpAlert(
                    alert_id=f"ARP-GRAT-FLOOD-{int(now_epoch * 1000)}",
                    alert_type="GRATUITOUS_FLOOD",
                    ip=src_ip,
                    claimed_mac=src_mac,
                    original_mac=src_mac,
                    severity=Severity.HIGH,
                    message=(
                        f"GRATUITOUS ARP FLOOD: Rogue device {src_mac} ({src_ip}) sent "
                        f"{len(self._gratuitous_timestamps[src_mac])} unsolicited announcements "
                        f"in {self.gratuitous_window}s."
                    ),
                    timestamp=ts,
                )
                alerts.append(alert)
                self._alerts.append(alert)

        # 4. Update device inventory
        is_gw = bool(self.known_gateway_ip and src_ip == self.known_gateway_ip)
        is_local = bool(self.local_host_ip and src_ip == self.local_host_ip)
        is_suspicious = len(alerts) > 0 or (
            src_ip in self._devices and self._devices[src_ip].is_suspicious
        )

        vendor = lookup_mac_vendor(src_mac)
        if src_ip in self._devices:
            dev = self._devices[src_ip]
            self._devices[src_ip] = dev.model_copy(
                update={
                    "mac": src_mac,
                    "vendor": vendor,
                    "is_gateway": is_gw or dev.is_gateway,
                    "is_local_host": is_local or dev.is_local_host,
                    "is_suspicious": is_suspicious or dev.is_suspicious,
                    "last_seen": ts,
                    "packet_count": dev.packet_count + 1,
                }
            )
        else:
            self._devices[src_ip] = ArpDevice(
                ip=src_ip,
                mac=src_mac,
                vendor=vendor,
                is_gateway=is_gw,
                is_local_host=is_local,
                is_suspicious=is_suspicious,
                first_seen=ts,
                last_seen=ts,
                packet_count=1,
            )

        self._ip_to_mac[src_ip] = src_mac
        return alerts

    def observe_packet(self, pkt: Any) -> list[ArpAlert]:
        """Convenience method to observe a Scapy packet object if it contains ARP."""
        try:
            # Check Scapy ARP layer
            if hasattr(pkt, "haslayer") and pkt.haslayer("ARP"):
                arp = pkt["ARP"]
                return self.observe_arp(
                    src_ip=str(getattr(arp, "psrc", "")),
                    src_mac=str(getattr(arp, "hwsrc", "")),
                    dst_ip=str(getattr(arp, "pdst", "")),
                    dst_mac=str(getattr(arp, "hwdst", "")),
                    op=int(getattr(arp, "op", 2)),
                )
        except Exception as exc:
            logger.debug("Failed to extract ARP from packet: %s", exc)
        return []

    def get_devices(self) -> list[ArpDevice]:
        """Return all discovered devices sorted by IP address."""
        def _ip_sort_key(dev: ArpDevice) -> tuple[int, ...]:
            try:
                return tuple(int(part) for part in dev.ip.split("."))
            except Exception:
                return (999, 999, 999, 999)

        return sorted(self._devices.values(), key=_ip_sort_key)

    def get_alerts(self) -> list[ArpAlert]:
        """Return all recorded ARP security alerts."""
        return list(self._alerts)

    def remove_device(self, ip: str) -> bool:
        """Remove a device that has disconnected from the subnet."""
        ip = ip.strip()
        if ip in self._devices:
            del self._devices[ip]
            self._ip_to_mac.pop(ip, None)
            return True
        return False

    def sync_active_ips(self, current_active_ips: set[str]) -> list[str]:
        """Prune devices that are no longer active on the subnet.

        Preserves the default gateway and local host. Returns list of removed IPs.
        """
        removed: list[str] = []
        for ip in list(self._devices.keys()):
            if (self.local_host_ip and ip == self.local_host_ip) or (
                self.known_gateway_ip and ip == self.known_gateway_ip
            ):
                continue
            if ip not in current_active_ips:
                del self._devices[ip]
                self._ip_to_mac.pop(ip, None)
                removed.append(ip)
        return removed

    def prune_stale(self, max_age_seconds: float = 60.0) -> list[str]:
        """Remove devices not seen within `max_age_seconds`.

        Preserves the default gateway and local host.
        """
        now = datetime.now(UTC)
        removed: list[str] = []
        for ip, dev in list(self._devices.items()):
            if (self.local_host_ip and ip == self.local_host_ip) or (
                self.known_gateway_ip and ip == self.known_gateway_ip
            ):
                continue
            age = (now - dev.last_seen).total_seconds()
            if age > max_age_seconds:
                del self._devices[ip]
                self._ip_to_mac.pop(ip, None)
                removed.append(ip)
        return removed

    def clear_alerts(self) -> None:
        """Clear recorded security alerts."""
        self._alerts.clear()
