"""Desktop service for ARP Radar, Subnet Rogue Device Scanning, and MITM Defense.

Bridges the network sensor ARP tracking engine to the PySide6 UI:
- Discovers local gateway and host parameters.
- Seeds device directory from OS ARP table and passive/active Scapy frames.
- Formats device rows and alert banners for the desktop console.
"""

from __future__ import annotations

import contextlib
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any

from aegis_network_sensor.arp_radar import (
    ArpAlert,
    ArpTracker,
    normalize_mac,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ArpDeviceRow:
    """Presentation row for the desktop ARP Radar table."""

    ip: str
    mac: str
    vendor: str
    role: str
    status: str
    is_suspicious: bool
    first_seen: str
    last_seen: str
    packets: int


class ArpRadarService:
    """Service managing subnet device discovery and ARP spoofing detection."""

    def __init__(
        self, tracker: ArpTracker | None = None, *, auto_seed: bool = True
    ) -> None:
        self.tracker = tracker or ArpTracker()
        self._gateway_ip: str = ""
        self._gateway_mac: str = ""
        self._local_ip: str = ""
        self._local_mac: str = ""
        self._subnet_cidr: str = ""
        self._detect_local_network()
        if auto_seed and tracker is None:
            self.read_system_arp_table()

    def _detect_local_network(self) -> None:
        """Detect local IP, default gateway, and subnet range."""
        if self.tracker.known_gateway_ip:
            self._gateway_ip = self.tracker.known_gateway_ip
        if self.tracker.local_host_ip:
            self._local_ip = self.tracker.local_host_ip

        try:
            import scapy.all as scapy_all

            conf_route = getattr(scapy_all.conf, "route", None)
            if conf_route is not None:
                route = conf_route.route("0.0.0.0")  # noqa: S104
                if route and len(route) >= 3:
                    if not self._local_ip:
                        self._local_ip = str(route[1])
                        self.tracker.local_host_ip = self._local_ip
                    if not self._gateway_ip:
                        self._gateway_ip = str(route[2])
                        self.tracker.known_gateway_ip = self._gateway_ip
        except Exception as exc:
            logger.debug("Could not determine route via scapy: %s", exc)

        # Fallback local IP detection via dummy UDP socket
        if not self._local_ip or self._local_ip.startswith("0."):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self._local_ip = s.getsockname()[0]
                    if not self.tracker.local_host_ip:
                        self.tracker.local_host_ip = self._local_ip
            except Exception:
                self._local_ip = "127.0.0.1"

        if self._local_ip and not self._local_ip.startswith("127."):
            parts = self._local_ip.split(".")
            if len(parts) == 4:
                self._subnet_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if not self._gateway_ip:
                    self._gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
                    if not self.tracker.known_gateway_ip:
                        self.tracker.known_gateway_ip = self._gateway_ip

    @property
    def gateway_ip(self) -> str:
        return self._gateway_ip or "—"

    @property
    def local_ip(self) -> str:
        return self._local_ip or "—"

    @property
    def subnet_cidr(self) -> str:
        return self._subnet_cidr or "192.168.1.0/24"

    def read_system_arp_table(self, *, sync_active: bool = False) -> list[ArpAlert]:
        """Read the OS ARP table cache (arp -a) to immediately seed active devices.

        This guarantees that even in environments without raw socket capture permissions,
        existing network devices and the default gateway are discovered.
        If `sync_active` is True, devices no longer present in the OS ARP cache are pruned.
        """
        alerts: list[ArpAlert] = []
        discovered_ips: set[str] = set()
        try:
            output = subprocess.check_output(
                ["arp", "-a"],  # noqa: S607
                stderr=subprocess.DEVNULL,
                timeout=3.0,
                text=True,
            )
            # Match IPv4 addresses followed by MAC addresses
            # Format: 192.168.1.1   00-11-22-33-44-55   dynamic
            pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
            )
            for match in pattern.finditer(output):
                ip, mac = match.groups()
                mac_norm = normalize_mac(mac)
                if mac_norm in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    continue
                if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                    continue

                discovered_ips.add(ip)
                new_alerts = self.tracker.observe_arp(
                    src_ip=ip,
                    src_mac=mac_norm,
                    op=2,
                )
                alerts.extend(new_alerts)

            if sync_active:
                self.tracker.sync_active_ips(discovered_ips)
        except Exception as exc:
            logger.debug("Failed reading system ARP cache: %s", exc)
        return alerts

    def sync_live_endpoints(self) -> list[str]:
        """Perform a real-time liveness check on active subnet endpoints.

        Fast unicast ping (150ms timeout) checks whether currently tracked endpoint devices
        (e.g., smartphones, laptops, IoT nodes) are still connected to the subnet.
        If a device disconnected or turned off its Wi-Fi, it fails the probe and is immediately
        pruned from the active ARP Radar directory.
        """
        import concurrent.futures

        devices = self.tracker.get_devices()
        # Endpoints to check (excluding default gateway and local host)
        endpoints = [
            d.ip
            for d in devices
            if not d.is_gateway
            and not d.is_local_host
            and d.ip != self._local_ip
            and d.ip != self._gateway_ip
        ]

        if not endpoints:
            self.read_system_arp_table(sync_active=True)
            return []

        dead_ips: list[str] = []

        def _check_endpoint(ip: str) -> tuple[str, bool]:
            with contextlib.suppress(Exception):
                res = subprocess.run(  # noqa: S603
                    ["ping", "-n", "1", "-w", "150", ip],  # noqa: S607
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.3,
                )
                return ip, (res.returncode == 0)
            return ip, False

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(16, len(endpoints))
            ) as executor:
                results = list(executor.map(_check_endpoint, endpoints))
                for ip, alive in results:
                    if not alive:
                        dead_ips.append(ip)
                        self.tracker.remove_device(ip)
        except Exception as exc:
            logger.debug("Endpoint liveness probe encountered error: %s", exc)

        # Harvest OS ARP table to sync any newly cached devices
        self.read_system_arp_table(sync_active=True)
        return dead_ips

    def _sweep_subnet_ping(self, subnet_cidr: str) -> None:
        """Perform a fast concurrent ping sweep to wake up sleeping Wi-Fi / mobile devices.

        Wi-Fi routers (especially 4G Wingles and mobile hotspots) suppress L2 broadcast ARP
        between wireless stations to save power. Probing the /24 subnet triggers the OS network
        stack to resolve ARP for every active node, immediately populating the OS ARP cache.
        """
        import concurrent.futures

        # Extract base /24 prefix
        parts = subnet_cidr.split("/")[0].split(".")
        if len(parts) < 3:
            return
        base = f"{parts[0]}.{parts[1]}.{parts[2]}"
        ips = [f"{base}.{i}" for i in range(1, 255)]

        def _ping_host(ip: str) -> None:
            with contextlib.suppress(Exception):
                subprocess.run(  # noqa: S603
                    ["ping", "-n", "1", "-w", "150", ip],  # noqa: S607
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.4,
                )

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
                list(executor.map(_ping_host, ips))
        except Exception as exc:
            logger.debug("Subnet ping sweep encountered error: %s", exc)

    def scan_subnet(
        self, custom_cidr: str | None = None, *, probe_sweep: bool = True
    ) -> tuple[int, list[ArpAlert]]:
        """Trigger an active ARP scan of the local subnet.

        1. Performs a fast concurrent ping sweep to wake up sleeping Wi-Fi endpoints.
        2. Reads the system ARP table cache.
        3. Attempts Scapy L2 ARP broadcast probe if supported.
        """
        all_alerts: list[ArpAlert] = []
        target_subnet = custom_cidr or self.subnet_cidr

        if probe_sweep:
            self._sweep_subnet_ping(target_subnet)

        # 1. Immediate system ARP table harvest
        sys_alerts = self.read_system_arp_table()
        all_alerts.extend(sys_alerts)

        # 2. Scapy active ARP broadcast if sensor extra is available
        try:
            import scapy.all as scapy_all
            from scapy.layers.l2 import ARP, Ether

            # Build ARP who-has broadcast
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)
            # Send and receive ARP responses (timeout bounded to 1.5s)
            ans, _ = scapy_all.srp(
                arp_req,
                timeout=1.5,
                verbose=False,
                retry=0,
            )
            for _, rcv in ans:
                if rcv.haslayer("ARP"):
                    arp_layer = rcv["ARP"]
                    new_alerts = self.tracker.observe_arp(
                        src_ip=str(arp_layer.psrc),
                        src_mac=str(arp_layer.hwsrc),
                        op=2,
                    )
                    all_alerts.extend(new_alerts)
        except Exception as exc:
            logger.debug("Scapy active ARP scan skipped or unsupported: %s", exc)

        return len(self.tracker.get_devices()), all_alerts

    def get_rows(self) -> list[ArpDeviceRow]:
        """Convert discovered devices into sorted presentation rows."""
        devices = self.tracker.get_devices()
        rows: list[ArpDeviceRow] = []

        for dev in devices:
            # Determine role
            if dev.is_suspicious:
                role = "🚨 SUSPICIOUS / SPOOFER"
                status = "ATTACK DETECTED"
            elif dev.is_gateway:
                role = "🌐 DEFAULT GATEWAY"
                status = "ACTIVE"
            elif dev.is_local_host or dev.ip == self._local_ip:
                role = "💻 THIS COMPUTER"
                status = "ONLINE"
            else:
                role = "📱 ENDPOINT NODE"
                status = "ACTIVE"

            rows.append(
                ArpDeviceRow(
                    ip=dev.ip,
                    mac=dev.mac,
                    vendor=dev.vendor,
                    role=role,
                    status=status,
                    is_suspicious=dev.is_suspicious,
                    first_seen=dev.first_seen.strftime("%H:%M:%S"),
                    last_seen=dev.last_seen.strftime("%H:%M:%S"),
                    packets=dev.packet_count,
                )
            )

        return rows

    def get_summary(self) -> dict[str, Any]:
        """Return high-level summary counters for radar header cards."""
        devices = self.tracker.get_devices()
        alerts = self.tracker.get_alerts()
        suspicious_count = sum(1 for d in devices if d.is_suspicious)

        return {
            "total_devices": len(devices),
            "gateway_ip": self.gateway_ip,
            "local_ip": self.local_ip,
            "subnet": self.subnet_cidr,
            "suspicious_count": suspicious_count,
            "alerts_count": len(alerts),
            "is_mitm_detected": any(a.alert_type == "GATEWAY_SPOOFING" for a in alerts),
        }
