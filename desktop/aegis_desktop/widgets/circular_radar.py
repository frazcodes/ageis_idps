"""Tactical Circular Radar Widget for Aegis IDPS.

Renders an authentic, military-grade 360-degree sweeping radar HUD:
- Concentric tactical distance rings with range labels.
- 360° rotating radar sweep cone with smooth phosphor decay trail.
- Active host blips mapped dynamically by subnet topology.
- Phosphor illumination flare when the sweep passes over connected devices.
- Flashing strobe alerts for rogue / spoofed devices.
- Interactive hover HUD displaying live IP, MAC, Vendor, and Role.
- Click-to-inspect integration with device tables.
"""

from __future__ import annotations

import math
from typing import Any

from PySide6.QtCore import QPointF, QRectF, QSize, QTimer, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QCursor,
    QFont,
    QMouseEvent,
    QPainter,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget

from aegis_desktop.services.arp_radar import ArpDeviceRow


class TacticalCircularRadarWidget(QWidget):
    """Military-grade circular sweeping radar console for subnet monitoring."""

    device_selected = Signal(str)  # Emits IP address when clicked

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(QSize(380, 380))
        self.setMouseTracking(True)

        self._devices: list[ArpDeviceRow] = []
        self._sweep_angle: float = 0.0
        self._hovered_ip: str | None = None
        self._blip_intensities: dict[str, float] = {}

        # 30 FPS smooth rotating sweep timer
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

    def set_devices(self, devices: list[ArpDeviceRow]) -> None:
        """Update active subnet devices displayed on the radar scope."""
        self._devices = list(devices)
        # Retain blip intensities for existing IPs
        current_ips = {d.ip for d in self._devices}
        self._blip_intensities = {
            ip: val for ip, val in self._blip_intensities.items() if ip in current_ips
        }
        self.update()

    def _on_tick(self) -> None:
        """Advance the sweep beam and decay phosphor flares."""
        self._sweep_angle = (self._sweep_angle + 2.5) % 360.0

        # Decay illuminated blip intensities
        for ip in list(self._blip_intensities.keys()):
            self._blip_intensities[ip] = max(0.0, self._blip_intensities[ip] - 0.035)

        # Trigger redraw
        self.update()

    def _calculate_blip_pos(
        self, dev: ArpDeviceRow, cx: float, cy: float, radius: float
    ) -> tuple[float, float, float]:
        """Compute (x, y, bearing_deg) for a device on the radar scope."""
        if dev.role.endswith("THIS COMPUTER") or "THIS COMPUTER" in dev.role:
            return cx, cy, 0.0

        if "GATEWAY" in dev.role or dev.role.endswith("DEFAULT GATEWAY"):
            # Gateway placed on inner ring at 45° bearing (Northeast)
            r_gw = radius * 0.32
            rad = math.radians(45.0)
            return cx + r_gw * math.cos(rad), cy - r_gw * math.sin(rad), 45.0

        # Endpoints: extract last octet for golden-ratio angular distribution
        try:
            last_octet = int(dev.ip.split(".")[-1])
        except Exception:
            last_octet = hash(dev.ip) % 254

        # Golden angle (137.5 deg) ensures nodes are never clumped together
        bearing_deg = (last_octet * 137.51) % 360.0
        # Distance spread cleanly across mid and outer tactical rings (0.55 to 0.88 R)
        depth_factor = 0.55 + ((last_octet % 5) * 0.075)
        r_dev = radius * min(0.88, depth_factor)

        rad = math.radians(bearing_deg)
        x = cx + r_dev * math.cos(rad)
        # Inverted Y for Cartesian quadrant mapping
        y = cy - r_dev * math.sin(rad)
        return x, y, bearing_deg

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        w = rect.width()
        h = rect.height()
        cx = w / 2.0
        cy = h / 2.0
        # Radar scope radius bounded by widget dimensions with margin
        radius = max(80.0, min(cx, cy) - 24.0)

        # 1. Dark Tactical Background & Outer Scope Bezel
        self._draw_scope_chassis(painter, cx, cy, radius)

        # 2. Concentric Range Rings & Compass Crosshairs
        self._draw_radar_grid(painter, cx, cy, radius)

        # 3. Rotating 360° Sweep Beam with Phosphor Fade Trail
        self._draw_sweep_beam(painter, cx, cy, radius)

        # 4. Device Blips & Flares
        hovered_row: ArpDeviceRow | None = None
        hovered_pos: tuple[float, float] = (0.0, 0.0)

        for dev in self._devices:
            bx, by, bearing = self._calculate_blip_pos(dev, cx, cy, radius)

            # Check if sweep beam is currently passing over the blip
            diff = (self._sweep_angle - bearing) % 360.0
            if diff < 12.0:
                self._blip_intensities[dev.ip] = 1.0

            intensity = self._blip_intensities.get(dev.ip, 0.0)
            is_hovered = dev.ip == self._hovered_ip
            if is_hovered:
                hovered_row = dev
                hovered_pos = (bx, by)

            self._draw_blip(painter, dev, bx, by, intensity, is_hovered)

        # 5. Tactical HUD Overlay (Telemetry & Hovered Device Details)
        self._draw_hud_telemetry(painter, w, h, radius)

        if hovered_row:
            self._draw_target_card(painter, hovered_row, hovered_pos[0], hovered_pos[1], w, h)

    def _draw_scope_chassis(
        self, painter: QPainter, cx: float, cy: float, radius: float
    ) -> None:
        """Draw deep obsidian background and tactical metallic bezel."""
        # Deep circular screen
        scope_rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)
        grad = QRadialGradient(cx, cy, radius)
        grad.setColorAt(0.0, QColor(6, 12, 22, 255))
        grad.setColorAt(0.7, QColor(4, 9, 17, 255))
        grad.setColorAt(1.0, QColor(2, 5, 10, 255))

        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(QColor(16, 185, 129, 60), 2.5))
        painter.drawEllipse(scope_rect)

        # Outer bezel ring
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(30, 41, 59, 200), 4.0))
        painter.drawEllipse(QRectF(cx - radius - 3, cy - radius - 3, (radius + 3) * 2, (radius + 3) * 2))

    def _draw_radar_grid(
        self, painter: QPainter, cx: float, cy: float, radius: float
    ) -> None:
        """Draw tactical distance range rings, crosshairs, and degree ticks."""
        grid_pen = QPen(QColor(16, 185, 129, 45), 1.0, Qt.PenStyle.DashLine)
        axis_pen = QPen(QColor(16, 185, 129, 70), 1.0)
        font = QFont("Segoe UI", 8, QFont.Weight.Bold)
        painter.setFont(font)

        # 4 Concentric Rings
        for fraction, label in [
            (0.25, "RANGE 10m"),
            (0.50, "RANGE 50m"),
            (0.75, "RANGE 100m"),
            (1.00, "SUBNET /24"),
        ]:
            r = radius * fraction
            painter.setPen(grid_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(cx - r, cy - r, r * 2, r * 2))

            # Range label on vertical axis
            painter.setPen(QPen(QColor(16, 185, 129, 110)))
            painter.drawText(int(cx + 4), int(cy - r + 12), label)

        # Crosshairs: Horizontal & Vertical Axes
        painter.setPen(axis_pen)
        painter.drawLine(int(cx - radius), int(cy), int(cx + radius), int(cy))
        painter.drawLine(int(cx), int(cy - radius), int(cx), int(cy + radius))

        # Compass Bearings
        painter.setPen(QPen(QColor(56, 189, 248, 200)))
        painter.drawText(int(cx - 5), int(cy - radius + 16), "N")
        painter.drawText(int(cx + radius - 16), int(cy + 4), "E")
        painter.drawText(int(cx - 5), int(cy + radius - 6), "S")
        painter.drawText(int(cx - radius + 6), int(cy + 4), "W")

        # 30-degree perimeter tick marks
        for deg in range(0, 360, 30):
            rad = math.radians(deg)
            r_in = radius - 5
            r_out = radius
            x1 = cx + r_in * math.cos(rad)
            y1 = cy - r_in * math.sin(rad)
            x2 = cx + r_out * math.cos(rad)
            y2 = cy - r_out * math.sin(rad)
            painter.setPen(QPen(QColor(16, 185, 129, 80), 1.5))
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))

    def _draw_sweep_beam(
        self, painter: QPainter, cx: float, cy: float, radius: float
    ) -> None:
        """Draw rotating 360-degree radar beam with phosphor fade fan."""
        painter.save()

        # Draw phosphor trail cone (fan of 28 fine sectors fading backward)
        cone_steps = 28
        cone_angle = 50.0  # degrees of phosphor trail
        for i in range(cone_steps):
            frac = i / float(cone_steps)
            trail_deg = (self._sweep_angle - (cone_angle * frac)) % 360.0
            alpha = int(75 * (1.0 - frac) ** 1.8)
            rad1 = math.radians(trail_deg)
            rad2 = math.radians((trail_deg + 2.0) % 360.0)

            p1 = QPointF(cx, cy)
            p2 = QPointF(cx + radius * math.cos(rad1), cy - radius * math.sin(rad1))
            p3 = QPointF(cx + radius * math.cos(rad2), cy - radius * math.sin(rad2))

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(16, 185, 129, alpha)))
            painter.drawPolygon([p1, p2, p3])

        # Main active laser line
        lead_rad = math.radians(self._sweep_angle)
        sweep_x = cx + radius * math.cos(lead_rad)
        sweep_y = cy - radius * math.sin(lead_rad)

        beam_pen = QPen(QColor(52, 211, 153, 230), 2.0)
        painter.setPen(beam_pen)
        painter.drawLine(int(cx), int(cy), int(sweep_x), int(sweep_y))

        painter.restore()

    def _draw_blip(
        self,
        painter: QPainter,
        dev: ArpDeviceRow,
        bx: float,
        by: float,
        intensity: float,
        is_hovered: bool,
    ) -> None:
        """Draw an active host blip with role-based colors, strobe rings, and labels."""
        is_suspicious = dev.is_suspicious
        is_gateway = "GATEWAY" in dev.role
        is_local = "THIS COMPUTER" in dev.role

        # Base color selection
        if is_suspicious:
            base_col = QColor(239, 68, 68)  # Crimson Red
        elif is_local:
            base_col = QColor(56, 189, 248)  # Cyber Sky Blue
        elif is_gateway:
            base_col = QColor(245, 158, 11)  # Amber
        else:
            base_col = QColor(16, 185, 129)  # Emerald Green

        # Flare glow ring when sweep hits blip
        if intensity > 0.05:
            flare_r = 7.0 + (intensity * 14.0)
            flare_alpha = int(intensity * 180)
            flare_col = QColor(base_col.red(), base_col.green(), base_col.blue(), flare_alpha)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(flare_col, 2.0))
            painter.drawEllipse(QRectF(bx - flare_r, by - flare_r, flare_r * 2, flare_r * 2))

        # Suspicious strobe ring
        if is_suspicious:
            strobe_r = 12.0 + (math.sin(self._sweep_angle * 0.15) * 4.0)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor(239, 68, 68, 220), 2.0, Qt.PenStyle.DashLine))
            painter.drawEllipse(QRectF(bx - strobe_r, by - strobe_r, strobe_r * 2, strobe_r * 2))

        # Core Blip
        dot_r = 6.0 if is_hovered else 4.5
        painter.setPen(QPen(QColor(255, 255, 255, 240), 1.5 if is_hovered else 1.0))
        painter.setBrush(QBrush(base_col))
        painter.drawEllipse(QRectF(bx - dot_r, by - dot_r, dot_r * 2, dot_r * 2))

        # Hostname/Vendor Label
        painter.setPen(QPen(QColor(226, 232, 240, 220)))
        font = QFont("Segoe UI", 8, QFont.Weight.Bold if is_hovered else QFont.Weight.Normal)
        painter.setFont(font)

        tag = "THIS PC" if is_local else ("GATEWAY" if is_gateway else dev.vendor.split()[0])
        painter.drawText(int(bx + 8), int(by + 4), f"{dev.ip} ({tag})")

    def _draw_hud_telemetry(
        self, painter: QPainter, w: int, h: int, radius: float
    ) -> None:
        """Render upper and lower digital HUD telemetry readouts."""
        painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold))

        # Top Left: Status & Pulse
        painter.setPen(QPen(QColor(16, 185, 129)))
        painter.drawText(14, 20, "● TACTICAL RADAR: ACTIVE SWEEP")

        # Top Right: Bearing & Speed
        painter.setPen(QPen(QColor(148, 163, 184)))
        painter.drawText(w - 180, 20, f"BEARING: {int(self._sweep_angle):03d}° | 30 FPS")

        # Bottom Left: Device Counts
        tot = len(self._devices)
        suspicious = sum(1 for d in self._devices if d.is_suspicious)
        stat_color = QColor(239, 68, 68) if suspicious > 0 else QColor(56, 189, 248)
        painter.setPen(QPen(stat_color))
        painter.drawText(
            14,
            h - 12,
            f"TARGETS ACQUIRED: {tot} HOSTS" + (f" | 🚨 {suspicious} THREATS" if suspicious else ""),
        )

    def _draw_target_card(
        self, painter: QPainter, dev: ArpDeviceRow, bx: float, by: float, w: int, h: int
    ) -> None:
        """Render glowing tactical target inspector box for hovered device."""
        card_w = 200.0
        card_h = 92.0
        # Position card cleanly near blip without overflowing screen
        card_x = bx + 14
        if card_x + card_w > w - 10:
            card_x = bx - card_w - 14
        card_y = by - 14
        if card_y + card_h > h - 10:
            card_y = h - card_h - 10

        card_rect = QRectF(card_x, card_y, card_w, card_h)

        # Background card
        painter.setBrush(QBrush(QColor(10, 16, 28, 245)))
        border_col = QColor(239, 68, 68) if dev.is_suspicious else QColor(56, 189, 248)
        painter.setPen(QPen(border_col, 1.5))
        painter.drawRoundedRect(card_rect, 6, 6)

        # Text inside HUD Card
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.setPen(QPen(border_col))
        painter.drawText(int(card_x + 10), int(card_y + 18), f"TARGET: {dev.ip}")

        painter.setFont(QFont("Consolas", 8))
        painter.setPen(QPen(QColor(203, 213, 225)))
        painter.drawText(int(card_x + 10), int(card_y + 36), f"MAC:    {dev.mac}")
        painter.drawText(int(card_x + 10), int(card_y + 52), f"VENDOR: {dev.vendor[:18]}")
        painter.drawText(int(card_x + 10), int(card_y + 68), f"ROLE:   {dev.role[:18]}")
        painter.drawText(int(card_x + 10), int(card_y + 84), f"STATUS: {dev.status}")

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        pos = event.position()
        mx = pos.x()
        my = pos.y()

        w = self.width()
        h = self.height()
        cx = w / 2.0
        cy = h / 2.0
        radius = max(80.0, min(cx, cy) - 24.0)

        found_ip: str | None = None
        for dev in self._devices:
            bx, by, _ = self._calculate_blip_pos(dev, cx, cy, radius)
            dist = math.hypot(mx - bx, my - by)
            if dist <= 14.0:
                found_ip = dev.ip
                break

        if found_ip != self._hovered_ip:
            self._hovered_ip = found_ip
            self.setCursor(
                QCursor(Qt.CursorShape.PointingHandCursor)
                if found_ip
                else QCursor(Qt.CursorShape.ArrowCursor)
            )
            self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._hovered_ip:
            self.device_selected.emit(self._hovered_ip)
