"""Elite enterprise SOC login screen for the Aegis IDPS desktop console.

A full-screen, frameless authentication window with:
  - Animated particle-network background (QPainter)
  - Pulsing animated shield / hex logo
  - Glassmorphism login card
  - Custom input fields with inline icons and eye-toggle
  - Live UTC clock + date strip
  - System pre-check status badges (DB · Agent · Sensor)
  - Animated "AEGIS" scan-line text reveal
  - Smooth fade-in on open, fade-out on success
  - Signal-based result handoff (credentials + success flag)

Usage::

    from aegis_desktop.login import LoginWindow

    def _on_auth(username: str, success: bool) -> None:
        if success:
            main_window.show()

    login = LoginWindow(on_authenticate=_on_auth)
    login.show()
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import random
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPointF,
    QPropertyAnimation,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QConicalGradient,
    QFont,
    QFontMetrics,
    QKeySequence,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
    QShortcut,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.services.license_client import LicenseClient, LocalLicense

# ---------------------------------------------------------------------------
# Station Session Management (4-Hour Secure Session Window)
# ---------------------------------------------------------------------------

SESSION_FILE = Path.home() / ".aegis" / "session.json"


def _check_station_session(expected_key: str | None) -> tuple[bool, int]:
    """Check if an active temporary unlock session exists. Returns (is_valid, minutes_left)."""
    if not expected_key:
        return (False, 0)
    try:
        if not SESSION_FILE.exists():
            return (False, 0)
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        saved_key = data.get("key", "").strip().upper()
        if saved_key != expected_key.strip().upper():
            return (False, 0)
        exp_ts = float(data.get("expires_at", 0))
        now_ts = datetime.now(UTC).timestamp()
        if exp_ts > now_ts:
            mins_left = max(1, int((exp_ts - now_ts) // 60))
            return (True, mins_left)
        # Expired session
        SESSION_FILE.unlink(missing_ok=True)
        return (False, 0)
    except Exception:
        return (False, 0)


def _save_station_session(key: str, hours: int = 4) -> None:
    """Persist session token for the given hours."""
    try:
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        exp_ts = datetime.now(UTC).timestamp() + (hours * 3600)
        SESSION_FILE.write_text(
            json.dumps({"key": key.strip().upper(), "expires_at": exp_ts}),
            encoding="utf-8",
        )
    except Exception:
        pass


def _clear_station_session() -> None:
    """Clear any persisted session token."""
    try:
        SESSION_FILE.unlink(missing_ok=True)
    except Exception:
        pass
# ---------------------------------------------------------------------------

_BG         = "#080D18"
_BG2        = "#0A0F1C"
_SURFACE    = "#0F1829"
_CARD       = "#111E30"
_CARD2      = "#16243A"
_BORDER     = "#1F2D44"
_BORDER2    = "#2A3D5A"
_ACCENT     = "#1D4ED8"
_ACCENT2    = "#2563EB"
_ACCENT3    = "#3B82F6"
_CYAN       = "#06B6D4"
_GREEN      = "#10B981"
_RED        = "#EF4444"
_AMBER      = "#F59E0B"
_TEXT       = "#F1F5F9"
_TEXT2      = "#CBD5E1"
_MUTED      = "#64748B"
_MUTED2     = "#94A3B8"
_FONT       = '"Inter", "Segoe UI", "Roboto", sans-serif'

# ---------------------------------------------------------------------------
# Particle system
# ---------------------------------------------------------------------------

class _Particle:
    """One floating node in the animated background network."""

    __slots__ = ("x", "y", "vx", "vy", "radius", "alpha", "pulse", "pulse_speed")

    def __init__(self, w: int, h: int) -> None:
        self.x: float = random.uniform(0, w)
        self.y: float = random.uniform(0, h)
        self.vx: float = random.uniform(-0.18, 0.18)
        self.vy: float = random.uniform(-0.12, 0.12)
        self.radius: float = random.uniform(1.2, 2.8)
        self.alpha: int = random.randint(60, 160)
        self.pulse: float = random.uniform(0, math.pi * 2)
        self.pulse_speed: float = random.uniform(0.02, 0.06)

    def step(self, w: int, h: int) -> None:
        self.x += self.vx
        self.y += self.vy
        self.pulse += self.pulse_speed
        if self.x < 0:   self.x += w
        if self.x > w:   self.x -= w
        if self.y < 0:   self.y += h
        if self.y > h:   self.y -= h


# ---------------------------------------------------------------------------
# Animated background canvas
# ---------------------------------------------------------------------------

class _BackgroundCanvas(QWidget):
    """Full-screen animated particle-network background."""

    _PARTICLE_COUNT = 90
    _CONNECT_DIST   = 130
    _TICK_MS        = 33   # ~30 fps for background

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._particles: list[_Particle] = []
        self._scan_y: float = 0.0
        self._tick: int = 0
        self._hex_angle: float = 0.0
        self._init_particles()

        self._timer = QTimer(self)
        self._timer.setInterval(self._TICK_MS)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

    def _init_particles(self) -> None:
        w, h = self.width() or 1920, self.height() or 1080
        self._particles = [_Particle(w, h) for _ in range(self._PARTICLE_COUNT)]

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        self._init_particles()
        super().resizeEvent(event)

    def _on_tick(self) -> None:
        self._tick += 1
        w, h = self.width(), self.height()
        self._scan_y = (self._scan_y + 0.6) % (h or 1)
        self._hex_angle = (self._hex_angle + 0.4) % 360
        for p in self._particles:
            p.step(w, h)
        self.update()

    # -- Painting ------------------------------------------------------------

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # Deep gradient background
        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0.00, QColor("#060B15"))
        bg.setColorAt(0.40, QColor(_BG2))
        bg.setColorAt(0.75, QColor("#080E1C"))
        bg.setColorAt(1.00, QColor("#040810"))
        painter.fillRect(0, 0, w, h, QBrush(bg))

        # Subtle vignette overlay
        vig = QRadialGradient(w / 2, h / 2, max(w, h) * 0.7)
        vig.setColorAt(0.0, QColor(0, 0, 0, 0))
        vig.setColorAt(1.0, QColor(0, 0, 0, 120))
        painter.fillRect(0, 0, w, h, QBrush(vig))

        # Horizontal scan-line glow
        scan_grad = QLinearGradient(0, self._scan_y - 40, 0, self._scan_y + 40)
        scan_grad.setColorAt(0.0, QColor(6, 182, 212, 0))
        scan_grad.setColorAt(0.5, QColor(6, 182, 212, 14))
        scan_grad.setColorAt(1.0, QColor(6, 182, 212, 0))
        painter.fillRect(0, int(self._scan_y - 40), w, 80, QBrush(scan_grad))

        # Particle connections
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        pts = self._particles
        n = len(pts)
        for i in range(n):
            for j in range(i + 1, n):
                dx = pts[i].x - pts[j].x
                dy = pts[i].y - pts[j].y
                dist = math.hypot(dx, dy)
                if dist < self._CONNECT_DIST:
                    alpha = int(50 * (1.0 - dist / self._CONNECT_DIST))
                    c = QColor(_ACCENT3)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, 0.6))
                    painter.drawLine(
                        QPointF(pts[i].x, pts[i].y),
                        QPointF(pts[j].x, pts[j].y),
                    )

        # Particle nodes
        painter.setPen(Qt.PenStyle.NoPen)
        for p in pts:
            pulse_alpha = int(p.alpha + 40 * math.sin(p.pulse))
            pulse_r = p.radius + 0.8 * math.sin(p.pulse)
            c = QColor(_ACCENT3)
            c.setAlpha(max(0, min(255, pulse_alpha)))
            painter.setBrush(QBrush(c))
            painter.drawEllipse(
                QPointF(p.x, p.y), pulse_r, pulse_r
            )

        painter.end()


# ---------------------------------------------------------------------------
# Animated Aegis Shield Logo
# ---------------------------------------------------------------------------

class _ShieldLogo(QWidget):
    """Custom-painted animated Aegis shield with rotating ring and pulse."""

    _SIZE = 96

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(self._SIZE, self._SIZE)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._angle: float = 0.0
        self._pulse: float = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self) -> None:
        self._angle = (self._angle + 1.2) % 360
        self._pulse = (self._pulse + 0.05) % (math.pi * 2)
        self.update()

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self._SIZE / 2, self._SIZE / 2
        s = self._SIZE

        # Outer pulsing glow ring
        glow_r = 44 + 3 * math.sin(self._pulse)
        glow = QRadialGradient(cx, cy, glow_r)
        glow.setColorAt(0.6, QColor(29, 78, 216, 0))
        glow.setColorAt(0.82, QColor(29, 78, 216, 60))
        glow.setColorAt(1.0, QColor(29, 78, 216, 0))
        p.setBrush(QBrush(glow))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(cx, cy), glow_r, glow_r)

        # Rotating dashed arc ring
        p.save()
        p.translate(cx, cy)
        p.rotate(self._angle)
        arc_pen = QPen(QColor(37, 99, 235, 140), 1.5)
        arc_pen.setStyle(Qt.PenStyle.DashLine)
        arc_pen.setDashPattern([4, 6])
        p.setPen(arc_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPointF(0, 0), 41, 41)
        p.restore()

        # Counter-rotating inner ring
        p.save()
        p.translate(cx, cy)
        p.rotate(-self._angle * 0.6)
        inner_pen = QPen(QColor(6, 182, 212, 90), 1.0)
        inner_pen.setStyle(Qt.PenStyle.DotLine)
        p.setPen(inner_pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPointF(0, 0), 33, 33)
        p.restore()

        # Shield body fill (gradient)
        shield_path = QPainterPath()
        r = 28.0
        shield_path.moveTo(cx, cy - r)
        shield_path.cubicTo(cx + r * 1.05, cy - r * 0.6,
                            cx + r * 1.05, cy + r * 0.2,
                            cx, cy + r * 1.1)
        shield_path.cubicTo(cx - r * 1.05, cy + r * 0.2,
                            cx - r * 1.05, cy - r * 0.6,
                            cx, cy - r)
        shield_path.closeSubpath()

        shield_fill = QLinearGradient(cx - r, cy - r, cx + r, cy + r)
        shield_fill.setColorAt(0.0, QColor("#1E3A6E"))
        shield_fill.setColorAt(0.5, QColor("#1D4ED8"))
        shield_fill.setColorAt(1.0, QColor("#0F2555"))
        p.setBrush(QBrush(shield_fill))
        shield_border = QPen(QColor(_ACCENT3), 1.5)
        p.setPen(shield_border)
        p.drawPath(shield_path)

        # Shield inner glow highlight
        shield_hl = QLinearGradient(cx - 12, cy - 20, cx + 12, cy)
        shield_hl.setColorAt(0.0, QColor(255, 255, 255, 40))
        shield_hl.setColorAt(1.0, QColor(255, 255, 255, 0))
        p.setBrush(QBrush(shield_hl))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(shield_path)

        # "A" letter on shield
        font = QFont("Segoe UI", 16, QFont.Weight.Black)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1)
        p.setFont(font)
        p.setPen(QPen(QColor(_TEXT)))
        p.drawText(
            QRectF(cx - 14, cy - 14, 28, 28),
            Qt.AlignmentFlag.AlignCenter,
            "A",
        )

        # Corner accent dots on ring
        for deg in [0, 90, 180, 270]:
            rad = math.radians(deg + self._angle)
            dx = 41 * math.cos(rad)
            dy = 41 * math.sin(rad)
            p.setBrush(QBrush(QColor(_CYAN)))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(cx + dx, cy + dy), 2.5, 2.5)

        p.end()


# ---------------------------------------------------------------------------
# Custom password input with eye-toggle
# ---------------------------------------------------------------------------

class _IconLineEdit(QFrame):
    """Styled input field with left icon label and optional eye-toggle."""

    returnPressed = Signal()

    def __init__(
        self,
        placeholder: str = "",
        *,
        password: bool = False,
        icon: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._is_password = password
        self._obscured = password

        self.setObjectName("LoginField")
        self.setFixedHeight(50)
        self.setStyleSheet(f"""
            #LoginField {{
                background-color: {_CARD2};
                border: 1.5px solid {_BORDER};
                border-radius: 10px;
            }}
            #LoginField:focus-within {{
                border: 1.5px solid {_ACCENT2};
                background-color: #1A2840;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 10, 0)
        layout.setSpacing(10)

        # Left icon label
        if icon:
            icon_lbl = QLabel(icon)
            icon_lbl.setFixedWidth(20)
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_lbl.setStyleSheet(f"color: {_MUTED2}; font-size: 15px; background: transparent;")
            layout.addWidget(icon_lbl)

        # Actual text input
        self._edit = QLineEdit()
        self._edit.setPlaceholderText(placeholder)
        if password:
            self._edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._edit.setStyleSheet(f"""
            QLineEdit {{
                background: transparent;
                border: none;
                color: {_TEXT};
                font-size: 14px;
                font-family: {_FONT};
                selection-background-color: {_ACCENT};
            }}
            QLineEdit::placeholder {{ color: {_MUTED}; }}
        """)
        self._edit.returnPressed.connect(self.returnPressed)
        layout.addWidget(self._edit, 1)

        # Eye toggle (password only)
        if password:
            self._eye_btn = QPushButton("👁")
            self._eye_btn.setFixedSize(28, 28)
            self._eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._eye_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    color: {_MUTED};
                    font-size: 15px;
                    padding: 0;
                }}
                QPushButton:hover {{ color: {_TEXT2}; }}
            """)
            self._eye_btn.clicked.connect(self._toggle_eye)
            layout.addWidget(self._eye_btn)

    def _toggle_eye(self) -> None:
        self._obscured = not self._obscured
        mode = QLineEdit.EchoMode.Password if self._obscured else QLineEdit.EchoMode.Normal
        self._edit.setEchoMode(mode)
        self._eye_btn.setText("👁" if self._obscured else "🙈")

    def text(self) -> str:
        return self._edit.text()

    def set_focus(self) -> None:
        self._edit.setFocus()

    def shake(self) -> None:
        """Brief horizontal shake animation on failed login."""
        anim = QPropertyAnimation(self, b"pos")
        anim.setDuration(350)
        orig = self.pos()
        anim.setKeyValueAt(0.0,  orig)
        anim.setKeyValueAt(0.10, QPoint(orig.x() - 8, orig.y()))
        anim.setKeyValueAt(0.25, QPoint(orig.x() + 8, orig.y()))
        anim.setKeyValueAt(0.40, QPoint(orig.x() - 6, orig.y()))
        anim.setKeyValueAt(0.60, QPoint(orig.x() + 6, orig.y()))
        anim.setKeyValueAt(0.80, QPoint(orig.x() - 3, orig.y()))
        anim.setKeyValueAt(1.0,  orig)
        anim.setEasingCurve(QEasingCurve.Type.Linear)
        self._shake_anim = anim
        anim.start()
        self.setStyleSheet(f"""
            #LoginField {{
                background-color: {_CARD2};
                border: 1.5px solid {_RED};
                border-radius: 10px;
            }}
        """)
        QTimer.singleShot(600, self._reset_border)

    def _reset_border(self) -> None:
        self.setStyleSheet(f"""
            #LoginField {{
                background-color: {_CARD2};
                border: 1.5px solid {_BORDER};
                border-radius: 10px;
            }}
            #LoginField:focus-within {{
                border: 1.5px solid {_ACCENT2};
                background-color: #1A2840;
            }}
        """)


# ---------------------------------------------------------------------------
# System status badge
# ---------------------------------------------------------------------------

class _StatusBadge(QWidget):
    """Compact animated status dot + label."""

    def __init__(self, label: str, *, status: str = "checking",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._dot_alpha: int = 255
        self._dot_dir: int = -6
        self._color = _AMBER
        self._status = status

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._dot = QLabel("●")
        self._dot.setFixedWidth(12)
        self._dot.setStyleSheet(f"color: {_AMBER}; font-size: 9px; background: transparent;")

        self._lbl = QLabel(label)
        self._lbl.setStyleSheet(f"color: {_MUTED2}; font-size: 11px; background: transparent;")

        layout.addWidget(self._dot)
        layout.addWidget(self._lbl)

        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._pulse)
        self._timer.start()

    def _pulse(self) -> None:
        if self._status == "checking":
            self._dot_alpha += self._dot_dir
            if self._dot_alpha <= 80 or self._dot_alpha >= 255:
                self._dot_dir *= -1
            c = QColor(_AMBER)
            c.setAlpha(self._dot_alpha)
            self._dot.setStyleSheet(
                f"color: rgba({c.red()},{c.green()},{c.blue()},{self._dot_alpha}); "
                f"font-size: 9px; background: transparent;"
            )

    def set_ok(self, text: str | None = None) -> None:
        self._status = "ok"
        self._timer.stop()
        self._dot.setStyleSheet(f"color: {_GREEN}; font-size: 9px; background: transparent;")
        if text:
            self._lbl.setText(text)

    def set_error(self, text: str | None = None) -> None:
        self._status = "error"
        self._timer.stop()
        self._dot.setStyleSheet(f"color: {_RED}; font-size: 9px; background: transparent;")
        if text:
            self._lbl.setText(text)


# ---------------------------------------------------------------------------
# Live UTC clock strip
# ---------------------------------------------------------------------------

class _ClockStrip(QLabel):
    """Live UTC date + time label, updated every second."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(
            f"color: {_MUTED}; font-size: 11px; letter-spacing: 1px; background: transparent;"
        )
        self._refresh()
        timer = QTimer(self)
        timer.setInterval(1000)
        timer.timeout.connect(self._refresh)
        timer.start()

    def _refresh(self) -> None:
        now = datetime.now(UTC)
        self.setText(now.strftime("UTC  %Y-%m-%d    %H:%M:%S"))


# ---------------------------------------------------------------------------
# Main login card (glassmorphism)
# ---------------------------------------------------------------------------

class _LoginCard(QFrame):
    """The centred semi-transparent login card with unified Node License Authentication."""

    authenticated = Signal(str, str)  # (operator_name, license_key)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(470, 640)
        self.setObjectName("LoginCard")
        self.setStyleSheet(f"""
            #LoginCard {{
                background-color: rgba(11, 22, 42, 0.90);
                border: 1.5px solid {_BORDER2};
                border-radius: 20px;
            }}
        """)

        # Card drop shadow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(60)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 190))
        self.setGraphicsEffect(shadow)

        self._client = LicenseClient()
        self._local_lic: LocalLicense | None = self._client.load_local_license()
        self._key_field: _IconLineEdit | None = None
        self._remember_cb: QCheckBox | None = None
        self._session_mins: int = 0

        if not self._local_lic:
            self._mode = "activate"
        elif self._local_lic.is_expired:
            self._mode = "expired"
        else:
            is_active, self._session_mins = _check_station_session(self._local_lic.key)
            self._mode = "session_active" if is_active else "locked"

        self._build()

    def _build(self) -> None:
        self._key_field = None
        self._remember_cb = None

        # Clear existing layout if rebuilding
        old_layout = self.layout()
        if old_layout is not None:
            QWidget().setLayout(old_layout)

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 28, 36, 24)
        root.setSpacing(0)

        # ── Logo + branding ──────────────────────────────────────────────
        logo_row = QHBoxLayout()
        logo_row.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._shield = _ShieldLogo()
        logo_row.addWidget(self._shield)
        root.addLayout(logo_row)
        root.addSpacing(10)

        product = QLabel("AEGIS IDPS")
        product.setAlignment(Qt.AlignmentFlag.AlignCenter)
        product.setStyleSheet(
            f"color: {_TEXT}; font-size: 22px; font-weight: 800; "
            f"letter-spacing: 4px; background: transparent;"
        )
        root.addWidget(product)

        tagline = QLabel("Security Operations Console")
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline.setStyleSheet(
            f"color: {_MUTED2}; font-size: 11px; letter-spacing: 2px; background: transparent;"
        )
        root.addWidget(tagline)
        root.addSpacing(10)

        # Divider line
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background: {_BORDER}; border: none;")
        root.addWidget(divider)
        root.addSpacing(10)

        # ── Hardware ID Card (Two-tier clean layout: Label + Copy Button on top, Monospace Key below) ──
        hwid_frame = QFrame()
        hwid_frame.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(15, 23, 42, 0.88);
                border: 1px solid rgba(56, 189, 248, 0.32);
                border-radius: 10px;
            }}
        """)
        hwid_layout = QVBoxLayout(hwid_frame)
        hwid_layout.setContentsMargins(14, 9, 14, 9)
        hwid_layout.setSpacing(6)

        # Top row: Label & Copy Button
        hwid_top_row = QHBoxLayout()
        hwid_top_row.setContentsMargins(0, 0, 0, 0)
        hwid_top_row.setSpacing(8)

        hwid_title = QLabel("ENDPOINT HARDWARE ID (HWID)")
        hwid_title.setStyleSheet(f"""
            color: {_CYAN};
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 1px;
            background: transparent;
        """)

        self._copy_btn = QPushButton("COPY HWID")
        self._copy_btn.setFixedHeight(24)
        self._copy_btn.setMinimumWidth(95)
        self._copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_btn.setToolTip("Click to copy HWID to clipboard")
        self._copy_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(6, 182, 212, 0.18);
                color: #38BDF8;
                border: 1px solid rgba(56, 189, 248, 0.50);
                border-radius: 5px;
                padding: 0 8px;
                font-size: 10.5px;
                font-weight: 800;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06B6D4,
                    stop:1 #2563EB
                );
                color: #FFFFFF;
                border: 1px solid #38BDF8;
            }}
            QPushButton:pressed {{
                background: #0284C7;
            }}
        """)
        self._copy_btn.clicked.connect(self._copy_hwid)

        hwid_top_row.addWidget(hwid_title)
        hwid_top_row.addStretch()
        hwid_top_row.addWidget(self._copy_btn)
        hwid_layout.addLayout(hwid_top_row)

        # Bottom row: The full 35-character code in a dedicated dark monospace box
        code_box = QFrame()
        code_box.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(2, 6, 23, 0.95);
                border: 1px solid rgba(51, 65, 85, 0.85);
                border-radius: 6px;
            }}
        """)
        code_layout = QHBoxLayout(code_box)
        code_layout.setContentsMargins(10, 5, 10, 5)

        hwid_val = QLabel(self._client.hardware_id)
        hwid_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hwid_val.setStyleSheet(f"""
            color: #F8FAFC;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.8px;
            background: transparent;
        """)
        code_layout.addWidget(hwid_val)
        hwid_layout.addWidget(code_box)

        root.addWidget(hwid_frame)
        root.addSpacing(12)

        # ── Dynamic Section: 4 Distinct States ───────────────────────────
        if self._mode == "session_active" and self._local_lic and not self._local_lic.is_expired:
            # STATE 1: Active 4-Hour Session Exists
            auth_badge = QLabel(f"●  STATION UNLOCKED — ACTIVE SESSION ({self._session_mins}m left)")
            auth_badge.setStyleSheet(f"color: {_GREEN}; font-size: 11px; font-weight: 700; letter-spacing: 0.8px; background: transparent;")
            root.addWidget(auth_badge)
            root.addSpacing(8)

            profile_card = QFrame()
            profile_card.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(16, 185, 129, 0.08);
                    border: 1px solid rgba(16, 185, 129, 0.30);
                    border-radius: 10px;
                }}
            """)
            p_layout = QVBoxLayout(profile_card)
            p_layout.setContentsMargins(14, 10, 14, 10)
            p_layout.setSpacing(3)

            op_name = QLabel(f"Operator: {self._local_lic.client_name}")
            op_name.setStyleSheet(f"color: {_TEXT}; font-size: 13px; font-weight: 700; background: transparent;")
            org_name = QLabel(f"Org: {self._local_lic.organization}  •  Key: {self._local_lic.key}")
            org_name.setStyleSheet(f"color: {_MUTED2}; font-size: 11px; background: transparent;")

            p_layout.addWidget(op_name)
            p_layout.addWidget(org_name)
            root.addWidget(profile_card)
            root.addSpacing(12)

            self._login_btn = QPushButton("RESUME SOC CONSOLE")
            self._login_btn.setFixedHeight(46)
            self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._login_btn.setObjectName("LoginBtn")
            self._login_btn.setStyleSheet(self._login_btn_style())
            self._login_btn.clicked.connect(self._on_resume_session)
            root.addWidget(self._login_btn)
            root.addSpacing(8)

            lock_btn = QPushButton("Lock station now / Require key on next launch")
            lock_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            lock_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    color: {_MUTED2};
                    font-size: 10.5px;
                }}
                QPushButton:hover {{ color: {_RED}; text-decoration: underline; }}
            """)
            lock_btn.clicked.connect(self._lock_station_now)
            root.addWidget(lock_btn)

        elif self._mode == "locked" and self._local_lic:
            # STATE 2: Station Locked (Default on App Close/Restart)
            lock_badge = QLabel("●  STATION LOCKED — AUTHENTICATION REQUIRED")
            lock_badge.setStyleSheet(f"color: {_CYAN}; font-size: 11px; font-weight: 700; letter-spacing: 0.8px; background: transparent;")
            root.addWidget(lock_badge)
            root.addSpacing(6)

            info_lbl = QLabel(f"Registered Station: {self._local_lic.client_name} ({self._local_lic.organization})")
            info_lbl.setStyleSheet(f"color: {_MUTED2}; font-size: 11px; background: transparent;")
            root.addWidget(info_lbl)
            root.addSpacing(8)

            desc = QLabel("Enter your 16-character License Key to unlock:")
            desc.setStyleSheet(f"color: {_TEXT}; font-size: 11px; font-weight: 600; background: transparent;")
            root.addWidget(desc)
            root.addSpacing(6)

            self._key_field = _IconLineEdit("AEGIS-XXXX-XXXX-XXXX", icon="🔑", parent=self)
            self._key_field._edit.setMaxLength(25)
            self._key_field._edit.setStyleSheet(self._key_field._edit.styleSheet() + "; font-family: 'Consolas', monospace; font-weight: bold; letter-spacing: 1px;")
            self._key_field._edit.textChanged.connect(lambda t: self._key_field._edit.setText(t.upper()) if t != t.upper() else None)
            self._key_field.returnPressed.connect(self._on_unlock_clicked)
            root.addWidget(self._key_field)
            root.addSpacing(8)

            # Checkbox: Remember for 4 hours
            self._remember_cb = QCheckBox("Keep station unlocked for 4 hours")
            self._remember_cb.setChecked(False)
            self._remember_cb.setCursor(Qt.CursorShape.PointingHandCursor)
            self._remember_cb.setStyleSheet(f"""
                QCheckBox {{
                    color: {_MUTED2};
                    font-size: 11px;
                    spacing: 8px;
                    background: transparent;
                }}
                QCheckBox:hover {{
                    color: {_TEXT};
                }}
            """)
            root.addWidget(self._remember_cb)
            root.addSpacing(12)

            self._login_btn = QPushButton("UNLOCK & ENTER SOC CONSOLE")
            self._login_btn.setFixedHeight(46)
            self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._login_btn.setObjectName("LoginBtn")
            self._login_btn.setStyleSheet(self._login_btn_style())
            self._login_btn.clicked.connect(self._on_unlock_clicked)
            root.addWidget(self._login_btn)
            root.addSpacing(8)

            switch_btn = QPushButton("Enter a different license key")
            switch_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            switch_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: none;
                    color: {_MUTED2};
                    font-size: 10.5px;
                }}
                QPushButton:hover {{ color: {_CYAN}; text-decoration: underline; }}
            """)
            switch_btn.clicked.connect(self._switch_to_activation_mode)
            root.addWidget(switch_btn)

        elif self._mode == "expired" and self._local_lic:
            # STATE 3: License Expired (Blocked)
            exp_badge = QLabel("●  LICENSE EXPIRED — ACCESS RESTRICTED")
            exp_badge.setStyleSheet(f"color: {_RED}; font-size: 11px; font-weight: 700; letter-spacing: 0.8px; background: transparent;")
            root.addWidget(exp_badge)
            root.addSpacing(6)

            exp_card = QFrame()
            exp_card.setStyleSheet(f"""
                QFrame {{
                    background-color: rgba(239, 68, 68, 0.08);
                    border: 1px solid rgba(239, 68, 68, 0.35);
                    border-radius: 10px;
                }}
            """)
            exp_layout = QVBoxLayout(exp_card)
            exp_layout.setContentsMargins(14, 8, 14, 8)
            exp_layout.setSpacing(3)

            exp_op = QLabel(f"Operator: {self._local_lic.client_name}")
            exp_op.setStyleSheet(f"color: {_TEXT}; font-size: 12px; font-weight: 700; background: transparent;")
            exp_notice = QLabel("License duration ended. Contact Master Admin to renew.")
            exp_notice.setStyleSheet(f"color: {_RED}; font-size: 11px; background: transparent;")

            exp_layout.addWidget(exp_op)
            exp_layout.addWidget(exp_notice)
            root.addWidget(exp_card)
            root.addSpacing(10)

            desc = QLabel("Enter your renewed 16-character license key:")
            desc.setStyleSheet(f"color: {_TEXT}; font-size: 11px; font-weight: 600; background: transparent;")
            root.addWidget(desc)
            root.addSpacing(6)

            self._key_field = _IconLineEdit("AEGIS-XXXX-XXXX-XXXX", icon="🔑", parent=self)
            self._key_field._edit.setMaxLength(25)
            self._key_field._edit.setStyleSheet(self._key_field._edit.styleSheet() + "; font-family: 'Consolas', monospace; font-weight: bold; letter-spacing: 1px;")
            self._key_field._edit.textChanged.connect(lambda t: self._key_field._edit.setText(t.upper()) if t != t.upper() else None)
            self._key_field.returnPressed.connect(self._on_unlock_clicked)
            root.addWidget(self._key_field)
            root.addSpacing(14)

            self._login_btn = QPushButton("VERIFY & ACTIVATE RENEWED KEY")
            self._login_btn.setFixedHeight(46)
            self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._login_btn.setObjectName("LoginBtn")
            self._login_btn.setStyleSheet(self._login_btn_style())
            self._login_btn.clicked.connect(self._on_unlock_clicked)
            root.addWidget(self._login_btn)

        else:
            # STATE 4: Fresh Node Activation (First Time)
            act_badge = QLabel("●  ENTERPRISE NODE ACTIVATION")
            act_badge.setStyleSheet(f"color: {_CYAN}; font-size: 11px; font-weight: 700; letter-spacing: 0.8px; background: transparent;")
            root.addWidget(act_badge)
            root.addSpacing(6)

            desc = QLabel("Enter your 16-character license key issued by Aegis Cloud:")
            desc.setStyleSheet(f"color: {_MUTED2}; font-size: 11px; background: transparent;")
            root.addWidget(desc)
            root.addSpacing(8)

            self._key_field = _IconLineEdit("AEGIS-XXXX-XXXX-XXXX", icon="🔑", parent=self)
            self._key_field._edit.setMaxLength(25)
            self._key_field._edit.setStyleSheet(self._key_field._edit.styleSheet() + "; font-family: 'Consolas', monospace; font-weight: bold; letter-spacing: 1px;")
            self._key_field._edit.textChanged.connect(lambda t: self._key_field._edit.setText(t.upper()) if t != t.upper() else None)
            self._key_field.returnPressed.connect(self._on_unlock_clicked)
            root.addWidget(self._key_field)
            root.addSpacing(8)

            self._remember_cb = QCheckBox("Keep station unlocked for 4 hours")
            self._remember_cb.setChecked(False)
            self._remember_cb.setCursor(Qt.CursorShape.PointingHandCursor)
            self._remember_cb.setStyleSheet(f"""
                QCheckBox {{
                    color: {_MUTED2};
                    font-size: 11px;
                    spacing: 8px;
                    background: transparent;
                }}
                QCheckBox:hover {{
                    color: {_TEXT};
                }}
            """)
            root.addWidget(self._remember_cb)
            root.addSpacing(12)

            self._login_btn = QPushButton("AUTHORIZE & ENTER CONSOLE")
            self._login_btn.setFixedHeight(46)
            self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._login_btn.setObjectName("LoginBtn")
            self._login_btn.setStyleSheet(self._login_btn_style())
            self._login_btn.clicked.connect(self._on_unlock_clicked)
            root.addWidget(self._login_btn)
            root.addSpacing(8)

            if self._local_lic and not self._local_lic.is_expired:
                cancel_btn = QPushButton("Cancel (Return to locked station)")
                cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                cancel_btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent;
                        border: none;
                        color: {_MUTED2};
                        font-size: 10.5px;
                    }}
                    QPushButton:hover {{ color: {_TEXT}; }}
                """)
                cancel_btn.clicked.connect(self._switch_to_locked_mode)
                root.addWidget(cancel_btn)

        # ── Error banner ─────────────────────────────────────────────────
        self._error_lbl = QLabel("")
        self._error_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error_lbl.setWordWrap(True)
        self._error_lbl.setFixedHeight(22)
        self._error_lbl.setStyleSheet(f"color: {_RED}; font-size: 11px; background: transparent;")
        root.addWidget(self._error_lbl)

        root.addStretch()

        # ── Bottom divider + system status ───────────────────────────────
        bot_div = QFrame()
        bot_div.setFixedHeight(1)
        bot_div.setStyleSheet(f"background: {_BORDER}; border: none;")
        root.addWidget(bot_div)
        root.addSpacing(10)

        status_row = QHBoxLayout()
        status_row.setSpacing(16)
        self._db_badge    = _StatusBadge("Database")
        self._agent_badge = _StatusBadge("Agent")
        self._net_badge   = _StatusBadge("Sensor")
        status_row.addStretch()
        status_row.addWidget(self._db_badge)
        status_row.addWidget(self._agent_badge)
        status_row.addWidget(self._net_badge)
        status_row.addStretch()
        root.addLayout(status_row)

        # Auto-simulate "checking → ok" for all status badges
        QTimer.singleShot(800,  lambda: self._db_badge.set_ok("Database"))
        QTimer.singleShot(1100, lambda: self._agent_badge.set_ok("Agent"))
        QTimer.singleShot(1400, lambda: self._net_badge.set_ok("Sensor"))

    # -- Actions -------------------------------------------------------------

    def _login_btn_style(self) -> str:
        return f"""
            #LoginBtn {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {_ACCENT},
                    stop:1 {_ACCENT2}
                );
                color: #FFFFFF;
                border: none;
                border-radius: 10px;
                font-size: 13px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
            #LoginBtn:hover {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {_ACCENT2},
                    stop:1 {_ACCENT3}
                );
            }}
            #LoginBtn:disabled {{
                background: #1E293B;
                color: {_MUTED};
            }}
        """

    def _format_validity(self, expires_at: str) -> str:
        if not expires_at or "2099" in expires_at or "lifetime" in expires_at.lower():
            return "Perpetual Lifetime License"
        try:
            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            now = datetime.now(UTC)
            diff = exp_dt.timestamp() - now.timestamp()
            if diff <= 0:
                return "Expired"
            days = max(1, int(diff // 86400))
            if days == 1:
                return f"Expires in 1 day ({exp_dt.strftime('%b %d, %Y')})"
            return f"{days} days remaining ({exp_dt.strftime('%b %d, %Y')})"
        except Exception:
            return f"Expires: {expires_at[:10]}"

    def _copy_hwid(self) -> None:
        """Copy Hardware ID to system clipboard with instant feedback."""
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(self._client.hardware_id)
            self._copy_btn.setText("COPIED!")
            self._copy_btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(16, 185, 129, 0.25);
                    color: #34D399;
                    border: 1px solid #10B981;
                    border-radius: 5px;
                    padding: 0 8px;
                    font-size: 10.5px;
                    font-weight: 800;
                    letter-spacing: 0.5px;
                }}
            """)

            def _restore() -> None:
                self._copy_btn.setText("COPY HWID")
                self._copy_btn.setStyleSheet(f"""
                    QPushButton {{
                        background: rgba(6, 182, 212, 0.18);
                        color: #38BDF8;
                        border: 1px solid rgba(56, 189, 248, 0.50);
                        border-radius: 5px;
                        padding: 0 8px;
                        font-size: 10.5px;
                        font-weight: 800;
                        letter-spacing: 0.5px;
                    }}
                    QPushButton:hover {{
                        background: qlineargradient(
                            x1:0, y1:0, x2:1, y2:0,
                            stop:0 #06B6D4,
                            stop:1 #2563EB
                        );
                        color: #FFFFFF;
                        border: 1px solid #38BDF8;
                    }}
                    QPushButton:pressed {{
                        background: #0284C7;
                    }}
                """)

            QTimer.singleShot(1800, _restore)

    def _switch_to_activation_mode(self) -> None:
        self._mode = "activate"
        self._build()
        if self._key_field is not None:
            try:
                self._key_field.set_focus()
            except RuntimeError:
                pass

    def _switch_to_locked_mode(self) -> None:
        self._local_lic = self._client.load_local_license()
        if not self._local_lic:
            self._mode = "activate"
        elif self._local_lic.is_expired:
            self._mode = "expired"
        else:
            is_active, self._session_mins = _check_station_session(self._local_lic.key)
            self._mode = "session_active" if is_active else "locked"
        self._build()

    def _on_resume_session(self) -> None:
        """Directly enter console when 4-hour session is active."""
        if not self._local_lic:
            self._switch_to_activation_mode()
            return
        self._set_loading(True, "Resuming Session…")
        op_name = self._local_lic.client_name
        key = self._local_lic.key
        QTimer.singleShot(400, lambda: self.authenticated.emit(op_name, key))

    def _lock_station_now(self) -> None:
        """Lock station immediately and clear active 4-hour session."""
        _clear_station_session()
        self._mode = "locked"
        self._build()
        if self._key_field is not None:
            try:
                self._key_field.set_focus()
            except RuntimeError:
                pass

    def set_focus(self) -> None:
        if self._key_field is not None:
            try:
                self._key_field.set_focus()
            except RuntimeError:
                pass

    def _on_unlock_clicked(self) -> None:
        """Validate license key to unlock the station."""
        if self._key_field is None:
            return

        try:
            key = self._key_field.text().strip().upper()
        except RuntimeError:
            return

        if not key or len(key) < 5:
            self._show_error("Please enter your 16-character license key.")
            try:
                self._key_field.shake()
            except RuntimeError:
                pass
            return

        self._error_lbl.setText("")
        self._set_loading(True, "Verifying Station Key…")

        def _do_auth() -> None:
            remember_4h = self._remember_cb.isChecked() if self._remember_cb is not None else False

            # Check if key matches local license
            if self._local_lic and key == self._local_lic.key.strip().upper():
                if self._local_lic.is_expired:
                    self._set_loading(False)
                    self._show_error("This license key has expired. Contact admin to renew.")
                    return
                if remember_4h:
                    _save_station_session(key, hours=4)
                else:
                    _clear_station_session()
                self._set_loading(False)
                self.authenticated.emit(self._local_lic.client_name, key)
                return

            # Otherwise, verify online against Firebase/Cloud
            res = self._client.activate_online(key)
            if res.get("success"):
                lic = self._client.load_local_license()
                name = lic.client_name if lic else "Authorized Operator"
                if remember_4h:
                    _save_station_session(key, hours=4)
                else:
                    _clear_station_session()
                self._set_loading(False)
                self.authenticated.emit(name, key)
            else:
                self._set_loading(False)
                err_msg = res.get("message", "Access denied. Invalid License Key.")
                self._show_error(err_msg)
                if self._key_field is not None:
                    try:
                        self._key_field.shake()
                    except RuntimeError:
                        pass

        QTimer.singleShot(100, _do_auth)

    def _show_error(self, msg: str) -> None:
        self._error_lbl.setText(f"⚠  {msg}")

    def clear_error(self) -> None:
        self._error_lbl.setText("")

    def show_auth_error(self) -> None:
        self._show_error("Access denied. License authentication rejected.")
        if self._key_field is not None:
            try:
                self._key_field.shake()
            except RuntimeError:
                pass

    def _set_loading(self, loading: bool, text: str = "Authenticating…") -> None:
        self._login_btn.setEnabled(not loading)
        if self._key_field is not None:
            try:
                self._key_field.setEnabled(not loading)
            except RuntimeError:
                self._key_field = None
        if self._remember_cb is not None:
            try:
                self._remember_cb.setEnabled(not loading)
            except RuntimeError:
                self._remember_cb = None

        if loading:
            self._login_btn.setText(text)
        else:
            if self._mode == "session_active":
                self._login_btn.setText("RESUME SOC CONSOLE")
            elif self._mode == "expired":
                self._login_btn.setText("VERIFY & ACTIVATE RENEWED KEY")
            elif self._mode == "locked":
                self._login_btn.setText("UNLOCK & ENTER SOC CONSOLE")
            else:
                self._login_btn.setText("AUTHORIZE & ENTER CONSOLE")


# ---------------------------------------------------------------------------
# Full-screen login window
# ---------------------------------------------------------------------------

class LoginWindow(QWidget):
    """Frameless full-screen login window.

    Emits ``login_successful(username)`` when authentication is accepted.
    The caller is responsible for validating credentials and calling
    :meth:`accept_login` or :meth:`reject_login` after verifying.

    For development / demo mode pass ``bypass=True`` to skip authentication
    and auto-accept any credentials.
    """

    #: Emitted with the username after :meth:`accept_login` is called.
    login_successful: Signal = Signal(str)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        on_authenticate: Callable[[str, str], None] | None = None,
        bypass: bool = False,
    ) -> None:
        super().__init__(parent)
        self._on_authenticate = on_authenticate
        self._bypass = bypass

        self.setWindowTitle("Aegis IDPS — Secure Login")
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Window
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        screen = QApplication.primaryScreen()
        if screen is not None:
            self.setGeometry(screen.geometry())
        else:
            self.resize(1920, 1080)

        self._build()
        self.setWindowOpacity(0.0)

        # Fade in
        self._fade_in = QPropertyAnimation(self, b"windowOpacity")
        self._fade_in.setDuration(700)
        self._fade_in.setStartValue(0.0)
        self._fade_in.setEndValue(1.0)
        self._fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Escape = quit
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self, self.close)

    def _build(self) -> None:
        # Animated background (full-screen)
        self._bg = _BackgroundCanvas(self)
        self._bg.setGeometry(self.rect())

        # Top accent bar
        self._top_bar = QFrame(self)
        self._top_bar.setFixedHeight(3)
        self._top_bar.setGeometry(0, 0, self.width(), 3)
        self._top_bar.setStyleSheet(
            f"""
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 transparent,
                stop:0.3 {_ACCENT},
                stop:0.5 {_CYAN},
                stop:0.7 {_ACCENT2},
                stop:1.0 transparent
            );
            border: none;
            """
        )

        # Centre column layout
        centre = QWidget(self)
        centre.setGeometry(self.rect())
        centre.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        centre.setStyleSheet("background: transparent;")

        root = QVBoxLayout(centre)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top nav strip ────────────────────────────────────────────────
        top_strip = QHBoxLayout()
        top_strip.setContentsMargins(32, 20, 32, 0)

        wordmark = QLabel("AEGIS  IDPS")
        wordmark.setStyleSheet(
            f"color: {_MUTED}; font-size: 11px; font-weight: 700; "
            f"letter-spacing: 3px; background: transparent;"
        )
        top_strip.addWidget(wordmark)
        top_strip.addStretch()

        classify = QLabel("⬛  RESTRICTED — AUTHORIZED USERS ONLY")
        classify.setStyleSheet(
            f"color: {_RED}; font-size: 10px; font-weight: 700; "
            f"letter-spacing: 2px; background: transparent;"
        )
        top_strip.addWidget(classify)
        root.addLayout(top_strip)

        # ── Clock strip (top-right) ──────────────────────────────────────
        clock_row = QHBoxLayout()
        clock_row.setContentsMargins(0, 6, 32, 0)
        clock_row.addStretch()
        clock_row.addWidget(_ClockStrip())
        root.addLayout(clock_row)

        root.addStretch(2)

        # ── Card centred ─────────────────────────────────────────────────
        card_row = QHBoxLayout()
        card_row.setContentsMargins(0, 0, 0, 0)
        card_row.addStretch()
        self._card = _LoginCard()
        self._card.authenticated.connect(self._on_credentials)
        card_row.addWidget(self._card)
        card_row.addStretch()
        root.addLayout(card_row)

        root.addStretch(2)

        # ── Bottom legal strip ───────────────────────────────────────────
        legal_row = QHBoxLayout()
        legal_row.setContentsMargins(0, 0, 0, 22)
        legal = QLabel(
            "Unauthorised access is strictly prohibited and may be subject to criminal prosecution.  "
            "All sessions are logged and monitored."
        )
        legal.setAlignment(Qt.AlignmentFlag.AlignCenter)
        legal.setStyleSheet(
            f"color: {_MUTED}; font-size: 10px; letter-spacing: 0.5px; background: transparent;"
        )
        legal.setWordWrap(True)
        legal_row.addStretch()
        legal_row.addWidget(legal, 8)
        legal_row.addStretch()
        root.addLayout(legal_row)

        # Try to read version
        try:
            from aegis_shared.version import __version__
            ver = f"v{__version__}"
        except Exception:
            ver = ""
        ver_lbl = QLabel(ver)
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_lbl.setStyleSheet(
            f"color: {_MUTED}; font-size: 10px; background: transparent; margin-bottom: 8px;"
        )
        root.addWidget(ver_lbl)

    # ── Geometry tracking ---------------------------------------------------

    def resizeEvent(self, event: Any) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._bg.setGeometry(self.rect())
        self._top_bar.setGeometry(0, 0, self.width(), 3)
        # Re-centre the children container
        for child in self.children():
            if isinstance(child, QWidget) and child is not self._bg and child is not self._top_bar:
                child.setGeometry(self.rect())

    # ── Show / hide animations ----------------------------------------------

    def show(self) -> None:
        super().show()
        self._fade_in.start()
        self._card.set_focus() if hasattr(self._card, "set_focus") else None

    def _fade_out_then(self, callback: Callable[[], None]) -> None:
        fade = QPropertyAnimation(self, b"windowOpacity")
        fade.setDuration(400)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.setEasingCurve(QEasingCurve.Type.InCubic)
        fade.finished.connect(callback)
        self._fade_out_anim = fade
        fade.start()

    # ── Auth handoff --------------------------------------------------------

    def _on_credentials(self, username: str, password: str) -> None:
        """Called when the card emits credentials. Validate then accept/reject."""
        if self._bypass:
            self.accept_login(username)
            return
        if self._on_authenticate is not None:
            self._on_authenticate(username, password)
            # Caller must call accept_login() or reject_login() after validation.

    def accept_login(self, username: str) -> None:
        """Call this after successful external credential verification."""
        try:
            import threading
            def _speak_worker() -> None:
                try:
                    import importlib
                    win32_mod = importlib.import_module("win32com.client")
                    speaker = getattr(win32_mod, "Dispatch")("SAPI.SpVoice")
                    speaker.Rate = 1
                    speaker.Speak(f"Welcome to Aegis, {username}")
                except Exception:
                    pass
            threading.Thread(target=_speak_worker, daemon=True).start()
        except Exception:
            pass

        def _after_fade() -> None:
            self.hide()
            self.close()
            self.deleteLater()
            self.login_successful.emit(username)
        self._fade_out_then(_after_fade)

    def reject_login(self) -> None:
        """Call this after failed credential verification."""
        self._card.show_auth_error()

    # ── Convenience class-method constructor --------------------------------

    @classmethod
    def show_blocking(
        cls,
        *,
        bypass: bool = False,
        on_success: Callable[[str], None] | None = None,
    ) -> "LoginWindow":
        """Create, connect and show the login window. Returns the instance.

        ``on_success`` receives the authenticated username when login succeeds.
        ``bypass=True`` skips credential checking (development mode).
        """
        win = cls(bypass=bypass)
        if on_success is not None:
            win.login_successful.connect(on_success)
        win.show()
        return win


__all__ = ["LoginWindow"]
