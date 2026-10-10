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

import math
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

# ---------------------------------------------------------------------------
# Design tokens (mirrors styles.py but standalone so login needs no deps)
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
    """The centred semi-transparent login card."""

    authenticated = Signal(str, str)  # (username, password)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(420, 560)
        self.setObjectName("LoginCard")
        self.setStyleSheet(f"""
            #LoginCard {{
                background-color: rgba(11, 22, 42, 0.88);
                border: 1.5px solid {_BORDER2};
                border-radius: 20px;
            }}
        """)

        # Card drop shadow
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(60)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 180))
        self.setGraphicsEffect(shadow)

        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(36, 36, 36, 32)
        root.setSpacing(0)

        # ── Logo + branding ──────────────────────────────────────────────
        logo_row = QHBoxLayout()
        logo_row.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._shield = _ShieldLogo()
        logo_row.addWidget(self._shield)
        root.addLayout(logo_row)
        root.addSpacing(16)

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
        root.addSpacing(22)

        # ── Sign-in label ────────────────────────────────────────────────
        sign_in = QLabel("Administrator Sign-in")
        sign_in.setStyleSheet(
            f"color: {_TEXT2}; font-size: 13px; font-weight: 600; background: transparent;"
        )
        root.addWidget(sign_in)
        root.addSpacing(14)

        # ── Username field ───────────────────────────────────────────────
        self._user_field = _IconLineEdit(
            "Username or email", icon="👤", parent=self
        )
        self._user_field.returnPressed.connect(self._pass_field_focus)
        root.addWidget(self._user_field)
        root.addSpacing(10)

        # ── Password field ───────────────────────────────────────────────
        self._pass_field = _IconLineEdit(
            "Password", password=True, icon="🔒", parent=self
        )
        self._pass_field.returnPressed.connect(self._on_login_clicked)
        root.addWidget(self._pass_field)
        root.addSpacing(10)

        # ── Remember me + Forgot ─────────────────────────────────────────
        opts_row = QHBoxLayout()
        opts_row.setContentsMargins(0, 0, 0, 0)
        self._remember = QCheckBox("Remember me")
        self._remember.setStyleSheet(f"""
            QCheckBox {{
                color: {_MUTED2};
                font-size: 12px;
                background: transparent;
                spacing: 6px;
            }}
            QCheckBox::indicator {{
                width: 14px; height: 14px;
                border: 1px solid {_BORDER2};
                background-color: {_CARD2};
                border-radius: 3px;
            }}
            QCheckBox::indicator:checked {{
                background-color: {_ACCENT};
                border-color: {_ACCENT};
            }}
        """)
        forgot = QPushButton("Forgot password?")
        forgot.setCursor(Qt.CursorShape.PointingHandCursor)
        forgot.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                color: {_ACCENT3};
                font-size: 12px;
                padding: 0;
            }}
            QPushButton:hover {{ color: {_CYAN}; }}
        """)
        opts_row.addWidget(self._remember)
        opts_row.addStretch()
        opts_row.addWidget(forgot)
        root.addLayout(opts_row)
        root.addSpacing(20)

        # ── Login button ─────────────────────────────────────────────────
        self._login_btn = QPushButton("Sign in to Console")
        self._login_btn.setFixedHeight(48)
        self._login_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._login_btn.setObjectName("LoginBtn")
        self._login_btn.setStyleSheet(f"""
            #LoginBtn {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {_ACCENT},
                    stop:1 {_ACCENT2}
                );
                color: #FFFFFF;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 0.5px;
            }}
            #LoginBtn:hover {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {_ACCENT2},
                    stop:1 #3B82F6
                );
            }}
            #LoginBtn:pressed {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1E40AF,
                    stop:1 {_ACCENT}
                );
            }}
            #LoginBtn:disabled {{
                background: #1E293B;
                color: {_MUTED};
            }}
        """)
        self._login_btn.clicked.connect(self._on_login_clicked)
        root.addWidget(self._login_btn)
        root.addSpacing(14)

        # ── Error banner ─────────────────────────────────────────────────
        self._error_lbl = QLabel("")
        self._error_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error_lbl.setWordWrap(True)
        self._error_lbl.setFixedHeight(20)
        self._error_lbl.setStyleSheet(
            f"color: {_RED}; font-size: 12px; background: transparent;"
        )
        root.addWidget(self._error_lbl)

        root.addStretch()

        # ── Bottom divider + system status ───────────────────────────────
        bot_div = QFrame()
        bot_div.setFixedHeight(1)
        bot_div.setStyleSheet(f"background: {_BORDER}; border: none;")
        root.addWidget(bot_div)
        root.addSpacing(14)

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
        QTimer.singleShot(900,  lambda: self._db_badge.set_ok("Database"))
        QTimer.singleShot(1300, lambda: self._agent_badge.set_ok("Agent"))
        QTimer.singleShot(1700, lambda: self._net_badge.set_ok("Sensor"))

    # -- Actions -------------------------------------------------------------

    def _pass_field_focus(self) -> None:
        self._pass_field.set_focus()

    def _on_login_clicked(self) -> None:
        username = self._user_field.text().strip()
        password = self._pass_field.text()

        if not username or not password:
            self._show_error("Please enter your username and password.")
            if not username:
                self._user_field.shake()
            if not password:
                self._pass_field.shake()
            return

        self._error_lbl.setText("")
        self._set_loading(True)
        # Simulate network latency; real impl replaces with JWT call
        QTimer.singleShot(800, lambda: self._emit_credentials(username, password))

    def _emit_credentials(self, username: str, password: str) -> None:
        self._set_loading(False)
        self.authenticated.emit(username, password)

    def _show_error(self, msg: str) -> None:
        self._error_lbl.setText(f"⚠  {msg}")

    def clear_error(self) -> None:
        self._error_lbl.setText("")

    def show_auth_error(self) -> None:
        self._show_error("Invalid credentials. Access denied.")
        self._user_field.shake()
        self._pass_field.shake()

    def _set_loading(self, loading: bool) -> None:
        self._login_btn.setEnabled(not loading)
        self._login_btn.setText(
            "Authenticating…" if loading else "Sign in to Console"
        )


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
