"""Elite full-screen boot sequence for Aegis IDPS.

Dramatically upgraded from the original small 520x340 splash:
  - Full-screen frameless window (same footprint as the login screen)
  - Animated particle-network background (70 nodes, Scapy-style aesthetic)
  - 120 px custom-painted Aegis shield with dual rotating rings + glow halo
  - Letter-by-letter "AEGIS" title reveal (100 ms / letter)
  - Sequential boot-phase checklist — each row transitions
      pending (○) → spinner (◐◓◑◒) → done (✓)
  - Neon 3-stop gradient progress bar (blue → cyan → green)
  - Smooth fade-in on launch, fade-out on completion
  - Same public API as before: ``SplashScreen(on_finished=…) / .start()``
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    Qt,
    QTimer,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Standalone design tokens (no dependency on theme.py)
# ---------------------------------------------------------------------------
_BG1 = "#060B15"
_BG2 = "#0A0F1C"
_SURF = "#0F1829"
_BDR = "#1F2D44"
_ACC = "#1D4ED8"
_ACC2 = "#2563EB"
_ACC3 = "#3B82F6"
_CYAN = "#06B6D4"
_GREEN = "#10B981"
_RED = "#EF4444"
_TEXT = "#F1F5F9"
_TEXT2 = "#CBD5E1"
_MUTED = "#64748B"
_MUTED2 = "#94A3B8"

# ---------------------------------------------------------------------------
# Boot phases: (component name, short description, delay_ms_before_advance)
# ---------------------------------------------------------------------------
_PHASES: tuple[tuple[str, str, int], ...] = (
    ("Aegis Core Runtime", "Initializing runtime engine & event bus", 300),
    ("Host Monitors", "Loading process, port & file integrity monitors", 340),
    ("ML Anomaly Engine", "Warming up anomaly detection models", 480),
    ("Threat Intelligence", "Loading deterministic detection rules", 260),
    ("Network Sensor", "Initializing passive packet capture layer", 280),
    ("Backend API", "Establishing connection to backend services", 280),
    ("SOC Console", "Launching security operations console", 140),
)

_SPINNER = ("◐", "◓", "◑", "◒")


# ---------------------------------------------------------------------------
# Particle system (self-contained — no import from login.py)
# ---------------------------------------------------------------------------


class _Particle:
    __slots__ = ("alpha", "ps", "pulse", "radius", "vx", "vy", "x", "y")

    def __init__(self, w: int, h: int) -> None:
        self.x = random.uniform(0, w)  # noqa: S311
        self.y = random.uniform(0, h)  # noqa: S311
        self.vx = random.uniform(-0.16, 0.16)  # noqa: S311
        self.vy = random.uniform(-0.11, 0.11)  # noqa: S311
        self.radius = random.uniform(1.2, 2.6)  # noqa: S311
        self.alpha = random.randint(55, 155)  # noqa: S311
        self.pulse = random.uniform(0, math.pi * 2)  # noqa: S311
        self.ps = random.uniform(0.02, 0.055)  # noqa: S311

    def step(self, w: int, h: int) -> None:
        self.x = (self.x + self.vx) % w
        self.y = (self.y + self.vy) % h
        self.pulse = (self.pulse + self.ps) % (math.pi * 2)


class _BgCanvas(QWidget):
    """Full-window animated particle-network background."""

    _N = 70
    _D = 115

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._pts: list[_Particle] = []
        self._sy: float = 0.0
        self._reset()
        t = QTimer(self)
        t.setInterval(35)
        t.timeout.connect(self._tick)
        t.start()

    def _reset(self) -> None:
        w, h = self.width() or 1920, self.height() or 1080
        self._pts = [_Particle(w, h) for _ in range(self._N)]

    def resizeEvent(self, ev: Any) -> None:  # noqa: N802
        self._reset()
        super().resizeEvent(ev)

    def _tick(self) -> None:
        w, h = self.width(), self.height()
        self._sy = (self._sy + 0.45) % (h or 1)
        for p in self._pts:
            p.step(w, h)
        self.update()

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        pr = QPainter(self)
        pr.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        g = QLinearGradient(0, 0, 0, h)
        g.setColorAt(0, QColor(_BG1))
        g.setColorAt(0.5, QColor(_BG2))
        g.setColorAt(1, QColor("#040810"))
        pr.fillRect(0, 0, w, h, QBrush(g))

        vg = QRadialGradient(w / 2, h / 2, max(w, h) * 0.72)
        vg.setColorAt(0, QColor(0, 0, 0, 0))
        vg.setColorAt(1, QColor(0, 0, 0, 110))
        pr.fillRect(0, 0, w, h, QBrush(vg))

        sg = QLinearGradient(0, self._sy - 50, 0, self._sy + 50)
        sg.setColorAt(0, QColor(6, 182, 212, 0))
        sg.setColorAt(0.5, QColor(6, 182, 212, 10))
        sg.setColorAt(1, QColor(6, 182, 212, 0))
        pr.fillRect(0, int(self._sy - 50), w, 100, QBrush(sg))

        pts = self._pts
        for i in range(len(pts)):
            for j in range(i + 1, len(pts)):
                dx, dy = pts[i].x - pts[j].x, pts[i].y - pts[j].y
                d = math.hypot(dx, dy)
                if d < self._D:
                    c = QColor(_ACC3)
                    c.setAlpha(int(42 * (1 - d / self._D)))
                    pr.setPen(QPen(c, 0.5))
                    pr.drawLine(QPointF(pts[i].x, pts[i].y), QPointF(pts[j].x, pts[j].y))

        pr.setPen(Qt.PenStyle.NoPen)
        for p in pts:
            c = QColor(_ACC3)
            c.setAlpha(max(0, min(255, int(p.alpha + 32 * math.sin(p.pulse)))))
            pr.setBrush(QBrush(c))
            pr.drawEllipse(
                QPointF(p.x, p.y),
                p.radius + 0.5 * math.sin(p.pulse),
                p.radius + 0.5 * math.sin(p.pulse),
            )
        pr.end()


# ---------------------------------------------------------------------------
# 120 px animated Aegis shield
# ---------------------------------------------------------------------------


class _Shield(QWidget):
    _S = 120

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedSize(self._S, self._S)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._ang: float = 0.0
        self._pulse: float = 0.0
        t = QTimer(self)
        t.setInterval(33)
        t.timeout.connect(self._tick)
        t.start()

    def _tick(self) -> None:
        self._ang = (self._ang + 0.85) % 360
        self._pulse = (self._pulse + 0.04) % (math.pi * 2)
        self.update()

    def paintEvent(self, _: Any) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = self._S
        cx, cy = s / 2, s / 2

        # Outer glow
        gr = 55 + 4 * math.sin(self._pulse)
        gl = QRadialGradient(cx, cy, gr)
        gl.setColorAt(0.55, QColor(29, 78, 216, 0))
        gl.setColorAt(0.80, QColor(29, 78, 216, 75))
        gl.setColorAt(1, QColor(29, 78, 216, 0))
        p.setBrush(QBrush(gl))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(cx, cy), gr, gr)

        # Outer rotating dashed ring
        p.save()
        p.translate(cx, cy)
        p.rotate(self._ang)
        pen = QPen(QColor(37, 99, 235, 125), 1.8)
        pen.setStyle(Qt.PenStyle.DashLine)
        pen.setDashPattern([5, 7])
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPointF(0, 0), 52, 52)
        p.restore()

        # Inner counter ring
        p.save()
        p.translate(cx, cy)
        p.rotate(-self._ang * 0.52)
        ip = QPen(QColor(6, 182, 212, 75), 1.0)
        ip.setStyle(Qt.PenStyle.DotLine)
        p.setPen(ip)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QPointF(0, 0), 42, 42)
        p.restore()

        # Shield body
        path = QPainterPath()
        r = 34.0
        path.moveTo(cx, cy - r)
        path.cubicTo(cx + r * 1.06, cy - r * 0.6, cx + r * 1.06, cy + r * 0.22, cx, cy + r * 1.12)
        path.cubicTo(cx - r * 1.06, cy + r * 0.22, cx - r * 1.06, cy - r * 0.6, cx, cy - r)
        path.closeSubpath()

        fill = QLinearGradient(cx - r, cy - r, cx + r, cy + r)
        fill.setColorAt(0, QColor("#1E3A6E"))
        fill.setColorAt(0.5, QColor("#1D4ED8"))
        fill.setColorAt(1, QColor("#0F2555"))
        p.setBrush(QBrush(fill))
        p.setPen(QPen(QColor(_ACC3), 1.5))
        p.drawPath(path)

        hl = QLinearGradient(cx - 16, cy - 26, cx + 16, cy)
        hl.setColorAt(0, QColor(255, 255, 255, 45))
        hl.setColorAt(1, QColor(255, 255, 255, 0))
        p.setBrush(QBrush(hl))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPath(path)

        # "A" glyph
        f = QFont("Segoe UI", 22, QFont.Weight.Black)
        p.setFont(f)
        p.setPen(QPen(QColor(_TEXT)))
        p.drawText(QRectF(cx - 18, cy - 16, 36, 36), Qt.AlignmentFlag.AlignCenter, "A")

        # Corner dots on outer ring
        for deg in [0, 90, 180, 270]:
            rad = math.radians(deg + self._ang)
            dx, dy2 = 52 * math.cos(rad), 52 * math.sin(rad)
            p.setBrush(QBrush(QColor(_CYAN)))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(cx + dx, cy + dy2), 3.0, 3.0)
        p.end()


# ---------------------------------------------------------------------------
# Individual boot phase row
# ---------------------------------------------------------------------------


class _PhaseRow(QWidget):
    """One boot phase: ○/spinner/✓ + name + description + status badge."""

    def __init__(self, name: str, desc: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(50)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._spin_idx = 0
        self._spin_timer = QTimer(self)
        self._spin_timer.setInterval(75)
        self._spin_timer.timeout.connect(self._spin)

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(14)

        # Status glyph
        self._icon = QLabel("○")
        self._icon.setFixedWidth(22)
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon.setStyleSheet(
            f"color:{_MUTED};font-size:15px;font-weight:700;background:transparent;"
        )

        # Text
        txt = QVBoxLayout()
        txt.setSpacing(2)
        self._name = QLabel(name)
        self._name.setStyleSheet(
            f"color:{_MUTED2};font-size:12px;font-weight:600;background:transparent;"
        )
        self._desc = QLabel(desc)
        self._desc.setStyleSheet(f"color:{_MUTED};font-size:10px;background:transparent;")
        txt.addWidget(self._name)
        txt.addWidget(self._desc)

        # Badge
        self._badge = QLabel("PENDING")
        self._badge.setFixedWidth(70)
        self._badge.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._badge.setStyleSheet(
            f"color:{_MUTED};font-size:9px;font-weight:700;letter-spacing:1px;background:transparent;"
        )

        lay.addWidget(self._icon)
        lay.addLayout(txt, 1)
        lay.addWidget(self._badge)

    def activate(self) -> None:
        self._spin_timer.start()
        self._name.setStyleSheet(
            f"color:{_TEXT2};font-size:12px;font-weight:700;background:transparent;"
        )
        self._badge.setText("LOADING…")
        self._badge.setStyleSheet(
            f"color:{_CYAN};font-size:9px;font-weight:700;letter-spacing:1px;background:transparent;"
        )
        self._icon.setStyleSheet(
            f"color:{_CYAN};font-size:15px;font-weight:700;background:transparent;"
        )

    def done(self) -> None:
        self._spin_timer.stop()
        self._icon.setText("✓")
        self._icon.setStyleSheet(
            f"color:{_GREEN};font-size:15px;font-weight:700;background:transparent;"
        )
        self._name.setStyleSheet(
            f"color:{_TEXT};font-size:12px;font-weight:600;background:transparent;"
        )
        self._badge.setText("OK")
        self._badge.setStyleSheet(
            f"color:{_GREEN};font-size:9px;font-weight:800;letter-spacing:1px;background:transparent;"
        )

    def error(self) -> None:
        self._spin_timer.stop()
        self._icon.setText("✗")
        self._icon.setStyleSheet(
            f"color:{_RED};font-size:15px;font-weight:700;background:transparent;"
        )
        self._badge.setText("ERROR")
        self._badge.setStyleSheet(
            f"color:{_RED};font-size:9px;font-weight:800;letter-spacing:1px;background:transparent;"
        )

    def _spin(self) -> None:
        self._icon.setText(_SPINNER[self._spin_idx % 4])
        self._spin_idx += 1


# ---------------------------------------------------------------------------
# Main SplashScreen — identical public API to original
# ---------------------------------------------------------------------------


class SplashScreen(QWidget):
    """Full-screen animated Aegis boot sequence.

    Identical public interface to the original splash:
        ``SplashScreen(parent=None, *, on_finished=None)``
        ``.start() -> None``
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        on_finished: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_finished = on_finished
        self._phase_idx = 0
        self._phase_rows: list[_PhaseRow] = []
        self._reveal_idx = 0

        self.setWindowTitle("")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        screen = QApplication.primaryScreen()
        if screen is not None:
            self.setGeometry(screen.geometry())
        else:
            self.resize(1920, 1080)

        self.setWindowOpacity(0.0)
        self._build_ui()

        # Fade-in
        self._fi = QPropertyAnimation(self, b"windowOpacity")
        self._fi.setDuration(550)
        self._fi.setStartValue(0.0)
        self._fi.setEndValue(1.0)
        self._fi.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Phase timer (one-shot, restarted each step)
        self._phase_timer = QTimer(self)
        self._phase_timer.setSingleShot(True)
        self._phase_timer.timeout.connect(self._advance)

        # Letter reveal timer
        self._reveal_timer = QTimer(self)
        self._reveal_timer.setInterval(100)
        self._reveal_timer.timeout.connect(self._reveal_letter)

    # ── UI build ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._bg = _BgCanvas(self)
        self._bg.setGeometry(self.rect())

        # Top accent bar
        self._top_bar = QFrame(self)
        self._top_bar.setFixedHeight(3)
        self._top_bar.setGeometry(0, 0, self.width(), 3)
        self._top_bar.setStyleSheet(f"""
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 transparent, stop:0.3 {_ACC}, stop:0.5 {_CYAN},
                stop:0.7 {_ACC2}, stop:1 transparent);
            border: none;
        """)

        # Content overlay
        over = QWidget(self)
        over.setGeometry(self.rect())
        over.setStyleSheet("background:transparent;")

        root = QVBoxLayout(over)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top strip ────────────────────────────────────────────────────
        top = QHBoxLayout()
        top.setContentsMargins(36, 22, 36, 0)
        wm = QLabel("AEGIS IDPS")
        wm.setStyleSheet(
            f"color:{_MUTED};font-size:11px;font-weight:700;letter-spacing:3px;background:transparent;"
        )
        top.addWidget(wm)
        top.addStretch()
        try:
            from aegis_shared.version import __version__

            vtxt = f"v{__version__}"
        except Exception:
            vtxt = "v0.1.0"
        vl = QLabel(vtxt)
        vl.setStyleSheet(
            f"color:{_MUTED};font-size:11px;letter-spacing:1px;background:transparent;"
        )
        top.addWidget(vl)
        root.addLayout(top)

        root.addStretch(2)

        # ── Centre column (fixed 540px) ───────────────────────────────────
        col_row = QHBoxLayout()
        col_row.setContentsMargins(0, 0, 0, 0)
        col_row.addStretch()

        wrap = QWidget()
        wrap.setFixedWidth(540)
        wrap.setStyleSheet("background:transparent;")
        col = QVBoxLayout(wrap)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        # Shield
        sr = QHBoxLayout()
        sr.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self._shield = _Shield()
        sr.addWidget(self._shield)
        col.addLayout(sr)
        col.addSpacing(18)

        # "AEGIS" title
        self._title = QLabel("")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setFixedHeight(70)
        self._title.setStyleSheet(
            f"color:{_TEXT};font-size:50px;font-weight:900;letter-spacing:14px;background:transparent;"
        )
        col.addWidget(self._title)
        col.addSpacing(4)

        # Subtitle
        sub = QLabel("HYBRID HOST  &  NETWORK INTRUSION DEFENSE SYSTEM")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(
            f"color:{_MUTED2};font-size:11px;letter-spacing:2.5px;background:transparent;"
        )
        col.addWidget(sub)
        col.addSpacing(20)

        # Divider
        col.addWidget(self._divider())
        col.addSpacing(12)

        # Phase rows
        for name, desc, _ in _PHASES:
            row = _PhaseRow(name, desc)
            self._phase_rows.append(row)
            col.addWidget(row)

        col.addSpacing(12)
        col.addWidget(self._divider())
        col.addSpacing(10)

        # Progress bar
        self._prog = QProgressBar()
        self._prog.setRange(0, 100)
        self._prog.setValue(0)
        self._prog.setTextVisible(False)
        self._prog.setFixedHeight(5)
        self._prog.setStyleSheet(f"""
            QProgressBar {{
                background:{_SURF};border:1px solid {_BDR};border-radius:2px;
            }}
            QProgressBar::chunk {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {_ACC}, stop:0.5 {_CYAN}, stop:1 {_GREEN});
                border-radius:2px;
            }}
        """)
        col.addWidget(self._prog)
        col.addSpacing(8)

        # Status text
        self._status = QLabel("Initializing Aegis…")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet(
            f"color:{_MUTED};font-size:11px;letter-spacing:0.5px;background:transparent;"
        )
        col.addWidget(self._status)

        col_row.addWidget(wrap)
        col_row.addStretch()
        root.addLayout(col_row)
        root.addStretch(1)

        # ── Bottom strip ──────────────────────────────────────────────────
        bot = QHBoxLayout()
        bot.setContentsMargins(0, 0, 0, 20)
        bl = QLabel("Aegis Security Systems  ·  All sessions are logged and monitored")
        bl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bl.setStyleSheet(f"color:{_MUTED};font-size:10px;background:transparent;")
        bot.addStretch()
        bot.addWidget(bl)
        bot.addStretch()
        root.addLayout(bot)

    @staticmethod
    def _divider() -> QFrame:
        f = QFrame()
        f.setFixedHeight(1)
        f.setStyleSheet(f"background:{_BDR};border:none;")
        return f

    # ── Geometry ──────────────────────────────────────────────────────────────

    def resizeEvent(self, ev: Any) -> None:  # noqa: N802
        super().resizeEvent(ev)
        self._bg.setGeometry(self.rect())
        self._top_bar.setGeometry(0, 0, self.width(), 3)
        for c in self.children():
            if isinstance(c, QWidget) and c not in (self._bg, self._top_bar):
                c.setGeometry(self.rect())

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin the boot sequence. Call this instead of show()."""
        self.show()
        self.raise_()
        self.activateWindow()
        self._fi.start()
        self._reveal_timer.start()

    # ── Letter reveal ─────────────────────────────────────────────────────────

    def _reveal_letter(self) -> None:
        txt = "AEGIS"
        if self._reveal_idx <= len(txt):
            self._title.setText(txt[: self._reveal_idx])
            self._reveal_idx += 1
        else:
            self._reveal_timer.stop()
            QTimer.singleShot(220, self._kick_phases)

    def _kick_phases(self) -> None:
        self._advance()

    # ── Phase loop ────────────────────────────────────────────────────────────

    def _advance(self) -> None:
        idx = self._phase_idx

        if idx == 0:
            self._phase_rows[0].activate()
            self._status.setText(f"Loading {_PHASES[0][0]}…")
            self._phase_timer.start(_PHASES[0][2])
            self._phase_idx += 1
            return

        done = idx - 1
        if 0 <= done < len(self._phase_rows):
            self._phase_rows[done].done()

        progress = int(idx / len(_PHASES) * 100)
        self._prog.setValue(progress)

        if idx < len(_PHASES):
            self._phase_rows[idx].activate()
            self._status.setText(f"Loading {_PHASES[idx][0]}…")
            self._phase_timer.start(_PHASES[idx][2])
            self._phase_idx += 1
        else:
            self._finish()

    def _finish(self) -> None:
        self._prog.setValue(100)
        self._status.setText("Ready — launching SOC Console…")
        QTimer.singleShot(380, self._fade_out)

    def _fade_out(self) -> None:
        fo = QPropertyAnimation(self, b"windowOpacity")
        fo.setDuration(320)
        fo.setStartValue(1.0)
        fo.setEndValue(0.0)
        fo.setEasingCurve(QEasingCurve.Type.InCubic)
        fo.finished.connect(self._done)
        self._fo = fo
        fo.start()

    def _done(self) -> None:
        self.hide()
        self.close()
        self.deleteLater()
        if self._on_finished is not None:
            self._on_finished()


__all__ = ["SplashScreen"]
