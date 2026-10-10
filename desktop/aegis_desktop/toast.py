"""Floating toast notification overlay for Aegis IDPS.

Notifications slide in from the top-right of the main window and
auto-dismiss after a configurable duration.  Up to 5 can be stacked.

Usage::

    manager = ToastManager(main_window)
    manager.show_toast("Threat Detected", "Critical activity on host-01", "critical")
"""

from __future__ import annotations

from typing import Literal

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QObject,
    QPoint,
    QPropertyAnimation,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

ToastLevel = Literal["info", "success", "warning", "error", "critical"]

_LEVEL_CONFIG: dict[str, tuple[str, str, str]] = {
    "info":     ("#3B82F6", "◆", "INFO"),
    "success":  ("#10B981", "✓", "OK"),
    "warning":  ("#F59E0B", "⚠", "WARN"),
    "error":    ("#EF4444", "✗", "ERROR"),
    "critical": ("#EC4899", "⛔", "CRITICAL"),
}

_TOAST_W   = 330
_MARGIN    = 18
_GAP       = 8
_MAX_STACK = 5


class _ToastWidget(QFrame):
    """A single animated toast notification card."""

    closed: Signal = Signal()

    def __init__(
        self,
        title: str,
        message: str,
        level: ToastLevel,
        duration_ms: int,
        parent: QWidget | None,
    ) -> None:
        super().__init__(parent)
        color, icon, tag = _LEVEL_CONFIG.get(level, _LEVEL_CONFIG["info"])

        self.setObjectName("ToastWidget")
        self.setFixedWidth(_TOAST_W)
        # The parent ToastManager passes through mouse events, but individual
        # toast cards must still be interactive (close button, etc.)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setStyleSheet(f"""
            #ToastWidget {{
                background-color: #0D1A2D;
                border: 1px solid #1F2D44;
                border-left: 3px solid {color};
                border-radius: 10px;
            }}
        """)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(28)
        shadow.setXOffset(0)
        shadow.setYOffset(6)
        shadow.setColor(QColor(0, 0, 0, 160))
        self.setGraphicsEffect(shadow)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 12, 12)
        root.setSpacing(5)

        # ── Title row ────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        hdr.setSpacing(8)

        badge = QLabel(f"{icon}  {tag}")
        badge.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: 800; "
            f"letter-spacing: 1px; background: transparent;"
        )
        hdr.addWidget(badge)
        hdr.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(20, 20)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("""
            QPushButton { background: transparent; border: none;
                          color: #4B5563; font-size: 11px; }
            QPushButton:hover { color: #9CA3AF; }
        """)
        close_btn.clicked.connect(self._dismiss)
        hdr.addWidget(close_btn)
        root.addLayout(hdr)

        # ── Title ────────────────────────────────────────────────────────
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            "color: #F1F5F9; font-size: 13px; font-weight: 700; background: transparent;"
        )
        root.addWidget(title_lbl)

        # ── Message ──────────────────────────────────────────────────────
        if message:
            msg_lbl = QLabel(message)
            msg_lbl.setWordWrap(True)
            msg_lbl.setStyleSheet(
                "color: #94A3B8; font-size: 12px; background: transparent;"
            )
            root.addWidget(msg_lbl)

        # ── Progress bar (countdown) ──────────────────────────────────────
        timer_bar = QFrame()
        timer_bar.setObjectName("ToastTimerBar")
        timer_bar.setFixedHeight(2)
        timer_bar.setStyleSheet(f"background: {color}; border: none; border-radius: 1px;")
        root.addWidget(timer_bar)

        self.adjustSize()
        self._timer_bar = timer_bar
        self._full_w = _TOAST_W - 28   # content width minus margins
        self._slide_anim: QPropertyAnimation | None = None
        self._fade_anim: QPropertyAnimation | None = None

        if duration_ms > 0:
            self._shrink_timer = QTimer(self)
            self._shrink_timer.setInterval(30)
            self._elapsed = 0
            self._duration = duration_ms
            self._shrink_timer.timeout.connect(
                lambda: self._tick_timer(duration_ms)
            )
            self._shrink_timer.start()
            QTimer.singleShot(duration_ms, self._dismiss)

    def _tick_timer(self, duration: int) -> None:
        self._elapsed += 30
        ratio = max(0.0, 1.0 - self._elapsed / duration)
        new_w = max(0, int(self._full_w * ratio))
        self._timer_bar.setFixedWidth(new_w)

    def _dismiss(self) -> None:
        if hasattr(self, "_shrink_timer"):
            self._shrink_timer.stop()
        fade = QPropertyAnimation(self, b"windowOpacity")
        fade.setDuration(200)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.setEasingCurve(QEasingCurve.Type.OutQuad)
        fade.finished.connect(self.closed)
        fade.finished.connect(self.deleteLater)
        self._fade_anim = fade
        fade.start()


class ToastManager(QObject):
    """Controller that manages active toast notifications attached to a QMainWindow.

    Does NOT create a full-window overlay widget, ensuring zero interference
    with mouse clicks on dashboard buttons, tables, and sidebar navigation.
    """

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._parent_widget: QWidget = parent
        self._toasts: list[_ToastWidget] = []
        parent.installEventFilter(self)

    def eventFilter(self, obj: object, event: object) -> bool:  # noqa: N802
        if isinstance(event, QEvent) and event.type() == QEvent.Type.Resize:
            self._reposition()
        return False

    def show_toast(
        self,
        title: str,
        message: str = "",
        level: ToastLevel = "info",
        duration_ms: int = 5000,
    ) -> None:
        """Show a new toast notification.

        Args:
            title:       Short heading line.
            message:     Optional detail text (can be empty).
            level:       ``info`` | ``success`` | ``warning`` | ``error`` | ``critical``
            duration_ms: Auto-dismiss delay (0 = never auto-dismiss).
        """
        # Evict oldest if at cap
        if len(self._toasts) >= _MAX_STACK and self._toasts:
            self._toasts[0]._dismiss()

        toast = _ToastWidget(title, message, level, duration_ms, self._parent_widget)
        toast.closed.connect(lambda: self._on_closed(toast))
        self._toasts.append(toast)
        toast.show()
        toast.raise_()
        self._reposition()
        self._slide_in(toast)

    def _slide_in(self, toast: _ToastWidget) -> None:
        p_width = self._parent_widget.width()
        end_x = p_width - _TOAST_W - _MARGIN
        start_x = p_width + 10
        y = toast.y()
        anim = QPropertyAnimation(toast, b"pos")
        anim.setDuration(280)
        anim.setStartValue(QPoint(start_x, y))
        anim.setEndValue(QPoint(end_x, y))
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        toast._slide_anim = anim   # keep reference
        anim.start()

    def _reposition(self) -> None:
        visible = [t for t in self._toasts if t.isVisible()]
        y = _MARGIN + 68  # Just below header
        p_width = self._parent_widget.width()
        x = p_width - _TOAST_W - _MARGIN
        for t in visible:
            t.move(x, y)
            t.raise_()
            y += t.height() + _GAP

    def _on_closed(self, toast: _ToastWidget) -> None:
        if toast in self._toasts:
            self._toasts.remove(toast)
        self._reposition()


__all__ = ["ToastLevel", "ToastManager"]

