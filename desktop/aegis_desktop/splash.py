"""Enterprise splash screen for the Aegis IDPS desktop console.

A frameless, dark-themed loading screen that simulates backend initialization
phases before the main SOC console appears.  Pure presentation -- no security
data is fabricated; the loading steps reflect real Aegis architecture components.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import QApplication, QLabel, QProgressBar, QWidget

from aegis_desktop.theme import (
    ACCENT,
    BACKGROUND,
    BORDER,
    INFO,
    PANEL,
    TEXT,
    TEXT_MUTED,
)

#: Total splash screen duration in milliseconds.
_SPLASH_DURATION_MS = 2800

#: Interval between loading phase updates in milliseconds.
_PHASE_INTERVAL_MS = 400

#: Loading phases -- each maps to a real Aegis architecture component.
_PHASES: tuple[tuple[str, float], ...] = (
    ("Initializing Aegis Core Runtime...", 0.0),
    ("Loading Host Telemetry Monitors...", 0.15),
    ("Warming up ML Anomaly Detection Models...", 0.35),
    ("Loading Deterministic Threat Rules...", 0.55),
    ("Establishing Secure Local Event Bus...", 0.75),
    ("Launching SOC Console...", 0.92),
)

#: Splash screen dimensions.
_SPLASH_WIDTH = 520
_SPLASH_HEIGHT = 340


class SplashScreen(QWidget):
    """Frameless enterprise splash screen with animated progress and phase text.

    The screen is non-interactive, centered on the primary display, and
    auto-closes after the loading sequence completes.  A callback is invoked
    when the splash is ready to hand off to the main window.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        on_finished: callable | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_finished = on_finished
        self._phase_index = 0
        self._opacity = 1.0

        self.setWindowTitle("")
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Dialog
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(_SPLASH_WIDTH, _SPLASH_HEIGHT)

        self._build_ui()
        self._center_on_screen()

        self._timer = QTimer(self)
        self._timer.setInterval(_PHASE_INTERVAL_MS)
        self._timer.timeout.connect(self._advance_phase)

    # -- UI construction ---------------------------------------------------

    def _build_ui(self) -> None:
        self.setLayout(None)

        self._status_label = QLabel(self)
        self._status_label.setObjectName("SplashStatus")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status_label.setStyleSheet(
            f"color: {TEXT_MUTED}; font-size: 12px; background: transparent;"
        )
        self._status_label.setGeometry(30, _SPLASH_HEIGHT - 70, _SPLASH_WIDTH - 60, 18)

        self._progress = QProgressBar(self)
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setFixedHeight(4)
        self._progress.setGeometry(40, _SPLASH_HEIGHT - 45, _SPLASH_WIDTH - 80, 4)
        self._progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 2px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {ACCENT},
                    stop:1 {INFO}
                );
                border-radius: 2px;
            }}
        """)

    def _center_on_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            x = (geo.width() - self.width()) // 2 + geo.x()
            y = (geo.height() - self.height()) // 2 + geo.y()
            self.move(x, y)

    # -- Painting ----------------------------------------------------------

    def paintEvent(self, event: object) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Background with subtle gradient
        gradient = QLinearGradient(0, 0, 0, h)
        gradient.setColorAt(0.0, QColor("#0C1322"))
        gradient.setColorAt(0.5, QColor(BACKGROUND))
        gradient.setColorAt(1.0, QColor("#0A0F1A"))
        painter.fillRect(0, 0, w, h, gradient)

        # Subtle top accent line
        accent_gradient = QLinearGradient(0, 0, w, 0)
        accent_gradient.setColorAt(0.0, QColor(ACCENT).darker(150))
        accent_gradient.setColorAt(0.5, QColor(ACCENT))
        accent_gradient.setColorAt(1.0, QColor(ACCENT).darker(150))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(accent_gradient))
        painter.drawRect(0, 0, int(w), 2)

        # Product name
        title_font = QFont("Segoe UI", 32, QFont.Weight.ExtraBold)
        title_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3.0)
        painter.setFont(title_font)
        painter.setPen(QPen(QColor(TEXT)))
        title_rect = self.rect().adjusted(0, 60, 0, -140)
        painter.drawText(
            title_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
            "AEGIS",
        )

        # Subtitle
        sub_font = QFont("Segoe UI", 11, QFont.Weight.Normal)
        sub_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.5)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(TEXT_MUTED)))
        sub_rect = self.rect().adjusted(0, 0, 0, -90)
        painter.drawText(
            sub_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
            "HYBRID HOST & NETWORK INTRUSION DEFENSE SYSTEM",
        )

        # Thin separator
        painter.setPen(QPen(QColor(BORDER), 1))
        sep_y = h - 95
        painter.drawLine(60, int(sep_y), w - 60, int(sep_y))

        # Version tag
        try:
            from aegis_shared.version import __version__
            version_text = f"v{__version__}"
        except Exception:
            version_text = ""
        if version_text:
            ver_font = QFont("Segoe UI", 9, QFont.Weight.Normal)
            painter.setFont(ver_font)
            painter.setPen(QPen(QColor(TEXT_MUTED)))
            ver_rect = self.rect().adjusted(0, 0, 0, -20)
            painter.drawText(
                ver_rect,
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
                version_text,
            )

        painter.end()

    # -- Animation ---------------------------------------------------------

    def start(self) -> None:
        """Begin the loading sequence.  Call this instead of show()."""
        self.show()
        self.raise_()
        self.activateWindow()
        self._timer.start()

    def _advance_phase(self) -> None:
        if self._phase_index >= len(_PHASES):
            self._timer.stop()
            self._finish()
            return

        text, progress = _PHASES[self._phase_index]
        self._status_label.setText(text)
        self._progress.setValue(int(progress * 100))
        self._phase_index += 1

    def _finish(self) -> None:
        self._progress.setValue(100)
        self._status_label.setText("Ready.")

        QTimer.singleShot(200, self._close_and_handoff)

    def _close_and_handoff(self) -> None:
        fade = QPropertyAnimation(self, b"windowOpacity")
        fade.setDuration(250)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.setEasingCurve(QEasingCurve.Type.OutQuad)
        fade.finished.connect(self._on_fade_complete)
        self._fade_animation = fade
        fade.start()

    def _on_fade_complete(self) -> None:
        self.close()
        if self._on_finished is not None:
            self._on_finished()


__all__ = ["SplashScreen"]
