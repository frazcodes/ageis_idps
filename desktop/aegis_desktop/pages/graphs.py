"""Lightweight QPainter-based graph widgets for the SOC dashboard.

No external charting dependencies.  Uses native Qt painting to draw
time-series line charts and a risk-score gauge.  All widgets are read-only
and display only data they receive -- no fabrication.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget

from aegis_desktop.theme import (
    CRITICAL,
    HIGH,
    INFO,
    OK,
    PANEL,
    SURFACE_ALT,
    TEXT,
    TEXT_MUTED,
    WARN,
)


class LineGraphWidget(QWidget):
    """Minimal time-series line graph with optional grid and labels.

    Each series is a list of float values plotted left-to-right.  The
    horizontal axis represents time (newest on the right).  The vertical
    axis auto-scales to the data range.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        title: str = "",
        series_configs: tuple[tuple[str, str], ...] = (),
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._series_configs = series_configs  # (label, color_hex)
        self._series_data: dict[str, list[float]] = {
            label: [] for label, _ in series_configs
        }
        self.setMinimumHeight(120)

    def update_data(self, series_name: str, values: list[float]) -> None:
        """Update one data series and trigger repaint."""
        if series_name in self._series_data:
            self._series_data[series_name] = values[:]
            self.update()

    def set_data(self, data: dict[str, list[float]]) -> None:
        """Replace all series data at once."""
        for key in self._series_data:
            self._series_data[key] = list(data.get(key, []))
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Background
        painter.fillRect(QRectF(0, 0, w, h), QColor(PANEL))

        margin_left = 55.0
        margin_right = 12.0
        margin_top = 30.0
        margin_bottom = 22.0

        plot_x = margin_left
        plot_y = margin_top
        plot_w = max(w - margin_left - margin_right, 1.0)
        plot_h = max(h - margin_top - margin_bottom, 1.0)

        # Title
        if self._title:
            painter.setPen(QPen(QColor(TEXT_MUTED)))
            font = painter.font()
            font.setPointSize(9)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(QRectF(8, 2, w - 16, 24), Qt.AlignmentFlag.AlignLeft, self._title)

        # Compute global max
        all_vals: list[float] = []
        for vals in self._series_data.values():
            all_vals.extend(v for v in vals if v >= 0)
        data_max = max(all_vals) if all_vals else 1.0
        if data_max == 0:
            data_max = 1.0

        # Grid lines (4 horizontal)
        painter.setPen(QPen(QColor(SURFACE_ALT), 1, Qt.PenStyle.DashLine))
        grid_font = painter.font()
        grid_font.setPointSize(8)
        grid_font.setBold(False)
        painter.setFont(grid_font)
        painter.setPen(QPen(QColor(TEXT_MUTED)))
        for i in range(5):
            gy = plot_y + plot_h * (1.0 - i / 4.0)
            painter.drawLine(plot_x, gy, plot_x + plot_w, gy)
            val = data_max * i / 4.0
            label = f"{val:,.0f}" if val >= 100 else f"{val:.1f}"
            painter.drawText(
                QRectF(2, gy - 8, margin_left - 4, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                label,
            )

        # Plot series
        for label, color_hex in self._series_configs:
            values = self._series_data.get(label, [])
            if len(values) < 2:
                continue

            pen = QPen(QColor(color_hex), 2)
            painter.setPen(pen)

            max_pts = len(values)
            points = []
            for idx, val in enumerate(values):
                px = plot_x + (idx / max(max_pts - 1, 1)) * plot_w
                py = plot_y + plot_h * (1.0 - val / data_max)
                points.append((px, py))

            for i in range(len(points) - 1):
                painter.drawLine(
                    points[i][0], points[i][1],
                    points[i + 1][0], points[i + 1][1],
                )

        # Legend (top right)
        legend_x = w - margin_right - 8
        legend_y = 6.0
        legend_font = painter.font()
        legend_font.setPointSize(8)
        legend_font.setBold(True)
        painter.setFont(legend_font)
        for label, color_hex in reversed(self._series_configs):
            painter.setPen(QPen(QColor(color_hex)))
            tw = painter.fontMetrics().horizontalAdvance(label)
            painter.drawText(
                QRectF(legend_x - tw, legend_y, tw + 4, 14),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            legend_x -= tw + 16

        # Empty state
        if not any(self._series_data.values()):
            painter.setPen(QPen(QColor(TEXT_MUTED)))
            font = painter.font()
            font.setPointSize(10)
            font.setBold(False)
            painter.setFont(font)
            painter.drawText(
                QRectF(plot_x, plot_y, plot_w, plot_h),
                Qt.AlignmentFlag.AlignCenter,
                "No telemetry data",
            )

        painter.end()


class RiskGaugeWidget(QWidget):
    """Horizontal bar gauge showing the current risk score (0-100)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int | None = None
        self._level: str = ""
        self.setFixedHeight(40)

    def set_score(self, score: int | None, level: str = "") -> None:
        """Update the displayed risk score."""
        self._score = score
        self._level = level
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Background bar
        bar_rect = QRectF(0, 4, w, h - 8)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(SURFACE_ALT)))
        painter.drawRoundedRect(bar_rect, 4, 4)

        if self._score is not None and self._score >= 0:
            fill_w = w * min(self._score / 100.0, 1.0)
            fill_rect = QRectF(0, 4, fill_w, h - 8)

            if self._score >= 80:
                color = QColor(CRITICAL)
            elif self._score >= 60:
                color = QColor(HIGH)
            elif self._score >= 40:
                color = QColor(WARN)
            elif self._score >= 20:
                color = QColor(INFO)
            else:
                color = QColor(OK)

            painter.setBrush(QBrush(color))
            painter.drawRoundedRect(fill_rect, 4, 4)

        # Score text
        painter.setPen(QPen(QColor(TEXT)))
        font = painter.font()
        font.setPointSize(10)
        font.setBold(True)
        painter.setFont(font)
        text = str(self._score) if self._score is not None else "\u2014"
        if self._level:
            text = f"{text}  ({self._level.upper()})"
        painter.drawText(QRectF(8, 4, w - 16, h - 8), Qt.AlignmentFlag.AlignCenter, text)

        painter.end()


__all__ = ["LineGraphWidget", "RiskGaugeWidget"]
