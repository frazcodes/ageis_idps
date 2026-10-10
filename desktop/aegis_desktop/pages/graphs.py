"""Enterprise QPainter-based cyber SOC graph and gauge widgets.

Uses native Qt painting to render modern SOC time-series charts with gradient
glow fills, antialiased lines, and a high-tech segmented HUD risk gauge.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QWidget

from aegis_desktop.theme import (
    ACCENT,
    CRITICAL,
    HIGH,
    INFO,
    OK,
    WARN,
)

_BG_CHART = "#0B1120"
_BORDER_CHART = "#1E293B"
_GRID_COLOR = "#162032"


class LineGraphWidget(QWidget):
    """Enterprise SOC time-series line graph with gradient fills and cyber styling."""

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
        self.setMinimumHeight(140)

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

        # Card Frame Background
        card_rect = QRectF(0, 0, w, h)
        painter.setPen(QPen(QColor(_BORDER_CHART), 1))
        painter.setBrush(QBrush(QColor(_BG_CHART)))
        painter.drawRoundedRect(card_rect, 8, 8)

        margin_left = 52.0
        margin_right = 14.0
        margin_top = 34.0
        margin_bottom = 22.0

        plot_x = margin_left
        plot_y = margin_top
        plot_w = max(w - margin_left - margin_right, 1.0)
        plot_h = max(h - margin_top - margin_bottom, 1.0)

        # Title
        if self._title:
            painter.setPen(QPen(QColor("#94A3B8")))
            font = painter.font()
            font.setPointSize(9)
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(
                QRectF(12, 8, w - 24, 20),
                Qt.AlignmentFlag.AlignLeft,
                self._title.upper(),
            )

        # Compute global max
        all_vals: list[float] = []
        for vals in self._series_data.values():
            all_vals.extend(v for v in vals if v >= 0)
        data_max = max(all_vals) if all_vals else 1.0
        if data_max == 0:
            data_max = 1.0

        # Grid lines (4 horizontal)
        grid_font = painter.font()
        grid_font.setPointSize(8)
        grid_font.setBold(False)
        painter.setFont(grid_font)

        for i in range(5):
            gy = plot_y + plot_h * (1.0 - i / 4.0)
            painter.setPen(QPen(QColor(_GRID_COLOR), 1, Qt.PenStyle.DashLine))
            painter.drawLine(QPointF(plot_x, gy), QPointF(plot_x + plot_w, gy))

            val = data_max * i / 4.0
            label = f"{val:,.0f}" if val >= 100 else f"{val:.1f}"
            painter.setPen(QPen(QColor("#64748B")))
            painter.drawText(
                QRectF(2, gy - 8, margin_left - 8, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                label,
            )

        # Plot series with gradient area fills + smooth lines
        has_data = any(len(v) >= 2 for v in self._series_data.values())

        for label, color_hex in self._series_configs:
            values = self._series_data.get(label, [])
            if len(values) < 2:
                continue

            max_pts = len(values)
            points: list[QPointF] = []
            for idx, val in enumerate(values):
                px = plot_x + (idx / max(max_pts - 1, 1)) * plot_w
                py = plot_y + plot_h * (1.0 - min(max(val, 0.0), data_max) / data_max)
                points.append(QPointF(px, py))

            # 1. Gradient Area Fill
            base_col = QColor(color_hex)
            area_grad = QLinearGradient(plot_x, plot_y, plot_x, plot_y + plot_h)
            c_top = QColor(base_col)
            c_top.setAlpha(60)
            c_bot = QColor(base_col)
            c_bot.setAlpha(0)
            area_grad.setColorAt(0.0, c_top)
            area_grad.setColorAt(1.0, c_bot)

            path = QPainterPath()
            path.moveTo(points[0].x(), plot_y + plot_h)
            path.lineTo(points[0])
            for pt in points[1:]:
                path.lineTo(pt)
            path.lineTo(points[-1].x(), plot_y + plot_h)
            path.closeSubpath()

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(area_grad))
            painter.drawPath(path)

            # 2. Glowing Line
            line_pen = QPen(base_col, 2.2)
            line_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            line_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(line_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)

            line_path = QPainterPath()
            line_path.moveTo(points[0])
            for pt in points[1:]:
                line_path.lineTo(pt)
            painter.drawPath(line_path)

            # 3. Glowing dot on latest data point
            last_pt = points[-1]
            halo_col = QColor(base_col)
            halo_col.setAlpha(90)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(halo_col))
            painter.drawEllipse(last_pt, 5.0, 5.0)

            painter.setBrush(QBrush(QColor("#FFFFFF")))
            painter.drawEllipse(last_pt, 2.5, 2.5)

        # Legend (top right)
        legend_x = w - margin_right - 10
        legend_y = 8.0
        legend_font = painter.font()
        legend_font.setPointSize(8)
        legend_font.setBold(True)
        painter.setFont(legend_font)

        for label, color_hex in reversed(self._series_configs):
            tw = painter.fontMetrics().horizontalAdvance(label)
            # Dot indicator
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(QColor(color_hex)))
            painter.drawEllipse(QPointF(legend_x - tw - 6, legend_y + 6), 3.5, 3.5)

            # Text
            painter.setPen(QPen(QColor("#CBD5E1")))
            painter.drawText(
                QRectF(legend_x - tw, legend_y, tw + 4, 14),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            legend_x -= tw + 22

        # Empty state
        if not has_data:
            painter.setPen(QPen(QColor("#475569")))
            font = painter.font()
            font.setPointSize(9)
            font.setBold(False)
            painter.setFont(font)
            painter.drawText(
                QRectF(plot_x, plot_y, plot_w, plot_h),
                Qt.AlignmentFlag.AlignCenter,
                "STREAM INACTIVE — AWAITING MONITORING TELEMETRY",
            )

        painter.end()


class RiskGaugeWidget(QWidget):
    """Segmented cyber HUD meter showing the current risk score (0-100)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score: int | None = None
        self._level: str = ""
        self.setFixedHeight(46)
        self.setMinimumWidth(180)

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

        # Frame
        painter.setPen(QPen(QColor("#1E293B"), 1))
        painter.setBrush(QBrush(QColor("#080D1A")))
        painter.drawRoundedRect(QRectF(0, 0, w, h), 6, 6)

        num_segments = 24
        bar_h = 10.0
        bar_y = h - bar_h - 8.0
        bar_x = 10.0
        total_bar_w = w - 20.0
        seg_gap = 2.5
        seg_w = max((total_bar_w - (num_segments - 1) * seg_gap) / num_segments, 2.0)

        score_val = self._score if self._score is not None else 0
        active_segs = (
            math.ceil(num_segments * (score_val / 100.0))
            if self._score is not None
            else 0
        )

        # Draw segmented meter
        for i in range(num_segments):
            seg_x = bar_x + i * (seg_w + seg_gap)
            ratio = i / float(num_segments - 1)

            # Color spectrum: OK -> CYAN -> WARN -> CRITICAL
            if ratio < 0.35:
                col = QColor(OK)
            elif ratio < 0.60:
                col = QColor(INFO)
            elif ratio < 0.80:
                col = QColor(WARN)
            else:
                col = QColor(CRITICAL)

            if i < active_segs:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QBrush(col))
            else:
                # Dim background segment
                dim = QColor(col)
                dim.setAlpha(35)
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QBrush(dim))

            painter.drawRoundedRect(QRectF(seg_x, bar_y, seg_w, bar_h), 2, 2)

        # Header Labels (SCORE + LEVEL)
        font = painter.font()
        font.setPointSize(9)
        font.setBold(True)
        painter.setFont(font)

        # Left label: Status
        painter.setPen(QPen(QColor("#94A3B8")))
        title_txt = "SYSTEM POSTURE GAUGE"
        painter.drawText(
            QRectF(10, 6, 160, 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            title_txt,
        )

        # Right label: Score badge
        if self._score is not None:
            if self._score >= 80:
                score_col = CRITICAL
            elif self._score >= 60:
                score_col = HIGH
            elif self._score >= 40:
                score_col = WARN
            elif self._score >= 20:
                score_col = INFO
            else:
                score_col = OK

            text = f"{self._score} / 100"
            if self._level:
                text = f"{text}  ·  {self._level.upper()}"
            painter.setPen(QPen(QColor(score_col)))
        else:
            text = "STANDBY"
            painter.setPen(QPen(QColor("#64748B")))

        painter.drawText(
            QRectF(w - 200, 6, 190, 16),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            text,
        )

        painter.end()


_MITRE_STAGES: tuple[tuple[str, str], ...] = (
    ("TA0043", "RECONNAISSANCE"),
    ("TA0001", "INITIAL ACCESS"),
    ("TA0002", "EXECUTION"),
    ("TA0003", "PERSISTENCE"),
    ("TA0011", "COMMAND & CTRL"),
    ("TA0010", "EXFILTRATION"),
)


class MitreKillChainWidget(QWidget):
    """6-stage MITRE ATT&CK kill-chain progression ribbon."""

    tactic_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._counts: dict[str, int] = {code: 0 for code, _ in _MITRE_STAGES}
        self._selected_stage: str | None = None
        self.setFixedHeight(68)
        self.setMinimumWidth(480)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Click any stage to filter threats by MITRE ATT&CK tactic")

    def selected_stage(self) -> str | None:
        """Return currently selected tactic code, or None."""
        return self._selected_stage

    def select_stage(self, stage_code: str | None) -> None:
        """Select a stage and emit tactic_selected."""
        if self._selected_stage != stage_code:
            self._selected_stage = stage_code
            self.update()
            self.tactic_selected.emit(stage_code or "")

    def clear_selection(self) -> None:
        """Clear active stage selection."""
        self.select_stage(None)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            w = float(self.width())
            n = len(_MITRE_STAGES)
            pad_x = 12.0
            gap = 18.0
            box_w = max((w - 2 * pad_x - (n - 1) * gap) / n, 60.0)
            click_x = event.position().x()

            for idx, (code, _) in enumerate(_MITRE_STAGES):
                bx = pad_x + idx * (box_w + gap)
                if bx <= click_x <= bx + box_w:
                    if self._selected_stage == code:
                        self.clear_selection()
                    else:
                        self.select_stage(code)
                    return
        super().mousePressEvent(event)

    def set_stage_counts(self, counts: dict[str, int]) -> None:
        """Update stage counts and repaint."""
        for code, _ in _MITRE_STAGES:
            self._counts[code] = max(0, counts.get(code, 0))
        self.update()

    def paintEvent(self, event: object) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        painter.setPen(QPen(QColor(_BORDER_CHART), 1))
        painter.setBrush(QBrush(QColor(_BG_CHART)))
        painter.drawRoundedRect(QRectF(0, 0, w, h), 8, 8)

        n = len(_MITRE_STAGES)
        pad_x = 12.0
        gap = 18.0
        box_w = max((w - 2 * pad_x - (n - 1) * gap) / n, 60.0)
        box_h = h - 16.0
        box_y = 8.0

        for idx, (code, name) in enumerate(_MITRE_STAGES):
            bx = pad_x + idx * (box_w + gap)
            count = self._counts.get(code, 0)
            is_selected = (self._selected_stage == code)

            if is_selected:
                accent = QColor("#38BDF8")
                text_col = QColor("#FFFFFF")
                badge_col = QColor("#38BDF8")
                bg_col = QColor("#0C2A4A")
            elif count == 0:
                accent = QColor("#1E293B")
                text_col = QColor("#64748B")
                badge_col = QColor(OK)
                bg_col = QColor("#0E1726")
            elif count == 1:
                accent = QColor(WARN)
                text_col = QColor("#F8FAFC")
                badge_col = QColor(WARN)
                bg_col = QColor("#1E1B18")
            else:
                accent = QColor(CRITICAL)
                text_col = QColor("#FFFFFF")
                badge_col = QColor(CRITICAL)
                bg_col = QColor("#251319")

            pen_w = 2.2 if is_selected else (1.4 if count > 0 else 1.0)
            painter.setPen(QPen(accent, pen_w))
            painter.setBrush(QBrush(bg_col))
            painter.drawRoundedRect(QRectF(bx, box_y, box_w, box_h), 6, 6)

            # Tactic code + count on top row
            f_code = painter.font()
            f_code.setPointSize(8)
            f_code.setBold(True)
            painter.setFont(f_code)
            painter.setPen(QPen(QColor("#38BDF8") if count > 0 else QColor("#475569")))
            painter.drawText(
                QRectF(bx + 8, box_y + 5, box_w - 34, 16),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                code,
            )

            # Count pill
            painter.setPen(QPen(badge_col))
            painter.drawText(
                QRectF(bx + box_w - 32, box_y + 5, 24, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(count),
            )

            # Stage name on bottom row
            f_name = painter.font()
            f_name.setPointSize(8)
            f_name.setBold(True)
            painter.setFont(f_name)
            painter.setPen(QPen(text_col))
            painter.drawText(
                QRectF(bx + 8, box_y + 24, box_w - 16, 20),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                name,
            )

            # Connector arrow to next stage
            if idx < n - 1:
                ax1 = bx + box_w + 3
                ax2 = bx + box_w + gap - 3
                ay = box_y + box_h / 2.0
                painter.setPen(QPen(QColor("#334155"), 1.2))
                painter.drawLine(QPointF(ax1, ay), QPointF(ax2, ay))
                painter.drawLine(QPointF(ax2 - 4, ay - 3), QPointF(ax2, ay))
                painter.drawLine(QPointF(ax2 - 4, ay + 3), QPointF(ax2, ay))

        painter.end()


class TopologyRadarWidget(QWidget):
    """Live Host-Peer radial network topology map with collision-free callout pills."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._hostname: str = "LOCAL-HOST"
        self._host_ip: str = "127.0.0.1"
        self._port_count: int = 0
        self._total_peers: int = 0
        # Tuple of (peer_label, protocol, direction, is_alert)
        self._peers: list[tuple[str, str, str, bool]] = []
        self.setMinimumHeight(230)
        self.setMinimumWidth(320)

    def set_topology(
        self,
        *,
        hostname: str,
        host_ip: str,
        port_count: int,
        peers: list[tuple[str, str, str, bool]],
        total_peers: int | None = None,
    ) -> None:
        """Update central host and surrounding peer nodes."""
        self._hostname = hostname or "LOCAL-HOST"
        self._host_ip = host_ip or "—"
        self._port_count = port_count
        self._total_peers = total_peers if total_peers is not None else len(peers)
        self._peers = list(peers[:8])
        if self._peers:
            lines = [f"Protected Host: {self._hostname} ({self._host_ip})"]
            for p_lbl, proto, direction, is_alert in self._peers:
                tag = " [ALERT]" if is_alert else ""
                lines.append(f"• {p_lbl}  ({proto.upper()} · {direction}){tag}")
            if self._total_peers > len(self._peers):
                lines.append(f"+ {self._total_peers - len(self._peers)} additional active peers")
            self.setToolTip("\n".join(lines))
        else:
            self.setToolTip(f"Protected Host: {self._hostname} ({self._host_ip})\nNo active peers")
        self.update()

    @staticmethod
    def _compact_endpoint(raw: str, max_len: int = 19) -> str:
        """Shorten long IPv6 or hostname endpoints so they fit cleanly in a pill."""
        text = raw.strip()
        if len(text) <= max_len:
            return text
        return text[: max_len - 1] + "…"

    def paintEvent(self, event: object) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        painter.setPen(QPen(QColor(_BORDER_CHART), 1))
        painter.setBrush(QBrush(QColor(_BG_CHART)))
        painter.drawRoundedRect(QRectF(0, 0, w, h), 8, 8)

        # 1. Top Header Bar
        f_title = painter.font()
        f_title.setPointSize(8)
        f_title.setBold(True)
        painter.setFont(f_title)
        painter.setPen(QPen(QColor("#94A3B8")))
        painter.drawText(
            QRectF(12, 6, w * 0.58, 18),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            "LIVE HOST-PEER TOPOLOGY",
        )

        extra = (
            f" (+{self._total_peers - len(self._peers)})"
            if self._total_peers > len(self._peers)
            else ""
        )
        status_txt = f"{self._port_count} PORTS · {len(self._peers)}{extra} PEERS"
        painter.setPen(QPen(QColor("#38BDF8")))
        painter.drawText(
            QRectF(w * 0.42, 6, w * 0.58 - 12, 18),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            status_txt,
        )

        # Subtle header divider
        painter.setPen(QPen(QColor("#162032"), 1))
        painter.drawLine(QPointF(10, 26), QPointF(w - 10, 26))

        # 2. Bottom Footer Bar (Host identity + Legend — never overlaps radar!)
        footer_y = h - 24.0
        painter.setPen(QPen(QColor("#162032"), 1))
        painter.drawLine(QPointF(10, footer_y), QPointF(w - 10, footer_y))

        f_foot = painter.font()
        f_foot.setPointSize(8)
        f_foot.setBold(True)
        painter.setFont(f_foot)
        painter.setPen(QPen(QColor("#CBD5E1")))
        host_summary = f"HOST: {self._hostname} ({self._host_ip})"
        painter.drawText(
            QRectF(12, footer_y + 2, w * 0.62, 20),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            host_summary,
        )

        painter.setPen(QPen(QColor("#64748B")))
        painter.drawText(
            QRectF(w * 0.55, footer_y + 2, w * 0.45 - 12, 20),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            "● OUT  ● IN  ● ALERT",
        )

        # 3. Radar Arena Geometry (between header y=28 and footer_y)
        arena_top = 30.0
        arena_bottom = footer_y - 4.0
        arena_h = max(arena_bottom - arena_top, 100.0)
        cx = w / 2.0
        cy = arena_top + arena_h / 2.0

        pill_w = min(max(w * 0.30, 108.0), 148.0)
        pill_h = 22.0
        radar_max_r = max(min((w - 2.0 * pill_w - 44.0) * 0.48, arena_h * 0.42), 28.0)

        # Concentric radar rings + crosshairs
        painter.setPen(QPen(QColor("#132035"), 1))
        painter.drawLine(
            QPointF(cx - radar_max_r, cy),
            QPointF(cx + radar_max_r, cy),
        )
        painter.drawLine(
            QPointF(cx, cy - radar_max_r),
            QPointF(cx, cy + radar_max_r),
        )

        for frac in (0.52, 0.92):
            r = radar_max_r * frac
            painter.setPen(QPen(QColor("#1E293B"), 1, Qt.PenStyle.DashLine))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), r, r)

        # 4. Split peers into Left (up to 4) and Right (up to 4) fixed vertical slots
        left_peers = self._peers[0::2][:4]
        right_peers = self._peers[1::2][:4]

        f_pill = painter.font()
        f_pill.setPointSize(8)
        f_pill.setBold(True)
        painter.setFont(f_pill)

        # Left angle slots (in radians, facing left from top-left to bottom-left)
        left_angles = (-2.45, -2.88, 2.88, 2.45)
        # Right angle slots (in radians, facing right from top-right to bottom-right)
        right_angles = (-0.69, -0.26, 0.26, 0.69)

        def _draw_side(
            side_peers: list[tuple[str, str, str, bool]],
            *,
            is_left: bool,
            angles: tuple[float, ...],
        ) -> None:
            count = len(side_peers)
            if count == 0:
                return
            slot_step = arena_h / float(max(count, 1))
            for idx, (peer_label, proto, direction, is_alert) in enumerate(side_peers):
                slot_cy = arena_top + slot_step * (idx + 0.5)
                angle = angles[min(idx, len(angles) - 1)]
                ring_r = radar_max_r * (0.88 if idx % 2 == 0 else 0.66)
                px = cx + math.cos(angle) * ring_r
                py = cy + math.sin(angle) * ring_r

                if is_alert:
                    col = QColor(CRITICAL)
                elif direction.lower() == "inbound":
                    col = QColor(OK)
                else:
                    col = QColor(ACCENT)

                # Pill rect in left or right column
                pill_x = 10.0 if is_left else (w - 10.0 - pill_w)
                pill_y = max(arena_top + 2.0, min(slot_cy - pill_h / 2.0, arena_bottom - pill_h))
                anchor_x = (pill_x + pill_w) if is_left else pill_x
                anchor_y = pill_y + pill_h / 2.0

                # Spoke from Host center -> Radar Node -> Pill Anchor
                spoke_col = QColor(col)
                spoke_col.setAlpha(155)
                painter.setPen(QPen(spoke_col, 1.3, Qt.PenStyle.SolidLine))
                painter.drawLine(QPointF(cx, cy), QPointF(px, py))
                painter.drawLine(QPointF(px, py), QPointF(anchor_x, anchor_y))

                # Radar node dot
                painter.setPen(QPen(col, 1.5))
                painter.setBrush(QBrush(QColor("#0B1120")))
                painter.drawEllipse(QPointF(px, py), 4.5, 4.5)

                # Pill background
                pill_rect = QRectF(pill_x, pill_y, pill_w, pill_h)
                painter.setPen(QPen(col, 1.0))
                painter.setBrush(QBrush(QColor("#0F172A")))
                painter.drawRoundedRect(pill_rect, 5, 5)

                # Protocol badge + compact peer endpoint text
                proto_str = (proto or "NET").upper()[:4]
                endpoint_str = self._compact_endpoint(peer_label, max_len=16)
                display_txt = f"{proto_str} · {endpoint_str}"

                painter.setPen(QPen(QColor("#E2E8F0")))
                painter.drawText(
                    QRectF(pill_x + 6.0, pill_y, pill_w - 12.0, pill_h),
                    Qt.AlignmentFlag.AlignVCenter
                    | (
                        Qt.AlignmentFlag.AlignLeft
                        if not is_left
                        else Qt.AlignmentFlag.AlignRight
                    ),
                    display_txt,
                )

        _draw_side(left_peers, is_left=True, angles=left_angles)
        _draw_side(right_peers, is_left=False, angles=right_angles)

        # 5. Central Host Hub Node
        halo = QColor(ACCENT)
        halo.setAlpha(45)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(halo))
        painter.drawEllipse(QPointF(cx, cy), 20.0, 20.0)

        painter.setPen(QPen(QColor("#38BDF8"), 2.0))
        painter.setBrush(QBrush(QColor("#0F172A")))
        painter.drawEllipse(QPointF(cx, cy), 13.0, 13.0)

        f_hub = painter.font()
        f_hub.setPointSize(7)
        f_hub.setBold(True)
        painter.setFont(f_hub)
        painter.setPen(QPen(QColor("#F8FAFC")))
        painter.drawText(
            QRectF(cx - 16.0, cy - 8.0, 32.0, 16.0),
            Qt.AlignmentFlag.AlignCenter,
            "HOST",
        )

        painter.end()


__all__ = [
    "LineGraphWidget",
    "MitreKillChainWidget",
    "RiskGaugeWidget",
    "TopologyRadarWidget",
]

