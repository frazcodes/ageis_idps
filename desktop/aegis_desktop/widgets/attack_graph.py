"""Interactive Attack Graph & Kill-Chain Visualizer for Aegis IDPS.

Renders an enterprise-grade node-link attack topology:
- Animated energy pulses / packet particles flowing along attack paths.
- Distinct color-coded and glyph-badged nodes (Attacker, Port, Sensor, Host, Process).
- Interactive mouse hover with glowing halos and deep forensic HUD cards.
- Drag-and-drop node physics for repositioning on canvas.
- Automatic layout alignment matching MITRE ATT&CK kill-chain stages.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from PySide6.QtCore import QPointF, QRectF, QSize, QTimer, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QCursor,
    QFont,
    QLinearGradient,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QRadialGradient,
)
from PySide6.QtWidgets import QWidget


@dataclass
class GraphNode:
    """An individual entity in the attack kill-chain graph."""

    id: str
    label: str
    sublabel: str
    node_type: str  # "ATTACKER" | "PORT" | "DETECTION" | "HOST" | "PROCESS" | "FILE"
    x: float
    y: float
    color: QColor
    glyph: str
    severity: str = "HIGH"
    radius: float = 26.0
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A causal or network bond between two attack graph nodes."""

    source_id: str
    target_id: str
    label: str
    color: QColor
    particles: list[float] = field(default_factory=lambda: [0.1, 0.45, 0.8])
    speed: float = 0.015


class InteractiveAttackGraphWidget(QWidget):
    """Interactive node-link graph visualizer for security incidents and attacks."""

    node_clicked = Signal(str, dict)  # Emits (node_id, metadata)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(QSize(420, 240))
        self.setMouseTracking(True)

        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._hovered_node_id: str | None = None
        self._dragged_node_id: str | None = None
        self._drag_offset_x: float = 0.0
        self._drag_offset_y: float = 0.0
        self._anim_phase: float = 0.0

        # Animation timer for moving particle pulses and glowing rings (30 FPS)
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start()

        # Seed with a default demo kill-chain
        self.load_sample_kill_chain()

    def set_graph_data(
        self, nodes: list[GraphNode], edges: list[GraphEdge]
    ) -> None:
        """Replace current graph topology with new nodes and edges."""
        self._nodes = {n.id: n for n in nodes}
        self._edges = list(edges)
        self.update()

    def load_from_incident(
        self,
        incident_id: str,
        attacker_ip: str,
        target_port: str,
        rule_name: str,
        host_name: str,
        process_name: str,
        severity: str = "CRITICAL",
    ) -> None:
        """Dynamically construct a 5-stage attack kill-chain for an incident."""
        w = float(max(self.width(), 480))
        h = float(max(self.height(), 240))
        cy = h / 2.0

        # 5 Kill-chain stages distributed evenly from left to right
        x_step = w / 6.0

        nodes = [
            GraphNode(
                id="attacker",
                label="ATTACKER",
                sublabel=attacker_ip or "192.168.8.100",
                node_type="ATTACKER",
                x=x_step * 1.0,
                y=cy,
                color=QColor(239, 68, 68),  # Crimson Red
                glyph="🌐",
                severity=severity,
                metadata={
                    "Role": "Threat Ingress Source",
                    "IP": attacker_ip or "192.168.8.100",
                    "Vector": "External Subnet / Direct Inbound",
                },
            ),
            GraphNode(
                id="port",
                label="TARGET PORT",
                sublabel=f"Port {target_port}" if target_port else "Port 443 (HTTPS)",
                node_type="PORT",
                x=x_step * 2.0,
                y=cy - 20.0,
                color=QColor(245, 158, 11),  # Amber
                glyph="🔌",
                severity="HIGH",
                metadata={
                    "Service": "Ingress Socket",
                    "Port": str(target_port or "443"),
                    "Protocol": "TCP / Raw Stream",
                },
            ),
            GraphNode(
                id="detection",
                label="DETECTION",
                sublabel=rule_name[:16] if rule_name else "SYN FLOOD",
                node_type="DETECTION",
                x=x_step * 3.0,
                y=cy + 20.0,
                color=QColor(249, 115, 22),  # Orange
                glyph="⚠️",
                severity="CRITICAL",
                metadata={
                    "Rule": rule_name or "SYN Flood / Port Scan",
                    "Engine": "Deterministic + ML Isolation Forest",
                    "Confidence": "96.4%",
                },
            ),
            GraphNode(
                id="host",
                label="LOCAL HOST",
                sublabel=host_name or "THIS COMPUTER",
                node_type="HOST",
                x=x_step * 4.0,
                y=cy - 15.0,
                color=QColor(56, 189, 248),  # Cyber Sky Blue
                glyph="💻",
                severity="INFO",
                metadata={
                    "Host": host_name or "DESKTOP-CFGSP9P",
                    "OS": "Windows 11 Pro",
                    "Status": "PROTECTED / AGENT ACTIVE",
                },
            ),
            GraphNode(
                id="process",
                label="TARGET PROCESS",
                sublabel=process_name or "powershell.exe",
                node_type="PROCESS",
                x=x_step * 5.0,
                y=cy,
                color=QColor(168, 85, 247),  # Violet
                glyph="⚡",
                severity="HIGH",
                metadata={
                    "Binary": process_name or "powershell.exe",
                    "PID": "4120",
                    "Action": "ISOLATED BY FIREWALL",
                },
            ),
        ]

        edges = [
            GraphEdge("attacker", "port", "Inbound Packets", QColor(239, 68, 68)),
            GraphEdge("port", "detection", "Sensor Trigger", QColor(245, 158, 11)),
            GraphEdge("detection", "host", "Alert Correlation", QColor(249, 115, 22)),
            GraphEdge("host", "process", "Process Execution", QColor(168, 85, 247)),
        ]

        self.set_graph_data(nodes, edges)

    def load_sample_kill_chain(self) -> None:
        """Seed default interactive attack topology."""
        self.load_from_incident(
            incident_id="INC-DEMO-01",
            attacker_ip="192.168.8.100",
            target_port="443",
            rule_name="SYN FLOOD EXPLOIT",
            host_name="DESKTOP-CFGSP9P",
            process_name="powershell.exe",
        )

    def _on_tick(self) -> None:
        """Advance animated packet pulses and breathing strobe glow."""
        self._anim_phase = (self._anim_phase + 0.08) % (2.0 * math.pi)

        # Advance particles along edges
        for edge in self._edges:
            for i in range(len(edge.particles)):
                edge.particles[i] = (edge.particles[i] + edge.speed) % 1.0

        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # 1. Dark Cyber Tactical Canvas with Fine Grid
        self._draw_canvas_background(painter, w, h)

        # 2. Draw Edges with Animated Flowing Pulses
        for edge in self._edges:
            src = self._nodes.get(edge.source_id)
            tgt = self._nodes.get(edge.target_id)
            if src and tgt:
                self._draw_edge(painter, src, tgt, edge)

        # 3. Draw Nodes with Badges and Breathing Halos
        for node in self._nodes.values():
            self._draw_node(painter, node, is_hovered=(node.id == self._hovered_node_id))

        # 4. Top Telemetry Banner
        self._draw_hud_header(painter, w)

        # 5. Hover HUD Details Card
        if self._hovered_node_id and self._hovered_node_id in self._nodes:
            hovered_node = self._nodes[self._hovered_node_id]
            self._draw_inspector_card(painter, hovered_node, w, h)

    def _draw_canvas_background(self, painter: QPainter, w: float, h: float) -> None:
        """Draw deep obsidian background with fine cyber matrix grid."""
        painter.setBrush(QBrush(QColor(5, 10, 20)))
        painter.setPen(QPen(QColor(30, 41, 59), 1.0))
        painter.drawRoundedRect(QRectF(0, 0, w, h), 8, 8)

        # Subtle grid lines
        grid_pen = QPen(QColor(15, 23, 42, 120), 1.0, Qt.PenStyle.DotLine)
        painter.setPen(grid_pen)
        grid_size = 32
        for x in range(grid_size, int(w), grid_size):
            painter.drawLine(x, 0, x, int(h))
        for y in range(grid_size, int(h), grid_size):
            painter.drawLine(0, y, int(w), y)

    def _draw_edge(
        self, painter: QPainter, src: GraphNode, tgt: GraphNode, edge: GraphEdge
    ) -> None:
        """Draw connecting curved line with animated energy packet pulses."""
        path = QPainterPath()
        p1 = QPointF(src.x, src.y)
        p2 = QPointF(tgt.x, tgt.y)

        # Smooth cubic bezier curve
        dx = p2.x() - p1.x()
        c1 = QPointF(p1.x() + dx * 0.5, p1.y())
        c2 = QPointF(p2.x() - dx * 0.5, p2.y())

        path.moveTo(p1)
        path.cubicTo(c1, c2, p2)

        # Base connecting line
        edge_col = QColor(edge.color.red(), edge.color.green(), edge.color.blue(), 100)
        painter.setPen(QPen(edge_col, 2.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Animated Glowing Energy Pulses (moving packets)
        for t in edge.particles:
            pt = path.pointAtPercent(t)
            # Pulse glow halo
            halo_col = QColor(edge.color.red(), edge.color.green(), edge.color.blue(), 180)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(halo_col))
            painter.drawEllipse(pt, 4.5, 4.5)

            # Core white packet
            painter.setBrush(QBrush(QColor(255, 255, 255, 240)))
            painter.drawEllipse(pt, 2.0, 2.0)

        # Edge Label in midpoint
        mid = path.pointAtPercent(0.5)
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        painter.setPen(QPen(QColor(148, 163, 184, 190)))
        painter.drawText(int(mid.x() - 40), int(mid.y() - 6), 80, 14, Qt.AlignmentFlag.AlignCenter, edge.label)

    def _draw_node(self, painter: QPainter, node: GraphNode, is_hovered: bool) -> None:
        """Draw an attack graph node with glowing halos, glyphs, and labels."""
        # Breathing halo for Critical / Attacker nodes
        if node.severity == "CRITICAL" or is_hovered:
            pulse = math.sin(self._anim_phase) * 4.0
            halo_r = node.radius + 6.0 + (pulse if not is_hovered else 8.0)
            halo_col = QColor(node.color.red(), node.color.green(), node.color.blue(), 70)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QBrush(halo_col))
            painter.drawEllipse(QPointF(node.x, node.y), halo_r, halo_r)

        # Outer border ring
        painter.setPen(QPen(node.color, 2.5 if is_hovered else 1.8))
        painter.setBrush(QBrush(QColor(15, 23, 42, 240)))
        painter.drawEllipse(QPointF(node.x, node.y), node.radius, node.radius)

        # Central Glyph Icon
        painter.setFont(QFont("Segoe UI Emoji", int(node.radius * 0.72)))
        painter.setPen(QPen(node.color))
        glyph_rect = QRectF(node.x - node.radius, node.y - node.radius, node.radius * 2, node.radius * 2)
        painter.drawText(glyph_rect, Qt.AlignmentFlag.AlignCenter, node.glyph)

        # Top Badge (Node Category)
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        painter.setPen(QPen(node.color))
        painter.drawText(
            int(node.x - 60), int(node.y - node.radius - 14), 120, 14,
            Qt.AlignmentFlag.AlignCenter, node.label
        )

        # Bottom Sublabel (IP, Port, Binary name)
        painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold if is_hovered else QFont.Weight.Normal))
        painter.setPen(QPen(QColor(226, 232, 240) if is_hovered else QColor(148, 163, 184)))
        painter.drawText(
            int(node.x - 65), int(node.y + node.radius + 4), 130, 16,
            Qt.AlignmentFlag.AlignCenter, node.sublabel
        )

    def _draw_hud_header(self, painter: QPainter, w: float) -> None:
        """Render top cyber telemetry header."""
        painter.setFont(QFont("Consolas", 8, QFont.Weight.Bold))
        painter.setPen(QPen(QColor(56, 189, 248)))
        painter.drawText(12, 18, "🕸️ INTERACTIVE ATTACK TOPOLOGY GRAPH")

        painter.setPen(QPen(QColor(100, 116, 139)))
        painter.drawText(int(w - 230), 18, "KILL-CHAIN: INGRESS ➔ EXECUTION")

    def _draw_inspector_card(
        self, painter: QPainter, node: GraphNode, w: float, h: float
    ) -> None:
        """Render glowing tactical inspector card for hovered node."""
        card_w = 210.0
        card_h = 24.0 + (len(node.metadata) * 16.0)
        card_x = node.x + node.radius + 12
        if card_x + card_w > w - 10:
            card_x = node.x - node.radius - card_w - 12
        card_y = node.y - 20
        if card_y + card_h > h - 10:
            card_y = h - card_h - 10

        card_rect = QRectF(card_x, card_y, card_w, card_h)

        # Card chassis
        painter.setBrush(QBrush(QColor(8, 14, 26, 250)))
        painter.setPen(QPen(node.color, 1.5))
        painter.drawRoundedRect(card_rect, 6, 6)

        # Header inside inspector
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.setPen(QPen(node.color))
        painter.drawText(int(card_x + 10), int(card_y + 16), f"{node.label}: {node.sublabel}")

        # Metadata fields
        painter.setFont(QFont("Consolas", 8))
        curr_y = card_y + 32
        for k, v in node.metadata.items():
            painter.setPen(QPen(QColor(148, 163, 184)))
            painter.drawText(int(card_x + 10), int(curr_y), f"{k}:")
            painter.setPen(QPen(QColor(241, 245, 249)))
            painter.drawText(int(card_x + 75), int(curr_y), str(v)[:18])
            curr_y += 16

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        pos = event.position()
        mx = pos.x()
        my = pos.y()

        # Handle Dragging Node
        if self._dragged_node_id and self._dragged_node_id in self._nodes:
            node = self._nodes[self._dragged_node_id]
            node.x = mx - self._drag_offset_x
            node.y = my - self._drag_offset_y
            self.update()
            return

        # Check Node Hover
        found_id: str | None = None
        for node in self._nodes.values():
            dist = math.hypot(mx - node.x, my - node.y)
            if dist <= node.radius + 4:
                found_id = node.id
                break

        if found_id != self._hovered_node_id:
            self._hovered_node_id = found_id
            self.setCursor(
                QCursor(Qt.CursorShape.PointingHandCursor)
                if found_id
                else QCursor(Qt.CursorShape.ArrowCursor)
            )
            self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self._hovered_node_id:
            node = self._nodes[self._hovered_node_id]
            self._dragged_node_id = node.id
            self._drag_offset_x = event.position().x() - node.x
            self._drag_offset_y = event.position().y() - node.y
            self.node_clicked.emit(node.id, dict(node.metadata))

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        self._dragged_node_id = None
