"""Dashboard page: real-time Security Operations Console.

The page is presentation only. All data comes from existing Aegis components.
Layout: live network activity -> findings -> incidents -> why this matters ->
network relationships -> risk -> alerts -> graphs.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.graphs import LineGraphWidget, RiskGaugeWidget
from aegis_desktop.services.alerts import AlertService
from aegis_desktop.services.dashboard import (
    INVENTORY_ERROR,
    DashboardSnapshot,
    collect_dashboard_snapshot,
    format_timestamp,
)
from aegis_desktop.services.live_network import (
    _PORT_WIDTHS,
    LiveActivityRow,
    LiveNetworkActivity,
    LiveNetworkTableModel,
)
from aegis_desktop.services.telemetry import TelemetryHistory, TelemetrySample
from aegis_desktop.theme import (
    ACCENT,
    CRITICAL,
    HIGH,
    INFO,
    OK,
    TEXT_MUTED,
    WARN,
    set_state,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_EMPTY = "\u2014"
_NO_DATA = "No data"

_MONITOR_ORDER = (
    "Process Monitoring",
    "Port Monitoring",
    "File Integrity Monitoring",
    "Network Sensor",
)


# ---------------------------------------------------------------------------
# Premium posture-card builder
# ---------------------------------------------------------------------------


def _posture_card(
    title: str,
    *,
    accent_color: str,
    number: str = _EMPTY,
    subtitle: str = "",
    button_text: str | None = None,
) -> tuple[QFrame, QLabel, QLabel, QPushButton | None]:
    """Build a premium SOC posture card with a coloured left accent bar.

    Returns ``(frame, number_label, subtitle_label, button)`` so callers can
    update the displayed values via ``.setText()``.
    """
    frame = QFrame()
    frame.setObjectName("Card")
    frame.setStyleSheet(
        f"QFrame#Card {{ border-left: 3px solid {accent_color}; }}"
    )

    outer = QVBoxLayout(frame)
    outer.setContentsMargins(18, 14, 18, 14)
    outer.setSpacing(2)

    title_lbl = QLabel(title.upper())
    title_lbl.setObjectName("CardTitle")
    outer.addWidget(title_lbl)

    num_lbl = QLabel(number)
    num_lbl.setObjectName("PostureNumber")
    num_lbl.setStyleSheet(
        f"font-size: 32px; font-weight: 800; color: {accent_color};"
    )
    outer.addWidget(num_lbl)

    sub_lbl = QLabel(subtitle)
    sub_lbl.setObjectName("CardHint")
    sub_lbl.setWordWrap(True)
    outer.addWidget(sub_lbl)

    btn: QPushButton | None = None
    if button_text is not None:
        btn = QPushButton(button_text)
        btn.setObjectName("PostureButton")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            f"QPushButton {{ background-color: #2a3042; color: {TEXT_MUTED}; "
            f"border: 1px solid {TEXT_MUTED}; border-radius: 4px; "
            f"padding: 4px 10px; font-size: 11px; font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: #363f56; color: #FFFFFF; "
            f"border-color: {ACCENT}; }}"
        )
        outer.addWidget(btn)

    return frame, num_lbl, sub_lbl, btn


def _risk_color(score: int | None) -> str:
    """Severity colour for a 0-100 risk score."""
    if score is None:
        return TEXT_MUTED
    if score >= 70:
        return CRITICAL
    if score >= 40:
        return WARN
    return OK


def _threat_color(count: int) -> str:
    """Severity colour for active threat count."""
    if count == 0:
        return OK
    if count <= 2:
        return WARN
    return CRITICAL


def _action_color(count: int) -> str:
    """Severity colour for pending actions."""
    if count == 0:
        return OK
    return HIGH


class DashboardPage(BasePage):
    """Real-time Security Operations Console for Aegis IDPS."""

    PAGE_KEY = "dashboard"
    TITLE = "Security Operations"
    SUBTITLE = (
        "Real-time SOC console: security posture, live network activity, "
        "findings, incidents, and contextual telemetry."
    )
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], DashboardSnapshot] | None = None,
        alert_service: AlertService | None = None,
        telemetry_history: TelemetryHistory | None = None,
        live_network: LiveNetworkActivity | None = None,
    ) -> None:
        self._provider: Callable[[], DashboardSnapshot] = provider or collect_dashboard_snapshot
        self._snapshot: DashboardSnapshot | None = None
        self._error_active = False

        self._monitor_labels: dict[str, QLabel] = {}
        self._metric_labels: dict[str, QLabel] = {}
        self._host_metric_labels: dict[str, QLabel] = {}
        self._network_metric_labels: dict[str, QLabel] = {}
        self._risk_value_label: QLabel | None = None
        self._risk_level_label: QLabel | None = None
        self._risk_count_label: QLabel | None = None
        self._risk_version_label: QLabel | None = None
        self._risk_context_label: QLabel | None = None

        # SOC posture card labels
        self._posture_risk_num: QLabel | None = None
        self._posture_risk_sub: QLabel | None = None
        self._posture_threat_num: QLabel | None = None
        self._posture_threat_sub: QLabel | None = None
        self._posture_action_num: QLabel | None = None
        self._posture_action_sub: QLabel | None = None

        self._live_metric_labels: dict[str, QLabel] = {}
        # Create hidden metric labels for backward-compat accessors / tests.
        for _key in (
            "events", "detections", "assessments", "processes", "ports",
            "assets", "peers",
        ):
            self._metric_labels[_key] = QLabel(_EMPTY)
        for _key in (
            "live_packets", "live_bytes", "live_flows", "live_active_flows",
            "live_high_findings", "live_open_incidents",
        ):
            self._live_metric_labels[_key] = QLabel(_EMPTY)
        self._network_graph: LineGraphWidget | None = None
        self._security_graph: LineGraphWidget | None = None
        self._risk_graph: LineGraphWidget | None = None
        self._risk_gauge: RiskGaugeWidget | None = None
        self._alert_container: QWidget | None = None
        self._alert_service = alert_service or AlertService()
        self._telemetry_history = telemetry_history or TelemetryHistory()
        self._last_finding_ids: frozenset[str] = frozenset()
        self._last_incident_ids: frozenset[str] = frozenset()

        self._live_network = live_network or LiveNetworkActivity()
        self._live_network_model: LiveNetworkTableModel | None = None
        self._findings_container: QWidget | None = None
        self._incidents_container: QWidget | None = None
        self._explanation_container: QWidget | None = None
        self._relationships_container: QWidget | None = None
        self._network_summary_labels: dict[str, QLabel] = {}
        self._main_window: object | None = None

        # Unified Threat Investigation Feed
        self._threat_feed_layout: QVBoxLayout | None = None

        super().__init__(parent)
        self.refresh()

    # -- Navigation ---------------------------------------------------------

    def set_main_window(self, window: object) -> None:
        """Set the MainWindow reference for click-to-navigate."""
        self._main_window = window

    def _navigate_to(self, key: str, **kwargs: object) -> None:
        """Navigate to a page via the MainWindow, if available."""
        if self._main_window is not None:
            self._main_window.navigate_to(key, **kwargs)

    # -- Construction ------------------------------------------------------

    def build_content(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        layout.addLayout(self._build_toolbar())

        self._error_label = QLabel("")
        self._error_label.setObjectName("ErrorBanner")
        self._error_label.setWordWrap(True)
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        # --- Compact System Health Bar ---
        self._health_bar = self._build_health_bar()
        layout.addWidget(self._health_bar)

        # --- Legacy 7-card status row (hidden, kept for test backward-compat) ---
        self._status_row_widget = QWidget()
        self._status_row_widget.setVisible(False)
        _sr_layout = QHBoxLayout(self._status_row_widget)
        _sr_layout.setContentsMargins(0, 0, 0, 0)
        _sr_layout.addLayout(self._build_status_row())
        layout.addWidget(self._status_row_widget)

        # --- SOC Posture Row (3 premium cards) -----------------------------
        layout.addWidget(self._make_section_label("SECURITY POSTURE"))
        posture_row = QHBoxLayout()
        posture_row.setSpacing(14)

        risk_frame, risk_num, risk_sub, _ = _posture_card(
            "Global Risk Level",
            accent_color=OK,
        )
        self._posture_risk_num = risk_num
        self._posture_risk_sub = risk_sub
        posture_row.addWidget(risk_frame, 1)

        threat_frame, threat_num, threat_sub, _ = _posture_card(
            "Active Threat Findings",
            accent_color=OK,
        )
        self._posture_threat_num = threat_num
        self._posture_threat_sub = threat_sub
        posture_row.addWidget(threat_frame, 1)

        action_frame, action_num, action_sub, action_btn = _posture_card(
            "Action Center",
            accent_color=OK,
            button_text="Review Actions",
        )
        self._posture_action_num = action_num
        self._posture_action_sub = action_sub
        if action_btn is not None:
            action_btn.clicked.connect(
                lambda: self._navigate_to("response"),
            )
        posture_row.addWidget(action_frame, 1)

        layout.addLayout(posture_row)

        # --- Unified Threat Investigation Feed ----------------------------
        layout.addWidget(self._make_section_label("ACTIVE THREAT INVESTIGATION FEED"))
        self._threat_feed_container = QFrame()
        self._threat_feed_container.setObjectName("Card")
        self._threat_feed_inner = QVBoxLayout(self._threat_feed_container)
        self._threat_feed_inner.setContentsMargins(0, 0, 0, 0)
        self._threat_feed_inner.setSpacing(0)
        self._threat_feed_layout = self._threat_feed_inner
        self._threat_feed_scroll = QScrollArea()
        self._threat_feed_scroll.setWidgetResizable(True)
        self._threat_feed_scroll.setMinimumHeight(200)
        self._threat_feed_scroll.setMaximumHeight(420)
        self._threat_feed_scroll.setWidget(self._threat_feed_container)
        layout.addWidget(self._threat_feed_scroll)

        # --- Live Network Activity Table ---
        layout.addWidget(self._make_section_label("LIVE NETWORK ACTIVITY"))
        self._live_network_model = LiveNetworkTableModel(self)
        self._live_network_table = QTableView()
        self._live_network_table.setModel(self._live_network_model)
        self._live_network_table.setSortingEnabled(True)
        self._live_network_table.setAlternatingRowColors(True)
        self._live_network_table.setSelectionBehavior(
            QTableView.SelectionBehavior.SelectRows,
        )
        self._live_network_table.setEditTriggers(
            QTableView.EditTrigger.NoEditTriggers,
        )
        self._live_network_table.verticalHeader().setVisible(False)
        self._live_network_table.horizontalHeader().setStretchLastSection(True)
        self._live_network_table.setMinimumHeight(140)
        self._live_network_table.setMaximumHeight(200)
        for idx, width in enumerate(_PORT_WIDTHS):
            self._live_network_table.setColumnWidth(idx, width)
        layout.addWidget(self._live_network_table)

        # --- Network Summary (compact) ---
        layout.addWidget(self._make_section_label("NETWORK SUMMARY"))
        net_summary_row = QHBoxLayout()
        net_summary_row.setSpacing(12)
        for label, key in (
            ("Total Packets", "total_packets"),
            ("Total Bytes", "total_bytes"),
            ("Total Flows", "total_flows"),
            ("Active Flows", "active_flows"),
            ("Network Events", "net_events"),
            ("Last Time", "last_time"),
        ):
            card, value_label = self._metric_card(label)
            self._network_summary_labels[key] = value_label
            net_summary_row.addWidget(card)
        layout.addLayout(net_summary_row)

        # --- Contextual Telemetry graphs (bottom section) ---
        layout.addWidget(self._make_section_label("CONTEXTUAL TELEMETRY"))
        graphs_row = QHBoxLayout()
        graphs_row.setSpacing(12)
        self._network_graph = LineGraphWidget(
            title="NETWORK THROUGHPUT",
            series_configs=(("Packets", ACCENT), ("Bytes", INFO)),
        )
        self._network_graph.setMinimumHeight(110)
        graphs_row.addWidget(self._network_graph, 1)
        self._security_graph = LineGraphWidget(
            title="SECURITY EVENTS",
            series_configs=(
                ("Events", ACCENT),
                ("Findings", WARN),
                ("Incidents", CRITICAL),
            ),
        )
        self._security_graph.setMinimumHeight(110)
        graphs_row.addWidget(self._security_graph, 1)
        layout.addLayout(graphs_row)

        # --- Hidden legacy containers (backward-compat for tests) ----------
        self._findings_container = QWidget()
        self._findings_layout = QVBoxLayout(self._findings_container)
        self._findings_layout.setContentsMargins(0, 0, 0, 0)
        self._findings_layout.setSpacing(4)
        self._findings_container.setVisible(False)

        self._incidents_container = QWidget()
        self._incidents_layout = QVBoxLayout(self._incidents_container)
        self._incidents_layout.setContentsMargins(0, 0, 0, 0)
        self._incidents_layout.setSpacing(4)
        self._incidents_container.setVisible(False)

        self._explanation_container = QFrame()
        self._explanation_container.setObjectName("Card")
        explanation_inner = QVBoxLayout(self._explanation_container)
        explanation_inner.setContentsMargins(16, 12, 16, 12)
        explanation_inner.setSpacing(6)
        self._explanation_hint = QLabel("Select a finding to see why it matters.")
        self._explanation_hint.setObjectName("CardHint")
        explanation_inner.addWidget(self._explanation_hint)
        self._explanation_content = QWidget()
        self._explanation_content_layout = QVBoxLayout(self._explanation_content)
        self._explanation_content_layout.setContentsMargins(0, 0, 0, 0)
        self._explanation_content_layout.setSpacing(4)
        self._explanation_content.setVisible(False)
        explanation_inner.addWidget(self._explanation_content)
        self._explanation_container.setVisible(False)

        self._relationships_container = QWidget()
        self._relationships_layout = QVBoxLayout(self._relationships_container)
        self._relationships_layout.setContentsMargins(0, 0, 0, 0)
        self._relationships_layout.setSpacing(4)
        self._relationships_container.setVisible(False)

        # Hidden risk/alerts row + host/network cards (for property accessors)
        self._risk_gauge = RiskGaugeWidget()
        self._risk_gauge.setVisible(False)
        self._risk_context_label = QLabel("")
        self._risk_context_label.setVisible(False)
        self._risk_graph = LineGraphWidget(
            title="RISK TREND",
            series_configs=(("Risk Score", HIGH),),
        )
        self._risk_graph.setVisible(False)
        self._alert_container = QWidget()
        self._alert_layout = QVBoxLayout(self._alert_container)
        self._alert_layout.setContentsMargins(0, 0, 0, 0)
        self._alert_layout.setSpacing(4)
        self._alert_container.setVisible(False)

        layout.addWidget(self._findings_container)
        layout.addWidget(self._incidents_container)
        layout.addWidget(self._explanation_container)
        layout.addWidget(self._relationships_container)

        # Hidden host + network cards (for backward-compat accessors / tests)
        self._hidden_host_card = self._build_host_card()
        self._hidden_host_card.setVisible(False)
        self._hidden_network_card = self._build_network_card()
        self._hidden_network_card.setVisible(False)

        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        return scroll

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)
        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.setObjectName("PrimaryButton")
        self._refresh_button.clicked.connect(self.refresh)
        self._last_updated_label = QLabel("Last updated: \u2014")
        self._last_updated_label.setObjectName("CardHint")
        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._last_updated_label)
        toolbar.addStretch(1)
        return toolbar

    # -- Status section ----------------------------------------------------

    def _build_status_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)
        for label, key in (
            ("Runtime", "runtime"),
            ("Host Monitoring", "host"),
            ("Network Capture", "network"),
            ("File Integrity", "fim"),
            ("Detection Engine", "detection"),
            ("Risk Engine", "risk"),
            ("Response Mode", "response"),
        ):
            card, value_label = self._status_card(label)
            self._monitor_labels[key] = value_label
            row.addWidget(card)
        return row

    @staticmethod
    def _status_card(label: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        title = QLabel(label.upper())
        title.setObjectName("CardTitle")
        value = QLabel(_EMPTY)
        value.setObjectName("FieldValue")
        value.setAlignment(Qt.AlignmentFlag.AlignLeft)
        value.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(value)
        return card, value

    # -- Compact System Health Bar ----------------------------------------

    _HEALTH_ITEMS: tuple[tuple[str, str], ...] = (
        ("Core", "runtime"),
        ("Host", "host"),
        ("Network", "network"),
        ("FIM", "fim"),
        ("Detection", "detection"),
        ("Risk", "risk"),
        ("Response", "response"),
    )

    def _build_health_bar(self) -> QFrame:
        """Single-line horizontal bar with dot indicators and compact text."""
        bar = QFrame()
        bar.setObjectName("HealthBar")
        bar.setStyleSheet(
            f"QFrame#HealthBar {{ background-color: #1a1f2e; "
            f"border: 1px solid {TEXT_MUTED}; border-radius: 6px; }}"
        )
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 6, 14, 6)
        h.setSpacing(18)

        title = QLabel("SYSTEM HEALTH")
        title.setObjectName("CardTitle")
        title.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: {TEXT_MUTED};"
        )
        h.addWidget(title)

        h.addSpacing(6)

        self._health_indicators: dict[str, tuple[QLabel, QLabel]] = {}
        for display_name, key in self._HEALTH_ITEMS:
            dot = QLabel("\u25cf")
            dot.setObjectName(f"dot_{key}")
            dot.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
            dot.setFixedWidth(12)
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)

            text = QLabel(f"{display_name}: {_EMPTY}")
            text.setObjectName(f"health_{key}")
            text.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED};")

            h.addWidget(dot)
            h.addWidget(text)
            h.addSpacing(4)

            self._health_indicators[key] = (dot, text)

        return bar

    def _update_health_bar(self) -> None:
        """Sync the compact health bar indicators from hidden monitor labels."""
        for key, (dot, text) in self._health_indicators.items():
            status = self._monitor_labels[key].text()
            display_name = next(
                (name for name, k in self._HEALTH_ITEMS if k == key), key
            )
            active = status in ("ACTIVE", "MONITOR (read-only)")
            color = OK if active else WARN if status in ("DISABLED",) else HIGH
            dot.setStyleSheet(f"color: {color}; font-size: 10px;")
            text.setText(f"{display_name}: {status}")
            text.setStyleSheet(f"font-size: 11px; color: {TEXT_MUTED};")

    @staticmethod
    def _metric_card(label: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)
        title = QLabel(label.upper())
        title.setObjectName("CardTitle")
        value = QLabel(_EMPTY)
        value.setObjectName("CardValue")
        value.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(title)
        layout.addWidget(value)
        return card, value

    @staticmethod
    def _make_section_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("CardTitle")
        return label

    # -- Host card ---------------------------------------------------------

    def _build_host_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(8)
        heading = QLabel("HOST")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)
        for label_text, key in (
            ("Hostname", "hostname"),
            ("Platform", "platform"),
            ("OS", "os"),
            ("Processes", "processes"),
            ("Listening Ports", "ports"),
            ("FIM Paths", "fim_paths"),
        ):
            row = QHBoxLayout()
            row.setSpacing(8)
            key_label = QLabel(label_text)
            key_label.setObjectName("FieldKey")
            value_label = QLabel(_EMPTY)
            value_label.setObjectName("FieldValue")
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(key_label)
            row.addStretch(1)
            row.addWidget(value_label)
            outer.addLayout(row)
            self._host_metric_labels[key] = value_label
        return card

    # -- Network card ------------------------------------------------------

    def _build_network_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 14, 16, 14)
        outer.setSpacing(8)
        heading = QLabel("NETWORK")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)
        for label_text, key in (
            ("Capture State", "capture_state"),
            ("Interface", "interface"),
            ("Promiscuous", "promiscuous"),
            ("Flow Window", "flow_window"),
            ("Local Addresses", "local_addrs"),
        ):
            row = QHBoxLayout()
            row.setSpacing(8)
            key_label = QLabel(label_text)
            key_label.setObjectName("FieldKey")
            value_label = QLabel(_EMPTY)
            value_label.setObjectName("FieldValue")
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(key_label)
            row.addStretch(1)
            row.addWidget(value_label)
            outer.addLayout(row)
            self._network_metric_labels[key] = value_label
        return card

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> DashboardSnapshot | None:
        """Re-read all read-only data from existing Aegis components."""
        try:
            snapshot = self._provider()
        except Exception as exc:
            logger.warning("Dashboard refresh failed: %s", exc)
            self._show_error(INVENTORY_ERROR)
            return None
        self._apply(snapshot)
        return snapshot

    def refresh_live(self) -> None:
        """Called on every QTimer tick while monitoring is active."""
        try:
            snapshot = self._provider()
        except Exception:
            return
        self._snapshot = snapshot
        self._sample_tlemetry(snapshot)
        self._detect_alerts(snapshot)
        self._update_posture_cards(snapshot)
        self._update_health_bar()
        self._update_threat_feed(snapshot)
        self._update_live_network(snapshot)
        self._update_graphs()
        self._update_network_summary(snapshot)
        if snapshot.inventory.available:
            self._set_error(None)
        self._last_updated_label.setText(
            f"Last updated: {format_timestamp(snapshot.collected_at)}",
        )

    def _apply(self, snapshot: DashboardSnapshot) -> None:
        self._snapshot = snapshot
        inventory = snapshot.inventory

        any_running = any(m.configured_enabled for m in snapshot.monitors)
        runtime_status = (
            "ACTIVE" if any_running or snapshot.pipeline_posture.running else "NOT RUNNING"
        )
        self._monitor_labels["runtime"].setText(runtime_status)

        host_enabled = False
        fim_enabled = False
        network_enabled = False
        for monitor in snapshot.monitors:
            if monitor.name in ("Process Monitoring", "Port Monitoring"):
                if monitor.configured_enabled:
                    host_enabled = True
            elif monitor.name == "File Integrity Monitoring":
                fim_enabled = monitor.configured_enabled
            elif monitor.name == "Network Sensor":
                network_enabled = monitor.configured_enabled

        self._monitor_labels["host"].setText("ACTIVE" if host_enabled else "DISABLED")
        self._monitor_labels["network"].setText("ACTIVE" if network_enabled else "DISABLED")
        self._monitor_labels["fim"].setText("ACTIVE" if fim_enabled else "DISABLED")

        detection = snapshot.detection
        det_status = (
            "ACTIVE"
            if detection.running and detection.enabled
            else ("NOT RUNNING" if not detection.running else "DISABLED")
        )
        self._monitor_labels["detection"].setText(det_status)

        risk = snapshot.risk
        risk_status = "ACTIVE" if risk.running else "NOT RUNNING"
        self._monitor_labels["risk"].setText(risk_status)
        self._monitor_labels["response"].setText("MONITOR (read-only)")

        self._set_metric("events", snapshot.event_count)
        self._set_metric("detections", detection.finding_count)
        self._set_metric("assessments", risk.assessment_count)
        self._set_metric("processes", snapshot.process_count)
        self._set_metric("ports", snapshot.port_count)
        self._set_metric("assets", snapshot.assets.assets)
        self._set_metric("peers", snapshot.assets.peers)

        agent = snapshot.agent_settings
        fim_paths = len(agent.file_integrity_paths)
        host_values = {
            "hostname": inventory.hostname,
            "platform": inventory.platform,
            "os": inventory.operating_system,
            "processes": str(snapshot.process_count) if snapshot.process_count else _EMPTY,
            "ports": str(snapshot.port_count) if snapshot.port_count else _EMPTY,
            "fim_paths": str(fim_paths) if fim_paths else _EMPTY,
        }
        for key, value in host_values.items():
            if key in self._host_metric_labels:
                self._host_metric_labels[key].setText(value or _EMPTY)

        sensor = snapshot.sensor_settings
        flow_win = f"{sensor.flow_window_seconds}s" if sensor.flow_window_seconds else _EMPTY
        local_addr = sensor.local_addresses or _EMPTY
        if isinstance(local_addr, list):
            local_addr = ", ".join(local_addr)
        net_values = {
            "capture_state": ("ACTIVE" if sensor.capture_enabled else "DISABLED"),
            "interface": sensor.interface or _EMPTY,
            "promiscuous": "Yes" if sensor.promiscuous else "No",
            "flow_window": flow_win,
            "local_addrs": local_addr,
        }
        for key, value in net_values.items():
            if key in self._network_metric_labels:
                self._network_metric_labels[key].setText(value or _EMPTY)

        self._set_risk_value(self._risk_value_label, risk.latest_score)
        self._set_risk_text(self._risk_level_label, risk.latest_level)
        if self._risk_level_label is not None and risk.latest_level:
            set_state(self._risk_level_label, risk.latest_level.lower())
        self._set_risk_text(
            self._risk_count_label, str(risk.assessment_count) if risk.assessment_count else None
        )
        self._set_risk_text(self._risk_version_label, risk.scoring_version)

        # Initial posture card update
        self._update_posture_cards(snapshot)
        self._update_health_bar()

        if inventory.available:
            self._set_error(None)
        else:
            self._set_error(inventory.error or INVENTORY_ERROR)
        self._last_updated_label.setText(f"Last updated: {format_timestamp(snapshot.collected_at)}")

    # -- SOC Posture cards -------------------------------------------------

    def _update_posture_cards(self, snapshot: DashboardSnapshot) -> None:
        """Refresh the three SOC posture cards from live data."""
        risk = snapshot.risk

        # -- Global Risk Level --
        score = risk.latest_score
        level = (risk.latest_level or "").upper()
        color = _risk_color(score)
        if self._posture_risk_num is not None:
            self._posture_risk_num.setText(str(score) if score is not None else _EMPTY)
            self._posture_risk_num.setStyleSheet(
                f"font-size: 32px; font-weight: 800; color: {color};"
            )
        if self._posture_risk_sub is not None:
            parts: list[str] = []
            if level:
                parts.append(f"Level: {level}")
            if risk.scoring_version:
                parts.append(f"v{risk.scoring_version}")
            self._posture_risk_sub.setText(" | ".join(parts) if parts else "No risk data")

        # -- Active Threat Findings --
        high_count = sum(
            1 for item in snapshot.high_risk_findings
            if item.severity in ("high", "critical")
        )
        open_incidents = sum(
            1 for item in snapshot.activity
            if item.kind == "incident"
        )
        t_color = _threat_color(high_count)
        if self._posture_threat_num is not None:
            display = str(high_count) if high_count else "0"
            self._posture_threat_num.setText(display)
            self._posture_threat_num.setStyleSheet(
                f"font-size: 32px; font-weight: 800; color: {t_color};"
            )
        if self._posture_threat_sub is not None:
            det_findings = snapshot.detection.finding_count
            parts_t: list[str] = []
            parts_t.append(f"{det_findings} total finding(s)")
            if high_count:
                parts_t.append(f"{high_count} high/critical")
            if open_incidents:
                parts_t.append(f"{open_incidents} open incident(s)")
            self._posture_threat_sub.setText(" | ".join(parts_t))

        # -- Action Center (pending responses) --
        pending = self._pending_response_count()
        a_color = _action_color(pending)
        if self._posture_action_num is not None:
            self._posture_action_num.setText(str(pending) if pending else "0")
            self._posture_action_num.setStyleSheet(
                f"font-size: 32px; font-weight: 800; color: {a_color};"
            )
        if self._posture_action_sub is not None:
            if pending:
                self._posture_action_sub.setText(
                    f"{pending} response request(s) awaiting approval"
                )
            else:
                self._posture_action_sub.setText("No pending actions")

    @staticmethod
    def _pending_response_count() -> int:
        """Return count of pending response approvals (lazy import)."""
        try:
            from aegis_desktop.services.response_workflow import get_workflow_manager

            mgr = get_workflow_manager()
            return mgr.pending_count()
        except Exception:
            return 0

    # -- Unified Threat Investigation Feed ---------------------------------

    def _update_threat_feed(self, snapshot: DashboardSnapshot) -> None:
        """Rebuild the unified threat feed from alerts + snapshot data."""
        layout = self._threat_feed_layout
        if layout is None:
            return
        self._clear_layout(layout)

        # Build feed items from AlertService (deduplicated HIGH/CRITICAL)
        alerts = self._alert_service.all_alerts()
        # Also include findings and incidents from the snapshot
        feed_items: list[dict[str, str]] = []

        for alert in alerts:
            feed_items.append({
                "timestamp": format_timestamp(alert.timestamp),
                "severity": alert.severity.upper(),
                "title": alert.description or alert.title,
                "host": alert.host_id or "\u2014",
                "evidence": f"{alert.alert_type.upper()} | ID: {alert.source_id}",
                "nav_type": alert.alert_type,
                "nav_id": alert.source_id,
            })

        # Supplement with high/critical findings not yet in alerts
        for item in snapshot.high_risk_findings:
            if item.description not in {fi["title"] for fi in feed_items}:
                feed_items.append({
                    "timestamp": format_timestamp(item.timestamp),
                    "severity": item.severity.upper(),
                    "title": item.description,
                    "host": "\u2014",
                    "evidence": "FINDING",
                    "nav_type": "finding",
                    "nav_id": "",
                })

        # Supplement with open incidents
        for item in snapshot.activity:
            if item.kind == "incident":
                feed_items.append({
                    "timestamp": format_timestamp(item.timestamp),
                    "severity": item.severity.upper(),
                    "title": item.description,
                    "host": "\u2014",
                    "evidence": "INCIDENT",
                    "nav_type": "incident",
                    "nav_id": "",
                })

        if not feed_items:
            empty = QLabel("No active threats detected. System posture is clean.")
            empty.setObjectName("CardHint")
            empty.setStyleSheet(
                f"font-size: 13px; padding: 20px; color: {OK};"
            )
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(empty)
            return

        for item in feed_items[:30]:
            layout.addWidget(self._build_threat_card(item))

    def _build_threat_card(self, item: dict[str, str]) -> QWidget:
        """Build a single stylised threat card for the feed."""
        severity = item.get("severity", "").lower()
        color = HIGH if severity == "high" else CRITICAL if severity == "critical" else WARN

        frame = QFrame()
        frame.setObjectName("Card")
        frame.setStyleSheet(
            f"QFrame#Card {{ border-left: 3px solid {color}; }}"
        )
        outer = QHBoxLayout(frame)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(12)

        # Severity badge
        badge = QLabel(item.get("severity", "?")[:4])
        badge.setObjectName("FieldValue")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedWidth(48)
        badge.setStyleSheet(
            f"background-color: {color}; color: #FFFFFF; font-weight: 800; "
            f"font-size: 11px; border-radius: 4px; padding: 4px 2px;"
        )
        outer.addWidget(badge)

        # Content column
        content = QVBoxLayout()
        content.setSpacing(2)

        title = QLabel(item.get("title", ""))
        title.setObjectName("FieldValue")
        title.setWordWrap(True)
        content.addWidget(title)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(12)
        ts_label = QLabel(item.get("timestamp", ""))
        ts_label.setObjectName("CardHint")
        host_label = QLabel("Host: " + item.get("host", _EMPTY))
        host_label.setObjectName("CardHint")
        ev_label = QLabel(item.get("evidence", ""))
        ev_label.setObjectName("CardHint")
        meta_row.addWidget(ts_label)
        meta_row.addWidget(host_label)
        meta_row.addWidget(ev_label)
        meta_row.addStretch(1)
        content.addLayout(meta_row)

        outer.addLayout(content, 1)

        nav_type = item.get("nav_type", "")
        nav_id = item.get("nav_id", "")
        if nav_id:
            frame.setCursor(Qt.CursorShape.PointingHandCursor)
            _nt, _nid = nav_type, nav_id
            frame.mousePressEvent = lambda _e, nt=_nt, nid=_nid: (
                self._navigate_to(
                    "detections" if nt == "finding" else "incidents",
                    select_id=nid,
                )
            )

        return frame

    # -- Live telemetry sampling --------------------------------------------

    def _sample_tlemetry(self, snapshot: DashboardSnapshot) -> None:
        from aegis_desktop.services.monitoring import get_active_monitoring_controller

        packets: int | None = None
        bytes_val: int | None = None
        flows: int | None = None
        active_flows: int | None = None
        controller = get_active_monitoring_controller()
        if controller is not None:
            status = controller.status()
            packets = status.counters.packets
            bytes_val = status.counters.bytes
            flows = status.counters.flows
            active_flows = status.counters.active_flows

        high_count = sum(
            1 for item in snapshot.high_risk_findings
            if item.severity in ("high", "critical")
        )
        open_incidents = sum(
            1 for item in snapshot.activity
            if item.kind == "incident"
        )

        risk_score: int | None = None
        if snapshot.risk.latest_score is not None:
            risk_score = snapshot.risk.latest_score

        sample = TelemetrySample(
            timestamp=snapshot.collected_at,
            packets=packets,
            bytes=bytes_val,
            flows=flows,
            active_flows=active_flows,
            events=snapshot.event_count,
            findings=snapshot.detection.finding_count,
            high_risk_findings=high_count,
            open_incidents=open_incidents,
            risk_score=risk_score,
        )
        self._telemetry_history.add(sample)

    def _detect_alerts(self, snapshot: DashboardSnapshot) -> None:
        try:
            from aegis_desktop.services.detections import collect_finding_view
            findings_view = collect_finding_view()
            finding_rows = findings_view.rows if findings_view.available else ()
        except Exception:
            finding_rows = ()
        try:
            from aegis_desktop.services.incidents import collect_incident_view
            incidents_view = collect_incident_view()
            incident_rows = incidents_view.rows if incidents_view.available else ()
        except Exception:
            incident_rows = ()
        self._alert_service.detect(
            findings=finding_rows,
            incidents=incident_rows,
            now=datetime.now(UTC),
        )

    # -- Live network activity ----------------------------------------------

    def _update_live_network(self, snapshot: DashboardSnapshot) -> None:
        from datetime import datetime as _dt

        from aegis_desktop.services.network import collect_network_monitoring_view

        try:
            view = collect_network_monitoring_view()
        except Exception:
            return

        now = _dt.now(UTC)
        for flow in view.flows:
            self._live_network.add(LiveActivityRow(
                timestamp=now,
                source=flow.source,
                destination=flow.destination,
                port="",
                protocol=flow.protocol,
                packets=flow.packets,
                bytes=flow.bytes,
                direction=flow.direction,
                state="active" if flow.duration_ms < 60000 else "idle",
                flow_id=flow.flow_id,
            ))
        for event in view.events:
            flow_id = f"evt-{event.timestamp.timestamp():.0f}"
            self._live_network.add(LiveActivityRow(
                timestamp=event.timestamp,
                source=event.source,
                destination=event.destination,
                port="",
                protocol=event.protocol,
                packets=event.packets or 0,
                bytes=event.bytes or 0,
                direction="",
                state="event",
                flow_id=flow_id,
            ))

        if self._live_network_model is not None:
            self._live_network_model.set_rows(self._live_network.rows())

    def _update_network_summary(self, snapshot: DashboardSnapshot) -> None:
        from aegis_desktop.services.dashboard import format_bytes
        from aegis_desktop.services.monitoring import get_active_monitoring_controller

        controller = get_active_monitoring_controller()
        packets_text = "\u2014"
        bytes_text = "\u2014"
        flows_text = "\u2014"
        active_flows_text = "\u2014"
        if controller is not None:
            status = controller.status()
            if status.counters.packets is not None:
                packets_text = str(status.counters.packets)
            if status.counters.bytes is not None:
                bytes_text = format_bytes(status.counters.bytes)
            if status.counters.flows is not None:
                flows_text = str(status.counters.flows)
            if status.counters.active_flows is not None:
                active_flows_text = str(status.counters.active_flows)

        last_time = "\u2014"
        latest = self._live_network.latest()
        if latest is not None:
            last_time = latest.timestamp.strftime("%H:%M:%S")

        self._set_network_summary("total_packets", packets_text)
        self._set_network_summary("total_bytes", bytes_text)
        self._set_network_summary("total_flows", flows_text)
        self._set_network_summary("active_flows", active_flows_text)
        event_count = snapshot.event_count
        self._set_network_summary("net_events", str(event_count) if event_count else "\u2014")
        self._set_network_summary("last_time", last_time)

    def _set_network_summary(self, key: str, value: str) -> None:
        label = self._network_summary_labels.get(key)
        if label is not None:
            label.setText(value)

    # -- Findings panel ----------------------------------------------------

    def _update_findings_panel(self) -> None:
        layout = self._findings_layout
        self._clear_layout(layout)
        try:
            from aegis_desktop.services.detections import collect_finding_view
            view = collect_finding_view()
            finding_rows = view.rows if view.available else ()
        except Exception:
            finding_rows = ()

        if not finding_rows:
            no_data = QLabel("No security findings")
            no_data.setObjectName("CardHint")
            layout.addWidget(no_data)
            return

        for row in finding_rows[:15]:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(8, 4, 8, 4)
            row_layout.setSpacing(8)

            sev_label = QLabel(row.severity.upper())
            sev_label.setObjectName("FieldValue")
            set_state(sev_label, row.severity)
            sev_label.setFixedWidth(65)

            title_label = QLabel(row.title)
            title_label.setObjectName("FieldValue")
            title_label.setWordWrap(True)

            rule_label = QLabel(row.rule_id)
            rule_label.setObjectName("CardHint")
            rule_label.setFixedWidth(120)

            time_label = QLabel(format_timestamp(row.timestamp))
            time_label.setObjectName("CardHint")
            time_label.setFixedWidth(140)

            row_layout.addWidget(sev_label)
            row_layout.addWidget(rule_label)
            row_layout.addWidget(title_label, 1)
            row_layout.addWidget(time_label)

            row_widget.setCursor(Qt.CursorShape.PointingHandCursor)
            row_widget.mousePressEvent = lambda _e, fid=row.finding_id: (
                self._navigate_to("detections", select_id=fid)
            )
            layout.addWidget(row_widget)

    # -- Incidents panel ---------------------------------------------------

    def _update_incidents_panel(self) -> None:
        layout = self._incidents_layout
        self._clear_layout(layout)
        try:
            from aegis_desktop.services.incidents import collect_incident_view
            view = collect_incident_view()
            incident_rows = view.rows if view.available else ()
        except Exception:
            incident_rows = ()

        open_incidents = [r for r in incident_rows if r.status == "open"]
        if not open_incidents:
            no_data = QLabel("No open incidents")
            no_data.setObjectName("CardHint")
            layout.addWidget(no_data)
            return

        for row in open_incidents[:10]:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(8, 4, 8, 4)
            row_layout.setSpacing(8)

            risk_label = QLabel(row.risk_level.upper())
            risk_label.setObjectName("FieldValue")
            set_state(risk_label, row.risk_level)
            risk_label.setFixedWidth(80)

            id_label = QLabel(row.incident_id)
            id_label.setObjectName("CardHint")
            id_label.setFixedWidth(100)

            summary_label = QLabel(row.summary)
            summary_label.setObjectName("FieldValue")
            summary_label.setWordWrap(True)

            findings_label = QLabel(f"{row.finding_count} findings")
            findings_label.setObjectName("CardHint")
            findings_label.setFixedWidth(70)

            row_layout.addWidget(risk_label)
            row_layout.addWidget(id_label)
            row_layout.addWidget(findings_label)
            row_layout.addWidget(summary_label, 1)

            row_widget.setCursor(Qt.CursorShape.PointingHandCursor)
            row_widget.mousePressEvent = lambda _e, iid=row.incident_id: (
                self._navigate_to("incidents", select_id=iid)
            )
            layout.addWidget(row_widget)

    # -- Explanation panel -------------------------------------------------

    def _update_explanation_panel(self) -> None:
        try:
            from aegis_desktop.services.correlation import correlation_for_finding
            from aegis_desktop.services.detections import collect_finding_view, describe_finding
            view = collect_finding_view()
            findings = view.findings if view.available else ()
        except Exception:
            findings = ()

        if not findings:
            self._explanation_hint.setVisible(True)
            self._explanation_content.setVisible(False)
            return

        latest = findings[-1]
        self._explanation_hint.setVisible(False)
        self._explanation_content.setVisible(True)
        self._clear_layout(self._explanation_content_layout)

        try:
            desc = describe_finding(latest)
        except Exception:
            desc = {}

        if desc:
            self._explanation_content_layout.addWidget(
                self._explanation_row("Rule", desc.get("rule_id", "")),
            )
            self._explanation_content_layout.addWidget(
                self._explanation_row("Title", desc.get("title", "")),
            )
            self._explanation_content_layout.addWidget(
                self._explanation_row("Severity", desc.get("severity", "")),
            )
            self._explanation_content_layout.addWidget(
                self._explanation_row("Description", desc.get("description", "")),
            )
            evidence_parts = [
                f"{k}={v}" for k, v in desc.items() if k.startswith("evidence.")
            ]
            if evidence_parts:
                self._explanation_content_layout.addWidget(
                    self._explanation_row("Evidence", " | ".join(evidence_parts)),
                )

        with contextlib.suppress(Exception):
            corr = correlation_for_finding(latest.finding_id)
            if corr is not None and corr.correlated:
                self._explanation_content_layout.addWidget(
                    self._explanation_row(
                        "Correlation",
                        f"{corr.host_finding_count} host + "
                        f"{corr.network_finding_count} network findings "
                        f"({corr.window_seconds}s window): {corr.reason}",
                    ),
                )

        with contextlib.suppress(Exception):
            from aegis_desktop.services.threat_intel import threat_intel_for_event
            from aegis_shared.pipeline import get_active_pipeline
            pipeline = get_active_pipeline()
            if pipeline is not None:
                for envelope in pipeline.peek():
                    if envelope.event.event_id == latest.event_id:
                        ti = threat_intel_for_event(envelope.event)
                        if ti is not None and ti.matched:
                            self._explanation_content_layout.addWidget(
                                self._explanation_row(
                                    "Threat Intel",
                                    f"{ti.count} IOC match(es): "
                                    f"{', '.join(ti.types)} from {', '.join(ti.sources)}",
                                ),
                            )
                        break

    @staticmethod
    def _explanation_row(label_text: str, value_text: str) -> QWidget:
        widget = QWidget()
        row = QHBoxLayout(widget)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(8)
        lbl = QLabel(label_text.upper())
        lbl.setObjectName("CardTitle")
        lbl.setFixedWidth(100)
        val = QLabel(value_text)
        val.setObjectName("FieldValue")
        val.setWordWrap(True)
        val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(lbl)
        row.addWidget(val, 1)
        return widget

    # -- Relationships panel -----------------------------------------------

    def _update_relationships_panel(self) -> None:
        layout = self._relationships_layout
        self._clear_layout(layout)
        try:
            from aegis_desktop.services.assets import collect_asset_view
            view = collect_asset_view()
            all_peers: list = []
            for host_peers in view.peers.values():
                all_peers.extend(host_peers)
        except Exception:
            all_peers = []

        if not all_peers:
            no_data = QLabel("No network relationships observed")
            no_data.setObjectName("CardHint")
            layout.addWidget(no_data)
            return

        for peer in all_peers[:15]:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(8, 4, 8, 4)
            row_layout.setSpacing(8)

            local_label = QLabel("LOCAL")
            local_label.setObjectName("FieldValue")
            set_state(local_label, "info")
            local_label.setFixedWidth(50)

            arrow_label = QLabel("\u2192")
            arrow_label.setObjectName("FieldValue")
            arrow_label.setFixedWidth(20)

            remote_label = QLabel(peer.remote_ip)
            remote_label.setObjectName("FieldValue")
            remote_label.setFixedWidth(130)

            port_label = QLabel(str(peer.remote_port) if peer.remote_port else "\u2014")
            port_label.setObjectName("CardHint")
            port_label.setFixedWidth(50)

            proto_label = QLabel(peer.protocol)
            proto_label.setObjectName("CardHint")
            proto_label.setFixedWidth(50)

            pkts_label = QLabel(str(peer.packet_count))
            pkts_label.setObjectName("CardHint")
            pkts_label.setFixedWidth(60)

            known_label = QLabel("known" if peer.known else "NEW")
            known_label.setObjectName("FieldValue")
            set_state(known_label, "open" if peer.known else "high")
            known_label.setFixedWidth(45)

            row_layout.addWidget(local_label)
            row_layout.addWidget(arrow_label)
            row_layout.addWidget(remote_label)
            row_layout.addWidget(port_label)
            row_layout.addWidget(proto_label)
            row_layout.addWidget(pkts_label)
            row_layout.addWidget(known_label, 1)
            layout.addWidget(row_widget)

    # -- Live metrics update -----------------------------------------------

    def _update_live_metrics(self, snapshot: DashboardSnapshot) -> None:
        from aegis_desktop.services.monitoring import get_active_monitoring_controller

        packets = "\u2014"
        bytes_text = "\u2014"
        flows = "\u2014"
        active_flows = "\u2014"
        controller = get_active_monitoring_controller()
        if controller is not None:
            status = controller.status()
            if status.counters.packets is not None:
                packets = str(status.counters.packets)
            if status.counters.bytes is not None:
                from aegis_desktop.services.dashboard import format_bytes
                bytes_text = format_bytes(status.counters.bytes)
            if status.counters.flows is not None:
                flows = str(status.counters.flows)
            if status.counters.active_flows is not None:
                active_flows = str(status.counters.active_flows)

        high_count = sum(
            1 for item in snapshot.high_risk_findings
            if item.severity in ("high", "critical")
        )

        self._set_live_metric("live_packets", packets)
        self._set_live_metric("live_bytes", bytes_text)
        self._set_live_metric("live_flows", flows)
        self._set_live_metric("live_active_flows", active_flows)
        self._set_live_metric("live_high_findings", str(high_count) if high_count else "\u2014")
        self._set_live_metric(
            "live_open_incidents",
            str(snapshot.detection.finding_count) if snapshot.detection.finding_count else "\u2014",
        )

    def _set_live_metric(self, key: str, value: str) -> None:
        label = self._live_metric_labels.get(key)
        if label is not None:
            label.setText(value)

    # -- Graphs update -----------------------------------------------------

    def _update_graphs(self) -> None:
        samples = self._telemetry_history.samples()
        if self._network_graph is not None:
            packets = [float(s.packets or 0) for s in samples]
            bytes_data = [float(s.bytes or 0) for s in samples]
            self._network_graph.set_data({"Packets": packets, "Bytes": bytes_data})
        if self._security_graph is not None:
            events = [float(s.events) for s in samples]
            findings = [float(s.findings) for s in samples]
            incidents = [float(s.open_incidents) for s in samples]
            self._security_graph.set_data({
                "Events": events,
                "Findings": findings,
                "Incidents": incidents,
            })
        if self._risk_graph is not None:
            risk_scores = [
                float(s.risk_score) for s in samples if s.risk_score is not None
            ]
            self._risk_graph.set_data({"Risk Score": risk_scores})
        if self._risk_gauge is not None:
            latest = self._telemetry_history.latest()
            if latest is not None:
                level = ""
                if self._snapshot is not None:
                    level = self._snapshot.risk.latest_level or ""
                self._risk_gauge.set_score(latest.risk_score, level)

        if self._risk_context_label is not None and self._snapshot is not None:
            self._update_risk_context()

    def _update_risk_context(self) -> None:
        risk = self._snapshot.risk if self._snapshot else None
        if risk is None or self._risk_context_label is None:
            return
        parts: list[str] = []
        if risk.latest_level:
            parts.append(f"Level: {risk.latest_level.upper()}")
        if risk.latest_score is not None:
            parts.append(f"Score: {risk.latest_score}")
        high_findings = sum(
            1 for item in (self._snapshot.high_risk_findings if self._snapshot else ())
            if item.severity in ("high", "critical")
        )
        if high_findings:
            parts.append(f"{high_findings} high/critical finding(s)")
        self._risk_context_label.setText(" | ".join(parts) if parts else "")

    # -- Alert display update ----------------------------------------------

    def _update_alert_display(self) -> None:
        layout = self._alert_layout
        self._clear_layout(layout)
        alerts = self._alert_service.all_alerts()
        if not alerts:
            no_alerts = QLabel("No security alerts")
            no_alerts.setObjectName("CardHint")
            layout.addWidget(no_alerts)
            return
        for alert in alerts[:20]:
            row_widget = QWidget()
            row = QHBoxLayout(row_widget)
            row.setContentsMargins(8, 4, 8, 4)
            row.setSpacing(8)
            sev_label = QLabel(alert.severity.upper())
            sev_label.setObjectName("FieldValue")
            set_state(sev_label, alert.severity)
            sev_label.setFixedWidth(60)
            type_label = QLabel(alert.alert_type)
            type_label.setObjectName("CardHint")
            type_label.setFixedWidth(55)
            desc_label = QLabel(alert.description)
            desc_label.setObjectName("FieldValue")
            desc_label.setWordWrap(True)
            row.addWidget(sev_label)
            row.addWidget(type_label)
            row.addWidget(desc_label, 1)
            if alert.alert_type == "finding" and alert.source_id:
                row_widget.setCursor(Qt.CursorShape.PointingHandCursor)
                sid = alert.source_id
                row_widget.mousePressEvent = lambda _e, s=sid: (
                    self._navigate_to("detections", select_id=s)
                )
            elif alert.alert_type == "incident" and alert.source_id:
                row_widget.setCursor(Qt.CursorShape.PointingHandCursor)
                sid = alert.source_id
                row_widget.mousePressEvent = lambda _e, s=sid: (
                    self._navigate_to("incidents", select_id=s)
                )
            layout.addWidget(row_widget)

    # -- Helpers -----------------------------------------------------------

    @staticmethod
    def _clear_layout(layout: QVBoxLayout) -> None:
        while layout.count():
            child = layout.takeAt(0)
            if child is None:
                break
            widget = child.widget()
            if widget is not None:
                widget.deleteLater()

    def _set_metric(self, key: str, value: int) -> None:
        label = self._metric_labels.get(key)
        if label is not None:
            label.setText(str(value) if value else _EMPTY)

    @staticmethod
    def _set_risk_value(label: QLabel | None, value: int | None) -> None:
        if label is not None:
            label.setText(str(value) if value is not None else _EMPTY)

    @staticmethod
    def _set_risk_text(label: QLabel | None, value: str | None) -> None:
        if label is not None:
            label.setText(value if value else _EMPTY)

    @staticmethod
    def _monitor_key(name: str) -> str | None:
        mapping = {
            "Process Monitoring": "host",
            "Port Monitoring": "host",
            "Network Sensor": "network",
        }
        return mapping.get(name)

    def _show_error(self, message: str) -> None:
        self._last_updated_label.setText("Last updated: \u2014")
        self._set_error(message)

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> DashboardSnapshot | None:
        return self._snapshot

    def status_text(self, key: str) -> str:
        return self._monitor_labels[key].text()

    def metric_text(self, key: str) -> str:
        return self._metric_labels[key].text()

    def host_value(self, key: str) -> str:
        return self._host_metric_labels[key].text()

    def network_value(self, key: str) -> str:
        return self._network_metric_labels[key].text()

    def risk_score_text(self) -> str:
        return self._risk_value_label.text() if self._risk_value_label is not None else ""

    def risk_level_text(self) -> str:
        return self._risk_level_label.text() if self._risk_level_label is not None else ""

    def risk_count_text(self) -> str:
        return self._risk_count_label.text() if self._risk_count_label is not None else ""

    def risk_version_text(self) -> str:
        return self._risk_version_label.text() if self._risk_version_label is not None else ""

    def last_updated_text(self) -> str:
        return self._last_updated_label.text()

    def has_error(self) -> bool:
        return self._error_active

    def error_text(self) -> str:
        return self._error_label.text()

    def live_metric_text(self, key: str) -> str:
        label = self._live_metric_labels.get(key)
        return label.text() if label is not None else ""

    @property
    def alert_service(self) -> AlertService:
        return self._alert_service

    @property
    def telemetry_history(self) -> TelemetryHistory:
        return self._telemetry_history

    @property
    def live_network(self) -> LiveNetworkActivity:
        return self._live_network

    @property
    def network_graph(self) -> LineGraphWidget | None:
        return self._network_graph

    @property
    def security_graph(self) -> LineGraphWidget | None:
        return self._security_graph

    @property
    def risk_graph(self) -> LineGraphWidget | None:
        return self._risk_graph

    @property
    def risk_gauge(self) -> RiskGaugeWidget | None:
        return self._risk_gauge


__all__ = ["DashboardPage"]
