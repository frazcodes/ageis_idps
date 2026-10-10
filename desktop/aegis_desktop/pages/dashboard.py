"""Dashboard page: real-time Security Operations Console.

The page is presentation only. All data comes from existing Aegis components.
Layout: live network activity -> findings -> incidents -> why this matters ->
network relationships -> risk -> alerts -> graphs.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import UTC, datetime

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.graphs import (
    LineGraphWidget,
    MitreKillChainWidget,
    RiskGaugeWidget,
    TopologyRadarWidget,
)
from aegis_desktop.services.alerts import AlertService
from aegis_desktop.services.audio_alert import get_audio_alert_service
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
from aegis_desktop.threat_sim import (
    SimulationOutcome,
    ThreatSimulationDialog,
    augment_snapshot,
    run_scenario,
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
        f"QFrame#Card {{ background-color: #0E1726; border: 1px solid #1E293B; "
        f"border-left: 4px solid {accent_color}; border-radius: 10px; }}"
    )

    outer = QVBoxLayout(frame)
    outer.setContentsMargins(18, 14, 18, 14)
    outer.setSpacing(4)

    title_lbl = QLabel(title.upper())
    title_lbl.setObjectName("CardTitle")
    title_lbl.setStyleSheet(
        "font-size: 11px; font-weight: 700; color: #94A3B8; letter-spacing: 0.8px;"
    )
    outer.addWidget(title_lbl)

    num_lbl = QLabel(number)
    num_lbl.setObjectName("PostureNumber")
    num_lbl.setStyleSheet(
        f"font-size: 34px; font-weight: 800; color: {accent_color}; padding: 2px 0;"
    )
    outer.addWidget(num_lbl)

    sub_lbl = QLabel(subtitle)
    sub_lbl.setObjectName("CardHint")
    sub_lbl.setWordWrap(True)
    sub_lbl.setStyleSheet("font-size: 12px; color: #64748B;")
    outer.addWidget(sub_lbl)

    btn: QPushButton | None = None
    if button_text is not None:
        btn = QPushButton(button_text)
        btn.setObjectName("PostureButton")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            "QPushButton { background-color: #1E293B; color: #E2E8F0; "
            "border: 1px solid #334155; border-radius: 6px; "
            "padding: 6px 14px; font-size: 12px; font-weight: 600; margin-top: 4px; }"
            "QPushButton:hover { background-color: #2563EB; color: #FFFFFF; "
            "border-color: #3B82F6; }"
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
    ICON       = "◈"
    ICON_COLOR = "#3B82F6"
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
        self._mitre_widget: MitreKillChainWidget | None = None
        self._topology_radar: TopologyRadarWidget | None = None
        self._alert_container: QWidget | None = None
        self._alert_service = alert_service or AlertService()
        self._telemetry_history = telemetry_history or TelemetryHistory()
        self._last_finding_ids: frozenset[str] = frozenset()
        self._last_incident_ids: frozenset[str] = frozenset()

        self._live_network = live_network or LiveNetworkActivity()
        self._live_network_model: LiveNetworkTableModel | None = None
        self._live_network_proxy: QSortFilterProxyModel | None = None
        self._live_network_filter: QLineEdit | None = None
        self._findings_container: QWidget | None = None
        self._incidents_container: QWidget | None = None
        self._explanation_container: QWidget | None = None
        self._relationships_container: QWidget | None = None
        self._network_summary_labels: dict[str, QLabel] = {}
        self._main_window: object | None = None
        self._simulation_dialog: ThreatSimulationDialog | None = None

        # Unified Threat Investigation Feed
        self._threat_feed_layout: QVBoxLayout | None = None
        self._selected_mitre_tactic: str | None = None
        self._threat_feed_filter_badge: QLabel | None = None
        self._threat_feed_clear_btn: QPushButton | None = None

        super().__init__(parent)
        self.refresh()

    # -- Navigation ---------------------------------------------------------

    def set_main_window(self, window: object) -> None:
        """Set the MainWindow reference for click-to-navigate."""
        self._main_window = window

    def _navigate_to(self, key: str, **kwargs: object) -> None:
        """Navigate to a page via the MainWindow, if available."""
        nav = getattr(self._main_window, "navigate_to", None)
        if callable(nav):
            nav(key, **kwargs)

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
        self._risk_gauge = RiskGaugeWidget()
        rf_lay = risk_frame.layout()
        if rf_lay is not None:
            rf_lay.addWidget(self._risk_gauge)
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

        # --- MITRE ATT&CK Kill-Chain Progression --------------------------
        layout.addWidget(self._make_section_label("MITRE ATT&CK KILL-CHAIN PROGRESSION"))
        self._mitre_widget = MitreKillChainWidget()
        self._mitre_widget.tactic_selected.connect(self._on_mitre_tactic_selected)
        layout.addWidget(self._mitre_widget)

        # --- Threat Feed (left 65%) + Live Topology Radar (right 35%) -----
        mid_row = QHBoxLayout()
        mid_row.setSpacing(14)

        feed_col = QVBoxLayout()
        feed_col.setSpacing(6)
        feed_hdr_row = QHBoxLayout()
        feed_hdr_row.addWidget(self._make_section_label("ACTIVE THREAT INVESTIGATION FEED"))
        feed_hdr_row.addStretch(1)

        self._threat_feed_filter_badge = QLabel("")
        self._threat_feed_filter_badge.setVisible(False)
        self._threat_feed_filter_badge.setStyleSheet(
            "background-color: rgba(56, 189, 248, 0.15); color: #38BDF8; "
            "border: 1px solid #38BDF8; border-radius: 4px; "
            "padding: 2px 8px; font-size: 11px; font-weight: bold;"
        )
        self._threat_feed_clear_btn = QPushButton("✕ Clear Filter")
        self._threat_feed_clear_btn.setVisible(False)
        self._threat_feed_clear_btn.setFixedHeight(22)
        self._threat_feed_clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._threat_feed_clear_btn.setStyleSheet(
            "QPushButton { background: transparent; color: #94A3B8; font-size: 11px; "
            "border: 1px solid #334155; border-radius: 4px; padding: 0 6px; } "
            "QPushButton:hover { background: #1E293B; color: #F1F5F9; border-color: #475569; }"
        )
        self._threat_feed_clear_btn.clicked.connect(self._clear_mitre_filter)
        feed_hdr_row.addWidget(self._threat_feed_filter_badge)
        feed_hdr_row.addWidget(self._threat_feed_clear_btn)
        feed_col.addLayout(feed_hdr_row)
        self._threat_feed_container = QFrame()
        self._threat_feed_container.setObjectName("Card")
        self._threat_feed_inner = QVBoxLayout(self._threat_feed_container)
        self._threat_feed_inner.setContentsMargins(0, 0, 0, 0)
        self._threat_feed_inner.setSpacing(0)
        self._threat_feed_layout = self._threat_feed_inner
        self._threat_feed_scroll = QScrollArea()
        self._threat_feed_scroll.setWidgetResizable(True)
        self._threat_feed_scroll.setMinimumHeight(235)
        self._threat_feed_scroll.setMaximumHeight(350)
        self._threat_feed_scroll.setWidget(self._threat_feed_container)
        feed_col.addWidget(self._threat_feed_scroll)
        mid_row.addLayout(feed_col, 11)

        radar_col = QVBoxLayout()
        radar_col.setSpacing(6)
        radar_col.addWidget(self._make_section_label("NETWORK TOPOLOGY & ATTACK SURFACE"))
        self._topology_radar = TopologyRadarWidget()
        self._topology_radar.setMinimumHeight(235)
        self._topology_radar.setMaximumHeight(350)
        radar_col.addWidget(self._topology_radar)
        mid_row.addLayout(radar_col, 9)

        layout.addLayout(mid_row)

        # --- Live Network Activity Table + SIEM Filter Bar ----------------
        net_hdr_row = QHBoxLayout()
        net_hdr_row.setSpacing(12)
        net_hdr_row.addWidget(self._make_section_label("LIVE NETWORK ACTIVITY"))
        net_hdr_row.addStretch(1)
        self._live_network_filter = QLineEdit()
        self._live_network_filter.setPlaceholderText(
            "Filter live flows (IP, Port, TCP/UDP, inbound/outbound)..."
        )
        self._live_network_filter.setFixedWidth(340)
        net_hdr_row.addWidget(self._live_network_filter)
        layout.addLayout(net_hdr_row)

        self._live_network_model = LiveNetworkTableModel(self)
        self._live_network_proxy = QSortFilterProxyModel(self)
        self._live_network_proxy.setSourceModel(self._live_network_model)
        self._live_network_proxy.setFilterCaseSensitivity(
            Qt.CaseSensitivity.CaseInsensitive
        )
        self._live_network_proxy.setFilterKeyColumn(-1)
        self._live_network_Proxy_sort = self._live_network_proxy
        self._live_network_proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self._live_network_filter.textChanged.connect(
            self._live_network_proxy.setFilterFixedString
        )

        self._live_network_table = QTableView()
        self._live_network_table.setModel(self._live_network_proxy)
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
        self._live_network_table.horizontalHeader().setSectionsMovable(True)
        self._live_network_table.setMinimumHeight(150)
        self._live_network_table.setMaximumHeight(220)
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
        layout.addWidget(self._make_section_label("CONTEXTUAL TELEMETRY & RISK TRENDS"))
        graphs_row = QHBoxLayout()
        graphs_row.setSpacing(14)
        self._network_graph = LineGraphWidget(
            title="NETWORK THROUGHPUT",
            series_configs=(("Packets", ACCENT), ("Bytes", INFO)),
        )
        self._network_graph.setMinimumHeight(140)
        graphs_row.addWidget(self._network_graph, 1)
        self._security_graph = LineGraphWidget(
            title="SECURITY EVENTS",
            series_configs=(
                ("Events", ACCENT),
                ("Findings", WARN),
                ("Incidents", CRITICAL),
            ),
        )
        self._security_graph.setMinimumHeight(140)
        graphs_row.addWidget(self._security_graph, 1)
        self._risk_graph = LineGraphWidget(
            title="RISK SCORE TREND",
            series_configs=(("Risk Score", HIGH),),
        )
        self._risk_graph.setMinimumHeight(140)
        graphs_row.addWidget(self._risk_graph, 1)
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
        self._risk_context_label = QLabel("")
        self._risk_context_label.setVisible(False)
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
        self._simulate_button = QPushButton("\U0001f9ea Simulate Threat")
        self._simulate_button.setObjectName("WarningButton")
        self._simulate_button.setToolTip("Run a synthetic attack playbook (demo mode)")
        self._simulate_button.clicked.connect(self.open_threat_simulation)
        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.setObjectName("PrimaryButton")
        self._refresh_button.clicked.connect(self.refresh)
        self._export_button = QPushButton("📄 Export SOC Brief")
        self._export_button.setObjectName("SecondaryButton")
        self._export_button.setToolTip(
            "Export comprehensive SOC incident & security posture report"
        )
        self._export_button.clicked.connect(self.export_soc_report)
        self._last_updated_label = QLabel("Last updated: —")
        self._last_updated_label.setObjectName("CardHint")
        toolbar.addWidget(self._simulate_button)
        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._export_button)
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
        """Top Hero 'Security Shield & Threat Defense Command Banner'."""
        bar = QFrame()
        bar.setObjectName("HeroShieldBanner")
        self._hero_banner = bar
        bar.setStyleSheet(
            "QFrame#HeroShieldBanner {"
            "  background: qlineargradient("
            "    x1:0, y1:0, x2:1, y2:0,"
            "    stop:0 #0B132B, stop:0.35 #0F1D36, stop:0.7 #0F233D, stop:1 #0B132B"
            "  );"
            "  border: 1px solid rgba(56, 189, 248, 0.35);"
            "  border-radius: 12px;"
            "}"
        )

        root_h = QHBoxLayout(bar)
        root_h.setContentsMargins(18, 14, 18, 14)
        root_h.setSpacing(16)

        # 1. Left: Holographic Shield Icon Box
        icon_box = QFrame()
        icon_box.setObjectName("HeroShieldIconBox")
        icon_box.setFixedSize(50, 50)
        icon_box.setStyleSheet(
            "QFrame#HeroShieldIconBox {"
            "  background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1E293B, stop:1 #0F172A);"
            "  border: 1px solid #38BDF8;"
            "  border-radius: 10px;"
            "}"
        )
        self._hero_shield_icon_box = icon_box
        ib_lay = QVBoxLayout(icon_box)
        ib_lay.setContentsMargins(0, 0, 0, 0)
        self._hero_shield_icon = QLabel("🛡️")
        self._hero_shield_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hero_shield_icon.setStyleSheet("font-size: 24px; background: transparent;")
        ib_lay.addWidget(self._hero_shield_icon)
        root_h.addWidget(icon_box)

        # 2. Status Titles & Telemetry Chips
        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 0, 0, 0)
        title_col.setSpacing(4)

        self._hero_status_title = QLabel("● SYSTEM PROTECTED  ·  ALL DEFENSE SHIELDS ARMED")
        self._hero_status_title.setObjectName("HeroStatusTitle")
        self._hero_status_title.setStyleSheet(
            "font-size: 14px; font-weight: 800; color: #10B981; letter-spacing: 0.6px;"
        )
        title_col.addWidget(self._hero_status_title)

        self._hero_status_subtitle = QLabel(
            "Hybrid Host & Network IDPS actively inspecting live packets, processes & files"
        )
        self._hero_status_subtitle.setStyleSheet("font-size: 11px; color: #94A3B8;")
        title_col.addWidget(self._hero_status_subtitle)

        # Telemetry Pill Chips Row
        pills_row = QHBoxLayout()
        pills_row.setSpacing(8)

        self._hero_pill_host = QLabel("🖥️ Host: Local Host")
        self._hero_pill_host.setStyleSheet(
            "background: rgba(30, 41, 59, 0.85); border: 1px solid #334155; "
            "border-radius: 8px; padding: 2px 8px; font-size: 10px; "
            "font-weight: 600; color: #E2E8F0;"
        )
        pills_row.addWidget(self._hero_pill_host)

        self._hero_pill_threats = QLabel("🛡️ Zero Active Threats")
        self._hero_pill_threats.setStyleSheet(
            "background: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; "
            "border-radius: 8px; padding: 2px 8px; font-size: 10px; "
            "font-weight: 600; color: #6EE7B7;"
        )
        pills_row.addWidget(self._hero_pill_threats)

        pills_row.addStretch(1)
        title_col.addLayout(pills_row)

        root_h.addLayout(title_col, 5)

        # 3. Middle: Core Component Micro Indicators
        comp_frame = QFrame()
        comp_frame.setStyleSheet("background: transparent; border: none;")
        comp_lay = QVBoxLayout(comp_frame)
        comp_lay.setContentsMargins(0, 0, 0, 0)
        comp_lay.setSpacing(4)

        comp_title = QLabel("DEFENSE ENGINE SENSORS")
        comp_title.setStyleSheet(
            "font-size: 9px; font-weight: 800; color: #64748B; letter-spacing: 0.6px;"
        )
        comp_lay.addWidget(comp_title)

        chips_grid = QHBoxLayout()
        chips_grid.setSpacing(10)

        self._health_indicators = {}
        for display_name, key in self._HEALTH_ITEMS:
            col_box = QHBoxLayout()
            col_box.setSpacing(4)

            dot = QLabel("●")
            dot.setObjectName(f"dot_{key}")
            dot.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 9px;")
            dot.setAlignment(Qt.AlignmentFlag.AlignCenter)

            text = QLabel(f"{display_name}")
            text.setObjectName(f"health_{key}")
            text.setStyleSheet(f"font-size: 10px; color: {TEXT_MUTED};")

            col_box.addWidget(dot)
            col_box.addWidget(text)
            chips_grid.addLayout(col_box)

            self._health_indicators[key] = (dot, text)

        comp_lay.addLayout(chips_grid)
        root_h.addWidget(comp_frame, 4)

        # 4. Right: Health Score Gauge Box
        gauge_box = QFrame()
        gauge_box.setObjectName("HeroGaugeBox")
        gauge_box.setStyleSheet(
            "QFrame#HeroGaugeBox {"
            "  background: rgba(15, 23, 42, 0.7);"
            "  border: 1px solid #334155;"
            "  border-radius: 10px;"
            "  padding: 4px 14px;"
            "}"
        )
        gb_lay = QVBoxLayout(gauge_box)
        gb_lay.setContentsMargins(10, 6, 10, 6)
        gb_lay.setSpacing(1)
        gb_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        t_lbl = QLabel("SYSTEM INTEGRITY")
        t_lbl.setStyleSheet(
            "font-size: 9px; font-weight: 800; color: #64748B; letter-spacing: 0.6px;"
        )
        t_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gb_lay.addWidget(t_lbl)

        self._hero_health_score = QLabel("100%")
        self._hero_health_score.setStyleSheet(
            "font-size: 22px; font-weight: 900; color: #10B981;"
        )
        self._hero_health_score.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gb_lay.addWidget(self._hero_health_score)

        root_h.addWidget(gauge_box, 2)

        return bar

    def _update_health_bar(self) -> None:
        """Sync the hero security banner and health indicators from live telemetry."""
        for key, (dot, text) in self._health_indicators.items():
            status = self._monitor_labels[key].text()
            display_name = next(
                (name for name, k in self._HEALTH_ITEMS if k == key), key
            )
            active = status in ("ACTIVE", "MONITOR (read-only)")
            color = OK if active else WARN if status in ("DISABLED",) else HIGH
            dot.setStyleSheet(f"color: {color}; font-size: 9px;")
            text.setText(f"{display_name}")
            text.setToolTip(f"{display_name}: {status}")

        snapshot = self._snapshot
        risk_score = 0
        high_findings = 0
        active_incidents = 0
        hostname = "Local Host"

        if snapshot is not None:
            if snapshot.risk.latest_score is not None:
                risk_score = snapshot.risk.latest_score
            high_findings = sum(
                1 for item in snapshot.high_risk_findings
                if item.severity in ("high", "critical")
            )
            active_incidents = sum(
                1 for item in snapshot.activity
                if item.kind == "incident"
            )
            if snapshot.inventory.hostname:
                hostname = snapshot.inventory.hostname

        health_pct = max(0, min(100, 100 - risk_score))
        self._hero_health_score.setText(f"{health_pct}%")
        self._hero_pill_host.setText(f"🖥️ Host: {hostname}")

        is_under_attack = (high_findings > 0) or (risk_score >= 60) or (active_incidents > 0)

        if is_under_attack:
            self._hero_banner.setStyleSheet(
                "QFrame#HeroShieldBanner {"
                "  background: qlineargradient("
                "    x1:0, y1:0, x2:1, y2:0,"
                "    stop:0 #2A080C, stop:0.5 #3B0D13, stop:1 #2A080C"
                "  );"
                "  border: 1px solid #EF4444;"
                "  border-radius: 12px;"
                "}"
            )
            self._hero_shield_icon_box.setStyleSheet(
                "QFrame#HeroShieldIconBox {"
                "  background: #450A0A; border: 1px solid #EF4444; border-radius: 10px;"
                "}"
            )
            self._hero_shield_icon.setText("🚨")
            self._hero_status_title.setText("● THREAT DETECTED  ·  ACTIVE EXPLOIT MITIGATION")
            self._hero_status_title.setStyleSheet(
                "font-size: 14px; font-weight: 800; color: #EF4444; letter-spacing: 0.6px;"
            )
            self._hero_status_subtitle.setText(
                f"Security engine detected {high_findings} high-severity finding(s) "
                f"and {active_incidents} incident(s)."
            )
            self._hero_pill_threats.setText(
                f"⚠️ {high_findings} Threats | {active_incidents} Incidents"
            )
            self._hero_pill_threats.setStyleSheet(
                "background: rgba(239, 68, 68, 0.2); border: 1px solid #EF4444; "
                "border-radius: 8px; padding: 2px 8px; font-size: 10px; "
                "font-weight: 700; color: #FCA5A5;"
            )
            self._hero_health_score.setStyleSheet(
                "font-size: 22px; font-weight: 900; color: #EF4444;"
            )
        else:
            self._hero_banner.setStyleSheet(
                "QFrame#HeroShieldBanner {"
                "  background: qlineargradient("
                "    x1:0, y1:0, x2:1, y2:0,"
                "    stop:0 #0B132B, stop:0.35 #0F1D36, stop:0.7 #0F233D, stop:1 #0B132B"
                "  );"
                "  border: 1px solid rgba(56, 189, 248, 0.35);"
                "  border-radius: 12px;"
                "}"
            )
            self._hero_shield_icon_box.setStyleSheet(
                "QFrame#HeroShieldIconBox {"
                "  background: qlineargradient("
                "    x1:0, y1:0, x2:1, y2:1, stop:0 #1E293B, stop:1 #0F172A"
                "  );"
                "  border: 1px solid #38BDF8;"
                "  border-radius: 10px;"
                "}"
            )
            self._hero_shield_icon.setText("🛡️")
            self._hero_status_title.setText("● SYSTEM PROTECTED  ·  ALL DEFENSE SHIELDS ARMED")
            self._hero_status_title.setStyleSheet(
                "font-size: 14px; font-weight: 800; color: #10B981; letter-spacing: 0.6px;"
            )
            self._hero_status_subtitle.setText(
                "Hybrid Host & Network IDPS actively inspecting live packets, processes & files"
            )
            self._hero_pill_threats.setText("🛡️ Zero Active Threats")
            self._hero_pill_threats.setStyleSheet(
                "background: rgba(16, 185, 129, 0.15); border: 1px solid #10B981; "
                "border-radius: 8px; padding: 2px 8px; font-size: 10px; "
                "font-weight: 600; color: #6EE7B7;"
            )
            self._hero_health_score.setStyleSheet(
                "font-size: 22px; font-weight: 900; color: #10B981;"
            )

    @staticmethod
    def _metric_card(label: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            "QFrame#Card { background-color: #0E1726; border: 1px solid #1E293B; "
            "border-radius: 8px; }"
            "QFrame#Card:hover { border-color: #3B82F6; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(3)
        title = QLabel(label.upper())
        title.setObjectName("CardTitle")
        title.setStyleSheet(
            "font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.6px;"
        )
        layout.addWidget(title)
        value = QLabel(_EMPTY)
        value.setObjectName("CardValue")
        value.setStyleSheet("font-size: 20px; font-weight: 800; color: #F8FAFC;")
        value.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(value)
        return card, value

    @staticmethod
    def _make_section_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("CardTitle")
        label.setStyleSheet(
            "font-size: 11px; font-weight: 800; color: #94A3B8; "
            "letter-spacing: 1px; padding: 6px 0 2px 0;"
        )
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
            snapshot = augment_snapshot(self._provider())
        except Exception as exc:
            logger.warning("Dashboard refresh failed: %s", exc)
            self._show_error(INVENTORY_ERROR)
            return None
        self._apply(snapshot)
        return snapshot

    def refresh_live(self) -> None:
        """Called on every QTimer tick while monitoring is active."""
        try:
            snapshot = augment_snapshot(self._provider())
        except Exception:
            return
        self._snapshot = snapshot
        self._sample_tlemetry(snapshot)
        self._detect_alerts(snapshot)
        self._update_posture_cards(snapshot)
        self._update_health_bar()
        self._update_threat_feed(snapshot)
        self._update_live_network(snapshot)
        self._update_mitre_and_topology(snapshot)
        self._update_graphs()
        self._update_network_summary(snapshot)
        if snapshot.inventory.available:
            self._set_error(None)
        self._last_updated_label.setText(
            f"Last updated: {format_timestamp(snapshot.collected_at)}",
        )

    # -- Threat simulation (demo mode) --------------------------------------

    @property
    def simulate_button(self) -> QPushButton:
        """Toolbar button that opens the threat simulation playbook dialog."""
        return self._simulate_button

    @property
    def simulation_dialog(self) -> ThreatSimulationDialog | None:
        """The playbook dialog that is currently open, or ``None``."""
        return self._simulation_dialog

    def open_threat_simulation(self) -> SimulationOutcome | None:
        """Show the playbook dialog, inject the chosen scenario, then refresh.

        Cancelling leaves the console untouched. A run injects synthetic
        findings through the existing alert and correlation services and then
        repaints the Threat Feed, Security Posture row and alert list through
        the normal refresh path.
        """
        dialog = ThreatSimulationDialog(self)
        self._simulation_dialog = dialog
        dialog.exec()
        accepted = dialog.result() == QDialog.DialogCode.Accepted
        self._simulation_dialog = None
        if not accepted:
            return None
        outcome = run_scenario(dialog.selected_key(), alert_service=self._alert_service)
        self._refresh_after_simulation()
        return outcome

    def export_soc_report(self) -> str | None:
        """Export comprehensive SOC security incident & posture brief as HTML/PDF report."""
        snapshot = self._snapshot or augment_snapshot(self._provider())
        ts_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        default_name = f"aegis_soc_incident_brief_{ts_str}.html"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save SOC Incident Brief",
            default_name,
            "HTML Report (*.html);;All Files (*.*)",
        )
        if not path:
            return None

        # Build clean, high-grade cyber SOC executive report HTML
        risk_score = (
            snapshot.risk.latest_score if snapshot.risk.latest_score is not None else "N/A"
        )
        risk_level = (snapshot.risk.latest_level or "NORMAL").upper()
        high_findings = [
            f for f in snapshot.high_risk_findings if f.severity in ("high", "critical")
        ]
        incidents = [a for a in snapshot.activity if a.kind == "incident"]

        findings_rows = []
        for f in high_findings[:20]:
            ts = format_timestamp(f.timestamp)
            findings_rows.append(
                f"<tr><td><b>{f.severity.upper()}</b></td><td>{f.description}</td><td>{ts}</td></tr>"
            )
        findings_html = "".join(findings_rows) or (
            "<tr><td colspan='3'>Zero critical findings detected.</td></tr>"
        )

        incidents_rows = []
        for inc in incidents[:20]:
            ts = format_timestamp(inc.timestamp)
            incidents_rows.append(
                f"<tr><td><b>{inc.severity.upper()}</b></td>"
                f"<td>{inc.description}</td><td>{ts}</td></tr>"
            )
        incidents_html = "".join(incidents_rows) or (
            "<tr><td colspan='3'>Zero active incidents.</td></tr>"
        )

        gen_ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        risk_badge_color = "#EF4444" if risk_level in ("CRITICAL", "HIGH") else "#10B981"
        host_name = snapshot.inventory.hostname or "localhost"
        host_os = snapshot.inventory.operating_system or "Unknown OS"

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Aegis IDPS — SOC Incident & Posture Brief</title>
<style>
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0B0F19;
    color: #E2E8F0;
    padding: 30px;
    margin: 0;
  }}
  .header {{
    border-bottom: 2px solid #2563EB;
    padding-bottom: 15px;
    margin-bottom: 25px;
  }}
  .title {{
    font-size: 24px;
    font-weight: 800;
    color: #38BDF8;
    letter-spacing: 1px;
  }}
  .sub {{
    font-size: 13px;
    color: #94A3B8;
    margin-top: 4px;
  }}
  .badge-grid {{
    display: flex;
    gap: 15px;
    margin-bottom: 25px;
  }}
  .card {{
    background: #0E1726;
    border: 1px solid #1E293B;
    border-radius: 8px;
    padding: 15px;
    flex: 1;
  }}
  .card-title {{
    font-size: 11px;
    font-weight: 700;
    color: #94A3B8;
    letter-spacing: 0.5px;
  }}
  .card-val {{
    font-size: 28px;
    font-weight: 800;
    color: #38BDF8;
    margin: 6px 0;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    background: #0E1726;
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid #1E293B;
    font-size: 13px;
  }}
  th {{
    background: #1E293B;
    color: #94A3B8;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
  }}
  .section {{
    margin-top: 30px;
  }}
  .section-h {{
    font-size: 14px;
    font-weight: 800;
    color: #F1F5F9;
    letter-spacing: 0.8px;
    border-left: 3px solid #38BDF8;
    padding-left: 10px;
    margin-bottom: 12px;
  }}
</style>
</head>
<body>
  <div class="header">
    <div class="title">AEGIS INTRUSION DEFENSE SYSTEM</div>
    <div class="sub">Executive SOC Incident Brief & Threat Audit  ·  Generated: {gen_ts}</div>
  </div>

  <div class="badge-grid">
    <div class="card">
      <div class="card-title">GLOBAL RISK SCORE</div>
      <div class="card-val" style="color: {risk_badge_color};">{risk_score} / 100</div>
      <div class="sub">Level: {risk_level}</div>
    </div>
    <div class="card">
      <div class="card-title">HIGH/CRITICAL THREATS</div>
      <div class="card-val">{len(high_findings)}</div>
      <div class="sub">{snapshot.detection.finding_count} Total Findings</div>
    </div>
    <div class="card">
      <div class="card-title">ACTIVE INCIDENTS</div>
      <div class="card-val">{len(incidents)}</div>
      <div class="sub">{snapshot.event_count} Events Monitored</div>
    </div>
    <div class="card">
      <div class="card-title">HOST MONITORED</div>
      <div class="card-val" style="font-size: 20px; line-height: 38px;">{host_name}</div>
      <div class="sub">{host_os}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-h">HIGH & CRITICAL DETECTION FINDINGS</div>
    <table>
      <thead><tr><th>Severity</th><th>Description</th><th>Timestamp</th></tr></thead>
      <tbody>{findings_html}</tbody>
    </table>
  </div>

  <div class="section">
    <div class="section-h">CORRELATED SECURITY INCIDENTS</div>
    <table>
      <thead><tr><th>Severity</th><th>Incident Summary</th><th>Timestamp</th></tr></thead>
      <tbody>{incidents_html}</tbody>
    </table>
  </div>
</body>
</html>
"""
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            msg = getattr(self._main_window, "show_toast", None)
            if callable(msg):
                msg("SOC Report Exported", f"Saved successfully to {path}", "success", 4000)
            return path
        except Exception as exc:
            logger.warning("Failed to export SOC report: %s", exc)
            return None

    def _refresh_after_simulation(self) -> None:
        """Repaint the views a simulated attack feeds, without a full rebuild."""
        try:
            snapshot = augment_snapshot(self._provider())
        except Exception as exc:
            logger.warning("Dashboard refresh after simulation failed: %s", exc)
            return
        self._snapshot = snapshot
        self._detect_alerts(snapshot)
        # Sound cyber alarm tone for simulated attack
        get_audio_alert_service().play_alarm(duration_seconds=15.0)
        self._update_posture_cards(snapshot)
        self._update_threat_feed(snapshot)
        self._update_mitre_and_topology(snapshot)
        self._update_alert_display()
        self._update_health_bar()
        if snapshot.inventory.available:
            self._set_error(None)
        self._last_updated_label.setText(
            f"Last updated: {format_timestamp(snapshot.collected_at)}"
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
        self._update_mitre_and_topology(snapshot)
        self._update_threat_feed(snapshot)
        self._update_health_bar()

        if inventory.available:
            self._set_error(None)
        else:
            self._set_error(inventory.error or INVENTORY_ERROR)
        self._last_updated_label.setText(f"Last updated: {format_timestamp(snapshot.collected_at)}")

    def _update_mitre_and_topology(self, snapshot: DashboardSnapshot) -> None:
        """Update the MITRE ATT&CK kill-chain strip and topology radar."""
        counts: dict[str, int] = {
            "TA0043": 0,
            "TA0001": 0,
            "TA0002": 0,
            "TA0003": 0,
            "TA0011": 0,
            "TA0010": 0,
        }
        texts: list[str] = [item.description.lower() for item in snapshot.high_risk_findings]
        texts.extend(
            item.description.lower()
            for item in snapshot.activity
            if item.kind in ("finding", "incident")
        )
        texts.extend(
            (alert.description or alert.title).lower()
            for alert in self._alert_service.all_alerts()[:20]
        )

        for txt in texts:
            if any(k in txt for k in ("scan", "port", "recon", "sweep", "probe")):
                counts["TA0043"] += 1
            elif any(k in txt for k in ("inbound", "brute", "login", "auth", "access")):
                counts["TA0001"] += 1
            elif any(k in txt for k in ("process", "powershell", "cmd", "spawn", "exec", "shell")):
                counts["TA0002"] += 1
            elif any(k in txt for k in ("file", "integrity", "fim", "persist", "registry", "cron")):
                counts["TA0003"] += 1
            elif any(k in txt for k in ("ioc", "beacon", "c2", "communicat", "uncommon", "tor")):
                counts["TA0011"] += 1
            elif any(k in txt for k in ("volume", "exfil", "anomaly", "spike", "flood")):
                counts["TA0010"] += 1
            else:
                counts["TA0002"] += 1

        if self._mitre_widget is not None:
            self._mitre_widget.set_stage_counts(counts)

        if self._topology_radar is not None:
            host_ip = "127.0.0.1"
            with contextlib.suppress(Exception):
                from aegis_desktop.services.assets import collect_asset_view

                asset_view = collect_asset_view()
                if asset_view.rows and asset_view.rows[0].ip_addresses:
                    host_ip = asset_view.rows[0].ip_addresses[0]

            peers: list[tuple[str, str, str, bool]] = []
            seen_peers: set[str] = set()
            for row in reversed(self._live_network.rows()):
                remote = row.destination if row.direction.lower() != "inbound" else row.source
                if not remote or remote in seen_peers:
                    continue
                seen_peers.add(remote)
                if len(peers) < 8:
                    peers.append((remote, row.protocol, row.direction, row.state == "event"))

            self._topology_radar.set_topology(
                hostname=snapshot.inventory.hostname,
                host_ip=host_ip,
                port_count=snapshot.port_count,
                peers=peers,
                total_peers=len(seen_peers),
            )

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

        if self._risk_gauge is not None:
            self._risk_gauge.set_score(score, level)

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
                    f"{pending} response request(s) awaiting action"
                )
            else:
                self._posture_action_sub.setText("No pending actions")

    @staticmethod
    def _pending_response_count() -> int:
        """Return count of response requests still awaiting action (lazy import)."""
        try:
            from aegis_desktop.services.response_workflow import get_workflow_manager

            mgr = get_workflow_manager()
            return mgr.actionable_count()
        except Exception:
            return 0

    def _on_mitre_tactic_selected(self, tactic_code: str) -> None:
        """Handle user clicking a MITRE kill chain stage."""
        self._selected_mitre_tactic = tactic_code if tactic_code else None
        self._update_threat_feed_filter_ui()
        if self._snapshot is not None:
            self._update_threat_feed(self._snapshot)

    def _clear_mitre_filter(self) -> None:
        """Reset MITRE kill chain stage filtering."""
        self._selected_mitre_tactic = None
        if self._mitre_widget is not None:
            self._mitre_widget.clear_selection()
        self._update_threat_feed_filter_ui()
        if self._snapshot is not None:
            self._update_threat_feed(self._snapshot)

    def _update_threat_feed_filter_ui(self) -> None:
        """Update the threat feed header filter badge and clear button."""
        tactic_names = {
            "TA0043": "RECONNAISSANCE",
            "TA0001": "INITIAL ACCESS",
            "TA0002": "EXECUTION",
            "TA0003": "PERSISTENCE",
            "TA0011": "COMMAND & CTRL",
            "TA0010": "EXFILTRATION",
        }
        if (
            self._selected_mitre_tactic
            and self._threat_feed_filter_badge is not None
            and self._threat_feed_clear_btn is not None
        ):
            name = tactic_names.get(self._selected_mitre_tactic, self._selected_mitre_tactic)
            self._threat_feed_filter_badge.setText(
                f"FILTERED: {self._selected_mitre_tactic} {name}"
            )
            self._threat_feed_filter_badge.setVisible(True)
            self._threat_feed_clear_btn.setVisible(True)
        elif (
            self._threat_feed_filter_badge is not None
            and self._threat_feed_clear_btn is not None
        ):
            self._threat_feed_filter_badge.setVisible(False)
            self._threat_feed_clear_btn.setVisible(False)

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

        # Tag each item with MITRE tactic
        for item in feed_items:
            txt = f"{item.get('title', '')} {item.get('evidence', '')}".lower()
            if any(k in txt for k in ("scan", "port", "recon", "sweep", "probe")):
                item["tactic_code"] = "TA0043"
                item["tactic"] = "TA0043 RECON"
            elif any(k in txt for k in ("inbound", "brute", "login", "auth", "access")):
                item["tactic_code"] = "TA0001"
                item["tactic"] = "TA0001 INITIAL ACCESS"
            elif any(k in txt for k in ("process", "powershell", "cmd", "spawn", "exec", "shell")):
                item["tactic_code"] = "TA0002"
                item["tactic"] = "TA0002 EXECUTION"
            elif any(k in txt for k in ("file", "integrity", "fim", "persist", "registry", "cron")):
                item["tactic_code"] = "TA0003"
                item["tactic"] = "TA0003 PERSISTENCE"
            elif any(k in txt for k in ("ioc", "beacon", "c2", "communicat", "uncommon", "tor")):
                item["tactic_code"] = "TA0011"
                item["tactic"] = "TA0011 C2"
            elif any(k in txt for k in ("volume", "exfil", "anomaly", "spike", "flood")):
                item["tactic_code"] = "TA0010"
                item["tactic"] = "TA0010 EXFILTRATION"
            else:
                item["tactic_code"] = "TA0002"
                item["tactic"] = "TA0002 EXECUTION"

        # Apply tactic filter if active
        active_tactic = self._selected_mitre_tactic
        displayed_items = feed_items
        if active_tactic:
            displayed_items = [
                fi for fi in feed_items if fi.get("tactic_code") == active_tactic
            ]

        if not displayed_items:
            empty = QFrame()
            empty.setObjectName("EmptyStateCard")
            empty_lay = QVBoxLayout(empty)
            empty_lay.setContentsMargins(20, 24, 20, 24)
            empty_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_icon = QLabel("🔍" if active_tactic else "🛡")
            e_icon.setStyleSheet("font-size: 32px; background: transparent;")
            e_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            if active_tactic:
                e_title = QLabel(f"NO ACTIVE ALERTS MATCHING MITRE {active_tactic}")
                e_title.setStyleSheet(
                    "font-size: 13px; font-weight: 800; color: #38BDF8; "
                    "background: transparent; letter-spacing: 0.8px;"
                )
                e_sub = QLabel(
                    f"There are currently 0 alerts classified under {active_tactic}. "
                    "Click 'Clear Filter' or select another kill-chain stage."
                )
            else:
                e_title = QLabel("SYSTEM POSTURE CLEAN — ZERO ACTIVE THREATS DETECTED")
                e_title.setStyleSheet(
                    f"font-size: 13px; font-weight: 800; color: {OK}; "
                    "background: transparent; letter-spacing: 0.8px;"
                )
                e_sub = QLabel(
                    "Deterministic rules & anomaly models are actively monitoring telemetry. "
                    "No security incidents or anomalies found."
                )
            e_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            e_sub.setStyleSheet("font-size: 12px; color: #64748B; background: transparent;")
            e_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty_lay.addWidget(e_icon)
            empty_lay.addWidget(e_title)
            empty_lay.addWidget(e_sub)
            layout.addWidget(empty)
            return

        for feed_entry in displayed_items[:30]:
            layout.addWidget(self._build_threat_card(feed_entry))

    def _build_threat_card(self, item: dict[str, str]) -> QWidget:
        """Build a single stylised threat card for the feed."""
        severity = item.get("severity", "").lower()
        color = HIGH if severity == "high" else CRITICAL if severity == "critical" else WARN

        frame = QFrame()
        frame.setObjectName("Card")
        frame.setStyleSheet(
            f"QFrame#Card {{ background-color: #0E1726; border: 1px solid #1E293B; "
            f"border-left: 4px solid {color}; border-radius: 8px; }}"
            f"QFrame#Card:hover {{ background-color: #162032; border-color: #334155; }}"
        )
        outer = QHBoxLayout(frame)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(14)

        # Severity badge
        sev_txt = item.get("severity", "?").upper()[:4]
        badge = QLabel(sev_txt)
        badge.setObjectName("FieldValue")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFixedWidth(54)
        badge.setStyleSheet(
            f"background-color: {color}25; color: {color}; border: 1px solid {color}88; "
            f"font-weight: 800; font-size: 11px; border-radius: 6px; padding: 4px 0;"
        )
        outer.addWidget(badge)

        # Content column
        content = QVBoxLayout()
        content.setSpacing(3)

        title = QLabel(item.get("title", ""))
        title.setObjectName("FieldValue")
        title.setStyleSheet("font-size: 13px; font-weight: 700; color: #F1F5F9;")
        title.setWordWrap(True)
        content.addWidget(title)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(16)
        ts_label = QLabel("⏱ " + item.get("timestamp", ""))
        ts_label.setObjectName("CardHint")
        ts_label.setStyleSheet("font-size: 11px; color: #64748B;")
        raw_host = item.get("host", _EMPTY)
        host_txt = f"Host: {raw_host}" if "host" not in raw_host.lower() else raw_host
        host_label = QLabel(f"🖥 {host_txt}")
        host_label.setObjectName("CardHint")
        host_label.setStyleSheet("font-size: 11px; color: #64748B;")
        ev_label = QLabel("⚡ " + item.get("evidence", ""))
        ev_label.setObjectName("CardHint")
        ev_label.setStyleSheet("font-size: 11px; color: #94A3B8;")
        meta_row.addWidget(ts_label)
        meta_row.addWidget(host_label)
        meta_row.addWidget(ev_label)

        tactic = item.get("tactic", "")
        if tactic:
            tactic_label = QLabel("🎯 " + tactic)
            tactic_label.setObjectName("CardHint")
            tactic_label.setStyleSheet(
                "font-size: 11px; color: #38BDF8; font-weight: 600; background: transparent;"
            )
            meta_row.addWidget(tactic_label)

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
            # Add explicit Investigate button
            inv_btn = QPushButton("Investigate →")
            inv_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            inv_btn.setStyleSheet(
                "QPushButton { background: #1E293B; color: #93C5FD; border: 1px solid #334155; "
                "border-radius: 6px; padding: 5px 12px; font-size: 11px; font-weight: 600; } "
                "QPushButton:hover { background: #2563EB; color: #FFFFFF; border-color: #3B82F6; }"
            )
            inv_btn.clicked.connect(lambda _c=False, nt=_nt, nid=_nid: (
                self._navigate_to(
                    "detections" if nt == "finding" else "incidents",
                    select_id=nid,
                )
            ))
            outer.addWidget(inv_btn)

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
        new_alerts = self._alert_service.detect(
            findings=finding_rows,
            incidents=incident_rows,
            now=datetime.now(UTC),
        )
        if new_alerts:
            # New cyber threats / high severity findings detected
            get_audio_alert_service().play_alarm(duration_seconds=15.0)

    # -- Live network activity ----------------------------------------------

    def _update_live_network(self, snapshot: DashboardSnapshot) -> None:
        from datetime import datetime as _dt

        from aegis_desktop.services.live_network import analyze_packet_threat
        from aegis_desktop.services.network import collect_network_monitoring_view

        try:
            view = collect_network_monitoring_view()
        except Exception:
            return

        now = _dt.now(UTC)
        for flow in view.flows:
            port = ""
            ep_base = flow.destination.split(" ", 1)[0]
            if ":" in ep_base:
                port = ep_base.rsplit(":", 1)[1]
            elif ":" in flow.source:
                port = flow.source.rsplit(":", 1)[1]
            flow_state = "active" if flow.duration_ms < 60000 else "idle"
            flow_sni = getattr(flow, "sni", None)
            is_suspicious, threat_tag, threat_detail = analyze_packet_threat(
                source=flow.source,
                destination=flow.destination,
                port=port,
                protocol=flow.protocol,
                packets=flow.packets,
                bytes_transferred=flow.bytes,
                state=flow_state,
                domain=flow_sni or "",
            )
            self._live_network.add(LiveActivityRow(
                timestamp=now,
                source=flow.source,
                destination=flow.destination,
                port=port,
                protocol=flow.protocol,
                packets=flow.packets,
                bytes=flow.bytes,
                direction=flow.direction,
                state=flow_state,
                flow_id=flow.flow_id,
                is_suspicious=is_suspicious,
                threat_tag=threat_tag,
                threat_detail=threat_detail,
                sni=flow_sni,
            ))
        for event in view.events:
            flow_id = f"evt-{event.timestamp.timestamp():.0f}"
            port = ""
            ep_base = event.destination.split(" ", 1)[0]
            if ":" in ep_base:
                port = ep_base.rsplit(":", 1)[1]
            elif ":" in event.source:
                port = event.source.rsplit(":", 1)[1]
            ev_pkts = event.packets or 0
            ev_bytes = event.bytes or 0
            event_sni = getattr(event, "sni", None)
            is_suspicious, threat_tag, threat_detail = analyze_packet_threat(
                source=event.source,
                destination=event.destination,
                port=port,
                protocol=event.protocol,
                packets=ev_pkts,
                bytes_transferred=ev_bytes,
                state=event.event_type or "event",
                domain=event_sni or "",
            )
            self._live_network.add(LiveActivityRow(
                timestamp=event.timestamp,
                source=event.source,
                destination=event.destination,
                port=port,
                protocol=event.protocol,
                packets=ev_pkts,
                bytes=ev_bytes,
                direction="",
                state="event",
                flow_id=flow_id,
                is_suspicious=is_suspicious,
                threat_tag=threat_tag,
                threat_detail=threat_detail,
                sni=event_sni,
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
        from aegis_desktop.services.correlation import correlation_for_finding
        from aegis_desktop.services.detections import collect_finding_view, describe_finding

        try:
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
