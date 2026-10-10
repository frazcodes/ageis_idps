"""The Aegis IDPS main window: header, sidebar, page stack and status bar.

The window owns the single :class:`~aegis_runtime.AegisRuntime` through a
:class:`~aegis_desktop.services.monitoring.MonitoringController`. The Start/Stop
control and one Qt timer drive that runtime; no second runtime loop exists.
Opening the window starts nothing. Pressing *Start Monitoring* first runs the
read-only :class:`~aegis_desktop.preflight.PreflightDialog` checklist; the
engine starts only after that checklist completes.
"""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.navigation import NAV_ITEMS, Sidebar
from aegis_desktop.pages import BasePage, DashboardPage, create_page
from aegis_desktop.preflight import PreflightDialog, preflight_enabled_from_env
from aegis_desktop.services.audio_alert import get_audio_alert_service
from aegis_desktop.services.monitoring import (
    CAPTURE_ACTIVE,
    CAPTURE_ERROR,
    MonitoringController,
    MonitoringStatus,
    set_active_monitoring_controller,
)
from aegis_desktop.theme import set_state
from aegis_desktop.toast import ToastLevel, ToastManager

STATUS_MESSAGE = "Monitoring disabled | UI infrastructure only | no response actions"


class MainWindow(QMainWindow):
    """The desktop console shell.

    Constructing the window builds UI only: it starts no monitor, no capture and
    no response action. Monitoring begins only when the user presses Start.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        controller: MonitoringController | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aegis IDPS")
        self.setMinimumSize(1024, 680)
        self.resize(1240, 800)

        self._controller = controller or MonitoringController()
        set_active_monitoring_controller(self._controller)

        self._preflight_enabled = preflight_enabled_from_env()
        self._preflight_dialog: PreflightDialog | None = None

        self._pages: dict[str, BasePage] = {}
        self._sidebar = Sidebar()
        self._stack = QStackedWidget()

        for item in NAV_ITEMS:
            page = create_page(item.key)
            self._pages[item.key] = page
            self._stack.addWidget(page)

        dashboard = self._pages.get("dashboard")
        if isinstance(dashboard, DashboardPage):
            dashboard.set_main_window(self)

        self._timer = QTimer(self)
        self._timer.setInterval(self._controller.poll_interval_ms)
        self._timer.timeout.connect(self._on_tick)

        self._build_layout()
        self._sidebar.currentRowChanged.connect(self._on_navigation)

        status_bar = QStatusBar()
        status_bar.showMessage(STATUS_MESSAGE)
        self.setStatusBar(status_bar)

        # Toast notification overlay (must be created after layout is built)
        self._toast_manager = ToastManager(self)

        # Live UTC clock in header (1 s tick)
        self._clock_timer = QTimer(self)
        self._clock_timer.setInterval(1000)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start()

        self._update_monitoring_ui()
        self._sidebar.navigate_to("dashboard")
        self._setup_shortcuts()

        # Connect audio alert service signals to active visual banner
        audio = get_audio_alert_service()
        audio.alarm_started.connect(self._on_alarm_started)
        audio.alarm_stopped.connect(self._on_alarm_stopped)

    # -- Layout ------------------------------------------------------------

    def _build_header(self) -> QWidget:
        # Outer frame includes a 2px accent bar at the very top
        outer = QWidget()
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(0, 0, 0, 0)
        outer_lay.setSpacing(0)

        # Top accent line
        accent = QFrame()
        accent.setFixedHeight(2)
        accent.setStyleSheet("""
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:0,
                stop:0 transparent,
                stop:0.25 #EF4444,
                stop:0.5 #DC2626,
                stop:0.75 #EF4444,
                stop:1   transparent
            ); border: none;
        """)
        outer_lay.addWidget(accent)

        header = QFrame()
        header.setObjectName("Header")
        header.setFixedHeight(62)
        outer_lay.addWidget(header)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 8, 20, 8)
        layout.setSpacing(12)

        # Brand block
        titles = QVBoxLayout()
        titles.setSpacing(0)
        app_title = QLabel("Aegis IDPS")
        app_title.setObjectName("AppTitle")
        subtitle = QLabel("Hybrid Host & Network IDPS  ·  Security Operations Console")
        subtitle.setObjectName("HeaderSubtitle")
        titles.addWidget(app_title)
        titles.addWidget(subtitle)
        layout.addLayout(titles)

        layout.addStretch(1)

        # Live UTC clock
        self._clock_lbl = QLabel()
        self._clock_lbl.setStyleSheet(
            "color:#64748B; font-size:11px; font-family:'Consolas','Courier New',monospace;"
            "background:transparent; letter-spacing:0.5px;"
        )
        self._update_clock()   # set initial text
        layout.addWidget(self._clock_lbl)

        _sep = QFrame()
        _sep.setFixedSize(1, 28)
        _sep.setStyleSheet("background:#1F2937; border:none;")
        layout.addWidget(_sep)

        # Notification bell
        self._bell_btn = QPushButton("🔔")
        self._bell_btn.setFixedSize(QSize(34, 34))
        self._bell_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._bell_btn.setToolTip("Show demo notification")
        self._bell_btn.setStyleSheet("""
            QPushButton {
                background: transparent; border: none;
                color: #64748B; font-size: 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #1E293B; color: #94A3B8;
            }
        """)
        self._bell_btn.clicked.connect(self._on_bell_clicked)
        layout.addWidget(self._bell_btn)

        # Audio Alert Sound / Mute toggle
        self._audio_btn = QPushButton("🔊")
        self._audio_btn.setFixedSize(QSize(34, 34))
        self._audio_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._audio_btn.setToolTip("Attack Audio Alert (Click to Mute/Unmute)")
        self._audio_btn.setStyleSheet("""
            QPushButton {
                background: transparent; border: none;
                color: #64748B; font-size: 16px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: #111827; color: #EF4444;
            }
        """)
        self._audio_btn.clicked.connect(self._on_audio_btn_clicked)
        layout.addWidget(self._audio_btn)

        _sep2 = QFrame()
        _sep2.setFixedSize(1, 28)
        _sep2.setStyleSheet("background:#1F2937; border:none;")
        layout.addWidget(_sep2)

        # Monitoring status
        self._header_status = QLabel("Monitoring: disabled")
        self._header_status.setObjectName("HeaderStatus")
        layout.addWidget(self._header_status)

        # Start / Stop button
        self._monitor_button = QPushButton("Start Monitoring")
        self._monitor_button.setObjectName("PrimaryButton")
        self._monitor_button.clicked.connect(self.toggle_monitoring)
        layout.addWidget(self._monitor_button)

        # Active Attack Alert Banner (visible only when alarm tone is sounding)
        self._alarm_banner = QFrame()
        self._alarm_banner.setFixedHeight(38)
        self._alarm_banner.setStyleSheet("""
            QFrame {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #7F1D1D,
                    stop:0.5 #991B1B,
                    stop:1 #7F1D1D
                );
                border-top: 1px solid #DC2626;
                border-bottom: 1px solid #DC2626;
            }
        """)
        ab_layout = QHBoxLayout(self._alarm_banner)
        ab_layout.setContentsMargins(20, 0, 20, 0)
        ab_layout.setSpacing(12)

        self._alarm_banner_text = QLabel("🔴 CRITICAL THREAT DETECTED — ACTIVE ATTACK IN PROGRESS")
        self._alarm_banner_text.setStyleSheet(
            "color: #FFFFFF; font-size: 11px; font-weight: 800; letter-spacing: 0.8px;"
        )
        ab_layout.addWidget(self._alarm_banner_text)
        ab_layout.addStretch(1)

        ack_btn = QPushButton("Acknowledge & Silence Alarm ✕")
        ack_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        ack_btn.setStyleSheet("""
            QPushButton {
                background: #450A0A;
                color: #FCA5A5;
                border: 1px solid #EF4444;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: #EF4444;
                color: #FFFFFF;
            }
        """)
        ack_btn.clicked.connect(self._silence_alarm_banner)
        ab_layout.addWidget(ack_btn)

        self._alarm_banner.setVisible(False)
        outer_lay.addWidget(self._alarm_banner)

        return outer

    def _build_sidebar(self) -> QWidget:
        """Sidebar column: brand block above the navigation list."""
        column = QWidget()
        column.setObjectName("SidebarColumn")
        column.setFixedWidth(220)

        layout = QVBoxLayout(column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        brand = QFrame()
        brand.setObjectName("SidebarBrand")
        brand_layout = QVBoxLayout(brand)
        brand_layout.setContentsMargins(18, 16, 18, 14)
        brand_layout.setSpacing(0)

        title = QLabel("AEGIS")
        title.setObjectName("SidebarBrandTitle")
        subtitle = QLabel("Intrusion Defense")
        subtitle.setObjectName("SidebarBrandSubtitle")
        brand_layout.addWidget(title)
        brand_layout.addWidget(subtitle)

        layout.addWidget(brand)
        layout.addWidget(self._sidebar, 1)

        # System Hygiene & Cleaner Button in sidebar footer
        hygiene_card = QFrame()
        hygiene_card.setObjectName("SidebarHygieneCard")
        hygiene_card.setStyleSheet("""
            QFrame#SidebarHygieneCard {
                background: #0B1120;
                border-top: 1px solid #1E293B;
            }
        """)
        hygiene_layout = QVBoxLayout(hygiene_card)
        hygiene_layout.setContentsMargins(12, 10, 12, 12)
        hygiene_layout.setSpacing(4)

        self._hygiene_btn = QPushButton("🧹  System Hygiene")
        self._hygiene_btn.setObjectName("SidebarHygieneBtn")
        self._hygiene_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._hygiene_btn.setToolTip(
            "Scan and purge temporary files & malware staging caches (Ctrl+Shift+C)"
        )
        self._hygiene_btn.setStyleSheet("""
            QPushButton#SidebarHygieneBtn {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0B101B,
                    stop:1 #111827
                );
                border: 1px solid #1E293B;
                border-radius: 6px;
                color: #FFFFFF;
                font-size: 12px;
                font-weight: 600;
                padding: 8px 10px;
                text-align: left;
            }
            QPushButton#SidebarHygieneBtn:hover {
                background: #161F30;
                border-color: #EF4444;
                color: #FFFFFF;
            }
        """)
        self._hygiene_btn.clicked.connect(self.open_system_hygiene)
        hygiene_layout.addWidget(self._hygiene_btn)

        layout.addWidget(hygiene_card)
        return column

    def _build_layout(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._build_header())
        right_layout.addWidget(self._stack, 1)

        root.addWidget(self._build_sidebar())
        root.addWidget(right, 1)
        self.setCentralWidget(central)

    # -- Monitoring control ------------------------------------------------

    @property
    def controller(self) -> MonitoringController:
        """The monitoring controller that owns the single runtime."""
        return self._controller

    def monitoring_status(self) -> MonitoringStatus:
        """Return the current runtime + capture status."""
        return self._controller.status()

    def toggle_monitoring(self) -> None:
        """Start monitoring after preflight, otherwise stop it."""
        if self._controller.is_running:
            self.stop_monitoring()
        else:
            self.start_monitoring_with_preflight()

    @property
    def preflight_enabled(self) -> bool:
        """Whether *Start Monitoring* runs the preflight checklist first."""
        return self._preflight_enabled

    @preflight_enabled.setter
    def preflight_enabled(self, value: bool) -> None:
        self._preflight_enabled = value

    @property
    def preflight_dialog(self) -> PreflightDialog | None:
        """The last preflight dialog that was executed, or ``None``."""
        return self._preflight_dialog

    def start_monitoring_with_preflight(self) -> bool:
        """Run the *System Diagnostics* checklist, then start monitoring.

        The dialog is modal and self-closing: once every check resolves and
        the settle delay elapses it closes itself and the engine starts. An
        early cancel (Esc/Cancel) leaves monitoring untouched.
        """
        if not self._preflight_enabled:
            return self.start_monitoring()

        dialog = PreflightDialog(self)
        self._preflight_dialog = dialog
        dialog.exec()
        if not dialog.is_completed():
            self.statusBar().showMessage(
                "Preflight cancelled \u2014 monitoring was not started."
            )
            self._preflight_dialog = None
            return False
        self._preflight_dialog = None
        return self.start_monitoring()

    def start_monitoring(self) -> bool:
        """Start the runtime and begin the single bounded poll timer."""
        started = self._controller.start()
        if started:
            self._timer.start()
        self._update_monitoring_ui()
        self._refresh_current_page_live()
        return started

    def stop_monitoring(self) -> None:
        """Stop the poll timer and the runtime."""
        self._timer.stop()
        self._controller.stop()
        self._update_monitoring_ui()
        self._refresh_current_page_live()

    def _on_tick(self) -> None:
        """One bounded cycle: poll the runtime, then refresh the visible page."""
        self._controller.poll()
        self._update_monitoring_ui()
        self._refresh_current_page_live()

    def _update_monitoring_ui(self) -> None:
        status = self._controller.status()
        self._monitor_button.setText(
            "Stop Monitoring" if status.running else "Start Monitoring"
        )
        self._header_status.setText(_header_status_text(status))
        if not status.running:
            set_state(self._header_status, "stopped")
        elif status.capture_state == CAPTURE_ERROR:
            set_state(self._header_status, "error")
        else:
            set_state(self._header_status, "running")
        if status.start_error:
            self.statusBar().showMessage(f"Monitoring error: {status.start_error}")
        elif status.running:
            self.statusBar().showMessage(_header_status_text(status))
        else:
            self.statusBar().showMessage(STATUS_MESSAGE)

    def _refresh_current_page_live(self) -> None:
        page = self._stack.currentWidget()
        refresh_live = getattr(page, "refresh_live", None)
        if callable(refresh_live):
            refresh_live()

        is_live_gui = (
            self._controller.is_running
            and getattr(self._controller, "_runtime_factory", None) is None
        )
        has_sim = False
        if not is_live_gui:
            try:
                from aegis_desktop.threat_sim import simulated_findings, simulated_incidents

                has_sim = bool(simulated_incidents() or simulated_findings())
            except Exception:
                has_sim = False

        if is_live_gui or has_sim:
            refresh_one = getattr(page, "refresh", None)
            if callable(refresh_one) and (
                not callable(refresh_live) or getattr(page, "snapshot", None) is None
            ):
                refresh_one()

    # -- Navigation --------------------------------------------------------

    def _on_navigation(self, row: int) -> None:
        self._stack.setCurrentIndex(row)
        self._refresh_current_page_live()

    def navigate_to(self, key: str, **kwargs: object) -> None:
        """Select the page registered for ``key`` with optional context.

        After switching to the page, calls ``handle_navigate(**kwargs)`` on it
        so it can react to navigation parameters such as ``select_id``.

        Raises:
            KeyError: if ``key`` is unknown.
        """
        self._sidebar.navigate_to(key)
        if kwargs:
            page = self._pages.get(key)
            if page is not None:
                page.handle_navigate(**kwargs)

    @property
    def current_page_key(self) -> str:
        """The navigation key of the visible page."""
        return self._sidebar.current_key

    @property
    def current_page(self) -> QWidget | None:
        """The currently visible page widget."""
        return self._stack.currentWidget()

    def page(self, key: str) -> BasePage:
        """Return the page instance registered for ``key``."""
        return self._pages[key]

    def page_keys(self) -> tuple[str, ...]:
        """Return every page key in navigation order."""
        return tuple(self._pages)

    # -- Toast notifications -----------------------------------------------

    def show_toast(
        self,
        title: str,
        message: str = "",
        level: ToastLevel = "info",
        duration_ms: int = 5000,
    ) -> None:
        """Show a floating toast notification overlay.

        Args:
            title:       Short heading line.
            message:     Optional detail text.
            level:       ``info`` | ``success`` | ``warning`` | ``error`` | ``critical``
            duration_ms: Auto-dismiss delay in ms (0 = keep until closed).
        """
        self._toast_manager.show_toast(title, message, level, duration_ms)

    # -- Header helpers ----------------------------------------------------

    def _update_clock(self) -> None:
        """Refresh the UTC clock label in the header."""
        if hasattr(self, "_clock_lbl"):
            now = datetime.now(UTC)
            self._clock_lbl.setText(now.strftime("UTC  %Y-%m-%d    %H:%M:%S"))

    def _on_bell_clicked(self) -> None:
        """Demo: fire a sample warning toast when the bell is pressed."""
        self.show_toast(
            "Anomaly Detected",
            "Unusual process activity on host-01 · Risk score: 78",
            "warning",
        )

    def _on_audio_btn_clicked(self) -> None:
        """Toggle mute/unmute for attack alert audio, or silence active alarm."""
        audio = get_audio_alert_service()
        if audio.is_playing:
            audio.stop_alarm()
            self.show_toast(
                "Audio Alert Silenced",
                "Attack alarm tone stopped by operator.",
                "info",
                3000,
            )
            return

        is_now_muted = audio.toggle_mute()
        if is_now_muted:
            self._audio_btn.setText("🔇")
            self._audio_btn.setStyleSheet("""
                QPushButton {
                    background: transparent; border: none;
                    color: #EF4444; font-size: 16px;
                    border-radius: 6px;
                }
            """)
            self.show_toast(
                "Alert Audio Muted",
                "Attack audio alarm tones are currently disabled.",
                "warning",
                3000,
            )
        else:
            self._audio_btn.setText("🔊")
            self._audio_btn.setStyleSheet("""
                QPushButton {
                    background: transparent; border: none;
                    color: #64748B; font-size: 16px;
                    border-radius: 6px;
                }
                QPushButton:hover {
                    background: #111827; color: #EF4444;
                }
            """)
            self.show_toast(
                "Alert Audio Enabled",
                "Attack audio alerts will play for 10-20s on threats.",
                "success",
                3000,
            )

    def _on_alarm_started(self, sound_name: str) -> None:
        """Show the active red attack banner across the top header."""
        if hasattr(self, "_alarm_banner"):
            self._alarm_banner.setVisible(True)

    def _on_alarm_stopped(self) -> None:
        """Hide the red attack banner when the alarm stops."""
        if hasattr(self, "_alarm_banner"):
            self._alarm_banner.setVisible(False)

    def _silence_alarm_banner(self) -> None:
        """Operator clicked the banner acknowledge/silence button."""
        get_audio_alert_service().stop_alarm()
        self._on_alarm_stopped()
        self.show_toast("Alarm Silenced", "Attack acknowledged by operator.", "info", 3000)

    def _setup_shortcuts(self) -> None:
        """Register global keyboard shortcuts for rapid SOC triage and navigation."""
        for idx, item in enumerate(NAV_ITEMS[:9]):
            sc = QShortcut(QKeySequence(f"Ctrl+{idx + 1}"), self)
            sc.activated.connect(lambda k=item.key: self.navigate_to(k))

        sc_set = QShortcut(QKeySequence("Ctrl+0"), self)
        sc_set.activated.connect(lambda: self.navigate_to("settings"))

        sc_m = QShortcut(QKeySequence("Ctrl+M"), self)
        sc_m.activated.connect(self.toggle_monitoring)

        sc_r = QShortcut(QKeySequence("Ctrl+R"), self)
        sc_r.activated.connect(self._refresh_current_page_live)
        sc_f5 = QShortcut(QKeySequence(Qt.Key.Key_F5), self)
        sc_f5.activated.connect(self._refresh_current_page_live)

        sc_t = QShortcut(QKeySequence("Ctrl+T"), self)
        sc_t.activated.connect(self._trigger_threat_simulation)

        sc_h = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        sc_h.activated.connect(self.open_system_hygiene)

    def _trigger_threat_simulation(self) -> None:
        dash = self._pages.get("dashboard")
        if isinstance(dash, DashboardPage):
            self.navigate_to("dashboard")
            dash.open_threat_simulation()

    def open_system_hygiene(self) -> None:
        """Open the System Hygiene & Storage Optimization dialog."""
        from aegis_desktop.hygiene_dialog import SystemHygieneDialog

        dialog = SystemHygieneDialog(self)
        dialog.exec()

    # -- Lifecycle ---------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Stop monitoring cleanly when the window closes."""
        self._clock_timer.stop()
        self._timer.stop()
        self._controller.stop()
        set_active_monitoring_controller(None)
        super().closeEvent(event)


def _header_status_text(status: MonitoringStatus) -> str:
    if not status.running:
        return "Monitoring: disabled"
    if status.capture_state == CAPTURE_ACTIVE:
        capture = "ACTIVE"
    elif status.capture_state == CAPTURE_ERROR:
        capture = "ERROR"
    else:
        capture = "INACTIVE"
    return f"Monitoring: RUNNING | Capture: {capture}"


__all__ = ["STATUS_MESSAGE", "MainWindow"]
