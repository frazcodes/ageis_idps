"""The Aegis IDPS main window: header, sidebar, page stack and status bar.

The window owns the single :class:`~aegis_runtime.AegisRuntime` through a
:class:`~aegis_desktop.services.monitoring.MonitoringController`. The Start/Stop
control and one Qt timer drive that runtime; no second runtime loop exists.
Opening the window starts nothing. Pressing *Start Monitoring* first runs the
read-only :class:`~aegis_desktop.preflight.PreflightDialog` checklist; the
engine starts only after that checklist completes.
"""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
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
from aegis_desktop.pages import BasePage, create_page
from aegis_desktop.preflight import PreflightDialog, preflight_enabled_from_env
from aegis_desktop.services.monitoring import (
    CAPTURE_ACTIVE,
    CAPTURE_ERROR,
    MonitoringController,
    MonitoringStatus,
    set_active_monitoring_controller,
)
from aegis_desktop.theme import set_state

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
        self.resize(1200, 780)

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
        if dashboard is not None and hasattr(dashboard, "set_main_window"):
            dashboard.set_main_window(self)

        self._timer = QTimer(self)
        self._timer.setInterval(self._controller.poll_interval_ms)
        self._timer.timeout.connect(self._on_tick)

        self._build_layout()
        self._sidebar.currentRowChanged.connect(self._on_navigation)

        status_bar = QStatusBar()
        status_bar.showMessage(STATUS_MESSAGE)
        self.setStatusBar(status_bar)

        self._update_monitoring_ui()
        self._sidebar.navigate_to("dashboard")

    # -- Layout ------------------------------------------------------------

    def _build_header(self) -> QWidget:
        header = QFrame()
        header.setObjectName("Header")
        header.setFixedHeight(64)

        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(12)

        titles = QVBoxLayout()
        titles.setSpacing(0)
        app_title = QLabel("Aegis IDPS")
        app_title.setObjectName("AppTitle")
        subtitle = QLabel("Hybrid Host & Network IDPS · Desktop Console")
        subtitle.setObjectName("HeaderSubtitle")
        titles.addWidget(app_title)
        titles.addWidget(subtitle)

        self._header_status = QLabel("Monitoring: disabled")
        self._header_status.setObjectName("HeaderStatus")

        self._monitor_button = QPushButton("Start Monitoring")
        self._monitor_button.setObjectName("PrimaryButton")
        self._monitor_button.clicked.connect(self.toggle_monitoring)

        layout.addLayout(titles)
        layout.addStretch(1)
        layout.addWidget(self._header_status)
        layout.addWidget(self._monitor_button)
        return header

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
        self._preflight_enabled = bool(value)

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
        refresh = getattr(page, "refresh_live", None)
        if callable(refresh):
            refresh()

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

    # -- Lifecycle ---------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Stop monitoring cleanly when the window closes."""
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
