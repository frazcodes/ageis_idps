"""Preflight diagnostic checklist shown before monitoring starts.

Pressing *Start Monitoring* no longer flips the engine on immediately: a
frameless :class:`PreflightDialog` runs three read-only probes one by one
(driven by a :class:`~PySide6.QtCore.QTimer` so the console stays visibly
alive), waits a short settle delay, closes itself, and only then lets the
window call
:meth:`~aegis_desktop.services.monitoring.MonitoringController.start`.

Every probe only *reads* OS, driver and model state: nothing here starts a
monitor, opens a packet capture, trains a model or performs a response, and
no backend module is modified.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# --- Contract ---------------------------------------------------------------

#: Dialog headline.
TITLE = "System Diagnostics"
#: Dialog sub-headline.
SUBTITLE = "Validating environment health before the monitoring engine starts."

#: Simulated-async pacing: one probe every 400 ms, then a 1 s settle delay.
CHECK_INTERVAL_MS = 400
SETTLE_DELAY_MS = 1000

#: Environment kill-switch used by automated UI tests to bypass the gate.
PREFLIGHT_ENV_VAR = "AEGIS_PREFLIGHT_ENABLED"

#: Result states (mirrors the theme's ``state`` property vocabulary).
STATE_PENDING = "pending"
STATE_RUNNING = "running"
STATE_OK = "ok"
STATE_WARNING = "warning"
STATE_ERROR = "error"

#: Status cell texts.
PENDING_TEXT = "\u2014"
RUNNING_TEXT = "..."
OK_TEXT = "\U0001f7e2 OK"
ERROR_TEXT = "\U0001f534 ERROR"
RESTRICTED_DETAIL = "Running in Restricted Mode (Dry-Run Only)"

#: Footer copy for the running and finished phases.
RUNNING_FOOTER = "Running system diagnostics\u2026"
COMPLETE_FOOTER = "All checks complete \u2014 starting monitoring\u2026"

#: Stable identifiers/labels of the checklist.
DRIVER_KEY = "driver"
DRIVER_LABEL = "Network Driver (Npcap)"
ADMIN_KEY = "admin"
ADMIN_LABEL = "Administrator Privileges (Firewall)"
ML_KEY = "ml"
ML_LABEL = "ML Engine Readiness"

#: Right/vertical alignment used for the status cell of every check row.
_RIGHT_VCENTER = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter


@dataclass(frozen=True)
class DiagnosticResult:
    """Outcome of one read-only preflight probe."""

    key: str
    label: str
    state: str
    status: str
    detail: str


# --- Probes (read-only) -----------------------------------------------------


def _npcap_present() -> bool:
    """Best-effort, read-only check for the Npcap driver library."""
    if sys.platform != "win32":
        return True
    root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
    npcap_dir = os.path.join(root, "System32", "Npcap")
    return any(
        os.path.exists(os.path.join(npcap_dir, name))
        for name in ("wpcap.dll", "npcap.dll")
    )


def check_network_driver() -> DiagnosticResult:
    """Check that the packet capture stack (scapy + Npcap) is usable."""
    try:
        from aegis_network_sensor.config import SensorSettings

        settings = SensorSettings()
        interface = (settings.interface or "").strip() or "automatic interface"
        capture_enabled = bool(settings.capture_enabled)
    except Exception as exc:  # pragma: no cover - only with broken config
        return DiagnosticResult(
            DRIVER_KEY,
            DRIVER_LABEL,
            STATE_ERROR,
            ERROR_TEXT,
            f"Sensor configuration unavailable ({type(exc).__name__})",
        )

    try:
        import scapy  # noqa: F401 - import only: no sniff, no capture
    except Exception:
        return DiagnosticResult(
            DRIVER_KEY,
            DRIVER_LABEL,
            STATE_ERROR,
            ERROR_TEXT,
            "Scapy capture library is not installed (sensor extra missing)",
        )

    if not _npcap_present():
        return DiagnosticResult(
            DRIVER_KEY,
            DRIVER_LABEL,
            STATE_WARNING,
            "\U0001f7e1 WARNING: Npcap driver not found \u2014 capture disabled",
            "Install Npcap from https://npcap.com/#download to enable packet capture",
        )

    mode = "" if capture_enabled else "; capture disabled in settings"
    return DiagnosticResult(
        DRIVER_KEY,
        DRIVER_LABEL,
        STATE_OK,
        OK_TEXT,
        f"Capture stack ready \u2014 interface {interface}{mode}",
    )


def _is_admin() -> bool:
    """Whether the process runs with elevated privileges (read-only)."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # pragma: no cover - only if the shell API is absent
            return False
    try:
        return os.geteuid() == 0
    except Exception:  # pragma: no cover - platform without geteuid
        return False


def check_admin_privileges() -> DiagnosticResult:
    """Check for administrator privileges (firewall rule management)."""
    if _is_admin():
        return DiagnosticResult(
            ADMIN_KEY,
            ADMIN_LABEL,
            STATE_OK,
            OK_TEXT,
            "Administrator session \u2014 firewall rule changes permitted",
        )
    return DiagnosticResult(
        ADMIN_KEY,
        ADMIN_LABEL,
        STATE_WARNING,
        f"\U0001f7e1 WARNING: {RESTRICTED_DETAIL}",
        "Elevate the console to manage firewall rules; detection still runs",
    )


def _runtime_models() -> list[object]:
    """Models bound to the published runtime, if one exists (read-only)."""
    from aegis_desktop.services.monitoring import get_active_monitoring_controller

    controller = get_active_monitoring_controller()
    runtime = getattr(controller, "runtime", None) if controller is not None else None
    if runtime is None:
        return []
    found: list[object] = []
    for attr in ("network_anomaly_model", "host_anomaly_model"):
        model = getattr(runtime, attr, None)
        if model is not None:
            found.append(model)
    return found


def check_ml_engine() -> DiagnosticResult:
    """Check that the ML engine and its anomaly models are ready (read-only)."""
    models = _runtime_models()
    if models:
        fitted = all(bool(getattr(model, "is_fitted", False)) for model in models)
        if fitted:
            return DiagnosticResult(
                ML_KEY,
                ML_LABEL,
                STATE_OK,
                OK_TEXT,
                f"{len(models)} baseline model(s) loaded on the runtime",
            )
        return DiagnosticResult(
            ML_KEY,
            ML_LABEL,
            STATE_WARNING,
            "\U0001f7e1 WARNING: Models present but not fitted",
            "Baselines will be trained on first assessment",
        )

    try:
        import aegis_ml_engine.anomaly.host_model
        import aegis_ml_engine.anomaly.model  # noqa: F401
    except Exception as exc:
        return DiagnosticResult(
            ML_KEY,
            ML_LABEL,
            STATE_WARNING,
            f"\U0001f7e1 WARNING: ML engine unavailable ({type(exc).__name__})",
            "Anomaly scoring stays off until the ml-engine extra is installed",
        )
    return DiagnosticResult(
        ML_KEY,
        ML_LABEL,
        STATE_OK,
        OK_TEXT,
        "Isolation Forest engine ready \u2014 models load on first assessment",
    )


#: The checklist in display order: (key, label, probe).
CHECKS: tuple[tuple[str, str, Callable[[], DiagnosticResult]], ...] = (
    (DRIVER_KEY, DRIVER_LABEL, check_network_driver),
    (ADMIN_KEY, ADMIN_LABEL, check_admin_privileges),
    (ML_KEY, ML_LABEL, check_ml_engine),
)


def preflight_enabled_from_env() -> bool:
    """Whether the preflight gate is enabled (``AEGIS_PREFLIGHT_ENABLED``)."""
    raw = os.environ.get(PREFLIGHT_ENV_VAR, "")
    return raw.strip().lower() not in {"0", "false", "no", "off"}


# --- Dialog -----------------------------------------------------------------


class PreflightDialog(QDialog):
    """Frameless *System Diagnostics* checklist run before monitoring starts.

    ``start()`` paces one probe per ``interval_ms`` tick through a single-shot
    sequence, then waits ``settle_ms`` before closing itself. ``run_checks()``
    runs the same probes synchronously for callers (and tests) that do not
    want an event loop.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        interval_ms: int = CHECK_INTERVAL_MS,
        settle_ms: int = SETTLE_DELAY_MS,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("PreflightDialog")
        self.setWindowTitle(TITLE)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setFixedWidth(480)

        self._interval_ms = interval_ms
        self._settle_ms = settle_ms
        self._index = 0
        self._started = False
        self._completed = False

        self._status_labels: list[QLabel] = []
        self._detail_labels: list[QLabel] = []
        self._results: list[DiagnosticResult | None] = [None] * len(CHECKS)

        self._build()

        self._runner = QTimer(self)
        self._runner.setInterval(interval_ms)
        self._runner.timeout.connect(self._advance)

        self._settle = QTimer(self)
        self._settle.setSingleShot(True)
        self._settle.setInterval(settle_ms)
        self._settle.timeout.connect(self._finish)

    # -- Layout ------------------------------------------------------------

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 20)
        root.setSpacing(14)

        title = QLabel(TITLE)
        title.setObjectName("PreflightTitle")
        subtitle = QLabel(SUBTITLE)
        subtitle.setObjectName("PreflightSubtitle")
        subtitle.setWordWrap(True)
        root.addWidget(title)
        root.addWidget(subtitle)

        for _key, label, _runner in CHECKS:
            row = QFrame()
            row.setObjectName("PreflightCheck")
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(14, 10, 14, 10)
            row_layout.setSpacing(12)

            text = QVBoxLayout()
            text.setSpacing(2)
            name = QLabel(label)
            name.setObjectName("PreflightCheckName")
            detail = QLabel(PENDING_TEXT)
            detail.setObjectName("PreflightCheckHint")
            text.addWidget(name)
            text.addWidget(detail)

            status = QLabel(PENDING_TEXT)
            status.setObjectName("PreflightStatus")
            status.setProperty("state", STATE_PENDING)

            row_layout.addLayout(text, 1)
            row_layout.addWidget(status, 0, _RIGHT_VCENTER)
            root.addWidget(row)
            self._status_labels.append(status)
            self._detail_labels.append(detail)

        self._progress = QProgressBar(self)
        self._progress.setObjectName("PreflightProgress")
        self._progress.setTextVisible(False)
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(6)
        root.addWidget(self._progress)

        self._footer = QLabel(RUNNING_FOOTER)
        self._footer.setObjectName("PreflightFooter")
        root.addWidget(self._footer)

        self._cancel = QPushButton("Cancel")
        self._cancel.setObjectName("DangerButton")
        self._cancel.setFixedWidth(96)
        self._cancel.clicked.connect(self.reject)
        footer_row = QHBoxLayout()
        footer_row.setContentsMargins(0, 0, 0, 0)
        footer_row.addWidget(self._footer, 1)
        footer_row.addWidget(self._cancel, 0)
        root.addLayout(footer_row)

        self._progress.setVisible(False)

    # -- Introspection -----------------------------------------------------

    @property
    def interval_ms(self) -> int:
        """Milliseconds between two probe ticks."""
        return self._interval_ms

    @property
    def settle_ms(self) -> int:
        """Milliseconds to wait after the last probe before closing."""
        return self._settle_ms

    def checks(self) -> tuple[tuple[str, str], ...]:
        """The ``(key, label)`` pair of every check, in display order."""
        return tuple((key, label) for key, label, _runner in CHECKS)

    def status_texts(self) -> tuple[str, ...]:
        """Status cell text for every check, in display order."""
        return tuple(label.text() for label in self._status_labels)

    def status_states(self) -> tuple[str, ...]:
        """Dynamic ``state`` property for every check, in display order."""
        return tuple(str(label.property("state")) for label in self._status_labels)

    def detail_texts(self) -> tuple[str, ...]:
        """Hint text for every check, in display order."""
        return tuple(label.text() for label in self._detail_labels)

    def footer_text(self) -> str:
        """Current footer message."""
        return self._footer.text()

    def results(self) -> tuple[DiagnosticResult, ...]:
        """Every probe result captured so far (``None`` slots are skipped)."""
        return tuple(result for result in self._results if result is not None)

    def is_completed(self) -> bool:
        """Whether every check finished and the settle delay elapsed."""
        return self._completed

    # -- Sequencing --------------------------------------------------------

    def exec(self) -> int:
        """Run the modal loop, starting the probe sequence on the way in.

        The sequence is started here (not in ``__init__``) so probes only run
        while the dialog is actually shown, and so any caller that simply does
        ``PreflightDialog(...).exec()`` gets a dialog that advances, completes
        and closes instead of hanging on pending checks.
        """
        self.start()
        return super().exec()

    def start(self) -> None:
        """Begin the timed, one-probe-per-tick sequence (idempotent)."""
        if self._started:
            return
        self._started = True
        self._index = 0
        self._set_busy(True)
        self._mark_running(0)
        self._runner.start()

    def run_checks(self) -> tuple[DiagnosticResult, ...]:
        """Run every probe immediately (no timers) and return the results."""
        results = tuple(_safe_run(runner) for _key, _label, runner in CHECKS)
        for position, result in enumerate(results):
            self._apply(position, result)
        self._index = len(CHECKS)
        self._started = True
        return results

    def _advance(self) -> None:
        """One timer tick: resolve the current probe and move to the next."""
        if self._index >= len(CHECKS):
            self._complete()
            return
        _key, _label, runner = CHECKS[self._index]
        self._apply(self._index, _safe_run(runner))
        self._index += 1
        if self._index < len(CHECKS):
            self._mark_running(self._index)
        else:
            self._complete()

    def _apply(self, position: int, result: DiagnosticResult) -> None:
        self._results[position] = result
        status = self._status_labels[position]
        status.setText(result.status)
        status.setProperty("state", result.state)
        _repaint(status)
        self._detail_labels[position].setText(result.detail)

    def _mark_running(self, position: int) -> None:
        status = self._status_labels[position]
        status.setText(RUNNING_TEXT)
        status.setProperty("state", STATE_RUNNING)
        _repaint(status)
        self._detail_labels[position].setText("Checking" + "\u2026")

    def _set_busy(self, busy: bool) -> None:
        self._progress.setVisible(busy)
        self._footer.setText(RUNNING_FOOTER if busy else COMPLETE_FOOTER)

    def _complete(self) -> None:
        """All probes resolved: stop ticking and start the settle delay."""
        self._runner.stop()
        self._set_busy(False)
        self._settle.start()

    def _finish(self) -> None:
        """Close the dialog after the settle delay (idempotent)."""
        if self._completed:
            return
        self._completed = True
        self.accept()


def _safe_run(runner: Callable[[], DiagnosticResult]) -> DiagnosticResult:
    """Run one probe, converting any failure into an honest error result."""
    try:
        return runner()
    except Exception as exc:  # pragma: no cover - probes already guard
        return DiagnosticResult(
            "unknown",
            "Unknown check",
            STATE_ERROR,
            ERROR_TEXT,
            f"Check failed ({type(exc).__name__})",
        )


def _repaint(widget: QWidget) -> None:
    """Re-evaluate QSS dynamic-property rules after a ``state`` change."""
    style = widget.style()
    if style is None:
        return
    style.unpolish(widget)
    style.polish(widget)


__all__ = [
    "ADMIN_LABEL",
    "CHECKS",
    "CHECK_INTERVAL_MS",
    "COMPLETE_FOOTER",
    "DRIVER_LABEL",
    "ML_LABEL",
    "OK_TEXT",
    "PREFLIGHT_ENV_VAR",
    "RESTRICTED_DETAIL",
    "RUNNING_FOOTER",
    "SETTLE_DELAY_MS",
    "TITLE",
    "DiagnosticResult",
    "PreflightDialog",
    "check_admin_privileges",
    "check_ml_engine",
    "check_network_driver",
    "preflight_enabled_from_env",
]
