"""Settings page: read-only configuration and security posture inspection.

The page is presentation only. It reads the real configuration objects through
:mod:`aegis_desktop.services.settings` and renders selected, safe fields as
label/value rows.

It offers no editable controls and no response actions: every value is a
read-only label. It never starts a monitor, capture, detection, risk evaluation,
ML or response, and never writes configuration.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.settings import (
    SETTINGS_ERROR,
    ConfigField,
    ConfigSection,
    SettingsView,
    collect_settings_view,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_INITIAL_HINT = (
    "Select Refresh to read the current configuration and security posture. Values are read-only."
)


class SettingsPage(BasePage):
    """Read-only configuration and security posture page."""

    PAGE_KEY = "settings"
    TITLE = "Settings"
    SUBTITLE = "Read-only configuration and security posture of the Aegis components."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], SettingsView] | None = None,
    ) -> None:
        self._provider: Callable[[], SettingsView] = provider or collect_settings_view
        self._snapshot: SettingsView | None = None
        self._error_active = False
        self._section_rows: dict[str, QFormLayout] = {}

        super().__init__(parent)
        # No automatic read: opening the page (and the app) must not start or
        # evaluate any security component.
        self._show_initial_state()

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

        self._hint_label = QLabel(_INITIAL_HINT)
        self._hint_label.setObjectName("EmptyState")
        self._hint_label.setWordWrap(True)
        layout.addWidget(self._hint_label)

        # Security posture section (populated on refresh).
        posture_card, posture_form = self._make_card("Security Posture")
        self._posture_form = posture_form
        self._posture_card = posture_card
        layout.addWidget(posture_card)

        # Configuration sections container (cards added on refresh).
        self._sections_container = QWidget()
        self._sections_layout = QVBoxLayout(self._sections_container)
        self._sections_layout.setContentsMargins(0, 0, 0, 0)
        self._sections_layout.setSpacing(14)
        layout.addWidget(self._sections_container)

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

        self._last_updated_label = QLabel("Last updated: —")
        self._last_updated_label.setObjectName("CardHint")

        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._last_updated_label)
        toolbar.addStretch(1)
        return toolbar

    @staticmethod
    def _make_card(title: str) -> tuple[QFrame, QFormLayout]:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(18, 16, 18, 16)
        outer.setSpacing(10)

        heading = QLabel(title.upper())
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        form = QFormLayout()
        form.setHorizontalSpacing(24)
        form.setVerticalSpacing(6)
        outer.addLayout(form)
        return card, form

    @staticmethod
    def _add_row(form: QFormLayout, field: ConfigField) -> None:
        key_label = QLabel(field.label)
        key_label.setObjectName("FieldKey")
        value_label = QLabel(field.value)
        value_label.setObjectName("FieldValue")
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(key_label, value_label)

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> SettingsView | None:
        """Re-read the existing configuration and runtime state.

        Never starts/stops a component, never enables/disables anything and
        never writes configuration. On failure a safe error state is shown.
        """
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Settings refresh failed: %s", exc)
            self._show_error(SETTINGS_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: SettingsView) -> None:
        self._snapshot = view
        self._clear_sections()

        if not view.available:
            self._hint_label.setVisible(False)
            self._posture_card.setVisible(False)
            self._last_updated_label.setText("Last updated: —")
            self._set_error(view.error or SETTINGS_ERROR)
            return

        self._set_error(None)
        self._hint_label.setVisible(False)
        self._posture_card.setVisible(True)

        for field in view.posture:
            self._add_row(self._posture_form, field)

        for section in view.sections:
            self._add_section(section)

        self._last_updated_label.setText(
            f"Last updated: {format_timestamp(view.collected_at)}"
            if view.collected_at is not None
            else "Last updated: —"
        )

    def _add_section(self, section: ConfigSection) -> None:
        card, form = self._make_card(section.title)
        for field in section.fields:
            self._add_row(form, field)
        self._sections_layout.addWidget(card)
        self._section_rows[section.title] = form

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._clear_sections()
        self._posture_card.setVisible(False)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setText(_INITIAL_HINT)
        self._hint_label.setVisible(True)
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._clear_sections()
        self._posture_card.setVisible(False)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(False)
        self._set_error(message)

    def _clear_sections(self) -> None:
        while self._posture_form.rowCount():
            self._posture_form.removeRow(0)
        while self._sections_layout.count():
            item = self._sections_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        self._section_rows.clear()

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> SettingsView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    def section_titles(self) -> tuple[str, ...]:
        """Return the titles of the configuration sections currently shown."""
        return tuple(self._section_rows)

    def value_for(self, section: str, label: str) -> str | None:
        """Return the displayed value for ``label`` within ``section``."""
        return self._snapshot.value_for(section, label) if self._snapshot is not None else None

    def posture_value(self, label: str) -> str | None:
        """Return the displayed value for a security-posture ``label``."""
        return self._snapshot.posture_value(label) if self._snapshot is not None else None

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()


__all__ = ["SettingsPage"]
