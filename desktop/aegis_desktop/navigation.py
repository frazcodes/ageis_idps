"""Sidebar navigation definition and widget.

The navigation entries are the single source of truth for the pages the console
exposes. Icons are standard Qt style icons, so no image assets are bundled.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QListWidget, QListWidgetItem, QStyle, QWidget


@dataclass(frozen=True)
class NavItem:
    """One sidebar destination."""

    key: str
    title: str


NAV_ITEMS: tuple[NavItem, ...] = (
    NavItem("dashboard", "Dashboard"),
    NavItem("assets", "Assets"),
    NavItem("processes", "Processes"),
    NavItem("network", "Network"),
    NavItem("files", "File Integrity"),
    NavItem("events", "Events"),
    NavItem("detections", "Detections"),
    NavItem("incidents", "Incidents"),
    NavItem("response", "Response Center"),
    NavItem("risk", "Risk"),
    NavItem("settings", "Settings"),
)

_ICON_BY_KEY: dict[str, QStyle.StandardPixmap] = {
    "dashboard": QStyle.StandardPixmap.SP_ComputerIcon,
    "assets": QStyle.StandardPixmap.SP_DriveHDIcon,
    "processes": QStyle.StandardPixmap.SP_FileDialogListView,
    "network": QStyle.StandardPixmap.SP_DriveNetIcon,
    "files": QStyle.StandardPixmap.SP_FileIcon,
    "events": QStyle.StandardPixmap.SP_FileDialogDetailedView,
    "detections": QStyle.StandardPixmap.SP_MessageBoxWarning,
    "incidents": QStyle.StandardPixmap.SP_MessageBoxCritical,
    "response": QStyle.StandardPixmap.SP_DialogApplyButton,
    "risk": QStyle.StandardPixmap.SP_MessageBoxCritical,
    "settings": QStyle.StandardPixmap.SP_FileDialogContentsView,
}


class Sidebar(QListWidget):
    """Left navigation list with one row per :data:`NAV_ITEMS` entry."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(220)

        for item in NAV_ITEMS:
            entry = QListWidgetItem(item.title)
            icon = _ICON_BY_KEY.get(item.key)
            if icon is not None:
                entry.setIcon(self.style().standardIcon(icon))
            self.addItem(entry)

        self.setCurrentRow(0)

    def keys(self) -> tuple[str, ...]:
        """Return every navigation key in display order."""
        return tuple(item.key for item in NAV_ITEMS)

    def navigate_to(self, key: str) -> None:
        """Select the navigation entry for ``key``.

        Raises:
            KeyError: if ``key`` is not a known navigation entry.
        """
        for row, item in enumerate(NAV_ITEMS):
            if item.key == key:
                self.setCurrentRow(row)
                return
        raise KeyError(f"unknown navigation key: {key!r}")

    @property
    def current_key(self) -> str:
        """The key of the currently selected entry."""
        return NAV_ITEMS[self.currentRow()].key


__all__ = ["NAV_ITEMS", "NavItem", "Sidebar"]
