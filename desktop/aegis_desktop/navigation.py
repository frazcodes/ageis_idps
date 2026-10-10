"""Sidebar navigation definition and widget.

Replaces the generic Qt built-in icons with custom-painted QPixmap icons:
each nav item gets a unique Unicode glyph on a semi-transparent
colour-coded rounded background — no image assets required.

Public API is unchanged so window.py requires no modifications.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QWidget


@dataclass(frozen=True)
class NavItem:
    """One sidebar destination."""

    key: str
    title: str


NAV_ITEMS: tuple[NavItem, ...] = (
    NavItem("dashboard",  "Dashboard"),
    NavItem("assets",     "Assets"),
    NavItem("processes",  "Processes"),
    NavItem("network",    "Network"),
    NavItem("files",      "File Integrity"),
    NavItem("events",     "Events"),
    NavItem("detections", "Detections"),
    NavItem("incidents",  "Incidents"),
    NavItem("response",   "Response Center"),
    NavItem("risk",       "Risk"),
    NavItem("settings",   "Settings"),
)

# Each nav key maps to (Unicode glyph, hex accent colour).
# Colors are chosen so every section has a distinct visual identity.
_ICON_MAP: dict[str, tuple[str, str]] = {
    "dashboard":  ("◈", "#EF4444"),   # crimson - SOC HQ overview
    "assets":     ("⬡", "#10B981"),   # emerald - hosts / devices
    "processes":  ("≡", "#8B5CF6"),   # violet  - running processes
    "network":    ("◎", "#10B981"),   # emerald - network flows
    "files":      ("▤", "#F59E0B"),   # amber   - file integrity
    "events":     ("◆", "#E2E8F0"),   # silver  - raw events log
    "detections": ("⚠", "#F97316"),   # orange  - anomaly findings
    "incidents":  ("⊗", "#EF4444"),   # red     - active incidents
    "response":   ("⚡", "#10B981"),   # green   - IPS response center
    "risk":       ("▲", "#EC4899"),   # pink    - risk scoring
    "settings":   ("⚙", "#94A3B8"),   # muted   - configuration
}

_ICON_SIZE = 22   # px — icon pixmap square


def _make_icon(glyph: str, color_hex: str, size: int = _ICON_SIZE) -> QIcon:
    """Paint *glyph* on a semi-transparent rounded background of *color_hex*.

    Returns a ``QIcon`` suitable for ``QListWidgetItem``.  No image files
    are needed — everything is rendered at runtime via ``QPainter``.
    """
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)

    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Soft coloured background
    bg = QColor(color_hex)
    bg.setAlpha(38)
    p.setBrush(QBrush(bg))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(0, 0, size, size, 5, 5)

    # Glyph
    font = QFont("Segoe UI", max(8, int(size * 0.52)), QFont.Weight.Bold)
    p.setFont(font)
    p.setPen(QPen(QColor(color_hex)))
    p.drawText(QRect(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, glyph)

    p.end()
    return QIcon(px)


class Sidebar(QListWidget):
    """Left navigation list with unique color-coded icons per section.

    Maintains the same interface as the original so ``window.py`` is
    unaffected:
    - ``setCurrentRow(row)``
    - ``currentRowChanged`` signal
    - ``navigate_to(key)``
    - ``current_key`` property
    - ``keys()``
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(220)
        self.setIconSize(QSize(_ICON_SIZE, _ICON_SIZE))

        for item in NAV_ITEMS:
            glyph, color = _ICON_MAP.get(item.key, ("○", "#94A3B8"))
            icon = _make_icon(glyph, color)
            entry = QListWidgetItem(icon, f"  {item.title}")
            entry.setSizeHint(QSize(200, 42))   # taller rows look more premium
            self.addItem(entry)

        self.setCurrentRow(0)

    def keys(self) -> tuple[str, ...]:
        """Return every navigation key in display order."""
        return tuple(item.key for item in NAV_ITEMS)

    def navigate_to(self, key: str) -> None:
        """Select the navigation entry for *key*.

        Raises:
            KeyError: if *key* is not a known navigation entry.
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
