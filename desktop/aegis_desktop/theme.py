"""Professional dark enterprise SOC theme for the Aegis desktop console.

Pure presentation: a Qt Fusion palette plus one centralized stylesheet. No images,
web fonts or external assets are used - standard Qt icons are used for navigation.

The design system is defined once here and referenced by object name from the
widgets (``#Sidebar``, ``#Header``, ``#Card``, ``#PageTitle`` ...). Pages hold no
stylesheet strings of their own, so the whole console can be re-themed in one
place. Status/severity emphasis is driven by a dynamic ``state`` property
(see :func:`set_state`) so label text never changes.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QWidget

# --- Dark SOC design tokens ------------------------------------------------
BACKGROUND = "#06090F"  # app canvas: obsidian carbon black
SIDEBAR = "#03060B"     # navigation: deep pure jet black
PANEL = "#0B101B"       # primary panels, cards, tables
SURFACE_ALT = "#101624" # secondary surface / alternating rows
ELEVATED = "#172032"    # elevated surface (buttons, menus)
BORDER = "#243044"      # crisp dark slate borders
BORDER_STRONG = "#2B3648"  # stronger borders
TEXT = "#FFFFFF"        # pure crisp white primary text
TEXT_SECONDARY = "#E2E8F0"  # secondary text: bright silver
TEXT_MUTED = "#94A3B8"  # muted labels
TEXT_DISABLED = "#64748B"  # disabled text
ACCENT = "#EF4444"      # primary accent: vivid defense red
ACCENT_HOVER = "#F87171"  # accent hover
ACCENT_PRESSED = "#DC2626"  # accent pressed
ACCENT_SOFT = "rgba(239, 68, 68, 0.16)"  # soft crimson glow
OK = "#10B981"          # success / healthy / active: emerald green
WARN = "#F59E0B"        # warning / medium: amber
HIGH = "#FB923C"        # high severity: orange
CRITICAL = "#EF4444"    # critical / error: crimson red
INFO = "#E2E8F0"        # informational: clean silver white
ROW_HOVER = "#121926"   # subtle slate row hover (no blue)
ROW_LINE = "#161E2D"    # subtle horizontal row separation

#: Object names that receive a dynamic ``state`` property. ID-scoped selectors
#: are required because a bare ``QLabel[state=...]`` is out-specified by ``#Card``
#: style ID rules in Qt Style Sheets.
_STATE_TARGETS = ("QLabel", "#FieldValue", "#CardHint", "#CardValue", "#HeaderStatus")

#: state -> (color token, font-weight)
_STATE_STYLES: dict[str, tuple[str, int]] = {
    "running": (OK, 700),
    "active": (OK, 700),
    "open": (OK, 700),
    "healthy": (OK, 700),
    "stopped": (TEXT_MUTED, 400),
    "inactive": (TEXT_MUTED, 400),
    "error": (CRITICAL, 700),
    "critical": (CRITICAL, 700),
    "high": (HIGH, 700),
    "warning": (WARN, 700),
    "medium": (WARN, 700),
    "low": (INFO, 600),
    "info": (INFO, 400),
    "informational": (INFO, 400),
}


def _build_state_css() -> str:
    rules: list[str] = []
    for state, (color, weight) in _STATE_STYLES.items():
        selectors = ", ".join(f'{target}[state="{state}"]' for target in _STATE_TARGETS)
        rules.append(f"{selectors} {{ color: {color}; font-weight: {weight}; }}")
    return "\n".join(rules)


_STATE_CSS = _build_state_css()

STYLESHEET = f"""
* {{ outline: 0; }}
QWidget {{
    background-color: {BACKGROUND};
    color: {TEXT};
    font-family: "Segoe UI", "Inter", "Roboto", "Arial", sans-serif;
    font-size: 13px;
}}
QMainWindow, QDialog {{ background-color: {BACKGROUND}; }}

QToolTip {{
    background-color: {ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER_STRONG};
    padding: 4px 6px;
}}

/* --- Sidebar ---------------------------------------------------------- */
#SidebarColumn {{ background-color: {SIDEBAR}; }}
#Sidebar {{
    background-color: {SIDEBAR};
    border: none;
    border-right: 1px solid {BORDER};
    outline: 0;
    padding: 8px 8px;
}}
#Sidebar::item {{
    padding: 9px 12px;
    margin: 1px 4px;
    border-radius: 6px;
    border-left: 3px solid transparent;
    color: {TEXT_MUTED};
}}
#Sidebar::item:hover {{
    background-color: rgba(255, 255, 255, 0.05);
    color: #FFFFFF;
    border-left: 3px solid rgba(239, 68, 68, 0.5);
}}
#Sidebar::item:selected {{
    background-color: {ACCENT_SOFT};
    color: #FFFFFF;
    font-weight: 700;
    border-left: 3px solid {ACCENT};
}}

#SidebarBrand {{
    background-color: {SIDEBAR};
    border-bottom: 1px solid {BORDER};
}}
#SidebarBrandTitle {{
    font-size: 16px;
    font-weight: 800;
    color: {TEXT};
    letter-spacing: 2px;
}}
#SidebarBrandSubtitle {{
    color: {TEXT_MUTED};
    font-size: 11px;
    letter-spacing: 1px;
}}

/* --- Header ----------------------------------------------------------- */
#Header {{
    background-color: {PANEL};
    border-bottom: 1px solid {BORDER};
}}
#AppTitle {{ font-size: 17px; font-weight: 700; color: {TEXT}; }}
#HeaderSubtitle {{ color: {TEXT_MUTED}; font-size: 12px; }}
#HeaderStatus {{ color: {TEXT_MUTED}; font-size: 12px; font-weight: 700; }}
#HeaderStatus[state="running"] {{ color: {OK}; }}
#HeaderStatus[state="stopped"] {{ color: {TEXT_MUTED}; }}
#HeaderStatus[state="error"] {{ color: {CRITICAL}; }}

/* --- Page chrome ------------------------------------------------------ */
#PageTitle {{ font-size: 22px; font-weight: 700; color: {TEXT}; }}
#PageSubtitle {{ color: {TEXT_MUTED}; font-size: 13px; }}
#EmptyState {{
    color: {TEXT_MUTED};
    background-color: {SURFACE_ALT};
    border: 1px dashed {BORDER_STRONG};
    border-radius: 8px;
    padding: 16px 18px;
}}

/* --- Cards & fields --------------------------------------------------- */
#Card {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
#CardTitle {{
    color: {TEXT_MUTED};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
}}
#CardValue {{ font-size: 28px; font-weight: 700; color: {TEXT}; }}
#CardHint {{ color: {TEXT_MUTED}; font-size: 12px; }}
#FieldKey {{ color: {TEXT_MUTED}; font-size: 12px; }}
#FieldValue {{ color: {TEXT_SECONDARY}; font-size: 13px; font-weight: 600; }}

/* --- Status / severity emphasis (dynamic ``state`` property) ---------- */
{_STATE_CSS}

/* --- Buttons ---------------------------------------------------------- */
QPushButton {{
    background-color: {ELEVATED};
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER_STRONG};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: #2C3B52; color: {TEXT}; }}
QPushButton:pressed {{ background-color: #1F2B3E; }}
QPushButton:disabled {{
    background-color: {SURFACE_ALT};
    color: {TEXT_DISABLED};
    border-color: {BORDER};
}}
#PrimaryButton {{
    background-color: {ACCENT};
    color: #FFFFFF;
    border: 1px solid {ACCENT};
    border-radius: 6px;
    padding: 6px 16px;
    font-weight: 700;
}}
#PrimaryButton:hover {{ background-color: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
#PrimaryButton:pressed {{ background-color: {ACCENT_PRESSED}; border-color: {ACCENT_PRESSED}; }}
#PrimaryButton:disabled {{
    background-color: {SURFACE_ALT};
    color: {TEXT_DISABLED};
    border-color: {BORDER};
}}

/* --- Banners ---------------------------------------------------------- */
#ErrorBanner {{
    color: #FECACA;
    background-color: #3B1D1D;
    border: 1px solid #7F1D1D;
    border-radius: 8px;
    padding: 10px 14px;
}}

/* --- Status bar ------------------------------------------------------- */
QStatusBar {{
    background-color: {SIDEBAR};
    border-top: 1px solid {BORDER};
    color: {TEXT_MUTED};
}}
QStatusBar::item {{ border: none; }}

/* --- Tables ----------------------------------------------------------- */
QTableView, QTableWidget {{
    background-color: {PANEL};
    alternate-background-color: {SURFACE_ALT};
    gridline-color: transparent;
    border: 1px solid {BORDER};
    border-radius: 8px;
    selection-background-color: {ACCENT_PRESSED};
    selection-color: #FFFFFF;
    outline: 0;
}}
QTableView::item, QTableWidget::item {{
    padding: 5px 8px;
    border-bottom: 1px solid {ROW_LINE};
}}
QTableView::item:hover, QTableWidget::item:hover {{ background-color: {ROW_HOVER}; }}
QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {ACCENT_PRESSED};
    color: #FFFFFF;
}}
QHeaderView {{ background-color: {SIDEBAR}; border: none; }}
QHeaderView::section {{
    background-color: {SIDEBAR};
    color: {TEXT_MUTED};
    font-weight: 700;
    padding: 8px 8px;
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER_STRONG};
}}
QHeaderView::section:hover {{ background-color: {SURFACE_ALT}; color: {TEXT_SECONDARY}; }}
QTableCornerButton::section {{ background-color: {SIDEBAR}; border: none; }}

/* --- Scrollbars ------------------------------------------------------- */
QScrollBar:vertical, QScrollBar:horizontal {{
    background: transparent;
    border: none;
    margin: 0;
}}
QScrollBar:vertical {{ width: 12px; }}
QScrollBar:horizontal {{ height: 12px; }}
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background-color: {BORDER_STRONG};
    border-radius: 5px;
    min-height: 28px;
    min-width: 28px;
}}
QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
    background-color: #64748B;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

/* --- Inputs (styled for future editable settings) -------------------- */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background-color: {SURFACE_ALT};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 5px 8px;
    selection-background-color: {ACCENT};
    selection-color: #FFFFFF;
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {ACCENT};
}}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDoubleSpinBox:disabled {{ color: {TEXT_DISABLED}; }}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background-color: {ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER_STRONG};
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT};
}}
QCheckBox, QRadioButton {{ color: {TEXT_SECONDARY}; spacing: 6px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 14px;
    height: 14px;
    border: 1px solid {BORDER_STRONG};
    background-color: {SURFACE_ALT};
}}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QRadioButton::indicator {{ border-radius: 7px; }}

/* --- Tabs ------------------------------------------------------------- */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    top: -1px;
    background-color: {PANEL};
}}
QTabBar::tab {{
    background-color: transparent;
    color: {TEXT_MUTED};
    padding: 7px 16px;
    margin-right: 2px;
    border-bottom: 2px solid transparent;
    font-weight: 600;
}}
QTabBar::tab:hover {{ color: {TEXT_SECONDARY}; }}
QTabBar::tab:selected {{ color: {TEXT}; border-bottom: 2px solid {ACCENT}; }}

/* --- Splitter & scroll areas ----------------------------------------- */
QSplitter::handle {{ background-color: {BORDER}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}
QScrollArea {{ border: none; background-color: transparent; }}

/* --- Menus ------------------------------------------------------------ */
QMenuBar {{ background-color: {SIDEBAR}; color: {TEXT_SECONDARY}; }}
QMenuBar::item:selected {{ background-color: {SURFACE_ALT}; }}
QMenu {{
    background-color: {ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER_STRONG};
}}
QMenu::item:selected {{ background-color: {ACCENT_SOFT}; }}
"""


def set_state(widget: QWidget, state: str) -> None:
    """Set a dynamic ``state`` property and repolish so QSS reflects it.

    ``state`` is one of ``running``, ``stopped``, ``active``, ``inactive``,
    ``error``, ``open``, ``info``, ``low``, ``medium``, ``high`` or ``critical``.
    The widget's text is never changed.
    """
    if widget.property("state") == state:
        return
    widget.setProperty("state", state)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)


#: Foreground colours for severity / risk / status vocabulary (tables, badges).
_STATE_COLORS: dict[str, str] = {
    "running": OK,
    "active": OK,
    "open": OK,
    "healthy": OK,
    "stopped": TEXT_MUTED,
    "inactive": TEXT_MUTED,
    "error": CRITICAL,
    "critical": CRITICAL,
    "high": HIGH,
    "warning": WARN,
    "medium": WARN,
    "low": INFO,
    "info": INFO,
    "informational": INFO,
}


def state_color(value: str) -> QColor:
    """Return the semantic colour for a severity/risk/status ``value``."""
    return QColor(_STATE_COLORS.get((value or "").strip().lower(), TEXT_SECONDARY))


def apply_theme(app: QApplication) -> None:
    """Apply the Aegis dark SOC theme to ``app``."""
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(BACKGROUND))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Base, QColor(PANEL))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(SURFACE_ALT))
    palette.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(ELEVATED))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT_SECONDARY))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(ELEVATED))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT_PRESSED))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(TEXT_DISABLED))
    palette.setColor(QPalette.ColorRole.Link, QColor(ACCENT))
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(TEXT_DISABLED)
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(TEXT_DISABLED)
    )
    palette.setColor(
        QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(TEXT_DISABLED)
    )
    app.setPalette(palette)

    app.setStyleSheet(STYLESHEET)


#: Backwards-compatible alias for the previous entry point name.
apply_dark_theme = apply_theme


__all__ = ["apply_dark_theme", "apply_theme", "set_state", "state_color"]
