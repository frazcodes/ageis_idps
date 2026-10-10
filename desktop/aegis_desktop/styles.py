"""Enterprise QSS Theme & Styling Manager for Aegis IDPS.

A centralized, modular stylesheet system for a million-dollar enterprise SOC platform.
Defines design tokens, global QSS, and visual helpers (shadows, badges, etc.).
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QWidget

# --- Enterprise Design Tokens ----------------------------------------------

# Backgrounds
BG_DEEP_NAVY = "#0A0F1C"          # Global app canvas
BG_SURFACE = "#111827"            # Card / panel background
BG_SURFACE_ALT = "#161E2E"        # Alternating rows, secondary surfaces
BG_ELEVATED = "#1E293B"           # Buttons, menus, dropdowns
BG_SIDEBAR = "#0C1320"            # Navigation sidebar

# Borders
BORDER_SUBTLE = "#1F2937"         # Card borders, subtle dividers
BORDER_MEDIUM = "#374151"         # Stronger borders, focus states
BORDER_STRONG = "#4B5563"         # Active/focused borders

# Typography
TEXT_PRIMARY = "#F8FAFC"          # Titles, primary text
TEXT_SECONDARY = "#CBD5E1"        # Body text
TEXT_MUTED = "#94A3B8"            # Labels, hints
TEXT_DISABLED = "#64748B"         # Disabled text

# Accents & Severity (Neon/Cyber palette)
ACCENT_PRIMARY = "#1D4ED8"        # Primary brand blue (sidebar active)
ACCENT_PRIMARY_HOVER = "#2563EB"
ACCENT_PRIMARY_PRESSED = "#1E40AF"
ACCENT_SOFT = "#172554"           # Soft blue surface

# Severity accents (Neon)
SEV_CRITICAL = "#EF4444"          # Neon Red
SEV_HIGH = "#FB923C"              # Neon Orange
SEV_MEDIUM = "#F59E0B"            # Neon Amber
SEV_LOW = "#10B981"               # Neon Green
SEV_INFO = "#38BDF8"              # Cyber Blue

# State colors
STATE_RUNNING = "#10B981"         # Green
STATE_STOPPED = "#94A3B8"         # Muted
STATE_WARNING = "#F59E0B"         # Amber
STATE_ERROR = "#EF4444"           # Red

# Table/Row states
ROW_HOVER = "#1A2A4A"             # Subtle blue-tinted hover
ROW_SELECTED = "#1E3A5F"          # Selected row
ROW_LINE = "#1E2A3E"              # Subtle horizontal divider

# Typography
FONT_FAMILY = '"Inter", "Segoe UI", "Roboto", "Arial", sans-serif'
FONT_SIZE_BASE = "13px"
FONT_SIZE_SM = "12px"
FONT_SIZE_XS = "11px"
FONT_SIZE_TITLE = "22px"
FONT_SIZE_SUBTITLE = "13px"
FONT_SIZE_LABEL = "11px"

# Spacing & Radius
RADIUS_SM = "4px"
RADIUS_MD = "6px"
RADIUS_LG = "8px"
RADIUS_XL = "12px"

# Shadows
SHADOW_BLUR = 15
SHADOW_OFFSET = 0
SHADOW_ALPHA = 60                 # 0-255
SHADOW_COLOR = QColor(0, 0, 0, SHADOW_ALPHA)


# --- QSS Stylesheet ---------------------------------------------------------

def _build_qss() -> str:
    """Build the complete enterprise QSS stylesheet."""
    return f"""
/* ========================================================================
   ENTERPRISE SOC PLATFORM - GLOBAL QSS
   ======================================================================== */

/* --- Reset & Global ----------------------------------------------------- */
* {{ outline: 0; }}

QWidget {{
    background-color: {BG_DEEP_NAVY};
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_BASE};
}}

QMainWindow, QDialog {{ background-color: {BG_DEEP_NAVY}; }}

/* --- Tooltips ----------------------------------------------------------- */
QToolTip {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_MEDIUM};
    border-radius: {RADIUS_MD};
    padding: 6px 10px;
    font-size: {FONT_SIZE_SM};
}}

/* --- Sidebar ------------------------------------------------------------ */
#SidebarColumn {{ background-color: {BG_SIDEBAR}; }}

#Sidebar {{
    background-color: {BG_SIDEBAR};
    border: none;
    border-right: 1px solid {BORDER_SUBTLE};
    outline: 0;
    padding: 10px 6px;
}}

#Sidebar::item {{
    padding: 9px 12px 9px 10px;
    margin: 1px 4px;
    border-radius: 8px;
    border-left: 3px solid transparent;
    color: {TEXT_MUTED};
    font-size: 12px;
    font-weight: 500;
    min-height: 32px;
}}

#Sidebar::item:hover {{
    background-color: rgba(30, 41, 59, 0.85);
    color: {TEXT_SECONDARY};
    border-left: 3px solid rgba(29, 78, 216, 0.4);
}}

#Sidebar::item:selected {{
    background-color: rgba(23, 37, 84, 0.80);
    color: {TEXT_PRIMARY};
    font-weight: 700;
    border-left: 3px solid {ACCENT_PRIMARY};
}}

#SidebarBrand {{
    background-color: {BG_SIDEBAR};
    border-bottom: 1px solid {BORDER_SUBTLE};
    padding: 16px 12px;
}}

#SidebarBrandTitle {{
    font-size: 18px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    letter-spacing: 1.5px;
}}

#SidebarBrandSubtitle {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_XS};
    letter-spacing: 1px;
    text-transform: uppercase;
}}

/* --- Header ------------------------------------------------------------- */
#Header {{
    background-color: {BG_SURFACE};
    border-bottom: 1px solid {BORDER_SUBTLE};
}}

#AppTitle {{
    font-size: 20px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    letter-spacing: 0.5px;
}}

#HeaderSubtitle {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
}}

#HeaderStatus {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
    font-weight: 700;
    padding: 4px 10px;
    border-radius: {RADIUS_SM};
}}

#HeaderStatus[state="running"] {{
    background-color: rgba(16, 185, 129, 0.15);
    color: {STATE_RUNNING};
    border: 1px solid {STATE_RUNNING};
}}

#HeaderStatus[state="stopped"] {{
    background-color: rgba(148, 163, 184, 0.15);
    color: {TEXT_MUTED};
    border: 1px solid {BORDER_MEDIUM};
}}

#HeaderStatus[state="error"] {{
    background-color: rgba(239, 68, 68, 0.15);
    color: {STATE_ERROR};
    border: 1px solid {STATE_ERROR};
}}

/* --- Page Chrome -------------------------------------------------------- */
#PageTitle {{
    font-size: 20px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    letter-spacing: -0.3px;
}}

#PageSubtitle {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
}}

#EmptyState {{
    color: {TEXT_MUTED};
    background-color: transparent;
    font-size: {FONT_SIZE_SM};
}}

#EmptyStateCard {{
    background-color: {BG_SURFACE_ALT};
    border: 1px dashed {BORDER_MEDIUM};
    border-radius: {RADIUS_XL};
}}

#PageHeaderOuter {{
    background-color: {BG_SURFACE};
    border-bottom: 1px solid {BORDER_SUBTLE};
}}

#CardHeader {{
    background-color: {BG_SURFACE_ALT};
    border-bottom: 1px solid {BORDER_SUBTLE};
    border-radius: 10px 10px 0 0;
}}

#SectionCard {{
    background-color: #0E1726;
    border: 1px solid #1E293B;
    border-radius: 10px;
}}

/* --- Cards & Panels ----------------------------------------------------- */
#Card {{
    background-color: #0E1726;
    border: 1px solid #1E293B;
    border-radius: 10px;
}}

#CardTitle {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_LABEL};
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}}

#CardValue {{
    font-size: 32px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
    line-height: 1.2;
}}

#CardHint {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
}}

#FieldKey {{
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
    font-weight: 500;
}}

#FieldValue {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_BASE};
    font-weight: 600;
}}

/* --- Severity Badge Classes (dynamic property: severity="critical|high|medium|low|info") --- */
QLabel[severity="critical"],
QFrame[severity="critical"],
QWidget[severity="critical"] {{
    background-color: rgba(239, 68, 68, 0.18);
    border: 1px solid {SEV_CRITICAL};
    color: {SEV_CRITICAL};
}}

QLabel[severity="high"],
QFrame[severity="high"],
QWidget[severity="high"] {{
    background-color: rgba(251, 146, 60, 0.18);
    border: 1px solid {SEV_HIGH};
    color: {SEV_HIGH};
}}

QLabel[severity="medium"],
QFrame[severity="medium"],
QWidget[severity="medium"] {{
    background-color: rgba(245, 158, 11, 0.18);
    border: 1px solid {SEV_MEDIUM};
    color: {SEV_MEDIUM};
}}

QLabel[severity="low"],
QFrame[severity="low"],
QWidget[severity="low"] {{
    background-color: rgba(16, 185, 129, 0.18);
    border: 1px solid {SEV_LOW};
    color: {SEV_LOW};
}}

QLabel[severity="info"],
QFrame[severity="info"],
QWidget[severity="info"] {{
    background-color: rgba(56, 189, 248, 0.18);
    border: 1px solid {SEV_INFO};
    color: {SEV_INFO};
}}

/* --- Buttons ------------------------------------------------------------ */
QPushButton {{
    background-color: {BG_ELEVATED};
    color: {TEXT_SECONDARY};
    border: 1px solid {BORDER_MEDIUM};
    border-radius: {RADIUS_MD};
    padding: 8px 18px;
    font-weight: 600;
    font-size: {FONT_SIZE_SM};
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: #2A3A56;
    color: {TEXT_PRIMARY};
    border-color: {BORDER_STRONG};
}}

QPushButton:pressed {{
    background-color: #1E2A3E;
    border-color: {BORDER_MEDIUM};
}}

QPushButton:disabled {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_DISABLED};
    border-color: {BORDER_SUBTLE};
}}

#PrimaryButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2563EB, stop:1 #1D4ED8);
    color: #FFFFFF;
    border: 1px solid #3B82F6;
    border-radius: 6px;
    padding: 7px 18px;
    font-weight: 700;
    font-size: 12px;
}}

#PrimaryButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3B82F6, stop:1 #2563EB);
    border-color: #60A5FA;
}}

#PrimaryButton:pressed {{
    background-color: #1E40AF;
    border-color: #1D4ED8;
}}

#PrimaryButton:disabled {{
    background-color: #161E2E;
    color: #64748B;
    border-color: #1F2937;
}}

/* Secondary/Ghost Button */
#SecondaryButton {{
    background-color: #1E293B;
    color: #E2E8F0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
}}

#SecondaryButton:hover {{
    background-color: #334155;
    color: #FFFFFF;
    border-color: #475569;
}}

/* Danger/Destructive Button (outlined) */
#DangerButton {{
    background-color: transparent;
    color: #EF4444;
    border: 1px solid #EF4444;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
}}

#DangerButton:hover {{
    background-color: rgba(239, 68, 68, 0.15);
    border-color: #F87171;
    color: #FCA5A5;
}}

/* Warning / elevated-intent Button (amber, solid) */
#WarningButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #F59E0B, stop:1 #D97706);
    color: #0B1120;
    border: 1px solid #FBBF24;
    border-radius: 6px;
    padding: 7px 18px;
    font-weight: 800;
    font-size: 12px;
}}

#WarningButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #FBBF24, stop:1 #F59E0B);
    border-color: #FBBF24;
    color: #0B1120;
}}

#WarningButton:pressed {{
    background-color: #D97706;
    border-color: #D97706;
}}

#WarningButton:disabled {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_DISABLED};
    border-color: {BORDER_SUBTLE};
}}

/* Critical execution Button (red, solid) */
#CriticalButton {{
    background-color: {SEV_CRITICAL};
    color: #FFFFFF;
    border: 1px solid {SEV_CRITICAL};
    border-radius: {RADIUS_MD};
    padding: 8px 22px;
    font-weight: 800;
    font-size: {FONT_SIZE_SM};
}}

#CriticalButton:hover {{
    background-color: #DC2626;
    border-color: #DC2626;
    color: #FFFFFF;
}}

#CriticalButton:pressed {{
    background-color: #B91C1C;
    border-color: #B91C1C;
}}

#CriticalButton:disabled {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_DISABLED};
    border-color: {BORDER_SUBTLE};
}}

/* --- Response pipeline stepper ------------------------------------------ */
#PipelineCard {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_LG};
}}

#PipelineMeta {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_SM};
    font-weight: 600;
}}

#PipelineArrow {{
    color: {TEXT_MUTED};
    font-size: 15px;
    font-weight: 700;
    background: transparent;
    border: none;
}}

#PipelineStage {{
    background-color: {BG_SURFACE_ALT};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_LG};
    padding: 6px;
}}

#PipelineStage[stage_state="done"] {{
    background-color: rgba(16, 185, 129, 0.10);
    border: 1px solid {SEV_LOW};
}}

#PipelineStage[stage_state="active"] {{
    background-color: rgba(37, 99, 235, 0.16);
    border: 2px solid {ACCENT_PRIMARY_HOVER};
}}

#PipelineStage[stage_state="future"] {{
    background-color: transparent;
    border: 1px dashed {BORDER_MEDIUM};
}}

#PipelineStage[stage_state="error"] {{
    background-color: rgba(239, 68, 68, 0.12);
    border: 1px solid {SEV_CRITICAL};
}}

#PipelineStageTitle {{
    font-size: {FONT_SIZE_XS};
    font-weight: 800;
    letter-spacing: 0.6px;
    color: {TEXT_MUTED};
    background: transparent;
    border: none;
}}

#PipelineStageTitle[stage_state="done"] {{ color: {SEV_LOW}; }}
#PipelineStageTitle[stage_state="active"] {{ color: #93C5FD; }}
#PipelineStageTitle[stage_state="future"] {{ color: {TEXT_DISABLED}; }}
#PipelineStageTitle[stage_state="error"] {{ color: {SEV_CRITICAL}; }}

#PipelineStageState {{
    font-size: {FONT_SIZE_XS};
    font-weight: 600;
    color: {TEXT_SECONDARY};
    background: transparent;
    border: none;
}}

#PipelineStageState[stage_state="future"] {{ color: {TEXT_DISABLED}; }}

#PipelineStageHint {{
    font-size: 10px;
    color: {TEXT_MUTED};
    background: transparent;
    border: none;
}}

/* --- Execution preview --------------------------------------------------- */
#PreviewStatus {{
    font-size: {FONT_SIZE_XS};
    font-weight: 800;
    letter-spacing: 1px;
    padding: 3px 8px;
    border-radius: {RADIUS_SM};
    background-color: {BG_SURFACE_ALT};
    border: 1px solid {BORDER_MEDIUM};
    color: {TEXT_MUTED};
}}

#PreviewStatus[severity="low"] {{
    background-color: rgba(16, 185, 129, 0.16);
    border: 1px solid {SEV_LOW};
    color: {SEV_LOW};
}}

#PreviewStatus[severity="medium"] {{
    background-color: rgba(245, 158, 11, 0.16);
    border: 1px solid {SEV_MEDIUM};
    color: {SEV_MEDIUM};
}}

#PreviewStatus[severity="critical"] {{
    background-color: rgba(239, 68, 68, 0.16);
    border: 1px solid {SEV_CRITICAL};
    color: {SEV_CRITICAL};
}}

#PreviewStatus[severity="info"] {{
    background-color: rgba(56, 189, 248, 0.16);
    border: 1px solid {SEV_INFO};
    color: {SEV_INFO};
}}

#PreviewAction {{
    font-size: 14px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background: transparent;
    border: none;
}}

#PreviewNote {{
    font-size: {FONT_SIZE_SM};
    color: {TEXT_MUTED};
    background: transparent;
    border: none;
}}

/* --- Banners ------------------------------------------------------------ */
#ErrorBanner {{
    color: #FECACA;
    background-color: rgba(239, 68, 68, 0.12);
    border: 1px solid {SEV_CRITICAL};
    border-radius: {RADIUS_LG};
    padding: 12px 16px;
    font-size: {FONT_SIZE_SM};
}}

#WarningBanner {{
    color: #FDE68A;
    background-color: rgba(245, 158, 11, 0.12);
    border: 1px solid {SEV_MEDIUM};
    border-radius: {RADIUS_LG};
    padding: 12px 16px;
    font-size: {FONT_SIZE_SM};
}}

#SuccessBanner {{
    color: #BBF7D0;
    background-color: rgba(16, 185, 129, 0.12);
    border: 1px solid {SEV_LOW};
    border-radius: {RADIUS_LG};
    padding: 12px 16px;
    font-size: {FONT_SIZE_SM};
}}

/* --- Status Bar --------------------------------------------------------- */
QStatusBar {{
    background-color: {BG_SIDEBAR};
    border-top: 1px solid {BORDER_SUBTLE};
    color: {TEXT_MUTED};
    font-size: {FONT_SIZE_SM};
}}

QStatusBar::item {{ border: none; }}

/* --- Tables ------------------------------------------------------------- */
QTableView, QTableWidget {{
    background-color: #0B1120;
    alternate-background-color: #0F172A;
    gridline-color: #1E293B;
    border: 1px solid #1E293B;
    border-radius: 8px;
    selection-background-color: #1D4ED8;
    selection-color: #FFFFFF;
    outline: 0;
}}

QTableView::item, QTableWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid #162032;
    color: #CBD5E1;
    font-size: 12px;
}}

QTableView::item:hover, QTableWidget::item:hover {{
    background-color: #1E293B;
    color: #F8FAFC;
}}

QTableView::item:selected, QTableWidget::item:selected {{
    background-color: #1E3A8A;
    color: #FFFFFF;
    font-weight: 600;
}}

QHeaderView {{
    background-color: #0A0F1C;
    border: none;
}}

QHeaderView::section {{
    background-color: #0C1322;
    color: #94A3B8;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 9px 12px;
    border: none;
    border-right: 1px solid #1E293B;
    border-bottom: 2px solid #1E293B;
}}

QHeaderView::section:hover {{
    background-color: #162032;
    color: #F8FAFC;
}}

QTableCornerButton::section {{
    background-color: #0C1322;
    border: none;
}}

/* --- Scrollbars --------------------------------------------------------- */
QScrollBar:vertical, QScrollBar:horizontal {{
    background: transparent;
    border: none;
    margin: 0;
}}

QScrollBar:vertical {{ width: 10px; }}
QScrollBar:horizontal {{ height: 10px; }}

QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
    background-color: {BORDER_MEDIUM};
    border-radius: 5px;
    min-height: 30px;
    min-width: 30px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
    background-color: {BORDER_STRONG};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0; width: 0;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* --- Inputs ------------------------------------------------------------- */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background-color: {BG_SURFACE_ALT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_MD};
    padding: 8px 12px;
    font-size: {FONT_SIZE_BASE};
    selection-background-color: {ACCENT_PRIMARY};
    selection-color: #FFFFFF;
}}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {ACCENT_PRIMARY};
    background-color: {BG_SURFACE};
}}

QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QDoubleSpinBox:disabled {{
    color: {TEXT_DISABLED};
    background-color: {BG_SURFACE_ALT};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_MEDIUM};
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT_PRIMARY};
    outline: 0;
}}

QCheckBox, QRadioButton {{
    color: {TEXT_SECONDARY};
    spacing: 8px;
    font-size: {FONT_SIZE_SM};
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {BORDER_MEDIUM};
    background-color: {BG_SURFACE_ALT};
    border-radius: {RADIUS_SM};
}}

QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: {ACCENT_PRIMARY};
    border-color: {ACCENT_PRIMARY};
    image: url(:/qt-project.org/styles/commonstyle/images/checkbox_checked.png);
}}

QRadioButton::indicator {{
    border-radius: 8px;
}}

/* --- Tabs --------------------------------------------------------------- */
QTabWidget::pane {{
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_LG};
    top: -1px;
    background-color: {BG_SURFACE};
}}

QTabBar::tab {{
    background-color: transparent;
    color: {TEXT_MUTED};
    padding: 10px 20px;
    margin-right: 2px;
    border-bottom: 2px solid transparent;
    font-weight: 600;
    font-size: {FONT_SIZE_SM};
}}

QTabBar::tab:hover {{ color: {TEXT_SECONDARY}; }}
QTabBar::tab:selected {{
    color: {TEXT_PRIMARY};
    border-bottom: 2px solid {ACCENT_PRIMARY};
}}

/* --- Splitter & Scroll Areas ------------------------------------------- */
QSplitter::handle {{
    background-color: #1E293B;
}}

QSplitter::handle:hover {{
    background-color: #3B82F6;
}}

QSplitter::handle:horizontal {{ width: 3px; }}
QSplitter::handle:vertical {{ height: 3px; }}

QScrollArea {{
    border: none;
    background-color: transparent;
}}

/* --- Menus -------------------------------------------------------------- */
QMenuBar {{
    background-color: {BG_SIDEBAR};
    color: {TEXT_SECONDARY};
    padding: 4px;
}}

QMenuBar::item:selected {{
    background-color: {BG_SURFACE_ALT};
    border-radius: {RADIUS_SM};
}}

QMenu {{
    background-color: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_MEDIUM};
    border-radius: {RADIUS_MD};
    padding: 6px;
}}

QMenu::item {{
    padding: 8px 24px;
    border-radius: {RADIUS_SM};
}}

QMenu::item:selected {{
    background-color: {ACCENT_SOFT};
    color: {TEXT_PRIMARY};
}}

QMenu::separator {{
    height: 1px;
    background-color: {BORDER_SUBTLE};
    margin: 4px 8px;
}}

/* --- Progress Bars ------------------------------------------------------ */
QProgressBar {{
    background-color: {BG_SURFACE_ALT};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_MD};
    text-align: center;
    color: {TEXT_PRIMARY};
    font-weight: 600;
    font-size: {FONT_SIZE_XS};
}}

QProgressBar::chunk {{
    background-color: {ACCENT_PRIMARY};
    border-radius: {RADIUS_SM};
}}

/* --- Preflight Diagnostics Modal ---------------------------------------- */
#PreflightDialog {{
    background-color: {BG_DEEP_NAVY};
    border: 1px solid {BORDER_MEDIUM};
}}

#PreflightTitle {{
    font-size: 18px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background-color: transparent;
}}

#PreflightSubtitle {{
    font-size: {FONT_SIZE_SM};
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#PreflightCheck {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_LG};
}}

#PreflightCheck:hover {{
    background-color: {BG_SURFACE_ALT};
    border-color: {BORDER_MEDIUM};
}}

#PreflightCheckName {{
    font-size: {FONT_SIZE_SM};
    font-weight: 600;
    color: {TEXT_PRIMARY};
    background-color: transparent;
}}

#PreflightCheckHint {{
    font-size: {FONT_SIZE_XS};
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#PreflightStatus {{
    font-size: {FONT_SIZE_SM};
    font-weight: 700;
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#PreflightStatus[state="running"] {{ color: {SEV_INFO}; }}
#PreflightStatus[state="ok"] {{ color: {SEV_LOW}; }}
#PreflightStatus[state="warning"] {{ color: {SEV_MEDIUM}; }}
#PreflightStatus[state="error"] {{ color: {SEV_CRITICAL}; }}

#PreflightProgress {{
    background-color: {BG_SURFACE_ALT};
    border: none;
    border-radius: {RADIUS_SM};
}}

#PreflightProgress::chunk {{
    background-color: {SEV_INFO};
    border-radius: {RADIUS_SM};
}}

#PreflightFooter {{
    font-size: {FONT_SIZE_XS};
    color: {TEXT_SECONDARY};
    background-color: transparent;
}}

/* --- Threat Simulation Playbooks ---------------------------------------- */
#ThreatSimDialog {{
    background-color: {BG_DEEP_NAVY};
    border: 1px solid {BORDER_MEDIUM};
}}

#ThreatSimTitle {{
    font-size: 18px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background-color: transparent;
}}

#ThreatSimSubtitle {{
    font-size: {FONT_SIZE_SM};
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#ScenarioCard {{
    background-color: {BG_SURFACE};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: {RADIUS_LG};
}}

#ScenarioCard:hover {{
    background-color: {BG_SURFACE_ALT};
    border-color: {BORDER_MEDIUM};
}}

#ScenarioCard[selected="true"] {{
    background-color: {ACCENT_SOFT};
    border: 1px solid {ACCENT_PRIMARY};
}}

#ScenarioTitle {{
    font-size: {FONT_SIZE_BASE};
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background-color: transparent;
}}

#ScenarioDomain {{
    font-size: {FONT_SIZE_XS};
    font-weight: 600;
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#ScenarioDesc {{
    font-size: {FONT_SIZE_SM};
    color: {TEXT_SECONDARY};
    background-color: transparent;
}}

#ScenarioHint {{
    font-size: {FONT_SIZE_XS};
    color: {TEXT_MUTED};
    background-color: transparent;
}}

#ScenarioSeverity {{
    font-size: {FONT_SIZE_XS};
    font-weight: 800;
    padding: 3px 8px;
    border-radius: {RADIUS_SM};
    color: #FFFFFF;
    background-color: {SEV_HIGH};
}}

#ScenarioSeverity[state="critical"] {{
    background-color: {SEV_CRITICAL};
}}

#ScenarioSeverity[state="high"] {{
    background-color: {SEV_HIGH};
}}

#ThreatSimNote {{
    font-size: {FONT_SIZE_XS};
    color: {TEXT_MUTED};
    background-color: transparent;
}}

/* --- State Property (dynamic) ------------------------------------------ */
QLabel[state="running"], #FieldValue[state="running"],
#CardHint[state="running"], #CardValue[state="running"],
#HeaderStatus[state="running"] {{
    color: {STATE_RUNNING};
    font-weight: 700;
}}

QLabel[state="stopped"], #FieldValue[state="stopped"],
#CardHint[state="stopped"], #CardValue[state="stopped"],
#HeaderStatus[state="stopped"] {{
    color: {TEXT_MUTED};
    font-weight: 400;
}}

QLabel[state="warning"], #FieldValue[state="warning"],
#CardHint[state="warning"], #CardValue[state="warning"],
#HeaderStatus[state="warning"] {{
    color: {STATE_WARNING};
    font-weight: 700;
}}

QLabel[state="error"], #FieldValue[state="error"],
#CardHint[state="error"], #CardValue[state="error"],
#HeaderStatus[state="error"] {{
    color: {STATE_ERROR};
    font-weight: 700;
}}
"""


# --- Public QSS getter ----------------------------------------------------

def get_stylesheet() -> str:
    """Return the complete enterprise QSS stylesheet."""
    return _build_qss()


# --- Shadow Effects Helper ------------------------------------------------

def apply_card_shadow(widget: QWidget, blur: int = SHADOW_BLUR,
                      offset: int = SHADOW_OFFSET,
                      color: QColor = SHADOW_COLOR) -> QGraphicsDropShadowEffect:
    """Apply a premium floating card shadow to a widget.

    Args:
        widget: The widget to apply shadow to (typically a QFrame with #Card).
        blur: Blur radius (default 15).
        offset: X/Y offset (default 0 for centered glow).
        color: Shadow color with alpha (default black with 60 alpha).

    Returns:
        The created QGraphicsDropShadowEffect (keep reference if needed).
    """
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setXOffset(offset)
    effect.setYOffset(offset)
    effect.setColor(color)
    widget.setGraphicsEffect(effect)
    return effect


def apply_elevated_shadow(widget: QWidget, blur: int = 25,
                          offset: int = 4,
                          color: QColor | None = None) -> QGraphicsDropShadowEffect:
    """Apply a stronger elevation shadow for modals/dropdowns."""
    if color is None:
        color = QColor(0, 0, 0, 80)
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setXOffset(0)
    effect.setYOffset(offset)
    effect.setColor(color)
    widget.setGraphicsEffect(effect)
    return effect


def animate_card_hover(widget: QWidget, enter: bool = True,
                       duration: int = 150) -> None:
    """Animate card elevation on hover (subtle lift effect).

    Args:
        widget: The card widget with an existing QGraphicsDropShadowEffect.
        enter: True for hover enter (lift up), False for leave (settle down).
        duration: Animation duration in ms.
    """
    effect = widget.graphicsEffect()
    if not isinstance(effect, QGraphicsDropShadowEffect):
        return

    target_offset = 0 if enter else 4
    target_blur = 25 if enter else 15

    anim = QPropertyAnimation(effect, b"blurRadius", widget)
    anim.setDuration(duration)
    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim.setStartValue(effect.blurRadius())
    anim.setEndValue(target_blur)
    anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    anim2 = QPropertyAnimation(effect, b"yOffset", widget)
    anim2.setDuration(duration)
    anim2.setEasingCurve(QEasingCurve.Type.OutCubic)
    anim2.setStartValue(effect.yOffset())
    anim2.setEndValue(target_offset)
    anim2.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


# --- Severity Badge Helper ------------------------------------------------

def apply_severity_style(widget: QWidget, severity: str) -> None:
    """Apply semantic severity styling via dynamic property.

    Args:
        widget: QLabel, QFrame, or QWidget to style.
        severity: One of "critical", "high", "medium", "low", "info".
    """
    severity = severity.lower().strip()
    valid = {"critical", "high", "medium", "low", "info"}
    if severity not in valid:
        severity = "info"
    widget.setProperty("severity", severity)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def create_severity_badge(text: str, severity: str, parent: QWidget | None = None):
    """Create a styled severity badge label.

    Args:
        text: Badge text (e.g., "CRITICAL", "HIGH").
        severity: Severity level.
        parent: Optional parent widget.

    Returns:
        Configured QLabel with severity styling applied.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel

    badge = QLabel(text.upper(), parent)
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    badge.setFixedWidth(72)
    badge.setObjectName("SeverityBadge")
    apply_severity_style(badge, severity)
    badge.setStyleSheet("""
        #SeverityBadge {
            font-size: 10px;
            font-weight: 800;
            padding: 3px 6px;
            border-radius: 4px;
        }
    """)
    return badge


# --- Theme Application ----------------------------------------------------

#: Marker rule proving the enterprise QSS is already installed on an app.
_QSS_MARKER = "#CriticalButton"


def apply_enterprise_theme(app) -> None:
    """Apply the base palette plus the enterprise QSS to ``app``.

    Re-applying a stylesheet repaints and re-polishes every live widget, which
    grows quadratically as a long-lived process (or a long test session)
    accumulates widgets.  The theme is deterministic, so it is installed once
    per application and skipped on every later call.
    """
    if _QSS_MARKER in (app.styleSheet() or ""):
        return
    from aegis_desktop.theme import apply_theme as _apply_base

    _apply_base(app)  # Apply base palette + existing styles
    app.setStyleSheet(app.styleSheet() + "\n" + _build_qss())


__all__ = [
    "animate_card_hover",
    "apply_card_shadow",
    "apply_elevated_shadow",
    "apply_enterprise_theme",
    "apply_severity_style",
    "create_severity_badge",
    "get_stylesheet",
]
