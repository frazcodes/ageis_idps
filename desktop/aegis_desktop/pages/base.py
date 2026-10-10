"""Base class shared by every console page.

Upgraded to a premium enterprise SOC standard:
- Page header with icon glyph, title, and coloured subtitle band
- Action toolbar slot (subclasses call ``add_action_button``)
- Premium empty-state panel with icon, heading, and hint text
- Consistent spacing and card-like surfaces
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QColor

# ---------------------------------------------------------------------------
# Design tokens (standalone, no theme.py dependency for portability)
# ---------------------------------------------------------------------------
_BG      = "#0A0F1C"
_SURF    = "#111827"
_SURF2   = "#161E2E"
_BDR     = "#1F2937"
_BDR2    = "#374151"
_ACC     = "#1D4ED8"
_ACC2    = "#2563EB"
_CYAN    = "#06B6D4"
_GREEN   = "#10B981"
_RED     = "#EF4444"
_AMBER   = "#F59E0B"
_TEXT    = "#F8FAFC"
_TEXT2   = "#CBD5E1"
_MUTED   = "#94A3B8"
_MUTED2  = "#64748B"

DEFAULT_EMPTY_STATE = (
    "This module will be connected to the Aegis engine in a later implementation step."
)


def _drop_shadow(widget: QWidget, blur: int = 18, alpha: int = 70) -> None:
    """Attach a subtle drop shadow to *widget*."""
    fx = QGraphicsDropShadowEffect(widget)
    fx.setBlurRadius(blur)
    fx.setXOffset(0)
    fx.setYOffset(3)
    fx.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(fx)


class BasePage(QWidget):
    """A titled page with premium header, optional action bar, and content area."""

    PAGE_KEY  = ""
    TITLE     = ""
    SUBTITLE  = ""
    ICON      = "◈"          # Unicode glyph shown in header — override per page
    ICON_COLOR = _ACC         # Accent colour for icon + subtitle bar
    EMPTY_STATE = DEFAULT_EMPTY_STATE

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName(f"page-{self.PAGE_KEY}")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Page header band ─────────────────────────────────────────────
        header = self._build_header()
        root.addWidget(header)

        # ── Scrollable content area ──────────────────────────────────────
        inner = QWidget()
        inner.setObjectName("PageInner")
        inner.setStyleSheet("QWidget#PageInner { background: transparent; }")
        inner_lay = QVBoxLayout(inner)
        inner_lay.setContentsMargins(24, 20, 24, 24)
        inner_lay.setSpacing(14)

        content = self.build_content()
        if content is not None:
            inner_lay.addWidget(content, 1)

        if self.EMPTY_STATE:
            self._empty_widget = self._build_empty_state()
            inner_lay.addWidget(self._empty_widget)
            inner_lay.addStretch(1)
        else:
            self._empty_widget = None

        root.addWidget(inner, 1)

    # ── Header ───────────────────────────────────────────────────────────────

    def _build_header(self) -> QWidget:
        outer = QWidget()
        outer.setObjectName("PageHeaderOuter")
        outer.setStyleSheet(f"""
            #PageHeaderOuter {{
                background-color: {_SURF};
                border-bottom: 1px solid {_BDR};
            }}
        """)

        lay = QHBoxLayout(outer)
        lay.setContentsMargins(24, 14, 24, 14)
        lay.setSpacing(14)

        # Coloured icon box with matching color scheme
        icon_box = QLabel(self.ICON)
        icon_box.setFixedSize(42, 42)
        icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        c = self.ICON_COLOR
        icon_box.setStyleSheet(f"""
            background-color: {c}20;
            border: 1px solid {c}55;
            border-radius: 10px;
            color: {c};
            font-size: 20px;
            font-weight: bold;
        """)
        lay.addWidget(icon_box)

        # Title + subtitle column
        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        title_lbl = QLabel(self.TITLE)
        title_lbl.setObjectName("PageTitle")
        title_lbl.setStyleSheet(
            f"color:{_TEXT}; font-size:20px; font-weight:800; background:transparent;"
        )
        text_col.addWidget(title_lbl)

        if self.SUBTITLE:
            sub_lbl = QLabel(self.SUBTITLE)
            sub_lbl.setObjectName("PageSubtitle")
            sub_lbl.setStyleSheet(
                f"color:{_MUTED}; font-size:12px; background:transparent;"
            )
            sub_lbl.setWordWrap(True)
            text_col.addWidget(sub_lbl)

        lay.addLayout(text_col, 1)

        # Action button area (filled by subclasses via add_action_button)
        self._action_row = QHBoxLayout()
        self._action_row.setSpacing(8)
        lay.addLayout(self._action_row)

        return outer

    # ── Empty state ───────────────────────────────────────────────────────────

    def _build_empty_state(self) -> QWidget:
        card = QFrame()
        card.setObjectName("EmptyStateCard")
        card.setStyleSheet(f"""
            #EmptyStateCard {{
                background-color: {_SURF2};
                border: 1px dashed {_BDR2};
                border-radius: 12px;
            }}
        """)

        lay = QVBoxLayout(card)
        lay.setContentsMargins(40, 36, 40, 36)
        lay.setSpacing(10)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_lbl = QLabel("◌")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(
            f"color:{_BDR2}; font-size:42px; background:transparent;"
        )
        lay.addWidget(icon_lbl)

        head_lbl = QLabel("No data available")
        head_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head_lbl.setStyleSheet(
            f"color:{_TEXT2}; font-size:15px; font-weight:700; background:transparent;"
        )
        lay.addWidget(head_lbl)

        hint_lbl = QLabel(self.EMPTY_STATE)
        hint_lbl.setObjectName("EmptyState")
        hint_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint_lbl.setWordWrap(True)
        hint_lbl.setStyleSheet(
            f"color:{_MUTED}; font-size:12px; background:transparent; max-width:460px;"
        )
        lay.addWidget(hint_lbl)

        return card

    # ── Subclass helpers ──────────────────────────────────────────────────────

    def add_action_button(
        self,
        text: str,
        *,
        primary: bool = False,
        danger: bool = False,
    ) -> QPushButton:
        """Add a styled button to the page header action row.

        Returns the QPushButton so the caller can connect signals.
        """
        btn = QPushButton(text)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        if danger:
            ss = f"""
                QPushButton {{
                    background:#7F1D1D; color:#FCA5A5; border:1px solid #EF4444;
                    border-radius:6px; padding:6px 16px; font-size:12px; font-weight:700;
                }}
                QPushButton:hover {{ background:#991B1B; color:#FEE2E2; }}
                QPushButton:pressed {{ background:#B91C1C; }}
            """
        elif primary:
            ss = f"""
                QPushButton {{
                    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {_ACC},stop:1 {_ACC2});
                    color:#FFFFFF; border:none;
                    border-radius:6px; padding:6px 18px; font-size:12px; font-weight:700;
                }}
                QPushButton:hover {{
                    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {_ACC2},stop:1 #3B82F6);
                }}
                QPushButton:pressed {{ background:{_ACC}; }}
            """
        else:
            ss = f"""
                QPushButton {{
                    background:{_SURF2}; color:{_TEXT2}; border:1px solid {_BDR2};
                    border-radius:6px; padding:6px 14px; font-size:12px; font-weight:600;
                }}
                QPushButton:hover {{ background:#1E2A3E; color:{_TEXT}; border-color:{_ACC}; }}
                QPushButton:pressed {{ background:#0F1829; }}
            """

        btn.setStyleSheet(ss)
        self._action_row.addWidget(btn)
        return btn

    def make_section_card(self, title: str = "") -> tuple[QFrame, QVBoxLayout]:
        """Create a premium section card. Returns (frame, inner_layout)."""
        card = QFrame()
        card.setObjectName("SectionCard")
        card.setStyleSheet(f"""
            #SectionCard {{
                background-color: {_SURF};
                border: 1px solid {_BDR};
                border-radius: 10px;
            }}
        """)
        _drop_shadow(card, blur=14)

        inner = QVBoxLayout(card)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.setSpacing(0)

        if title:
            hdr = QWidget()
            hdr.setObjectName("CardHeader")
            hdr.setStyleSheet(f"""
                QWidget#CardHeader {{
                    background-color: {_SURF2};
                    border-bottom: 1px solid {_BDR};
                    border-radius: 10px 10px 0 0;
                }}
            """)
            hdr_lay = QHBoxLayout(hdr)
            hdr_lay.setContentsMargins(16, 10, 16, 10)
            lbl = QLabel(title.upper())
            lbl.setStyleSheet(
                f"color:{_MUTED}; font-size:10px; font-weight:800; letter-spacing:1.5px; background:transparent;"
            )
            hdr_lay.addWidget(lbl)
            inner.addWidget(hdr)

        return card, inner

    # ── Overridable ───────────────────────────────────────────────────────────

    def build_content(self) -> QWidget | None:
        """Override to add page-specific content. Returns ``None`` by default."""
        return None

    def handle_navigate(self, **kwargs: object) -> None:
        """Handle an incoming navigation event with optional context.

        Subclasses may override this to react to navigation parameters
        such as ``select_id`` for row selection.  The default implementation
        does nothing.
        """


__all__ = ["DEFAULT_EMPTY_STATE", "BasePage"]
