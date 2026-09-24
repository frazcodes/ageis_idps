"""Base class shared by every console page.

GUI-1 pages are structural: a heading, an optional subtitle and a clear
empty-state message. No page performs monitoring, detection, scoring or any
response.
"""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

DEFAULT_EMPTY_STATE = (
    "This module will be connected to the Aegis engine in a later implementation step."
)


class BasePage(QWidget):
    """A titled page with optional content and an empty-state notice."""

    PAGE_KEY = ""
    TITLE = ""
    SUBTITLE = ""
    EMPTY_STATE = DEFAULT_EMPTY_STATE

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName(f"page-{self.PAGE_KEY}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(10)

        title = QLabel(self.TITLE)
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        if self.SUBTITLE:
            subtitle = QLabel(self.SUBTITLE)
            subtitle.setObjectName("PageSubtitle")
            subtitle.setWordWrap(True)
            layout.addWidget(subtitle)

        content = self.build_content()
        if content is not None:
            layout.addWidget(content)

        if self.EMPTY_STATE:
            empty_state = QLabel(self.EMPTY_STATE)
            empty_state.setObjectName("EmptyState")
            empty_state.setWordWrap(True)
            layout.addWidget(empty_state)

        layout.addStretch(1)

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
