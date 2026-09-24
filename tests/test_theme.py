"""Deterministic tests for the Aegis dark SOC theme (UI-only, presentation).

These verify the palette and centralized stylesheet are dark and that the
documented object names remain, without asserting exact colors (so the design can
evolve). No security behaviour is involved.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication, QLabel

from aegis_desktop import theme
from aegis_desktop.app import create_application

_OBJECT_NAMES = (
    "Sidebar",
    "SidebarBrand",
    "SidebarBrandTitle",
    "SidebarBrandSubtitle",
    "Header",
    "AppTitle",
    "HeaderSubtitle",
    "PageTitle",
    "PageSubtitle",
    "Card",
    "CardTitle",
    "CardValue",
    "CardHint",
    "FieldKey",
    "FieldValue",
    "PrimaryButton",
    "ErrorBanner",
    "EmptyState",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _luminance(hex_color: str) -> float:
    value = hex_color.lstrip("#")
    r, g, b = (int(value[i : i + 2], 16) for i in (0, 2, 4))
    return 0.299 * r + 0.587 * g + 0.114 * b


def test_dark_palette_is_applied(app: QApplication) -> None:
    palette = app.palette()
    window = palette.color(QPalette.ColorRole.Window).name()
    base = palette.color(QPalette.ColorRole.Base).name()
    text = palette.color(QPalette.ColorRole.WindowText).name()

    assert _luminance(window) < 60  # dark canvas
    assert _luminance(base) < 90  # dark panels
    assert _luminance(text) > 200  # light readable text


def test_theme_tokens_are_dark(app: QApplication) -> None:
    assert _luminance(theme.BACKGROUND) < 60
    assert _luminance(theme.PANEL) < 90
    assert _luminance(theme.TEXT) > 200
    # Borders sit between the canvas and the text for visible separation.
    assert 40 < _luminance(theme.BORDER) < 140


def test_stylesheet_is_centralized_and_dark(app: QApplication) -> None:
    stylesheet = app.styleSheet()

    assert stylesheet
    # The old light surface/border tokens must not survive anywhere.
    for old_light in ("#f5f6f8", "#f2f4f7", "#e2e5ea", "#fafbfc", "#eef1fd"):
        assert old_light not in stylesheet
    for object_name in _OBJECT_NAMES:
        assert f"#{object_name}" in stylesheet


def test_set_state_sets_dynamic_property(app: QApplication) -> None:
    label = QLabel("RUNNING")
    theme.set_state(label, "running")

    assert label.property("state") == "running"
    assert label.text() == "RUNNING"  # text is never changed


def test_state_color_maps_severity() -> None:
    assert theme.state_color("critical").name().lower() == theme.CRITICAL.lower()
    assert theme.state_color("medium").name().lower() == theme.WARN.lower()
    assert theme.state_color("running").name().lower() == theme.OK.lower()
    # Unknown values fall back to a readable secondary text colour.
    assert theme.state_color("unknown").name().lower() == theme.TEXT_SECONDARY.lower()


def test_backwards_compatible_alias() -> None:
    assert theme.apply_dark_theme is theme.apply_theme
