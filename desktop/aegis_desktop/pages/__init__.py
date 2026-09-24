"""Console pages and the navigation-key to page mapping."""

from __future__ import annotations

from aegis_desktop.pages.assets import AssetsPage
from aegis_desktop.pages.base import DEFAULT_EMPTY_STATE, BasePage
from aegis_desktop.pages.dashboard import DashboardPage
from aegis_desktop.pages.detections import DetectionsPage
from aegis_desktop.pages.events import EventsPage
from aegis_desktop.pages.files import FilesPage
from aegis_desktop.pages.incidents import IncidentsPage
from aegis_desktop.pages.network import NetworkPage
from aegis_desktop.pages.processes import ProcessesPage
from aegis_desktop.pages.response_center import ResponseCenterPage
from aegis_desktop.pages.risk import RiskPage
from aegis_desktop.pages.settings import SettingsPage

#: Navigation key -> page class. Mirrors ``aegis_desktop.navigation.NAV_ITEMS``.
PAGE_FACTORIES: dict[str, type[BasePage]] = {
    "dashboard": DashboardPage,
    "assets": AssetsPage,
    "processes": ProcessesPage,
    "network": NetworkPage,
    "files": FilesPage,
    "events": EventsPage,
    "detections": DetectionsPage,
    "incidents": IncidentsPage,
    "response": ResponseCenterPage,
    "risk": RiskPage,
    "settings": SettingsPage,
}


def create_page(key: str) -> BasePage:
    """Construct the page registered for ``key``.

    Raises:
        KeyError: if ``key`` has no registered page.
    """
    try:
        factory = PAGE_FACTORIES[key]
    except KeyError as exc:
        raise KeyError(f"no page registered for key: {key!r}") from exc
    return factory()


__all__ = [
    "DEFAULT_EMPTY_STATE",
    "PAGE_FACTORIES",
    "AssetsPage",
    "BasePage",
    "DashboardPage",
    "DetectionsPage",
    "EventsPage",
    "FilesPage",
    "IncidentsPage",
    "NetworkPage",
    "ProcessesPage",
    "ResponseCenterPage",
    "RiskPage",
    "SettingsPage",
    "create_page",
]
