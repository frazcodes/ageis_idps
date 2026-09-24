"""Application bootstrap for the Aegis desktop console."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from aegis_desktop.theme import apply_theme
from aegis_shared.version import __version__


def create_application(argv: list[str] | None = None) -> QApplication:
    """Return the process-wide :class:`QApplication`, creating it if needed.

    Idempotent so tests and embedders can reuse a single application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        app = existing
    else:
        app = QApplication(argv if argv is not None else sys.argv)

    app.setApplicationName("Aegis IDPS")
    app.setApplicationDisplayName("Aegis IDPS")
    app.setOrganizationName("Aegis IDPS")
    app.setApplicationVersion(__version__)
    apply_theme(app)
    return app


def run(argv: list[str] | None = None, *, splash: bool = True) -> int:
    """Create the application, show the splash screen, then launch the window.

    When *splash* is ``True`` (the default), a loading screen appears for
    ~2.8 seconds simulating backend initialisation before the main console
    is revealed.  Pass ``splash=False`` to skip the splash (e.g. in tests).
    """
    app = create_application(argv)

    if not splash:
        from aegis_desktop.window import MainWindow
        window = MainWindow()
        window.show()
        return int(app.exec())

    from aegis_desktop.splash import SplashScreen

    _state: dict[str, object] = {}

    def _on_splash_finished() -> None:
        from aegis_desktop.window import MainWindow
        window = MainWindow()
        window.show()
        _state["window"] = window

    splash = SplashScreen(on_finished=_on_splash_finished)
    splash.start()
    return int(app.exec())


__all__ = ["create_application", "run"]
