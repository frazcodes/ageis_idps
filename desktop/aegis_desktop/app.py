"""Application bootstrap for the Aegis desktop console."""

from __future__ import annotations

import os
import sys

from PySide6.QtWidgets import QApplication

from aegis_desktop.styles import apply_enterprise_theme
from aegis_shared.version import __version__

# Silence noisy Qt Multimedia FFmpeg hardware-encoder scanning messages
os.environ.setdefault("QT_LOGGING_RULES", "qt.multimedia*=false")


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
    apply_enterprise_theme(app)
    return app


def _launch_splash_then_main(state: dict[str, object]) -> None:
    """Show the animated splash screen, then open the main console."""
    from aegis_desktop.splash import SplashScreen

    def _on_splash_finished() -> None:
        from aegis_desktop.window import MainWindow
        window = MainWindow()
        window.show()
        state["window"] = window

    splash_screen = SplashScreen(on_finished=_on_splash_finished)
    state["splash"] = splash_screen
    splash_screen.start()


def run(
    argv: list[str] | None = None,
    *,
    splash: bool = True,
    login: bool = True,
    login_bypass: bool = False,
) -> int:
    """Create the application, show the login screen, splash, then main window.

    Flow (default):
        LoginWindow  ──(success)──►  SplashScreen  ──(done)──►  MainWindow

    Args:
        argv: Command-line arguments forwarded to QApplication.
        splash: Show the animated splash screen before the main window.
        login: Show the login screen before everything else.
        login_bypass: Skip credential validation in LoginWindow (dev mode).
            Set to ``True`` during development so any username/password works.
    """
    app = create_application(argv)

    # Dev / test shortcut: skip both login and splash
    if not login and not splash:
        from aegis_desktop.window import MainWindow
        window = MainWindow()
        window.show()
        return app.exec()

    _state: dict[str, object] = {}

    def _on_login_success(username: str) -> None:
        """Callback fired by LoginWindow after the user is authenticated."""
        if splash:
            _launch_splash_then_main(_state)
        else:
            from aegis_desktop.window import MainWindow
            window = MainWindow()
            window.show()
            _state["window"] = window

    if login:
        from aegis_desktop.login import LoginWindow

        login_win = LoginWindow(bypass=login_bypass)
        login_win.login_successful.connect(_on_login_success)
        login_win.show()
        _state["login"] = login_win
    else:
        # No login screen requested — go straight to splash / main
        if splash:
            _launch_splash_then_main(_state)
        else:
            from aegis_desktop.window import MainWindow
            window = MainWindow()
            window.show()
            _state["window"] = window

    return app.exec()


__all__ = ["create_application", "run"]
