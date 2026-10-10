"""Aegis IDPS native desktop administrator console (PySide6).

GUI-1 is UI infrastructure only. The console does not collect telemetry, run
detection, score risk or perform any response - it is a shell that later steps
will connect to the existing Aegis engines.
"""

from __future__ import annotations

from aegis_desktop.app import create_application, run
from aegis_desktop.login import LoginWindow
from aegis_desktop.splash import SplashScreen
from aegis_desktop.window import MainWindow

__all__ = ["LoginWindow", "MainWindow", "SplashScreen", "create_application", "run"]
