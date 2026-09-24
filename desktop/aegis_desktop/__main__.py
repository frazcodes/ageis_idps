"""Entry point for ``python -m aegis_desktop``."""

from __future__ import annotations

import sys

from aegis_desktop.app import run


def main(argv: list[str] | None = None) -> int:
    """Launch the Aegis desktop console."""
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
