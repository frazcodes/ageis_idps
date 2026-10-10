"""Entry point for ``python -m aegis_desktop``."""

from __future__ import annotations

import sys

from aegis_desktop.app import run


def main(argv: list[str] | None = None) -> int:
    """Launch the Aegis desktop console.

    login_bypass=True: auth backend is not yet implemented so any
    username / password is accepted.  Remove this flag once the JWT
    endpoint is wired up.
    """
    return run(argv, login_bypass=True)


if __name__ == "__main__":
    sys.exit(main())
