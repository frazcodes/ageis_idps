"""Version constants for the Aegis IDPS shared contracts."""

from __future__ import annotations

__version__ = "0.1.0"

#: Version of the :class:`aegis_shared.events.SecurityEvent` envelope.
#:
#: Bump the MAJOR component for breaking changes (field removed/renamed/type-changed),
#: the MINOR component for additive, backward-compatible fields. Producers stamp every
#: event with this value so consumers can migrate safely.
EVENT_SCHEMA_VERSION = "1.3.0"

__all__ = ["EVENT_SCHEMA_VERSION", "__version__"]
