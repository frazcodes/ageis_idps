"""Event reporting to the central backend (not yet implemented).

Responsible for batching, retrying and authenticating delivery of
:class:`aegis_shared.events.SecurityEvent` records, plus heartbeat emission.
"""

from __future__ import annotations

__all__: list[str] = []
