"""Host monitors, each independently enable-able.

Implemented:

* ``process`` (:mod:`aegis_agent.monitors.process`) - read-only process
  enumeration and snapshot diffing into ``SecurityEvent`` records.
* ``port`` (:mod:`aegis_agent.monitors.port`) - read-only local listening-port
  discovery with owning-process correlation.
* ``file_integrity`` (:mod:`aegis_agent.monitors.file_integrity`) - read-only
  baseline diffing of explicitly configured paths with streaming SHA-256.

Planned, not yet implemented:

* ``connection``       - local connection open/close observations
* ``yara``             - on-demand YARA scanning of flagged files
"""

from __future__ import annotations

__all__: list[str] = []
