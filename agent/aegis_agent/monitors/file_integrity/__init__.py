"""Read-only file-integrity monitoring (FIM).

Public API
----------
* :func:`collect_file_snapshot` / :class:`FileCollector` - metadata + SHA-256.
* :class:`FileRecord` / :class:`FileSnapshot` / :class:`FileChanges` - models.
* :class:`FileIntegrityMonitor` - baseline diffing
  (``start``/``snapshot``/``poll``/``stop``).
* :func:`changes_to_events` - map changes onto ``aegis_shared`` ``SecurityEvent``.
* :func:`collector_from_settings` - build a collector from agent configuration.

FIM is detection-only and strictly read-only: it never writes, deletes,
quarantines, executes or remediates a file, and it inspects only explicitly
configured paths. YARA and response actions are out of scope for this module.
"""

from __future__ import annotations

from aegis_agent.monitors.file_integrity.collector import (
    FileCollector,
    collect_file_snapshot,
    collector_from_settings,
    normalize_path,
)
from aegis_agent.monitors.file_integrity.events import build_file_event, changes_to_events
from aegis_agent.monitors.file_integrity.models import (
    FileChanges,
    FileIdentity,
    FileModification,
    FileRecord,
    FileSnapshot,
)
from aegis_agent.monitors.file_integrity.monitor import FileIntegrityMonitor

__all__ = [
    "FileChanges",
    "FileCollector",
    "FileIdentity",
    "FileIntegrityMonitor",
    "FileModification",
    "FileRecord",
    "FileSnapshot",
    "build_file_event",
    "changes_to_events",
    "collect_file_snapshot",
    "collector_from_settings",
    "normalize_path",
]
