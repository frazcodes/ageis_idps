"""Deterministic feature extraction from host behavioral telemetry.

Converts existing host monitor snapshots and change sets - processes, listening
ports and file-integrity changes - into a small, fixed-length numeric feature
representation suitable for a future host anomaly detector.

This module is **pure**: it performs no I/O, starts no threads, reads no process
table or socket, touches no files and mutates no input. Host model types are
imported lazily (``TYPE_CHECKING`` only) so importing the ML engine never pulls
in the agent's platform dependencies such as ``psutil``.

Feature contract
----------------
* Counts are derived only from fields that already exist on the host models.
* Missing/empty inputs yield ``0`` for their counts; they are never negative,
  ``NaN`` or infinity.
* No usernames, command lines, paths, credentials, secrets or file contents are
  read or stored - only aggregate counts and an optional ``host_id``.
* Input objects are never mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_agent.monitors.file_integrity.models import FileChanges
    from aegis_agent.monitors.port.models import PortChanges, PortSnapshot
    from aegis_agent.monitors.process.models import ProcessChanges, ProcessSnapshot

# ---------------------------------------------------------------------------
# Feature representation
# ---------------------------------------------------------------------------

_FEATURE_VERSION = "1.0.0"


@dataclass(frozen=True)
class HostBehaviorFeatures:
    """Immutable numeric features summarising host activity in one window.

    Only aggregate counts are included. No process names, command lines, file
    paths or other sensitive detail is stored.
    """

    #: --- Identity / traceability (optional) ---
    host_id: str | None

    #: --- Current-state counts (from snapshots) ---
    #: Number of processes observed in the snapshot.
    process_count: int
    #: Number of listening/bound ports observed in the snapshot.
    listening_port_count: int

    #: --- Activity counts (from change sets) ---
    #: Total file changes (created + modified + deleted).
    file_change_count: int
    #: Processes started since the previous poll.
    new_process_count: int
    #: Processes stopped since the previous poll.
    terminated_process_count: int
    #: Ports that began listening since the previous poll.
    new_listening_port_count: int
    #: Ports that stopped listening since the previous poll.
    removed_listening_port_count: int
    #: Files created since the previous poll.
    file_created_count: int
    #: Files modified since the previous poll.
    file_modified_count: int
    #: Files deleted since the previous poll.
    file_deleted_count: int

    #: Feature schema version (deterministic, bump on field changes).
    feature_version: str = _FEATURE_VERSION


# ---------------------------------------------------------------------------
# Pure extraction
# ---------------------------------------------------------------------------

def extract_host_features(
    *,
    host_id: str | None = None,
    process_snapshot: ProcessSnapshot | None = None,
    port_snapshot: PortSnapshot | None = None,
    process_changes: ProcessChanges | None = None,
    port_changes: PortChanges | None = None,
    file_changes: FileChanges | None = None,
) -> HostBehaviorFeatures:
    """Extract host behavioral features from existing telemetry.

    Every input is optional; omitted or empty inputs contribute ``0`` to their
    respective counts. The function is pure: no I/O, no mutation, deterministic
    output.
    """
    process_count = len(process_snapshot.processes) if process_snapshot is not None else 0
    listening_port_count = len(port_snapshot.ports) if port_snapshot is not None else 0

    new_process_count = len(process_changes.started) if process_changes is not None else 0
    terminated_process_count = len(process_changes.stopped) if process_changes is not None else 0

    new_listening_port_count = len(port_changes.started) if port_changes is not None else 0
    removed_listening_port_count = len(port_changes.stopped) if port_changes is not None else 0

    file_created_count = len(file_changes.created) if file_changes is not None else 0
    file_modified_count = len(file_changes.modified) if file_changes is not None else 0
    file_deleted_count = len(file_changes.deleted) if file_changes is not None else 0

    return HostBehaviorFeatures(
        host_id=host_id,
        process_count=_non_negative(process_count),
        listening_port_count=_non_negative(listening_port_count),
        file_change_count=_non_negative(
            file_created_count + file_modified_count + file_deleted_count
        ),
        new_process_count=_non_negative(new_process_count),
        terminated_process_count=_non_negative(terminated_process_count),
        new_listening_port_count=_non_negative(new_listening_port_count),
        removed_listening_port_count=_non_negative(removed_listening_port_count),
        file_created_count=_non_negative(file_created_count),
        file_modified_count=_non_negative(file_modified_count),
        file_deleted_count=_non_negative(file_deleted_count),
    )


def _non_negative(value: int) -> int:
    """Clamp a count to be non-negative (defensive; counts are never negative)."""
    return value if value >= 0 else 0


__all__ = [
    "_FEATURE_VERSION",
    "HostBehaviorFeatures",
    "extract_host_features",
]
