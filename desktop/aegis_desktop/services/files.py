"""Files adapter: existing Step 5 FIM models/configuration -> UI-friendly data.

Strictly read-only. It reads the existing agent FIM configuration and, only when
FIM is enabled **and** at least one path is configured, performs one bounded
one-shot collection through the existing Step 5
:class:`~aegis_agent.monitors.file_integrity.FileCollector`.

It never hashes during rendering, never starts the ``FileIntegrityMonitor``
lifecycle, never scans the filesystem on import, and never modifies a file. The
collector is imported lazily so opening the application (or any other page) does
not load it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_agent.config import AgentSettings, get_agent_settings
from aegis_desktop.services.processes import MISSING
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_agent.monitors.file_integrity import FileRecord, FileSnapshot

logger = get_logger(__name__)

#: Non-sensitive message shown when collection fails.
FILE_ERROR = "Unable to inspect configured files"
#: Non-sensitive message shown when FIM is off or has no configured paths.
FIM_DISABLED_NOTICE = (
    "File integrity monitoring is disabled or has no configured paths. "
    "Enable it and configure paths through the agent configuration."
)


@dataclass(frozen=True)
class FileIntegrityConfig:
    """Read-only view of the current FIM posture."""

    enabled: bool
    configured_paths: int
    symlink_policy: str
    max_hash_bytes: int


@dataclass(frozen=True)
class FileRow:
    """One filesystem object, flattened for display and sorting."""

    path: str
    file_type: str
    size_bytes: int | None
    modified_at: datetime | None
    #: Full SHA-256 (never truncated); ``None`` when no hash was produced.
    sha256: str | None
    hash_status: str
    identity: str


@dataclass(frozen=True)
class FileSnapshotView:
    """Read-only view of one FIM collection plus the active configuration."""

    available: bool
    error: str | None
    notice: str | None
    collected_at: datetime | None
    config: FileIntegrityConfig
    rows: tuple[FileRow, ...]

    @property
    def count(self) -> int:
        """Number of filesystem objects in the snapshot."""
        return len(self.rows)


def file_integrity_config(settings: AgentSettings | None = None) -> FileIntegrityConfig:
    """Return the current FIM posture from the existing agent configuration."""
    resolved = settings or get_agent_settings()
    return FileIntegrityConfig(
        enabled=resolved.enable_file_integrity,
        configured_paths=len(resolved.file_integrity_paths),
        symlink_policy=resolved.file_integrity_symlink_policy.value,
        max_hash_bytes=resolved.file_integrity_max_hash_bytes,
    )


def _collector_for(settings: AgentSettings) -> FileSnapshot:
    # Imported lazily: opening the application must not load the FIM collector.
    from aegis_agent.monitors.file_integrity import FileCollector

    return FileCollector(
        paths=settings.file_integrity_paths,
        max_hash_bytes=settings.file_integrity_max_hash_bytes,
        symlink_policy=settings.file_integrity_symlink_policy,
    ).collect()


def _to_row(record: FileRecord) -> FileRow:
    return FileRow(
        path=record.path,
        file_type=record.file_type.value,
        size_bytes=record.size_bytes,
        modified_at=record.modified_at,
        sha256=record.sha256,
        hash_status=record.hash_status.value,
        identity=record.identity.key,
    )


def collect_file_view(
    *,
    settings: AgentSettings | None = None,
    collector: Callable[[], FileSnapshot] | None = None,
) -> FileSnapshotView:
    """Perform one bounded read-only FIM collection and translate it for the UI.

    Args:
        settings: Overrides agent configuration (tests inject one).
        collector: Overrides the existing collector. Defaults to a one-shot
            collection using the existing Step 5 ``FileCollector`` built from the
            resolved configuration. The ``FileIntegrityMonitor`` lifecycle is
            never started.

    Returns:
        A :class:`FileSnapshotView`. When FIM is disabled or unconfigured,
        ``available`` is ``False`` with a ``notice`` and no filesystem access
        occurs. On failure, ``error`` carries a safe, non-sensitive message.
    """
    resolved = settings or get_agent_settings()
    config = file_integrity_config(resolved)

    if not config.enabled or config.configured_paths == 0:
        return FileSnapshotView(
            available=False,
            error=None,
            notice=FIM_DISABLED_NOTICE,
            collected_at=None,
            config=config,
            rows=(),
        )

    collect = collector or (lambda: _collector_for(resolved))
    try:
        snapshot = collect()
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("File integrity collection failed: %s", exc)
        return FileSnapshotView(
            available=False,
            error=FILE_ERROR,
            notice=None,
            collected_at=None,
            config=config,
            rows=(),
        )

    return FileSnapshotView(
        available=True,
        error=None,
        notice=None,
        collected_at=snapshot.captured_at,
        config=config,
        rows=tuple(_to_row(record) for record in snapshot.files),
    )


__all__ = [
    "FILE_ERROR",
    "FIM_DISABLED_NOTICE",
    "MISSING",
    "FileIntegrityConfig",
    "FileRow",
    "FileSnapshotView",
    "collect_file_view",
    "file_integrity_config",
]
