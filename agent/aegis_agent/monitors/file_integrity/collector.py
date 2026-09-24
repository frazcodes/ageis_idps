"""Read-only file metadata collection with streaming SHA-256 hashing.

Scope and safety
----------------
Only the paths explicitly passed to the collector are inspected. Directories are
traversed recursively (that is the explicit configuration); nothing else on the
filesystem is scanned. Traversal never follows symlinked directories, so it
cannot escape the configured tree or loop.

Hashing streams the file in fixed-size chunks and stops at the configured size
cap, so large files are neither loaded into memory nor hashed. Nothing is ever
written, deleted, quarantined or executed.

Failure handling policy
-----------------------
* Missing configured roots are logged and skipped.
* ``PermissionError``/``OSError`` while listing or stating an entry skip that
  entry; they never abort the scan.
* A file that cannot be hashed records the reason in ``hash_status`` rather than
  being reported as unchanged.
* Unexpected programming errors are not caught here.
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

from aegis_agent.config import DEFAULT_MAX_HASH_BYTES, SymlinkPolicy, get_agent_settings
from aegis_agent.monitors.file_integrity.models import FileRecord, FileSnapshot
from aegis_shared.enums import FileType, HashStatus
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Read size for streaming hashes (1 MiB): bounded memory for any file size.
HASH_CHUNK_SIZE = 1024 * 1024


def normalize_path(path: str) -> str:
    """Return an absolute, normalized path preserving the original case."""
    return os.path.normpath(os.path.abspath(path))


def _to_datetime(raw: float | None) -> datetime | None:
    if raw is None:
        return None
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class FileCollector:
    """Collect metadata for a fixed set of explicitly configured paths."""

    def __init__(
        self,
        *,
        paths: Iterable[str],
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
        symlink_policy: SymlinkPolicy = SymlinkPolicy.SKIP,
        recursive: bool = True,
    ) -> None:
        self._paths = [normalize_path(path) for path in paths]
        self._max_hash_bytes = max_hash_bytes
        self._symlink_policy = symlink_policy
        self._recursive = recursive

    @property
    def paths(self) -> tuple[str, ...]:
        """The normalized configured paths."""
        return tuple(self._paths)

    def collect(self) -> FileSnapshot:
        """Return a snapshot of the configured paths, ordered by identity key."""
        records: dict[str, FileRecord] = {}
        for root in self._paths:
            for record in self._scan(root):
                records.setdefault(record.identity.key, record)
        return FileSnapshot(files=tuple(sorted(records.values(), key=lambda r: r.identity.key)))

    # -- Traversal ---------------------------------------------------------

    def _scan(self, target: str) -> Iterator[FileRecord]:
        try:
            target_stat = os.lstat(target)
        except FileNotFoundError:
            logger.warning("Configured path does not exist: %s", target)
            return
        except PermissionError:
            logger.warning("Permission denied for configured path: %s", target)
            return
        except OSError as exc:
            logger.warning("Cannot inspect configured path %s: %s", target, exc)
            return

        if stat_module.S_ISLNK(target_stat.st_mode):
            yield from self._scan_symlink(target, target_stat)
            return
        if stat_module.S_ISDIR(target_stat.st_mode):
            yield self._build_record(
                target, target_stat, FileType.DIRECTORY, HashStatus.NOT_APPLICABLE
            )
            if self._recursive:
                yield from self._walk(target)
            return
        if stat_module.S_ISREG(target_stat.st_mode):
            yield self._build_record(target, target_stat, FileType.REGULAR)
            return
        yield self._build_record(target, target_stat, FileType.OTHER, HashStatus.UNSUPPORTED)

    def _walk(self, root: str) -> Iterator[FileRecord]:
        """Depth-first traversal that never follows symlinked directories."""
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as scanner:
                    entries = list(scanner)
            except PermissionError:
                logger.warning("Permission denied listing directory: %s", current)
                continue
            except OSError as exc:
                logger.warning("Cannot list directory %s: %s", current, exc)
                continue

            for entry in entries:
                path = entry.path
                try:
                    if entry.is_symlink():
                        yield from self._scan_symlink(path)
                    elif entry.is_dir(follow_symlinks=False):
                        entry_stat = entry.stat(follow_symlinks=False)
                        yield self._build_record(
                            path, entry_stat, FileType.DIRECTORY, HashStatus.NOT_APPLICABLE
                        )
                        stack.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        entry_stat = entry.stat(follow_symlinks=False)
                        yield self._build_record(path, entry_stat, FileType.REGULAR)
                    else:
                        entry_stat = entry.stat(follow_symlinks=False)
                        yield self._build_record(
                            path, entry_stat, FileType.OTHER, HashStatus.UNSUPPORTED
                        )
                except FileNotFoundError:
                    continue
                except PermissionError:
                    logger.warning("Permission denied for: %s", path)
                except OSError as exc:
                    logger.warning("Cannot inspect %s: %s", path, exc)

    def _scan_symlink(
        self, path: str, link_stat: os.stat_result | None = None
    ) -> Iterator[FileRecord]:
        if self._symlink_policy is SymlinkPolicy.SKIP:
            return
        if link_stat is None:
            try:
                link_stat = os.lstat(path)
            except OSError:
                return

        target = self._read_link(path)

        if self._symlink_policy is SymlinkPolicy.REPORT:
            yield self._build_record(
                path,
                link_stat,
                FileType.SYMLINK,
                HashStatus.NOT_APPLICABLE,
                is_symlink=True,
                link_target=target,
            )
            return

        # FOLLOW: describe the target, but never traverse through it.
        try:
            target_stat = os.stat(path)
        except PermissionError:
            yield self._build_record(
                path,
                link_stat,
                FileType.SYMLINK,
                HashStatus.PERMISSION_DENIED,
                is_symlink=True,
                link_target=target,
            )
            return
        except OSError as exc:
            logger.warning("Cannot follow symlink %s: %s", path, exc)
            yield self._build_record(
                path,
                link_stat,
                FileType.SYMLINK,
                HashStatus.ERROR,
                is_symlink=True,
                link_target=target,
            )
            return

        if stat_module.S_ISDIR(target_stat.st_mode):
            file_type, hash_status = FileType.DIRECTORY, HashStatus.NOT_APPLICABLE
        elif stat_module.S_ISREG(target_stat.st_mode):
            file_type, hash_status = FileType.REGULAR, None
        else:
            file_type, hash_status = FileType.OTHER, HashStatus.UNSUPPORTED

        yield self._build_record(
            path,
            target_stat,
            file_type,
            hash_status,
            is_symlink=True,
            link_target=target,
        )

    # -- Record building ---------------------------------------------------

    def _build_record(
        self,
        path: str,
        file_stat: os.stat_result,
        file_type: FileType,
        hash_status: HashStatus | None = None,
        *,
        is_symlink: bool = False,
        link_target: str | None = None,
    ) -> FileRecord:
        sha256: str | None = None
        status = hash_status
        if file_type is FileType.REGULAR:
            sha256, status = self._hash_file(path, file_stat.st_size)
        elif status is None:
            status = HashStatus.NOT_APPLICABLE

        return FileRecord(
            path=path,
            file_type=file_type,
            size_bytes=int(file_stat.st_size) if file_stat.st_size >= 0 else None,
            modified_at=_to_datetime(file_stat.st_mtime),
            sha256=sha256,
            hash_status=status,
            is_symlink=is_symlink,
            link_target=link_target,
        )

    def _hash_file(self, path: str, size: int | None) -> tuple[str | None, HashStatus]:
        """Stream a SHA-256 digest, honouring the configured size cap."""
        if size is not None and size > self._max_hash_bytes:
            return None, HashStatus.SKIPPED_SIZE

        digest = hashlib.sha256()
        total = 0
        try:
            with open(path, "rb") as handle:
                while True:
                    chunk = handle.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self._max_hash_bytes:
                        # File grew past the cap between stat and read.
                        return None, HashStatus.SKIPPED_SIZE
                    digest.update(chunk)
        except PermissionError:
            return None, HashStatus.PERMISSION_DENIED
        except OSError as exc:
            logger.debug("Cannot hash %s: %s", path, exc)
            return None, HashStatus.ERROR
        return digest.hexdigest(), HashStatus.HASHED

    @staticmethod
    def _read_link(path: str) -> str | None:
        try:
            return os.readlink(path)
        except OSError:
            return None


def collector_from_settings() -> FileCollector:
    """Build a collector from the process-wide agent settings."""
    settings = get_agent_settings()
    return FileCollector(
        paths=settings.file_integrity_paths,
        max_hash_bytes=settings.file_integrity_max_hash_bytes,
        symlink_policy=settings.file_integrity_symlink_policy,
    )


def collect_file_snapshot(paths: Iterable[str]) -> FileSnapshot:
    """Convenience wrapper for a single read-only snapshot of ``paths``."""
    return FileCollector(paths=paths).collect()


__all__ = ["FileCollector", "collect_file_snapshot", "collector_from_settings", "normalize_path"]
