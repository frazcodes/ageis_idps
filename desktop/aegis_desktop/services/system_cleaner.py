"""System Hygiene & Storage Optimization service.

Scans and purges temporary staging directories, malware dropper caches,
Windows crash dumps, and prefetch artifacts safely.
Handles in-use and locked files gracefully without interrupting operations.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime

from aegis_desktop.services.dashboard import format_bytes
from aegis_shared.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class HygieneCategory:
    """Scan statistics for one target directory category."""

    id: str
    name: str
    description: str
    path: str
    file_count: int
    size_bytes: int
    accessible: bool
    is_safe_to_purge: bool = True

    @property
    def size_formatted(self) -> str:
        return format_bytes(self.size_bytes)


@dataclass(frozen=True)
class HygieneScanResult:
    """Outcome of a system hygiene scan."""

    total_files: int
    total_bytes: int
    categories: tuple[HygieneCategory, ...]
    scanned_at: datetime
    error: str | None = None

    @property
    def total_bytes_formatted(self) -> str:
        return format_bytes(self.total_bytes)


@dataclass(frozen=True)
class HygieneCleanResult:
    """Outcome of a system hygiene purge/clean action."""

    cleaned_files: int
    reclaimed_bytes: int
    skipped_files: int
    cleaned_categories: tuple[str, ...]
    cleaned_at: datetime
    error: str | None = None

    @property
    def reclaimed_bytes_formatted(self) -> str:
        return format_bytes(self.reclaimed_bytes)


def _measure_tree(path: str) -> tuple[int, int]:
    """Measure total file count and byte size in a directory tree."""
    count = 0
    total_bytes = 0
    try:
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    stat = os.stat(os.path.join(root, f))
                    total_bytes += stat.st_size
                    count += 1
                except (OSError, PermissionError):
                    count += 1
    except (OSError, PermissionError):
        pass
    return count, total_bytes


def _clean_tree_lenient(path: str) -> tuple[int, int, int]:
    """Recursively delete files in tree, skipping locked files without crashing."""
    c = 0
    b = 0
    s = 0
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            f_p = os.path.join(root, f)
            try:
                st = os.stat(f_p)
                f_sz = st.st_size
                os.unlink(f_p)
                c += 1
                b += f_sz
            except (OSError, PermissionError):
                s += 1
        for d in dirs:
            d_p = os.path.join(root, d)
            with contextlib.suppress(OSError, PermissionError):
                os.rmdir(d_p)
    with contextlib.suppress(OSError, PermissionError):
        os.rmdir(path)
    return c, b, s


def scan_category(cat_id: str, name: str, desc: str, path: str) -> HygieneCategory:
    """Safely scan a target directory category."""
    if not path or not os.path.exists(path):
        return HygieneCategory(
            id=cat_id,
            name=name,
            description=desc,
            path=path or "",
            file_count=0,
            size_bytes=0,
            accessible=False,
        )

    file_count = 0
    size_bytes = 0
    accessible = True

    try:
        for root, _dirs, files in os.walk(path):
            for f in files:
                f_path = os.path.join(root, f)
                try:
                    stat = os.stat(f_path)
                    size_bytes += stat.st_size
                    file_count += 1
                except (OSError, PermissionError):
                    file_count += 1
    except (OSError, PermissionError):
        accessible = False

    return HygieneCategory(
        id=cat_id,
        name=name,
        description=desc,
        path=path,
        file_count=file_count,
        size_bytes=size_bytes,
        accessible=accessible,
    )


def clean_category_path(path: str) -> tuple[int, int, int]:
    """Clean files and subdirectories inside path without deleting path itself.

    Returns:
        (cleaned_files, reclaimed_bytes, skipped_files)
    """
    if not path or not os.path.exists(path) or not os.path.isdir(path):
        return 0, 0, 0

    cleaned_files = 0
    reclaimed_bytes = 0
    skipped_files = 0

    norm_path = os.path.abspath(path)

    try:
        entries = list(os.scandir(norm_path))
    except (OSError, PermissionError):
        return 0, 0, 1

    for entry in entries:
        entry_path = entry.path
        if not entry_path.startswith(norm_path):
            continue

        try:
            if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                try:
                    st = entry.stat(follow_symlinks=False)
                    f_size = st.st_size
                except (OSError, PermissionError):
                    f_size = 0
                os.unlink(entry_path)
                cleaned_files += 1
                reclaimed_bytes += f_size
            elif entry.is_dir(follow_symlinks=False):
                tree_files, tree_bytes = _measure_tree(entry_path)
                try:
                    shutil.rmtree(entry_path, ignore_errors=False)
                    cleaned_files += tree_files
                    reclaimed_bytes += tree_bytes
                except (OSError, PermissionError):
                    c, b, s = _clean_tree_lenient(entry_path)
                    cleaned_files += c
                    reclaimed_bytes += b
                    skipped_files += s
        except (OSError, PermissionError):
            skipped_files += 1

    return cleaned_files, reclaimed_bytes, skipped_files


def get_hygiene_target_paths() -> list[tuple[str, str, str, str]]:
    """Return configured targets: (cat_id, name, description, path)."""
    targets: list[tuple[str, str, str, str]] = []

    # 1. User Temp Directory
    user_temp = os.environ.get("TEMP") or os.environ.get("TMP") or tempfile.gettempdir()
    targets.append((
        "user_temp",
        "User Temporary Files (%TEMP%)",
        "Application caches, session tokens, and common malware dropper staging directory.",
        os.path.abspath(user_temp),
    ))

    # 2. Windows System Temp
    sys_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
    sys_temp = os.path.join(sys_root, "Temp")
    if os.path.exists(sys_temp):
        targets.append((
            "system_temp",
            "Windows System Temp (%WINDIR%\\Temp)",
            "OS-level installer residue, update staging, and service temp files.",
            os.path.abspath(sys_temp),
        ))

    # 3. Prefetch Artifacts
    prefetch = os.path.join(sys_root, "Prefetch")
    if os.path.exists(prefetch):
        targets.append((
            "prefetch",
            "Windows Prefetch Artifacts",
            "Execution trace files (.pf) used for launch timing and forensic tracking.",
            os.path.abspath(prefetch),
        ))

    # 4. Crash Dumps
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        crash_dumps = os.path.join(local_appdata, "CrashDumps")
        if os.path.exists(crash_dumps):
            targets.append((
                "crash_dumps",
                "Crash Dumps & Minidumps",
                "Windows Error Reporting core memory dumps and application failure logs.",
                os.path.abspath(crash_dumps),
            ))

    return targets


def scan_system_hygiene() -> HygieneScanResult:
    """Scan all configured hygiene targets and compute file counts and sizes."""
    targets = get_hygiene_target_paths()
    categories: list[HygieneCategory] = []
    total_files = 0
    total_bytes = 0

    for cat_id, name, desc, path in targets:
        cat = scan_category(cat_id, name, desc, path)
        categories.append(cat)
        total_files += cat.file_count
        total_bytes += cat.size_bytes

    return HygieneScanResult(
        total_files=total_files,
        total_bytes=total_bytes,
        categories=tuple(categories),
        scanned_at=datetime.now(UTC),
    )


def clean_system_hygiene(
    category_ids: list[str] | tuple[str, ...] | None = None,
) -> HygieneCleanResult:
    """Purge temporary and cache files from selected target categories."""
    targets = get_hygiene_target_paths()
    total_cleaned = 0
    total_reclaimed = 0
    total_skipped = 0
    cleaned_cats: list[str] = []

    for cat_id, name, _desc, path in targets:
        if category_ids is not None and cat_id not in category_ids:
            continue
        c, r, s = clean_category_path(path)
        total_cleaned += c
        total_reclaimed += r
        total_skipped += s
        cleaned_cats.append(name)

    return HygieneCleanResult(
        cleaned_files=total_cleaned,
        reclaimed_bytes=total_reclaimed,
        skipped_files=total_skipped,
        cleaned_categories=tuple(cleaned_cats),
        cleaned_at=datetime.now(UTC),
    )


__all__ = [
    "HygieneCategory",
    "HygieneCleanResult",
    "HygieneScanResult",
    "clean_category_path",
    "clean_system_hygiene",
    "get_hygiene_target_paths",
    "scan_category",
    "scan_system_hygiene",
]
