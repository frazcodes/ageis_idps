"""Typed models for read-only file-integrity monitoring.

Representation layer: :class:`FileRecord` is one filesystem object,
:class:`FileSnapshot` is the observed set at one instant, and
:class:`FileChanges` is the difference between two snapshots.

File identity vs change signature
---------------------------------
Two different concerns, deliberately kept apart:

* :attr:`FileIdentity.key` is the **normalized path** - the stable anchor used to
  pair objects across snapshots. It intentionally excludes size/mtime/hash, so a
  content change is reported as a *modification*, not as a delete plus create.
* :attr:`FileRecord.change_signature` captures type/size/mtime/hash and the hash
  status. A modification is raised when this signature differs. Because the hash
  status is part of the signature, a hash that becomes unavailable (permission,
  size limit, error) is never silently treated as "unchanged".

File contents are never part of the identity.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import FileType, HashStatus


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class FileIdentity(BaseModel):
    """Stable identity of a filesystem object: the normalized path."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, max_length=4096)

    @property
    def key(self) -> str:
        """Opaque, comparable identity key used to diff snapshots.

        Case is folded on case-insensitive platforms (Windows) so a path that
        only changes case does not produce a spurious event; on POSIX it is
        case-sensitive, matching the filesystem.
        """
        return os.path.normcase(self.path)


class FileRecord(BaseModel):
    """Safe metadata about one filesystem object.

    Contains no file contents and no environment data - only metadata plus a
    SHA-256 digest when the object is eligible and readable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    path: str = Field(min_length=1, max_length=4096)
    file_type: FileType
    size_bytes: int | None = Field(default=None, ge=0)
    modified_at: datetime | None = Field(default=None)
    #: Lowercase hex SHA-256, or ``None`` when hashing was not possible.
    sha256: str | None = Field(default=None, max_length=64)
    hash_status: HashStatus = HashStatus.NOT_APPLICABLE
    #: Whether this entry is a symlink (relevant when policy is ``report``/``follow``).
    is_symlink: bool = False
    #: Symlink target as reported by the OS, when this entry is a symlink.
    link_target: str | None = Field(default=None, max_length=4096)

    @field_validator("modified_at")
    @classmethod
    def _modified_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def identity(self) -> FileIdentity:
        """The stable identity (normalized path) of this object."""
        return FileIdentity(path=self.path)

    @property
    def change_signature(self) -> tuple[object, ...]:
        """Fields whose difference means the object was modified."""
        return (
            self.file_type,
            self.size_bytes,
            self.modified_at,
            self.sha256,
            self.hash_status,
        )

    def differs_from(self, other: FileRecord) -> bool:
        """Whether this record represents a meaningful change from ``other``."""
        return self.change_signature != other.change_signature

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class FileSnapshot(BaseModel):
    """The set of filesystem objects observed at one instant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    files: tuple[FileRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def by_path(self) -> dict[str, FileRecord]:
        """Map each object to its identity key for snapshot diffing."""
        return {record.identity.key: record for record in self.files}

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class FileModification(BaseModel):
    """A file that exists in both snapshots with a changed signature."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    previous: FileRecord
    current: FileRecord

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class FileChanges(BaseModel):
    """Filesystem objects created, modified or deleted between two snapshots."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created: tuple[FileRecord, ...] = ()
    modified: tuple[FileModification, ...] = ()
    deleted: tuple[FileRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def is_empty(self) -> bool:
        """Whether nothing changed."""
        return not self.created and not self.modified and not self.deleted

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = [
    "FileChanges",
    "FileIdentity",
    "FileModification",
    "FileRecord",
    "FileSnapshot",
]
