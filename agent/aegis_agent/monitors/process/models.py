"""Typed models for the read-only process monitor.

These are the *representation* layer: :class:`ProcessRecord` is a single process,
:class:`ProcessSnapshot` is the observed process set at one instant, and
:class:`ProcessChanges` is the difference between two snapshots. Collection lives
in :mod:`aegis_agent.monitors.process.collector` and comparison in
:mod:`aegis_agent.monitors.process.monitor`.

Process identity
----------------
A PID alone is **not** a valid identity: operating systems reuse PIDs. If a
process exits and another is later assigned the same PID, treating them as the
same process would corrupt the event stream. Identity is therefore
``(pid, create_time)`` when creation time is available, encoded by
:attr:`ProcessIdentity.key`. When creation time is unavailable the key degrades
to the PID alone - a documented limitation that is acceptable because it only
affects exotic platforms.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class ProcessIdentity(BaseModel):
    """Stable identity of a process, safe against PID reuse."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pid: int = Field(ge=0)
    create_time: datetime | None = None

    @property
    def key(self) -> str:
        """Opaque, comparable identity key used to diff snapshots."""
        if self.create_time is None:
            return f"{self.pid}:unknown"
        return f"{self.pid}:{self.create_time.isoformat()}"

    @property
    def is_reliable(self) -> bool:
        """Whether creation time was available (PID-reuse detection is exact)."""
        return self.create_time is not None


class ProcessRecord(BaseModel):
    """Safe metadata about one process.

    Deliberately excludes environment variables, memory contents, file contents,
    credentials and any other sensitive data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    pid: int = Field(ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: str | None = Field(default=None, max_length=255)
    parent_name: str | None = Field(default=None, max_length=255)
    executable_path: str | None = Field(default=None, max_length=1024)
    username: str | None = Field(default=None, max_length=255)
    #: Already passed through the command-line sanitizer before construction.
    command_line: str | None = Field(default=None, max_length=8192)
    create_time: datetime | None = Field(
        default=None,
        description="Process start time in UTC; part of the identity when present.",
    )

    @field_validator("create_time")
    @classmethod
    def _create_time_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def identity(self) -> ProcessIdentity:
        """The PID-reuse-safe identity of this process."""
        return ProcessIdentity(pid=self.pid, create_time=self.create_time)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class ProcessSnapshot(BaseModel):
    """The set of processes observed at one instant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    processes: tuple[ProcessRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def by_identity(self) -> dict[str, ProcessRecord]:
        """Map each process to its identity key for snapshot diffing."""
        return {record.identity.key: record for record in self.processes}

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class ProcessChanges(BaseModel):
    """Processes that appeared or disappeared between two snapshots."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started: tuple[ProcessRecord, ...] = ()
    stopped: tuple[ProcessRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def is_empty(self) -> bool:
        """Whether nothing changed."""
        return not self.started and not self.stopped

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["ProcessChanges", "ProcessIdentity", "ProcessRecord", "ProcessSnapshot"]
