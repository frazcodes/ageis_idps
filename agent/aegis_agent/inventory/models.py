"""Structured representation of an endpoint's system inventory.

The model is deliberately a closed, immutable Pydantic model, matching the
conventions used by :mod:`aegis_shared.events`: unknown fields fail loudly and
timestamps must be timezone-aware UTC. It is the *representation* half of the
inventory component - collection lives in :mod:`aegis_agent.inventory.collector`
and identity in :mod:`aegis_agent.inventory.identity`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import Platform
from aegis_shared.events import HostRef

#: Version of the inventory document. Bump MINOR for additive fields, MAJOR for
#: breaking changes, so consumers can migrate deliberately.
INVENTORY_SCHEMA_VERSION = "1.0.0"


class SystemInventory(BaseModel):
    """Non-sensitive technical facts about the host the agent runs on.

    This intentionally excludes anything privacy- or security-sensitive: no
    usernames, environment variables, files, credentials or hardware serials.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    schema_version: str = Field(default=INVENTORY_SCHEMA_VERSION, max_length=16)

    # --- Identity ---------------------------------------------------------
    host_id: str = Field(
        min_length=1,
        max_length=128,
        description="Stable agent-assigned host identifier (see aegis_agent.inventory.identity).",
    )
    hostname: str = Field(min_length=1, max_length=255)

    # --- Operating system -------------------------------------------------
    platform: Platform = Platform.UNKNOWN
    os_name: str = Field(min_length=1, max_length=128)
    os_version: str | None = Field(default=None, max_length=255)
    architecture: str = Field(min_length=1, max_length=64)

    # --- Software ---------------------------------------------------------
    python_version: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(min_length=1, max_length=32)

    # --- Resources (may be unavailable on restricted platforms) -----------
    boot_time: datetime | None = Field(
        default=None,
        description="Host boot time in UTC, when the platform exposes it.",
    )
    cpu_count: int | None = Field(default=None, ge=0, description="Logical CPU count.")
    total_memory_bytes: int | None = Field(default=None, ge=0)

    # --- Provenance -------------------------------------------------------
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("boot_time", "collected_at")
    @classmethod
    def _require_aware_utc(cls, value: datetime | None, info: Any) -> datetime | None:
        """Reject naive timestamps and normalise aware ones to UTC."""
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError(f"{info.field_name} must be timezone-aware UTC")
        return value.astimezone(UTC)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping (enums as strings, datetimes as ISO 8601)."""
        return self.model_dump(mode="json")

    def to_host_ref(self) -> HostRef:
        """Build the shared :class:`~aegis_shared.events.HostRef` for this host.

        Monitors reuse this so every emitted event carries the same stable
        ``host_id`` and platform description as the inventory.
        """
        return HostRef(
            host_id=self.host_id,
            hostname=self.hostname,
            platform=self.platform,
            os_version=self.os_version,
        )


__all__ = ["INVENTORY_SCHEMA_VERSION", "SystemInventory"]
