"""Configuration for the Aegis endpoint agent.

Every collection feature is **off by default**. Enabling a monitor is an explicit,
auditable decision, because process, connection and file monitoring are
privacy-sensitive on a user's machine.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings

#: Default cap on file size that will be hashed by file-integrity monitoring.
DEFAULT_MAX_HASH_BYTES = 10 * 1024 * 1024


class SymlinkPolicy(StrEnum):
    """How file-integrity monitoring treats symbolic links.

    ``SKIP`` is the default because following links can escape the configured
    tree and traverse into unrelated parts of the filesystem.
    """

    SKIP = "skip"
    REPORT = "report"
    FOLLOW = "follow"


class AgentSettings(AegisSettings):
    """Settings for a single endpoint agent instance."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    backend_url: str = Field(
        default="http://127.0.0.1:8000",
        description="Base URL of the central backend API.",
    )
    agent_id: str = Field(
        default="",
        description="Stable agent identifier, assigned on enrolment.",
    )
    state_dir: str = Field(
        default="",
        description="Directory for agent state such as the persisted host identity. "
        "Empty uses the platform default.",
    )
    heartbeat_interval: int = Field(
        default=30,
        ge=5,
        le=3600,
        description="Seconds between heartbeats to the backend.",
    )

    # --- Monitors (all opt-in) -------------------------------------------
    enable_process_monitor: bool = False
    enable_port_monitor: bool = False
    enable_connection_monitor: bool = False
    enable_file_integrity: bool = False
    enable_yara: bool = False

    # --- File integrity monitoring (opt-in, explicit paths only) ----------
    file_integrity_paths: list[str] = Field(
        default_factory=list,
        description="Explicit files/directories to monitor. Nothing is scanned by default. "
        "Comma-separated in the environment.",
    )
    file_integrity_interval: int = Field(
        default=300,
        ge=5,
        le=86400,
        description="Seconds between file-integrity polls when run continuously.",
    )
    file_integrity_max_hash_bytes: int = Field(
        default=DEFAULT_MAX_HASH_BYTES,
        ge=0,
        description="Files larger than this are not hashed (0 disables hashing).",
    )
    file_integrity_symlink_policy: SymlinkPolicy = Field(
        default=SymlinkPolicy.SKIP,
        description="How symlinks are handled: skip, report or follow.",
    )

    # --- Host event pipeline (in-memory only) -----------------------------
    event_buffer_max_events: int = Field(
        default=1000,
        ge=1,
        le=1_000_000,
        description="Maximum events held in the in-memory pipeline buffer.",
    )

    @field_validator("file_integrity_paths", mode="before")
    @classmethod
    def _split_paths(cls, value: object) -> object:
        """Accept a comma-separated string from the environment as well as a list."""
        if isinstance(value, str):
            raw = value.strip()
            if not raw or raw.startswith("["):
                return value if raw else []
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value

    @property
    def enabled_monitors(self) -> tuple[str, ...]:
        """Names of the monitors that have been explicitly enabled."""
        candidates = {
            "process": self.enable_process_monitor,
            "port": self.enable_port_monitor,
            "connection": self.enable_connection_monitor,
            "file_integrity": self.enable_file_integrity,
            "yara": self.enable_yara,
        }
        return tuple(name for name, enabled in candidates.items() if enabled)


@lru_cache(maxsize=1)
def get_agent_settings() -> AgentSettings:
    """Return the process-wide agent settings (loaded once)."""
    return AgentSettings()


__all__ = ["AgentSettings", "get_agent_settings"]
