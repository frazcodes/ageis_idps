"""Configuration for the Aegis response engine.

Safety model, in order of precedence:

1. ``mode`` selects between observing (``monitor``), simulating (``dry_run``) and
   acting (``enforce``).
2. ``dry_run`` forces simulation even when ``mode`` is ``enforce``.
3. ``require_approval`` demands an explicit human/policy approval before execution.

The defaults are the safest possible: observe, simulate, require approval.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings
from aegis_shared.enums import ResponseMode


class ResponseEngineSettings(AegisSettings):
    """Settings for the response/IPS engine."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_RESPONSE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    mode: ResponseMode = Field(
        default=ResponseMode.MONITOR,
        description="Operating mode. Only 'monitor' is safe by default.",
    )
    dry_run: bool = Field(
        default=True,
        description="Simulate actions without modifying the host or network.",
    )
    require_approval: bool = Field(
        default=True,
        description="Require approval before any action is executed.",
    )

    @property
    def enforcement_enabled(self) -> bool:
        """Whether real actions may be executed.

        ``True`` only when the engine is explicitly in ``enforce`` mode *and*
        ``dry_run`` has been turned off.
        """
        return self.mode is ResponseMode.ENFORCE and not self.dry_run


@lru_cache(maxsize=1)
def get_response_settings() -> ResponseEngineSettings:
    """Return the process-wide response settings (loaded once)."""
    return ResponseEngineSettings()


__all__ = ["ResponseEngineSettings", "get_response_settings"]
