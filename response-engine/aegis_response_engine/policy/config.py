"""Typed configuration for the response policy engine.

The defaults are **fail-closed**: response execution is disabled, approval and a
dry run are required, and the risk threshold is conservative. An action is never
considered executable when the policy is missing or ambiguous.

Environment prefix: ``AEGIS_RESPONSE_POLICY_``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings
from aegis_shared.enums import ActionType, RiskLevel


class ResponsePolicySettings(AegisSettings):
    """Bounded, safe-by-default response policy."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_RESPONSE_POLICY_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    policy_version: str = Field(
        default="1.0.0",
        min_length=1,
        max_length=32,
        description="Deterministic policy version stamped on every decision.",
    )

    response_enabled: bool = Field(
        default=False,
        description="Master switch. Disabled by default so nothing is executable.",
    )
    automatic_execution: bool = Field(
        default=False,
        description="Whether actions could ever run without an explicit request.",
    )
    approval_required: bool = Field(
        default=True,
        description="Require administrator approval before any future execution.",
    )
    dry_run_required: bool = Field(
        default=True,
        description="Require a dry run before any future execution.",
    )

    min_risk_level: RiskLevel = Field(
        default=RiskLevel.HIGH,
        description="Minimum observed risk level required for an action to be permitted.",
    )
    min_risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Minimum observed risk score required for an action to be permitted.",
    )

    allowed_actions: list[str] = Field(
        default_factory=list,
        description=(
            "Explicit allow-list of action values (e.g. 'block_ip'). Empty means all "
            "supported actions are permitted by this dimension."
        ),
    )

    @field_validator("allowed_actions", mode="before")
    @classmethod
    def _split_actions(cls, value: object) -> object:
        if isinstance(value, str):
            raw = value.strip()
            if not raw or raw.startswith("["):
                return value if raw else []
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value

    @field_validator("allowed_actions")
    @classmethod
    def _clean_actions(cls, value: list[str]) -> list[str]:
        known = {action.value for action in ActionType}
        cleaned: list[str] = []
        for item in value:
            text = item.strip().lower()
            if not text:
                continue
            if text not in known:
                raise ValueError(f"unknown response action: {item!r}")
            cleaned.append(text)
        return sorted(set(cleaned))


@lru_cache(maxsize=1)
def get_response_policy_settings() -> ResponsePolicySettings:
    """Return the process-wide response policy settings (loaded once)."""
    return ResponsePolicySettings()


__all__ = ["ResponsePolicySettings", "get_response_policy_settings"]
