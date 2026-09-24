"""Consistent, secret-aware logging for every Aegis component.

Security software logs a lot of untrusted input. Two rules keep that safe:

1. **Structured by default in production** - JSON records ship cleanly to a SIEM.
2. **Redact aggressively** - values whose key looks like a credential are replaced
   with ``***REDACTED***`` before a record is emitted.

Use :func:`configure_logging` once at process start and :func:`get_logger`
everywhere else.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

REDACTED = "***REDACTED***"

#: Substrings that mark a mapping key as sensitive (matched case-insensitively).
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "credential",
    "session_key",
)

#: Standard ``LogRecord`` attributes that should not be copied into JSON extras.
_RESERVED_RECORD_KEYS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_KEY_PARTS)


def redact(value: Any) -> Any:
    """Recursively replace sensitive values with :data:`REDACTED`.

    Mappings are filtered by key name; sequences are redacted element-wise.
    Anything else is returned unchanged.
    """
    if isinstance(value, Mapping):
        return {
            key: REDACTED if _is_sensitive_key(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


class RedactingFilter(logging.Filter):
    """Scrub credential-looking values from a record's structured extras."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, Mapping):
            record.args = redact(record.args)
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED_RECORD_KEYS:
                continue
            if _is_sensitive_key(key):
                record.__dict__[key] = REDACTED
            elif isinstance(value, Mapping):
                record.__dict__[key] = redact(value)
        return True


class JsonFormatter(logging.Formatter):
    """Render a log record as a single-line JSON object."""

    def __init__(self, *, service: str | None = None) -> None:
        super().__init__()
        self._service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self._service is not None:
            payload["service"] = self._service
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_KEYS or key.startswith("_"):
                continue
            payload[key] = REDACTED if _is_sensitive_key(key) else redact(value)

        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable formatter that also renders structured extras."""

    def __init__(self, *, service: str | None = None) -> None:
        prefix = "%(asctime)s %(levelname)-8s %(name)s"
        if service is not None:
            prefix = f"%(asctime)s %(levelname)-8s [{service}] %(name)s"
        super().__init__(fmt=f"{prefix}: %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool = False,
    service: str | None = None,
) -> None:
    """Configure the root logger for a process.

    Idempotent: repeated calls replace the handlers rather than stacking them.

    Args:
        level: Root log level name (e.g. ``"INFO"``, ``"DEBUG"``).
        json_output: Emit JSON when ``True``, human-readable text otherwise.
        service: Optional service name stamped on every record.
    """
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(
        JsonFormatter(service=service) if json_output else TextFormatter(service=service)
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    """Return the named logger.

    Thin wrapper that keeps a single import site for logging across components.
    """
    return logging.getLogger(name)


__all__ = [
    "REDACTED",
    "JsonFormatter",
    "RedactingFilter",
    "TextFormatter",
    "configure_logging",
    "get_logger",
    "redact",
]
