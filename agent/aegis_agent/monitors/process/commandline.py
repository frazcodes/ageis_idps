"""Best-effort redaction of secrets from process command lines.

Command lines are valuable for attack-chain analysis but can contain credentials
(``--password=...``, ``PASSWORD=...``, ``Authorization: Bearer ...``, database
URLs). The shared :func:`aegis_shared.logging.redact` only handles *mapping
values keyed by name*, so it cannot help with a free-text command line.

This module applies a small set of conservative regexes that replace the value
of secret-looking options/assignments with :data:`aegis_shared.logging.REDACTED`.

Limitation
----------
This is heuristic, not a guarantee: a secret passed in an unusual form (e.g.
split across arguments, base64-encoded, or under an unrecognised flag) may
survive. Command lines are therefore still treated as sensitive data and should
be access-controlled at the backend. Process memory is never inspected.
"""

from __future__ import annotations

import re

from aegis_shared.logging import REDACTED

#: Command lines are truncated to this many characters before storage.
MAX_COMMAND_LINE_LENGTH = 4096

_TRUNCATION_SUFFIX = "...[truncated]"

#: Option/assignment names whose value is likely a secret.
_SENSITIVE_NAMES = (
    r"(?:password|passwd|pwd|pass|token|secret|api[-_]?key|apikey|"
    r"access[-_]?key|private[-_]?key|credential|credentials|"
    r"auth|authorization|bearer|client[-_]?secret)"
)

#: ``--password=value`` / ``--token value`` / ``/pwd:value`` (Windows style).
_SENSITIVE_OPTION = re.compile(
    rf"(?i)((?:--?|/){_SENSITIVE_NAMES}(?:[=\s:]+))(\"[^\"]*\"|'[^']*'|\S+)"
)

#: ``PASSWORD=value`` / ``API_KEY=value`` (environment-style assignment).
_ENV_ASSIGNMENT = re.compile(rf"(?i)\b((?:{_SENSITIVE_NAMES})[A-Z0-9_]*=)(\"[^\"]*\"|'[^']*'|\S+)")

#: ``scheme://user:password@host`` connection strings.
_URL_CREDENTIALS = re.compile(r"(?i)(://[^/\s:@]+:)([^/\s@]+)(@)")

#: ``Authorization: Bearer <token>``.
_BEARER_TOKEN = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._\-]+)")


def sanitize_command_line(command_line: str | None) -> str | None:
    """Return ``command_line`` with obvious secrets redacted and length capped.

    ``None`` and empty input return ``None`` so downstream models store a clean
    "unavailable" rather than an empty string.
    """
    if not command_line:
        return None

    sanitized = command_line.strip()
    sanitized = _URL_CREDENTIALS.sub(rf"\1{REDACTED}\3", sanitized)
    sanitized = _BEARER_TOKEN.sub(rf"\1{REDACTED}", sanitized)
    sanitized = _ENV_ASSIGNMENT.sub(rf"\1{REDACTED}", sanitized)
    sanitized = _SENSITIVE_OPTION.sub(rf"\1{REDACTED}", sanitized)

    if len(sanitized) > MAX_COMMAND_LINE_LENGTH:
        sanitized = sanitized[:MAX_COMMAND_LINE_LENGTH] + _TRUNCATION_SUFFIX
    return sanitized


__all__ = ["MAX_COMMAND_LINE_LENGTH", "sanitize_command_line"]
