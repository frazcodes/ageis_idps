"""Tests for secret redaction and JSON log formatting."""

from __future__ import annotations

import logging

from aegis_shared.logging import REDACTED, JsonFormatter, RedactingFilter, redact


def test_redact_mapping_removes_sensitive_keys() -> None:
    result = redact({"user": "alice", "api_key": "abc123", "nested": {"password": "hunter2"}})
    assert result["user"] == "alice"
    assert result["api_key"] == REDACTED
    assert result["nested"]["password"] == REDACTED


def test_redact_sequences_element_wise() -> None:
    assert redact([{"token": "x"}, "plain"]) == [{"token": REDACTED}, "plain"]


def _record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        name="aegis.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_includes_message_and_redacts_secrets() -> None:
    output = JsonFormatter(service="test-service").format(_record(api_key="super-secret"))
    assert "hello world" in output
    assert "test-service" in output
    assert "super-secret" not in output
    assert REDACTED in output


def test_redacting_filter_scrubs_mapping_args() -> None:
    record = _record()
    record.args = {"password": "hunter2", "user": "alice"}
    assert RedactingFilter().filter(record)
    assert record.args["password"] == REDACTED
    assert record.args["user"] == "alice"
