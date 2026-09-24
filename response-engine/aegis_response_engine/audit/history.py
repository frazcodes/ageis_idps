"""Bounded in-memory audit history store.

:class:`ResponseAuditHistory` maintains an append-only, FIFO-evicting ring of
:class:`ResponseAuditRecord` instances.  The store is process-scoped and
never touches disk.
"""

from __future__ import annotations

from aegis_response_engine.audit.models import ResponseAuditRecord

#: Default bound for the audit history.
MAX_AUDIT_RECORDS: int = 512


class ResponseAuditHistory:
    """Bounded, append-only in-memory audit history.

    When the store reaches ``max_records`` the oldest record is evicted.
    """

    def __init__(self, max_records: int = MAX_AUDIT_RECORDS) -> None:
        self._max = max_records
        self._records: list[ResponseAuditRecord] = []

    @property
    def count(self) -> int:
        """Current number of stored audit records."""
        return len(self._records)

    def add(self, record: ResponseAuditRecord) -> None:
        """Append a record, evicting the oldest when at capacity."""
        self._records.append(record)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]

    def all_records(self) -> tuple[ResponseAuditRecord, ...]:
        """Return all records, newest first."""
        return tuple(reversed(self._records))

    def records_for_request(self, request_id: str) -> tuple[ResponseAuditRecord, ...]:
        """Return audit records for a specific request, newest first."""
        matches = [r for r in self._records if r.request_id == request_id]
        return tuple(reversed(matches))

    def clear(self) -> None:
        """Remove all records."""
        self._records.clear()


__all__ = ["MAX_AUDIT_RECORDS", "ResponseAuditHistory"]
