"""Host event pipeline: the shared transport plus host-monitor adapters.

The generic transport (validation, bounded dedup, bounded buffer, counters)
lives in :mod:`aegis_shared.pipeline` and is reused by every producer. This
subclass adds only the host-specific entry point that turns process/port/file
change sets into canonical events.
"""

from __future__ import annotations

from datetime import datetime

from aegis_agent.monitors.file_integrity.models import FileChanges
from aegis_agent.monitors.port.models import PortChanges
from aegis_agent.monitors.process.models import ProcessChanges
from aegis_agent.pipeline.collectors import collect_monitor_events
from aegis_shared.events import HostRef, SourceRef
from aegis_shared.pipeline import DEFAULT_DEDUP_WINDOW, EventPipeline

__all__ = ["DEFAULT_DEDUP_WINDOW", "HostEventPipeline"]


class HostEventPipeline(EventPipeline):
    """The shared event pipeline with host-monitor producer adapters."""

    def submit_monitor_changes(
        self,
        *,
        source: SourceRef,
        host: HostRef,
        timestamp: datetime | None = None,
        process_changes: ProcessChanges | None = None,
        port_changes: PortChanges | None = None,
        file_changes: FileChanges | None = None,
    ) -> list:
        """Convert monitor change sets to events and submit them."""
        events = collect_monitor_events(
            source=source,
            host=host,
            timestamp=timestamp,
            process_changes=process_changes,
            port_changes=port_changes,
            file_changes=file_changes,
        )
        return self.submit_all(events)
