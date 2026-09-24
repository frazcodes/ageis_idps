"""Aegis IDPS shared contracts.

Single source of truth for cross-component vocabulary, the canonical
:class:`~aegis_shared.events.SecurityEvent` envelope, configuration bases and
logging helpers. Import from the concrete submodules for anything not re-exported
here:

* :mod:`aegis_shared.enums`
* :mod:`aegis_shared.events`
* :mod:`aegis_shared.config`
* :mod:`aegis_shared.logging`
* :mod:`aegis_shared.version`
"""

from __future__ import annotations

from .config import AegisSettings, Environment, get_settings
from .enums import (
    ActionStatus,
    ActionType,
    AddressFamily,
    AlertStatus,
    EventCategory,
    EventType,
    FileType,
    HashStatus,
    IncidentStatus,
    NetworkDirection,
    Platform,
    ResponseMode,
    RiskBand,
    Severity,
    SourceKind,
    TransportProtocol,
)
from .events import (
    ActorRef,
    CorrelationRef,
    FileContext,
    HostRef,
    NetworkContext,
    ProcessContext,
    RiskAssessment,
    SecurityEvent,
    SocketContext,
    SourceRef,
    band_for_score,
    severity_for_score,
)
from .logging import configure_logging, get_logger
from .version import EVENT_SCHEMA_VERSION, __version__

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "ActionStatus",
    "ActionType",
    "ActorRef",
    "AddressFamily",
    "AegisSettings",
    "AlertStatus",
    "CorrelationRef",
    "Environment",
    "EventCategory",
    "EventType",
    "FileContext",
    "FileType",
    "HashStatus",
    "HostRef",
    "IncidentStatus",
    "NetworkContext",
    "NetworkDirection",
    "Platform",
    "ProcessContext",
    "ResponseMode",
    "RiskAssessment",
    "RiskBand",
    "SecurityEvent",
    "Severity",
    "SocketContext",
    "SourceKind",
    "SourceRef",
    "TransportProtocol",
    "__version__",
    "band_for_score",
    "configure_logging",
    "get_logger",
    "get_settings",
    "severity_for_score",
]
