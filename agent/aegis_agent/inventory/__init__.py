"""System inventory and host identity for the endpoint agent.

Public API
----------
* :func:`collect_system_inventory` - read the local host's non-sensitive facts.
* :class:`SystemInventory` - the validated, JSON-serialisable result.
* :class:`HostIdentityProvider` / :class:`HostIdentity` - stable host identity.

Future agent modules (process, port, file-integrity, YARA) reuse
:func:`collect_system_inventory` and the resolved host identity so every event
carries the same ``host_id`` and platform description.
"""

from __future__ import annotations

from aegis_agent.inventory.collector import collect_system_inventory
from aegis_agent.inventory.identity import (
    HOST_ID_FILENAME,
    HostIdentity,
    HostIdentityProvider,
    HostIdSource,
    default_state_dir,
)
from aegis_agent.inventory.models import INVENTORY_SCHEMA_VERSION, SystemInventory

__all__ = [
    "HOST_ID_FILENAME",
    "INVENTORY_SCHEMA_VERSION",
    "HostIdSource",
    "HostIdentity",
    "HostIdentityProvider",
    "SystemInventory",
    "collect_system_inventory",
    "default_state_dir",
]
