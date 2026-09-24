"""Stable host identity for the endpoint agent.

Design goals
------------
* **Stable across restarts.** The identifier must not change every time the agent
  starts, otherwise host telemetry fragments across many phantom hosts.
* **Privacy-preserving.** No MAC addresses, disk serials, Windows ``MachineGuid``
  or other hardware fingerprints are read. Those are invasive and unnecessary for
  a host label.
* **Cross-platform.** Windows, Linux and macOS resolve their own application
  state directory.

Resolution order
----------------
1. ``AEGIS_AGENT_ID`` (operator-provided) - explicit and fully reproducible.
2. A previously persisted identifier in the agent's application state directory.
3. Otherwise a new UUIDv4 is generated **once** and persisted atomically.

The persisted identifier is an ordinary random UUID, not a hardware-derived
value. Deleting the state file simply causes a new identity to be minted on the
next run; set ``AEGIS_AGENT_ID`` when a fixed identifier is required.
"""

from __future__ import annotations

import contextlib
import os
import sys
import uuid
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

#: Name of the file holding the persisted host identifier.
HOST_ID_FILENAME = "host-id"

#: Maximum length accepted for a host identifier (mirrors the event schema).
_MAX_HOST_ID_LENGTH = 128


class HostIdSource(StrEnum):
    """Where the resolved host identifier came from."""

    CONFIGURED = "configured"
    PERSISTED = "persisted"
    GENERATED = "generated"


class HostIdentity(BaseModel):
    """The resolved identity of the local host."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str = Field(min_length=1, max_length=_MAX_HOST_ID_LENGTH)
    source: HostIdSource
    #: Where the identifier is persisted. ``None`` when it was configured externally.
    state_path: Path | None = None


def default_state_dir() -> Path:
    """Return the platform-appropriate application state directory.

    The path is namespaced to Aegis so nothing outside the agent's own state is
    ever written.
    """
    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        return base / "Aegis" / "agent"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Aegis" / "agent"

    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg_state_home) if xdg_state_home else Path.home() / ".local" / "state"
    return base / "aegis" / "agent"


def _restrict_permissions(path: Path, mode: int) -> None:
    """Best-effort permission tightening (POSIX only; Windows uses profile ACLs)."""
    if os.name == "nt":
        return
    # A restrictive mode is desirable but not worth failing startup over.
    with contextlib.suppress(OSError):
        path.chmod(mode)


class HostIdentityProvider:
    """Resolve, and if necessary persist, the local host identifier."""

    def __init__(
        self,
        *,
        state_dir: Path | None = None,
        configured_id: str | None = None,
    ) -> None:
        self._state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self._configured_id = (configured_id or "").strip()

    @property
    def state_dir(self) -> Path:
        """Directory holding the persisted identifier."""
        return self._state_dir

    @property
    def state_path(self) -> Path:
        """Full path of the persisted identifier file."""
        return self._state_dir / HOST_ID_FILENAME

    def resolve(self) -> HostIdentity:
        """Return the host identity, creating and persisting one if needed."""
        if self._configured_id:
            return HostIdentity(host_id=self._configured_id, source=HostIdSource.CONFIGURED)

        persisted = self._read_persisted()
        if persisted is not None:
            return HostIdentity(
                host_id=persisted,
                source=HostIdSource.PERSISTED,
                state_path=self.state_path,
            )

        host_id = str(uuid.uuid4())
        self._persist(host_id)
        return HostIdentity(
            host_id=host_id,
            source=HostIdSource.GENERATED,
            state_path=self.state_path,
        )

    def _read_persisted(self) -> str | None:
        """Read a valid identifier from disk, or ``None`` if absent/corrupt."""
        try:
            content = self.state_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not content or len(content) > _MAX_HOST_ID_LENGTH:
            return None
        return content

    def _persist(self, host_id: str) -> None:
        """Write the identifier atomically so a crash cannot leave a partial file."""
        self._state_dir.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(self._state_dir, 0o700)

        temp_path = self.state_path.with_suffix(".tmp")
        temp_path.write_text(f"{host_id}\n", encoding="utf-8")
        os.replace(temp_path, self.state_path)
        _restrict_permissions(self.state_path, 0o600)


__all__ = [
    "HOST_ID_FILENAME",
    "HostIdSource",
    "HostIdentity",
    "HostIdentityProvider",
    "default_state_dir",
]
