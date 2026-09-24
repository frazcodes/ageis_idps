"""Network detectors (not implemented - by design).

This foundation produces normalized telemetry only. Port-scan, brute-force, DoS,
suspicious-egress, DNS and C2 detection all belong to the future NIDS detection
step and must consume the normalized records/events produced here rather than
touching packets directly.
"""

from __future__ import annotations

__all__: list[str] = []
