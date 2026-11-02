"""Custom interactive tactical widgets for Aegis IDPS."""

from aegis_desktop.widgets.attack_graph import InteractiveAttackGraphWidget
from aegis_desktop.widgets.circular_radar import TacticalCircularRadarWidget
from aegis_desktop.widgets.world_attack_map import GlobalThreatMapContainer, WorldAttackMapWidget

__all__ = [
    "GlobalThreatMapContainer",
    "InteractiveAttackGraphWidget",
    "TacticalCircularRadarWidget",
    "WorldAttackMapWidget",
]
