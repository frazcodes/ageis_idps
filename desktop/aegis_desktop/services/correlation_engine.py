# Correlation Engine Service
# Loads JSON rule definitions from config/rules/ and evaluates them against incoming SecurityEvent objects.
# Each rule defines a name, optional description, a list of "conditions" expressed as simple attribute checks,
# and an "action" indicating what to do when the rule matches (e.g., raise_alert, block_ip).

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List

from aegis_shared.logging import get_logger

logger = get_logger(__name__)

# Simple condition evaluator – supports '=', '!=', '<', '<=', '>', '>=' on event attributes.
_OPERATORS: Dict[str, Callable[[Any, Any], bool]] = {
    "=": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
}


class CorrelationRule:
    def __init__(self, data: Dict[str, Any]):
        self.name: str = data.get("name", "unnamed_rule")
        self.description: str = data.get("description", "")
        self.conditions: List[Dict[str, Any]] = data.get("conditions", [])
        self.action: str = data.get("action", "raise_alert")
        self.action_params: Dict[str, Any] = data.get("action_params", {})

    def matches(self, event: Dict[str, Any]) -> bool:
        """Return True if all conditions are satisfied for the given event dict.
        Condition format: {"field": "src_ip", "op": "=", "value": "192.168.1.10"}
        """
        for cond in self.conditions:
            field = cond.get("field")
            op = cond.get("op")
            value = cond.get("value")
            if field is None or op is None:
                logger.warning(f"Invalid condition in rule {self.name}: {cond}")
                return False
            if op not in _OPERATORS:
                logger.warning(f"Unsupported operator '{op}' in rule {self.name}")
                return False
            event_value = event.get(field)
            try:
                if not _OPERATORS[op](event_value, value):
                    return False
            except Exception as e:
                logger.error(f"Error evaluating condition {cond} on event {event}: {e}")
                return False
        return True


class CorrelationEngine:
    """Loads JSON rule files from a directory and evaluates events against them.
    The engine is deliberately lightweight – it does not keep state, only matches per‑event.
    """

    def __init__(self, rules_dir: str | None = None):
        # Default directory is ``config/rules`` at the project root.
        default_dir = Path(__file__).resolve().parents[2] / "config" / "rules"
        self.rules_path: Path = Path(rules_dir) if rules_dir else default_dir
        self.rules: List[CorrelationRule] = []
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            logger.info(f"Correlation rules directory does not exist: {self.rules_path}")
            return
        for file in self.rules_path.glob("*.json"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                rule = CorrelationRule(data)
                self.rules.append(rule)
                logger.debug(f"Loaded correlation rule: {rule.name}")
            except Exception as e:
                logger.error(f"Failed to load rule from {file}: {e}")

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return a list of actions for rules that match the given event.
        Each entry is ``{"action": <action>, "params": <action_params>, "rule": <rule_name>}``.
        """
        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            if rule.matches(event):
                matches.append({
                    "action": rule.action,
                    "params": rule.action_params,
                    "rule": rule.name,
                })
                logger.info(f"Correlation rule matched: {rule.name} on event {event.get('id')}")
        return matches

    def reload(self) -> None:
        """Reload rule files – useful when a user edits JSON files at runtime."""
        self.rules.clear()
        self._load_rules()


# Provide a shared singleton for the rest of the application.
correlation_engine = CorrelationEngine()
