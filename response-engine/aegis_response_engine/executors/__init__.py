"""Action executors.

Platform-specific execution of approved actions (firewall rules, process
termination, file quarantine).  Executors must be idempotent, reversible where
possible, and must refuse to run unless the workflow is approved.
"""

from __future__ import annotations

from aegis_response_engine.executors.executor import ExecutionResult, ResponseExecutor

__all__ = ["ExecutionResult", "ResponseExecutor"]
