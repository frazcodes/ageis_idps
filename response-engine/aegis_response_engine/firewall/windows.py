"""Windows Firewall adapter using ``netsh advfirewall``.

All OS interaction is isolated inside this module.  The adapter uses argument
arrays (no ``shell=True``), validated IP targets, captured stdout/stderr,
timeouts and return-code checking.  Rule names are deterministic and Aegis-owned.
"""

from __future__ import annotations

import ipaddress
import subprocess
from datetime import datetime

from aegis_response_engine.firewall.base import FirewallAdapter
from aegis_response_engine.firewall.models import FirewallActionResult, FirewallActionStatus
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Prefix for all Aegis-owned firewall rules.
_RULE_PREFIX = "AEGIS-BLOCK-IP"


def _normalize_ip(ip: str) -> str:
    """Normalize an IP address to its canonical form.

    Raises ``ValueError`` if the address is invalid.
    """
    addr = ipaddress.ip_address(ip.strip())
    return str(addr)


def _rule_name(ip: str) -> str:
    """Deterministic Aegis rule name for a given IP target."""
    normalized = _normalize_ip(ip)
    safe = normalized.replace(":", "-")
    return f"{_RULE_PREFIX}-{safe}"


def _validate_ip(ip: str) -> str | None:
    """Return a human-readable error if the IP is invalid, else ``None``."""
    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return f"Invalid IP address: {ip!r}"
    return None


class WindowsFirewallAdapter(FirewallAdapter):
    """Windows Firewall adapter using ``netsh advfirewall``.

    All commands are executed via ``subprocess.run`` with explicit argument
    arrays, no shell interaction, captured output and timeouts.
    """

    @property
    def adapter_name(self) -> str:
        return "Windows Firewall"

    def block_ip(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Add an inbound block rule for ``ip`` (idempotent)."""
        validation_error = _validate_ip(ip)
        if validation_error is not None:
            return FirewallActionResult(
                action="block_ip",
                target=ip,
                status=FirewallActionStatus.INVALID_TARGET,
                message=validation_error,
                changed=False,
                verified=False,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
            )

        normalized = _normalize_ip(ip)
        rule = _rule_name(normalized)

        # Check if rule already exists
        check_result = self._run_netsh(
            ["advfirewall", "firewall", "show", "rule", f"name={rule}"],
            timeout=timeout,
        )
        if check_result.returncode == 0 and rule in (check_result.stdout or ""):
            return FirewallActionResult(
                action="block_ip",
                target=normalized,
                status=FirewallActionStatus.ALREADY_APPLIED,
                message=f"Aegis rule '{rule}' already exists for {normalized}.",
                changed=False,
                verified=True,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
                rule_name=rule,
            )

        # Create the inbound block rule
        desc = f"Aegis IDPS: inbound block for {normalized}"
        cmd = [
            "advfirewall", "firewall", "add", "rule",
            "name=" + rule,
            "dir=in",
            "action=block",
            "remoteip=" + normalized,
            "enable=yes",
            "profile=any",
            "description=" + desc,
        ]
        result = self._run_netsh(cmd, timeout=timeout)

        if result.returncode != 0:
            err_text = result.stderr.strip() or result.stdout.strip() or "unknown error"
            msg = f"netsh returned {result.returncode}: {err_text}"
            return FirewallActionResult(
                action="block_ip",
                target=normalized,
                status=FirewallActionStatus.FAILED,
                message=msg,
                changed=False,
                verified=False,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
                rule_name=rule,
                command=f"netsh {' '.join(cmd)}",
            )

        # Verify the rule was created
        verify = self.is_blocked(normalized, timeout=timeout)
        return FirewallActionResult(
            action="block_ip",
            target=normalized,
            status=FirewallActionStatus.APPLIED,
            message=f"Aegis rule '{rule}' created for {normalized}.",
            changed=True,
            verified=verify.verified,
            adapter=self.adapter_name,
            timestamp=datetime.now(),
            rule_name=rule,
            command=f"netsh {' '.join(cmd)}",
        )

    def unblock_ip(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Remove the Aegis block rule for ``ip``."""
        validation_error = _validate_ip(ip)
        if validation_error is not None:
            return FirewallActionResult(
                action="unblock_ip",
                target=ip,
                status=FirewallActionStatus.INVALID_TARGET,
                message=validation_error,
                changed=False,
                verified=False,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
            )

        normalized = _normalize_ip(ip)
        rule = _rule_name(normalized)

        # Check if rule exists
        check_result = self._run_netsh(
            ["advfirewall", "firewall", "show", "rule", f"name={rule}"],
            timeout=timeout,
        )
        if check_result.returncode != 0 or rule not in (check_result.stdout or ""):
            return FirewallActionResult(
                action="unblock_ip",
                target=normalized,
                status=FirewallActionStatus.ALREADY_APPLIED,
                message=f"Aegis rule '{rule}' does not exist for {normalized}.",
                changed=False,
                verified=True,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
                rule_name=rule,
            )

        # Delete the rule
        cmd = ["advfirewall", "firewall", "delete", "rule", f"name={rule}"]
        result = self._run_netsh(cmd, timeout=timeout)

        if result.returncode != 0:
            err_text = result.stderr.strip() or result.stdout.strip() or "unknown error"
            msg = f"netsh returned {result.returncode}: {err_text}"
            return FirewallActionResult(
                action="unblock_ip",
                target=normalized,
                status=FirewallActionStatus.FAILED,
                message=msg,
                changed=False,
                verified=False,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
                rule_name=rule,
                command=f"netsh {' '.join(cmd)}",
            )

        return FirewallActionResult(
            action="unblock_ip",
            target=normalized,
            status=FirewallActionStatus.APPLIED,
            message=f"Aegis rule '{rule}' removed for {normalized}.",
            changed=True,
            verified=True,
            adapter=self.adapter_name,
            timestamp=datetime.now(),
            rule_name=rule,
            command=f"netsh {' '.join(cmd)}",
        )

    def is_blocked(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Verify whether ``ip`` is blocked by an Aegis rule."""
        validation_error = _validate_ip(ip)
        if validation_error is not None:
            return FirewallActionResult(
                action="is_blocked",
                target=ip,
                status=FirewallActionStatus.INVALID_TARGET,
                message=validation_error,
                changed=False,
                verified=False,
                adapter=self.adapter_name,
                timestamp=datetime.now(),
            )

        normalized = _normalize_ip(ip)
        rule = _rule_name(normalized)

        result = self._run_netsh(
            ["advfirewall", "firewall", "show", "rule", f"name={rule}"],
            timeout=timeout,
        )

        found = result.returncode == 0 and rule in (result.stdout or "")
        return FirewallActionResult(
            action="is_blocked",
            target=normalized,
            status=FirewallActionStatus.APPLIED if found else FirewallActionStatus.NOT_SUPPORTED,
            message=(
                f"Aegis rule '{rule}' found for {normalized}."
                if found
                else f"Aegis rule '{rule}' not found for {normalized}."
            ),
            changed=False,
            verified=found,
            adapter=self.adapter_name,
            timestamp=datetime.now(),
            rule_name=rule,
        )

    # -- internal helpers --------------------------------------------------

    @staticmethod
    def _run_netsh(
        args: list[str],
        *,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess[str]:
        """Execute ``netsh`` with the given arguments.

        Returns a ``CompletedProcess`` with captured stdout/stderr.
        Never uses ``shell=True``.
        """
        cmd = ["netsh", *args]
        logger.debug("Executing: %s", " ".join(cmd))
        try:
            proc = subprocess.run(  # noqa: S603 - validated, non-shell subprocess
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                check=False,
            )
            return proc
        except subprocess.TimeoutExpired:
            logger.warning("netsh command timed out after %.1fs: %s", timeout, " ".join(cmd))
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr="Command timed out",
            )
        except FileNotFoundError:
            logger.warning("netsh not found on this system")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr="netsh not found",
            )
        except Exception as exc:
            logger.warning("netsh execution failed: %s", exc)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=str(exc),
            )


__all__ = ["WindowsFirewallAdapter"]
