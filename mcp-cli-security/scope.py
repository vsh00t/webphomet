"""Scope validation for MCP CLI-Security server.

Ensures that all tool executions stay within approved targets and IP ranges.
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


class ScopeValidator:
    """Validates that security tool commands respect the configured scope.

    Parameters
    ----------
    allowed_hosts:
        Set of hostnames/domains that are allowed.
    allowed_ips:
        Set of IP address/ranges (CIDR notation) that are allowed.
    blocked_ips:
        Set of IP addresses that are explicitly blocked (RFC1918, etc.).
    """

    def __init__(
        self,
        allowed_hosts: Sequence[str] | None = None,
        allowed_ips: Sequence[str] | None = None,
        blocked_ips: Sequence[str] | None = None,
    ) -> None:
        self.allowed_hosts = set(allowed_hosts or [])
        self.allowed_ip_ranges = [
            ipaddress.ip_network(ip) for ip in (allowed_ips or [])
        ]
        self.blocked_ip_set = set(blocked_ips or [])

        logger.info(
            "ScopeValidator initialized: %d hosts, %d IP ranges, %d blocked IPs",
            len(self.allowed_hosts),
            len(self.allowed_ip_ranges),
            len(self.blocked_ip_set),
        )

    def validate_command(
        self,
        tool_name: str,
        args: list[str],
    ) -> bool:
        """Validate that all targets in a command are within scope.

        Parameters
        ----------
        tool_name:
            Name of the security tool being executed.
        args:
            Command-line arguments passed to the tool.

        Returns
        -------
        True if all targets are in scope, False otherwise.
        """
        # Extract potential targets from arguments
        targets = self._extract_targets(tool_name, args)

        if not targets:
            # No targets found, allow by default
            return True

        for target in targets:
            if not self._is_target_in_scope(target):
                logger.warning(
                    "Target out of scope: %s (tool: %s)",
                    target,
                    tool_name,
                )
                return False

        return True

    def _extract_targets(
        self,
        tool_name: str,
        args: list[str],
    ) -> list[str]:
        """Extract potential target hosts/IPs from command arguments.

        This is a simple heuristic - in production, use proper parsing
        per tool to avoid false positives.
        """
        targets = []

        for arg in args:
            # Skip flags and options
            if arg.startswith("-"):
                continue

            # Try to parse as hostname or IP
            if self._looks_like_target(arg):
                targets.append(arg)

        return targets

    def _looks_like_target(self, value: str) -> bool:
        """Check if a value looks like a hostname or IP address."""
        value = value.strip()

        # Skip file paths
        if "/" in value and value.startswith("/"):
            return False
        if value.endswith(".xml") or value.endswith(".txt") or value.endswith(".json"):
            return False

        # Skip port numbers
        try:
            int(value)
            return False
        except ValueError:
            pass

        # Check for IP address
        try:
            ipaddress.ip_address(value.split(":")[0])  # Handle IPv6
            return True
        except ValueError:
            pass

        # Check for hostname (has at least one dot)
        if "." in value and not value.startswith("-"):
            return True

        return False

    def _is_target_in_scope(self, target: str) -> bool:
        """Check if a single target is within the allowed scope."""
        # First, check if explicitly blocked
        if target in self.blocked_ip_set:
            return False

        # Check if IP is blocked by range
        try:
            ip = ipaddress.ip_address(target.split(":")[0])
            for network in self.allowed_ip_ranges:
                if ip in network:
                    return True
        except ValueError:
            # Not an IP, check hostname
            pass

        # Check hostname against allowed list
        if self.allowed_hosts:
            # Check exact match
            if target in self.allowed_hosts:
                return True

            # Check subdomain match
            for allowed in self.allowed_hosts:
                if target.endswith(f".{allowed}"):
                    return True

        # If no restrictions defined, allow everything (unsafe but default)
        if not self.allowed_hosts and not self.allowed_ip_ranges:
            logger.warning(
                "No scope restrictions defined, allowing target: %s",
                target,
            )
            return True

        return False
