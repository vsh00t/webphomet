"""Scope validation — ensures all tool activity stays within authorised boundaries."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ScopeValidator:
    """Validates whether a host, IP, or command target is within the authorised scope.

    Parameters
    ----------
    allowed_hosts:
        Set of domain names / wildcard patterns that are in scope
        (e.g. ``{"example.com", "*.example.com"}``).
    allowed_ips:
        Set of IP addresses or CIDR networks that are in scope
        (e.g. ``{"10.0.0.0/24", "192.168.1.100"}``).
    exclusions:
        Explicit hosts or IPs that must **never** be targeted, even if they
        fall within an allowed range.
    """

    allowed_hosts: set[str] = field(default_factory=set)
    allowed_ips: set[str] = field(default_factory=set)
    exclusions: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def validate_target(self, host_or_ip: str) -> bool:
        """Return ``True`` if *host_or_ip* is within scope and not excluded."""
        # Strip scheme / path if a full URL was passed
        parsed = urlparse(host_or_ip if "://" in host_or_ip else f"http://{host_or_ip}")
        target: str = parsed.hostname or host_or_ip

        if target in self.exclusions:
            logger.warning("Target %s is explicitly excluded from scope", target)
            return False

        # Check IP ranges
        if self._is_ip(target):
            return self._ip_in_scope(target)

        # Check host patterns
        return self._host_in_scope(target)

    def validate_command(self, command_name: str, args: list[str]) -> bool:
        """Check that every target-like argument in *args* is within scope.

        Inspects each argument and — if it looks like a host, IP, or URL —
        validates it against the scope.
        """
        target_flags = {"-t", "--target", "-u", "--url", "-h", "--host", "-iL"}
        check_next = False

        for arg in args:
            if check_next:
                if not self.validate_target(arg):
                    logger.warning(
                        "Command %s targets out-of-scope address: %s",
                        command_name,
                        arg,
                    )
                    return False
                check_next = False
                continue

            if arg in target_flags:
                check_next = True
                continue

            # Positional URL / IP argument heuristic
            if re.match(r"^https?://", arg) or self._is_ip(arg):
                if not self.validate_target(arg):
                    logger.warning(
                        "Command %s targets out-of-scope address: %s",
                        command_name,
                        arg,
                    )
                    return False

        return True

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Return ``True`` if *value* looks like an IPv4 / IPv6 address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _ip_in_scope(self, ip_str: str) -> bool:
        """Check whether an IP address falls within any allowed IP / CIDR."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        for entry in self.allowed_ips:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if ip in network:
                    return True
            except ValueError:
                # It's a plain IP
                if ip_str == entry:
                    return True

        return False

    def _host_in_scope(self, host: str) -> bool:
        """Check whether a hostname matches any allowed host pattern."""
        host = host.lower()
        for pattern in self.allowed_hosts:
            pattern = pattern.lower()
            if pattern == host:
                return True
            # Wildcard: *.example.com matches sub.example.com
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
        return False
