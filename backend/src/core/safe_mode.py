"""Safe Mode Policy — prevents destructive or out-of-scope operations.

When ``settings.SAFE_MODE`` is ``True`` (the default), the policy enforcer:

1. Blocks tools classified as "destructive" (exploit, brute-force, DoS).
2. Blocks command arguments that use destructive nmap scripts, sqlmap
   ``--os-shell``, nuclei ``-severity critical`` with exploit templates, etc.
3. Enforces rate-limits: max N tool invocations per session per hour.
4. Delegates scope checks to :class:`ScopeValidator`.

The enforcer is intended to be called **before** dispatching any tool
execution — both from the API layer and the agent orchestrator.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.config import settings
from src.core.scope import ScopeValidator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Blocked patterns
# ---------------------------------------------------------------------------

# Tools that are never allowed in safe mode
BLOCKED_TOOLS_SAFE: set[str] = {
    "sqlmap",
    "dalfox",
    "kxss",
}

# CLI argument patterns that indicate destructive intent
BLOCKED_ARG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"--os-shell", re.IGNORECASE),
    re.compile(r"--os-pwn", re.IGNORECASE),
    re.compile(r"--os-cmd", re.IGNORECASE),
    re.compile(r"--priv-esc", re.IGNORECASE),
    re.compile(r"--(dump|dump-all|passwords)", re.IGNORECASE),
    re.compile(r"--brute", re.IGNORECASE),
    re.compile(r"--exploit", re.IGNORECASE),
    re.compile(r"--dos\b", re.IGNORECASE),
    re.compile(r"script=.*exploit", re.IGNORECASE),
    re.compile(r"script=.*brute", re.IGNORECASE),
    re.compile(r"--batch\b.*--risk\s*[3-9]", re.IGNORECASE),
]

# Nmap scripts that are considered aggressive / destructive
BLOCKED_NMAP_SCRIPTS: set[str] = {
    "exploit",
    "brute",
    "dos",
    "fuzzer",
}


# ---------------------------------------------------------------------------
# Rate limiter (in-memory, per-session)
# ---------------------------------------------------------------------------

# Max tool invocations per session per hour
RATE_LIMIT_PER_HOUR: int = 60


@dataclass
class _RateBucket:
    """Simple sliding-window rate limiter bucket."""

    timestamps: list[float] = field(default_factory=list)

    def allow(self, limit: int, window: float = 3600.0) -> bool:
        now = time.monotonic()
        self.timestamps = [t for t in self.timestamps if now - t < window]
        if len(self.timestamps) >= limit:
            return False
        self.timestamps.append(now)
        return True


_rate_buckets: dict[str, _RateBucket] = defaultdict(_RateBucket)


# ---------------------------------------------------------------------------
# Policy enforcer
# ---------------------------------------------------------------------------


@dataclass
class SafeModePolicy:
    """Enforces safe-mode constraints on tool execution.

    Parameters
    ----------
    scope_validator:
        Optional pre-configured scope validator.  If ``None``, scope
        checks are skipped (caller is responsible).
    enabled:
        Whether safe mode is active.  Defaults to ``settings.SAFE_MODE``.
    rate_limit:
        Maximum tool invocations per session per hour.
    """

    scope_validator: ScopeValidator | None = None
    enabled: bool = field(default_factory=lambda: settings.SAFE_MODE)
    rate_limit: int = RATE_LIMIT_PER_HOUR

    def check(
        self,
        *,
        session_id: str,
        tool_name: str,
        command: str,
        target: str | None = None,
    ) -> PolicyResult:
        """Evaluate whether a tool execution is allowed.

        Returns a :class:`PolicyResult` indicating pass/fail with reason.
        """
        # 1. Scope check
        if target and self.scope_validator:
            if not self.scope_validator.validate_target(target):
                return PolicyResult(
                    allowed=False,
                    reason=f"Target {target!r} is out of scope",
                    rule="scope",
                )

        # If safe mode is disabled, only scope matters
        if not self.enabled:
            # Still enforce rate limit even with safe mode off
            return self._check_rate(session_id, tool_name)

        # 2. Blocked tools
        if tool_name.lower() in BLOCKED_TOOLS_SAFE:
            return PolicyResult(
                allowed=False,
                reason=f"Tool {tool_name!r} is blocked in safe mode",
                rule="blocked_tool",
            )

        # 3. Blocked argument patterns
        for pattern in BLOCKED_ARG_PATTERNS:
            if pattern.search(command):
                return PolicyResult(
                    allowed=False,
                    reason=f"Command contains blocked pattern: {pattern.pattern}",
                    rule="blocked_args",
                )

        # 4. Nmap script category check
        nmap_script_match = re.search(r"--script[= ]([^\s]+)", command)
        if nmap_script_match:
            scripts = nmap_script_match.group(1).lower()
            for blocked in BLOCKED_NMAP_SCRIPTS:
                if blocked in scripts:
                    return PolicyResult(
                        allowed=False,
                        reason=f"Nmap script category {blocked!r} is blocked in safe mode",
                        rule="blocked_nmap_script",
                    )

        # 5. Nuclei severity + exploit template check
        if tool_name.lower() == "nuclei":
            if re.search(r"-t\s+\S*exploit", command, re.IGNORECASE):
                return PolicyResult(
                    allowed=False,
                    reason="Nuclei exploit templates are blocked in safe mode",
                    rule="blocked_nuclei_exploit",
                )

        # 6. Rate limit
        return self._check_rate(session_id, tool_name)

    def _check_rate(self, session_id: str, tool_name: str) -> PolicyResult:
        """Check per-session rate limit."""
        bucket = _rate_buckets[session_id]
        if not bucket.allow(self.rate_limit):
            return PolicyResult(
                allowed=False,
                reason=(
                    f"Rate limit exceeded: max {self.rate_limit} tool "
                    f"invocations per hour per session"
                ),
                rule="rate_limit",
            )
        return PolicyResult(allowed=True)


@dataclass
class PolicyResult:
    """Outcome of a policy check."""

    allowed: bool
    reason: str = ""
    rule: str = ""

    def enforce(self) -> None:
        """Raise if not allowed — convenience for API/executor guards."""
        if not self.allowed:
            raise PolicyViolation(self.reason, self.rule)


class PolicyViolation(Exception):
    """Raised when a safe-mode policy check fails."""

    def __init__(self, reason: str, rule: str = "") -> None:
        self.reason = reason
        self.rule = rule
        super().__init__(reason)
