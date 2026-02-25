"""Breakpoint system for the agent orchestration loop.

Allows operators to configure phases where the agent pauses and
waits for human confirmation before proceeding.

Breakpoint types:
- **phase**: Pause between pentest phases (post-recon, post-owasp, pre-exploit)
- **tool**: Pause before executing a specific tool
- **severity**: Pause when a high/critical finding is detected
- **manual**: Operator manually pauses the agent

Flow:
    Agent proposes action → breakpoint check → if hit:
        1. Store pending breakpoint in Redis
        2. Publish PENDING event via WebSocket
        3. Agent blocks (polls Redis for resolution or timeout)
        4. Operator approves / rejects / modifies via API
        5. Agent resumes or aborts

State is stored in Redis so that the FastAPI backend and Celery workers
share the same breakpoint configs and pending breakpoints.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import redis

from src.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis client (sync — works in both FastAPI and Celery contexts)
# ---------------------------------------------------------------------------

_redis: redis.Redis | None = None


def _get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


# Redis key prefixes
_CFG_PREFIX = "bp:cfg:"       # bp:cfg:{session_id} → JSON config
_PENDING_PREFIX = "bp:pend:"  # bp:pend:{breakpoint_id} → JSON pending bp
_RESOLVE_PREFIX = "bp:res:"   # bp:res:{breakpoint_id} → JSON resolution


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class BreakpointPhase(str, Enum):
    """Named pentest phases where breakpoints can trigger."""

    PRE_RECON = "pre_recon"
    POST_RECON = "post_recon"
    PRE_SCANNING = "pre_scanning"
    POST_SCANNING = "post_scanning"
    PRE_EXPLOIT = "pre_exploit"
    POST_EXPLOIT = "post_exploit"
    PRE_REPORT = "pre_report"
    POST_OWASP = "post_owasp"


class BreakpointAction(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    TIMEOUT = "timeout"


@dataclass
class BreakpointConfig:
    """Per-session breakpoint configuration."""

    session_id: uuid.UUID
    enabled: bool = True
    phase_breaks: set[BreakpointPhase] = field(default_factory=lambda: {
        BreakpointPhase.POST_RECON,
        BreakpointPhase.POST_OWASP,
        BreakpointPhase.PRE_EXPLOIT,
    })
    tool_breaks: set[str] = field(default_factory=set)
    """Specific tool names that require approval."""
    severity_break: bool = True
    """Pause when a critical-severity finding is discovered."""
    auto_approve_timeout: float = 0.0
    """Seconds after which a pending breakpoint auto-approves. 0 = wait forever."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": str(self.session_id),
            "enabled": self.enabled,
            "phase_breaks": [p.value for p in self.phase_breaks],
            "tool_breaks": list(self.tool_breaks),
            "severity_break": self.severity_break,
            "auto_approve_timeout": self.auto_approve_timeout,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BreakpointConfig:
        return cls(
            session_id=uuid.UUID(d["session_id"]),
            enabled=d.get("enabled", True),
            phase_breaks={BreakpointPhase(p) for p in d.get("phase_breaks", [])},
            tool_breaks=set(d.get("tool_breaks", [])),
            severity_break=d.get("severity_break", True),
            auto_approve_timeout=float(d.get("auto_approve_timeout", 0.0)),
        )


@dataclass
class PendingBreakpoint:
    """A breakpoint that is waiting for operator resolution."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    phase: str = ""
    tool_name: str = ""
    proposed_action: str = ""
    proposed_args: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: BreakpointAction = BreakpointAction.PENDING
    operator_message: str = ""
    modified_args: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "phase": self.phase,
            "tool_name": self.tool_name,
            "proposed_action": self.proposed_action,
            "proposed_args": self.proposed_args,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "action": self.action.value,
            "operator_message": self.operator_message,
            "modified_args": self.modified_args,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PendingBreakpoint:
        return cls(
            id=d["id"],
            session_id=d.get("session_id", ""),
            phase=d.get("phase", ""),
            tool_name=d.get("tool_name", ""),
            proposed_action=d.get("proposed_action", ""),
            proposed_args=d.get("proposed_args", {}),
            reason=d.get("reason", ""),
            timestamp=d.get("timestamp", ""),
            action=BreakpointAction(d.get("action", "pending")),
            operator_message=d.get("operator_message", ""),
            modified_args=d.get("modified_args"),
        )


# ---------------------------------------------------------------------------
# Manager — Redis-backed, shared across processes
# ---------------------------------------------------------------------------


class BreakpointManager:
    """Manages breakpoint configs and pending breakpoints via Redis.

    Config and pending state are stored in Redis so that the FastAPI
    backend and Celery workers share the same view.
    """

    def __init__(self) -> None:
        self._ws_callback: Any | None = None

    @property
    def _r(self) -> redis.Redis:
        return _get_redis()

    # ── configuration ───────────────────────────────────────

    def configure(self, session_id: str, **kwargs: Any) -> BreakpointConfig:
        """Create or update breakpoint config for a session (stored in Redis)."""
        cfg = self.get_config(session_id)

        if "enabled" in kwargs:
            cfg.enabled = bool(kwargs["enabled"])
        if "phase_breaks" in kwargs:
            cfg.phase_breaks = {BreakpointPhase(p) for p in kwargs["phase_breaks"]}
        if "tool_breaks" in kwargs:
            cfg.tool_breaks = set(kwargs["tool_breaks"])
        if "severity_break" in kwargs:
            cfg.severity_break = bool(kwargs["severity_break"])
        if "auto_approve_timeout" in kwargs:
            cfg.auto_approve_timeout = float(kwargs["auto_approve_timeout"])

        # Persist to Redis
        self._r.set(
            f"{_CFG_PREFIX}{session_id}",
            json.dumps(cfg.to_dict()),
            ex=86400,  # 24h TTL
        )
        return cfg

    def get_config(self, session_id: str) -> BreakpointConfig:
        """Load config from Redis, or create default."""
        raw = self._r.get(f"{_CFG_PREFIX}{session_id}")
        if raw:
            return BreakpointConfig.from_dict(json.loads(raw))
        # Return default (not persisted until configure() is called)
        return BreakpointConfig(session_id=uuid.UUID(session_id))

    def set_ws_callback(self, callback: Any) -> None:
        """Register WebSocket broadcast callback for breakpoint events."""
        self._ws_callback = callback

    # ── breakpoint evaluation ────────────────────────────────

    async def check_phase(
        self,
        session_id: str,
        phase: BreakpointPhase,
        context: str = "",
    ) -> PendingBreakpoint | None:
        """Check if a phase breakpoint should trigger. Returns PendingBreakpoint if so."""
        cfg = self.get_config(session_id)
        if not cfg.enabled:
            return None
        if phase not in cfg.phase_breaks:
            return None

        bp = PendingBreakpoint(
            session_id=session_id,
            phase=phase.value,
            proposed_action=f"Continue to phase: {phase.value}",
            reason=f"Phase breakpoint at {phase.value}. {context}",
        )
        return await self._wait_for_resolution(bp)

    async def check_tool(
        self,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> PendingBreakpoint | None:
        """Check if a tool-level breakpoint should trigger."""
        cfg = self.get_config(session_id)
        if not cfg.enabled:
            return None
        if tool_name not in cfg.tool_breaks:
            return None

        bp = PendingBreakpoint(
            session_id=session_id,
            tool_name=tool_name,
            proposed_action=f"Execute tool: {tool_name}",
            proposed_args=tool_args,
            reason=f"Tool breakpoint for {tool_name}",
        )
        return await self._wait_for_resolution(bp)

    async def check_severity(
        self,
        session_id: str,
        finding_title: str,
        severity: str,
    ) -> PendingBreakpoint | None:
        """Check if a severity-based breakpoint should trigger."""
        cfg = self.get_config(session_id)
        if not cfg.enabled or not cfg.severity_break:
            return None
        if severity not in ("critical",):
            return None

        bp = PendingBreakpoint(
            session_id=session_id,
            proposed_action=f"Critical finding: {finding_title}",
            reason=f"Critical severity finding detected: {finding_title}",
        )
        return await self._wait_for_resolution(bp)

    # ── resolution ──────────────────────────────────────────

    async def _wait_for_resolution(self, bp: PendingBreakpoint) -> PendingBreakpoint:
        """Store pending breakpoint in Redis and poll for resolution or timeout."""
        # Store in Redis
        bp_key = f"{_PENDING_PREFIX}{bp.id}"
        res_key = f"{_RESOLVE_PREFIX}{bp.id}"
        self._r.set(bp_key, json.dumps(bp.to_dict()), ex=3600)

        # Notify via WebSocket
        await self._notify(bp, "breakpoint_hit")

        logger.info(
            "Breakpoint %s triggered for session %s: %s",
            bp.id, bp.session_id, bp.reason,
        )

        # Determine timeout
        cfg = self.get_config(bp.session_id)
        timeout = cfg.auto_approve_timeout if cfg.auto_approve_timeout > 0 else 0
        elapsed = 0.0
        poll_interval = 1.0  # Check Redis every second

        # Poll Redis for operator resolution
        while True:
            # Check if operator resolved (wrote to resolution key)
            resolution_raw = self._r.get(res_key)
            if resolution_raw:
                resolution = json.loads(resolution_raw)
                bp.action = BreakpointAction(resolution.get("action", "approved"))
                bp.operator_message = resolution.get("message", "")
                if resolution.get("modified_args"):
                    bp.modified_args = resolution["modified_args"]
                logger.info(
                    "Breakpoint %s resolved by operator: %s",
                    bp.id, bp.action.value,
                )
                break

            # Check timeout
            if timeout > 0 and elapsed >= timeout:
                bp.action = BreakpointAction.TIMEOUT
                bp.operator_message = "Auto-approved (timeout)"
                logger.info("Breakpoint %s auto-approved (timeout %.0fs)", bp.id, timeout)
                break

            # Sleep without blocking the event loop
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        # Clean up Redis
        self._r.delete(bp_key, res_key)
        await self._notify(bp, "breakpoint_resolved")
        return bp

    def resolve(
        self,
        breakpoint_id: str,
        action: BreakpointAction,
        message: str = "",
        modified_args: dict[str, Any] | None = None,
    ) -> bool:
        """Operator resolves a pending breakpoint (writes to Redis)."""
        bp_key = f"{_PENDING_PREFIX}{breakpoint_id}"
        if not self._r.exists(bp_key):
            return False

        res_key = f"{_RESOLVE_PREFIX}{breakpoint_id}"
        self._r.set(res_key, json.dumps({
            "action": action.value,
            "message": message,
            "modified_args": modified_args,
        }), ex=3600)
        return True

    def list_pending(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """List all pending breakpoints from Redis, optionally filtered by session."""
        results = []
        for key in self._r.scan_iter(f"{_PENDING_PREFIX}*"):
            raw = self._r.get(key)
            if not raw:
                continue
            bp_data = json.loads(raw)
            if session_id and bp_data.get("session_id") != session_id:
                continue
            results.append(bp_data)
        return results

    # ── WebSocket notification ───────────────────────────────

    async def _notify(self, bp: PendingBreakpoint, event_type: str) -> None:
        if self._ws_callback is None:
            return
        try:
            await self._ws_callback(
                session_id=bp.session_id,
                event_type=event_type,
                data={
                    "breakpoint_id": bp.id,
                    "phase": bp.phase,
                    "tool_name": bp.tool_name,
                    "proposed_action": bp.proposed_action,
                    "proposed_args": bp.proposed_args,
                    "reason": bp.reason,
                    "action": bp.action.value,
                    "operator_message": bp.operator_message,
                },
            )
        except Exception:
            logger.exception("Failed to send WS notification for breakpoint %s", bp.id)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

breakpoint_manager = BreakpointManager()
