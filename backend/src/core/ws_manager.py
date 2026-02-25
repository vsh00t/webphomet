"""WebSocket connection manager for real-time notifications.

Supports:
- Per-session channels (session_id → set of websockets)
- Broadcast to all connections
- Typed events: finding, tool_run, breakpoint, phase_change, agent_message
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections grouped by session_id."""

    def __init__(self) -> None:
        # session_id → set of active websockets
        self._sessions: dict[str, set[WebSocket]] = {}
        # global connections (not tied to a specific session)
        self._global: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    # ── connection lifecycle ────────────────────────────────

    async def connect(self, ws: WebSocket, session_id: str | None = None) -> None:
        """Accept and register a WebSocket connection."""
        await ws.accept()
        async with self._lock:
            if session_id:
                if session_id not in self._sessions:
                    self._sessions[session_id] = set()
                self._sessions[session_id].add(ws)
            else:
                self._global.add(ws)
        logger.info("WebSocket connected: session=%s", session_id or "global")

    async def disconnect(self, ws: WebSocket, session_id: str | None = None) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if session_id and session_id in self._sessions:
                self._sessions[session_id].discard(ws)
                if not self._sessions[session_id]:
                    del self._sessions[session_id]
            self._global.discard(ws)
        logger.debug("WebSocket disconnected: session=%s", session_id or "global")

    # ── send methods ────────────────────────────────────────

    async def send_to_session(
        self,
        session_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Send an event to all connections watching a specific session."""
        message = json.dumps({
            "type": event_type,
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }, default=str)

        targets: set[WebSocket] = set()
        async with self._lock:
            targets.update(self._sessions.get(session_id, set()))
            targets.update(self._global)

        dead: list[tuple[WebSocket, str | None]] = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                # Connection dead — schedule removal
                sid = session_id if ws in self._sessions.get(session_id, set()) else None
                dead.append((ws, sid))

        for ws, sid in dead:
            await self.disconnect(ws, sid)

    async def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an event to ALL connected websockets."""
        message = json.dumps({
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }, default=str)

        all_ws: set[WebSocket] = set()
        async with self._lock:
            for sockets in self._sessions.values():
                all_ws.update(sockets)
            all_ws.update(self._global)

        dead: list[tuple[WebSocket, str | None]] = []
        for ws in all_ws:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append((ws, None))

        for ws, sid in dead:
            await self.disconnect(ws, sid)

    @property
    def active_connections(self) -> int:
        count = len(self._global)
        for sockets in self._sessions.values():
            count += len(sockets)
        return count


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

ws_manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Convenience callback for BreakpointManager
# ---------------------------------------------------------------------------

async def ws_breakpoint_callback(
    session_id: str,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Adapter for BreakpointManager.set_ws_callback()."""
    await ws_manager.send_to_session(session_id, event_type, data)
