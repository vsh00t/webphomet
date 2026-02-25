"""REST + WebSocket endpoints for breakpoints and real-time notifications."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from src.core.breakpoints import BreakpointAction, BreakpointPhase, breakpoint_manager
from src.core.ws_manager import ws_manager

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class BreakpointConfigRequest(BaseModel):
    session_id: uuid.UUID
    enabled: bool = True
    phase_breaks: list[str] | None = None
    tool_breaks: list[str] | None = None
    severity_break: bool = True
    auto_approve_timeout: float = 0.0


class ResolveBreakpointRequest(BaseModel):
    breakpoint_id: str
    action: str  # approved, rejected, modified
    message: str = ""
    modified_args: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Breakpoint configuration
# ---------------------------------------------------------------------------


@router.post("/breakpoints/configure")
async def configure_breakpoints(payload: BreakpointConfigRequest) -> dict[str, Any]:
    """Configure breakpoints for a session."""
    kwargs: dict[str, Any] = {
        "enabled": payload.enabled,
        "severity_break": payload.severity_break,
        "auto_approve_timeout": payload.auto_approve_timeout,
    }
    if payload.phase_breaks is not None:
        kwargs["phase_breaks"] = payload.phase_breaks
    if payload.tool_breaks is not None:
        kwargs["tool_breaks"] = payload.tool_breaks

    cfg = breakpoint_manager.configure(str(payload.session_id), **kwargs)
    return {
        "session_id": str(payload.session_id),
        "enabled": cfg.enabled,
        "phase_breaks": [p.value for p in cfg.phase_breaks],
        "tool_breaks": sorted(cfg.tool_breaks),
        "severity_break": cfg.severity_break,
        "auto_approve_timeout": cfg.auto_approve_timeout,
    }


@router.get("/breakpoints/config/{session_id}")
async def get_breakpoint_config(session_id: uuid.UUID) -> dict[str, Any]:
    """Get the breakpoint configuration for a session."""
    cfg = breakpoint_manager.get_config(str(session_id))
    return {
        "session_id": str(session_id),
        "enabled": cfg.enabled,
        "phase_breaks": [p.value for p in cfg.phase_breaks],
        "tool_breaks": sorted(cfg.tool_breaks),
        "severity_break": cfg.severity_break,
        "auto_approve_timeout": cfg.auto_approve_timeout,
    }


# ---------------------------------------------------------------------------
# Pending breakpoints
# ---------------------------------------------------------------------------


@router.get("/breakpoints/pending")
async def list_pending_breakpoints(
    session_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """List all pending breakpoints (optionally filtered by session)."""
    sid = str(session_id) if session_id else None
    pending = breakpoint_manager.list_pending(sid)
    return {"pending": pending, "count": len(pending)}


@router.post("/breakpoints/resolve")
async def resolve_breakpoint(payload: ResolveBreakpointRequest) -> dict[str, Any]:
    """Approve, reject, or modify a pending breakpoint."""
    try:
        action = BreakpointAction(payload.action)
    except ValueError:
        return {"error": f"Invalid action: {payload.action}. Use: approved, rejected, modified"}

    ok = breakpoint_manager.resolve(
        payload.breakpoint_id,
        action=action,
        message=payload.message,
        modified_args=payload.modified_args,
    )
    if not ok:
        return {"error": f"Breakpoint {payload.breakpoint_id} not found or already resolved"}

    return {"breakpoint_id": payload.breakpoint_id, "action": action.value, "resolved": True}


# ---------------------------------------------------------------------------
# Breakpoint phases reference
# ---------------------------------------------------------------------------


@router.get("/breakpoints/phases")
async def list_phases() -> dict[str, Any]:
    """List all available breakpoint phases."""
    return {
        "phases": [
            {"value": p.value, "name": p.name}
            for p in BreakpointPhase
        ]
    }


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/{session_id}")
async def ws_session(ws: WebSocket, session_id: str) -> None:
    """WebSocket for real-time session events (findings, tool runs, breakpoints)."""
    await ws_manager.connect(ws, session_id)
    try:
        while True:
            # Keep-alive + receive operator commands
            data = await ws.receive_text()
            # Parse inline breakpoint resolution from WebSocket
            try:
                import json
                msg = json.loads(data)
                if msg.get("type") == "resolve_breakpoint":
                    action = BreakpointAction(msg.get("action", "approved"))
                    breakpoint_manager.resolve(
                        msg["breakpoint_id"],
                        action=action,
                        message=msg.get("message", ""),
                        modified_args=msg.get("modified_args"),
                    )
                    await ws.send_text(json.dumps({
                        "type": "breakpoint_resolved",
                        "breakpoint_id": msg["breakpoint_id"],
                        "action": action.value,
                    }))
                elif msg.get("type") == "ping":
                    await ws.send_text('{"type":"pong"}')
            except Exception:
                pass  # Ignore malformed messages
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws, session_id)


@router.websocket("/ws")
async def ws_global(ws: WebSocket) -> None:
    """Global WebSocket — receives events from all sessions."""
    await ws_manager.connect(ws, session_id=None)
    try:
        while True:
            data = await ws.receive_text()
            try:
                import json
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_text('{"type":"pong"}')
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws, session_id=None)
