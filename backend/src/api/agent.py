"""API endpoints for the autonomous pentesting agent."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.database import get_db
from src.jobs.celery_app import celery_app

router = APIRouter()


class StartAgentRequest(BaseModel):
    """Request to start the autonomous agent."""

    session_id: uuid.UUID
    max_iterations: int = 30
    model: str | None = None


@router.post(
    "/start",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start autonomous pentesting agent",
)
async def start_agent(
    payload: StartAgentRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Launch the autonomous agent loop for a pentest session.

    The agent runs as a long-lived Celery task and autonomously drives
    the full pentesting lifecycle: recon → enumeration → scanning →
    analysis → reporting.
    """
    # Verify session exists
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    task = celery_app.send_task(
        "jobs.run_agent",
        kwargs={
            "session_id": str(payload.session_id),
            "max_iterations": payload.max_iterations,
            "model": payload.model,
        },
    )

    return {
        "task_id": task.id,
        "session_id": str(payload.session_id),
        "status": "agent_started",
        "max_iterations": payload.max_iterations,
    }


@router.get(
    "/status/{task_id}",
    summary="Check agent task status",
)
async def agent_status(task_id: str) -> dict[str, Any]:
    """Query the status of a running agent task."""
    result = celery_app.AsyncResult(task_id)
    response: dict[str, Any] = {
        "task_id": task_id,
        "status": result.status,
    }
    if result.ready():
        response["result"] = result.result
    return response


@router.post(
    "/stop/{task_id}",
    summary="Request agent stop (revoke task)",
)
async def stop_agent(task_id: str) -> dict[str, Any]:
    """Revoke a running agent task."""
    celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    return {
        "task_id": task_id,
        "status": "revoke_requested",
    }


class StopBySessionRequest(BaseModel):
    session_id: uuid.UUID


@router.post(
    "/stop",
    summary="Stop the agent for a session (cooperative)",
)
async def stop_agent_by_session(
    payload: StopBySessionRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Set a cooperative stop flag so the running agent exits cleanly."""
    from src.agent.orchestrator import request_stop

    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    request_stop(str(payload.session_id))
    return {
        "session_id": str(payload.session_id),
        "status": "stop_requested",
    }
