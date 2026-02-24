"""CRUD endpoints for pentest sessions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.schemas import SessionCreate, SessionResponse
from src.db.database import get_db
from src.db.models import PentestSession, SessionStatus

router = APIRouter()


@router.post(
    "/",
    response_model=SessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new pentest session",
)
async def create_session(
    payload: SessionCreate,
    db: AsyncSession = Depends(get_db),
) -> PentestSession:
    """Create a new pentest session."""
    session = PentestSession(
        target_base_url=str(payload.target_base_url),
        app_type=payload.app_type,
        scope=payload.scope,
        config=payload.config,
        status=SessionStatus.CREATED,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


@router.get(
    "/",
    response_model=list[SessionResponse],
    summary="List all pentest sessions",
)
async def list_sessions(
    db: AsyncSession = Depends(get_db),
) -> list[PentestSession]:
    """Return all pentest sessions ordered by creation date (newest first)."""
    result = await db.execute(
        select(PentestSession).order_by(PentestSession.created_at.desc())
    )
    return list(result.scalars().all())


@router.get(
    "/{session_id}",
    response_model=SessionResponse,
    summary="Get a pentest session by ID",
)
async def get_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> PentestSession:
    """Return a single pentest session."""
    result = await db.execute(
        select(PentestSession).where(PentestSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    return session


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a pentest session",
)
async def delete_session(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a pentest session and all related data."""
    result = await db.execute(
        select(PentestSession).where(PentestSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )
    await db.delete(session)
