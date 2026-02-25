"""Retention / admin endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from src.core.retention import purge_old_sessions, get_retention_stats

router = APIRouter()


class PurgeRequest(BaseModel):
    days: int | None = None


@router.post("/purge")
async def purge(body: PurgeRequest | None = None):
    """Delete sessions older than N days (default: RETENTION_DAYS)."""
    days = body.days if body else None
    return await purge_old_sessions(days)


@router.get("/stats")
async def stats():
    """Return current data‐size stats."""
    return await get_retention_stats()
