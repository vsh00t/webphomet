"""Correlation API endpoints — link static code hotspots to dynamic findings."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.correlator import run_correlation
from src.db import dal
from src.db.database import get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RunCorrelationRequest(BaseModel):
    """Run the correlation engine for a session + repo."""

    session_id: uuid.UUID
    repo_name: str
    hotspots: list[dict[str, Any]]
    """Raw hotspot dicts from mcp-git-code ``find_hotspots``."""
    min_confidence: float = 0.3
    persist: bool = True


class CorrelationResponse(BaseModel):
    finding_id: str
    finding_title: str
    finding_vuln_type: str
    hotspot_file: str
    hotspot_line: int
    hotspot_category: str
    hotspot_snippet: str
    confidence: float
    correlation_type: str
    notes: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/run",
    response_model=list[CorrelationResponse],
    summary="Run correlation engine",
)
async def run_correlation_endpoint(
    payload: RunCorrelationRequest,
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Correlate static hotspots with dynamic findings for a session."""
    results = await run_correlation(
        db,
        session_id=payload.session_id,
        repo_name=payload.repo_name,
        hotspots=payload.hotspots,
        min_confidence=payload.min_confidence,
        persist=payload.persist,
    )
    await db.commit()
    return results


@router.get(
    "/session/{session_id}",
    summary="List stored correlations for a session",
)
async def list_correlations(
    session_id: uuid.UUID,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Return persisted correlations ordered by confidence."""
    corrs = await dal.get_correlations(db, session_id, min_confidence=min_confidence)
    return [
        {
            "id": str(c.id),
            "finding_id": str(c.finding_id),
            "repo_name": c.repo_name,
            "hotspot_file": c.hotspot_file,
            "hotspot_line": c.hotspot_line,
            "hotspot_category": c.hotspot_category,
            "hotspot_snippet": c.hotspot_snippet or "",
            "confidence": c.confidence,
            "correlation_type": c.correlation_type,
            "notes": c.notes or "",
            "created_at": c.created_at.isoformat() if c.created_at else "",
        }
        for c in corrs
    ]


@router.get(
    "/finding/{finding_id}",
    summary="Get correlations for a specific finding",
)
async def correlations_for_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> list[dict[str, Any]]:
    """Return all hotspot correlations linked to a finding."""
    corrs = await dal.get_correlations_for_finding(db, finding_id)
    return [
        {
            "id": str(c.id),
            "repo_name": c.repo_name,
            "hotspot_file": c.hotspot_file,
            "hotspot_line": c.hotspot_line,
            "hotspot_category": c.hotspot_category,
            "hotspot_snippet": c.hotspot_snippet or "",
            "confidence": c.confidence,
            "correlation_type": c.correlation_type,
            "notes": c.notes or "",
        }
        for c in corrs
    ]


@router.delete(
    "/session/{session_id}",
    summary="Clear all correlations for a session",
)
async def clear_correlations(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Delete all correlations for a session."""
    count = await dal.delete_correlations_for_session(db, session_id)
    await db.commit()
    return {"deleted": count}
