"""CRUD endpoints for security findings."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.schemas import FindingCreate, FindingResponse
from src.db import dal
from src.db.database import get_db

router = APIRouter()


@router.post(
    "/",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new finding",
)
async def create_finding(
    payload: FindingCreate,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    """Record a security finding for a session."""
    finding = await dal.create_finding(
        db,
        session_id=payload.session_id,
        vuln_type=payload.vuln_type,
        title=payload.title,
        severity=payload.severity.value,
        description=payload.description,
        evidence=payload.evidence,
        impact=payload.impact,
        likelihood=payload.likelihood,
        poc=payload.poc,
        recommendation=payload.recommendation,
        references=payload.references,
    )
    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.get(
    "/session/{session_id}",
    response_model=list[FindingResponse],
    summary="List findings for a session",
)
async def list_findings(
    session_id: uuid.UUID,
    severity: str | None = Query(None),
    finding_status: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
) -> list[FindingResponse]:
    """Return all findings for a session, optionally filtered."""
    findings = await dal.get_findings(
        db,
        session_id,
        severity=severity,
        status=finding_status,
    )
    return [FindingResponse.model_validate(f) for f in findings]


@router.get(
    "/session/{session_id}/summary",
    summary="Get findings summary for a session",
)
async def findings_summary(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return aggregated findings statistics."""
    return await dal.get_findings_summary(db, session_id)
