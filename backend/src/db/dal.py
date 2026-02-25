"""Data Access Layer — CRUD operations for all WebPhomet models.

Provides async repository functions for sessions, targets, findings,
tool runs, and artifacts.  All functions accept an AsyncSession so they
compose cleanly with FastAPI's dependency injection.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.db.models import (
    Artifact,
    Finding,
    FindingStatus,
    PentestSession,
    RunStatus,
    SessionStatus,
    Target,
    ToolRun,
)

# ═══════════════════════════════════════════════════════════════
# Sessions
# ═══════════════════════════════════════════════════════════════


async def create_session(
    db: AsyncSession,
    *,
    target_base_url: str,
    app_type: str | None = None,
    scope: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> PentestSession:
    """Insert a new pentest session and return it."""
    session = PentestSession(
        target_base_url=target_base_url,
        app_type=app_type,
        scope=scope,
        config=config,
        status=SessionStatus.CREATED,
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


async def get_session(
    db: AsyncSession,
    session_id: uuid.UUID,
) -> PentestSession | None:
    """Fetch a session by ID (eagerly loads relationships)."""
    result = await db.execute(
        select(PentestSession)
        .options(
            selectinload(PentestSession.targets),
            selectinload(PentestSession.findings),
            selectinload(PentestSession.tool_runs),
        )
        .where(PentestSession.id == session_id)
    )
    return result.scalar_one_or_none()


async def list_sessions(
    db: AsyncSession,
    *,
    limit: int = 50,
    offset: int = 0,
) -> Sequence[PentestSession]:
    """List sessions ordered by creation date, newest first."""
    result = await db.execute(
        select(PentestSession)
        .order_by(PentestSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


async def update_session_status(
    db: AsyncSession,
    session_id: uuid.UUID,
    status: SessionStatus,
) -> None:
    """Update the status of a pentest session."""
    await db.execute(
        update(PentestSession)
        .where(PentestSession.id == session_id)
        .values(status=status, updated_at=func.now())
    )
    await db.flush()


# ═══════════════════════════════════════════════════════════════
# Targets
# ═══════════════════════════════════════════════════════════════


async def create_target(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    host: str,
    ports: dict[str, Any] | None = None,
    technologies: dict[str, Any] | None = None,
    notes: str | None = None,
) -> Target:
    """Insert a new target and return it."""
    target = Target(
        session_id=session_id,
        host=host,
        ports=ports,
        technologies=technologies,
        notes=notes,
    )
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


async def upsert_target(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    host: str,
    ports: dict[str, Any] | None = None,
    technologies: dict[str, Any] | None = None,
    notes: str | None = None,
) -> Target:
    """Insert or update a target by (session_id, host)."""
    result = await db.execute(
        select(Target).where(
            Target.session_id == session_id,
            Target.host == host,
        )
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        if ports:
            existing.ports = {**(existing.ports or {}), **ports}
        if technologies:
            existing.technologies = {**(existing.technologies or {}), **technologies}
        if notes:
            existing.notes = (existing.notes or "") + "\n" + notes
        await db.flush()
        await db.refresh(existing)
        return existing

    return await create_target(
        db,
        session_id=session_id,
        host=host,
        ports=ports,
        technologies=technologies,
        notes=notes,
    )


async def get_targets(
    db: AsyncSession,
    session_id: uuid.UUID,
) -> Sequence[Target]:
    """Fetch all targets for a session."""
    result = await db.execute(
        select(Target).where(Target.session_id == session_id)
    )
    return result.scalars().all()


# ═══════════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════════


async def create_finding(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    vuln_type: str,
    title: str,
    severity: str,
    description: str | None = None,
    evidence: str | None = None,
    impact: str | None = None,
    likelihood: str | None = None,
    poc: str | None = None,
    recommendation: str | None = None,
    references: dict[str, Any] | None = None,
    caido_finding_id: str | None = None,
    caido_request_id: str | None = None,
) -> Finding:
    """Insert a new finding and return it."""
    finding = Finding(
        session_id=session_id,
        vuln_type=vuln_type,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        impact=impact,
        likelihood=likelihood,
        poc=poc,
        recommendation=recommendation,
        references=references,
        caido_finding_id=caido_finding_id,
        caido_request_id=caido_request_id,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)
    return finding


async def get_finding_by_caido_id(
    db: AsyncSession,
    caido_finding_id: str,
) -> Finding | None:
    """Fetch a finding by its Caido finding ID (for dedup)."""
    result = await db.execute(
        select(Finding).where(Finding.caido_finding_id == caido_finding_id)
    )
    return result.scalar_one_or_none()


async def get_findings_without_caido_id(
    db: AsyncSession,
    session_id: uuid.UUID,
) -> Sequence[Finding]:
    """Fetch findings that have a caido_request_id but no caido_finding_id (push candidates)."""
    result = await db.execute(
        select(Finding).where(
            Finding.session_id == session_id,
            Finding.caido_request_id.isnot(None),
            Finding.caido_finding_id.is_(None),
        )
    )
    return result.scalars().all()


async def update_finding_caido_ids(
    db: AsyncSession,
    finding_id: uuid.UUID,
    *,
    caido_finding_id: str | None = None,
    caido_request_id: str | None = None,
) -> None:
    """Update Caido-related fields on a finding."""
    values: dict[str, Any] = {}
    if caido_finding_id is not None:
        values["caido_finding_id"] = caido_finding_id
    if caido_request_id is not None:
        values["caido_request_id"] = caido_request_id
    if values:
        await db.execute(
            update(Finding)
            .where(Finding.id == finding_id)
            .values(**values)
        )
        await db.flush()


async def get_findings(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    severity: str | None = None,
    status: str | None = None,
) -> Sequence[Finding]:
    """Fetch findings for a session, optionally filtered."""
    stmt = select(Finding).where(Finding.session_id == session_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    stmt = stmt.order_by(Finding.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()


async def update_finding_status(
    db: AsyncSession,
    finding_id: uuid.UUID,
    status: FindingStatus,
) -> None:
    """Update the status of a finding."""
    await db.execute(
        update(Finding)
        .where(Finding.id == finding_id)
        .values(status=status)
    )
    await db.flush()


async def get_findings_summary(
    db: AsyncSession,
    session_id: uuid.UUID,
) -> dict[str, Any]:
    """Return summary stats of findings for a session."""
    findings = await get_findings(db, session_id)
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        by_status[st] = by_status.get(st, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status,
    }


# ═══════════════════════════════════════════════════════════════
# Tool Runs
# ═══════════════════════════════════════════════════════════════


async def create_tool_run(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    tool_name: str,
    command: str,
    args: dict[str, Any] | None = None,
) -> ToolRun:
    """Insert a new tool run record (initially PENDING)."""
    run = ToolRun(
        session_id=session_id,
        tool_name=tool_name,
        command=command,
        args=args,
        status=RunStatus.PENDING,
    )
    db.add(run)
    await db.flush()
    await db.refresh(run)
    return run


async def start_tool_run(
    db: AsyncSession,
    tool_run_id: uuid.UUID,
) -> None:
    """Mark a tool run as RUNNING with current timestamp."""
    await db.execute(
        update(ToolRun)
        .where(ToolRun.id == tool_run_id)
        .values(
            status=RunStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
    )
    await db.flush()


async def complete_tool_run(
    db: AsyncSession,
    tool_run_id: uuid.UUID,
    *,
    status: RunStatus = RunStatus.SUCCESS,
    stdout: str | None = None,
    stderr: str | None = None,
    exit_code: int | None = None,
) -> None:
    """Mark a tool run as completed (SUCCESS or FAILED)."""
    await db.execute(
        update(ToolRun)
        .where(ToolRun.id == tool_run_id)
        .values(
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            finished_at=datetime.now(timezone.utc),
        )
    )
    await db.flush()


async def get_tool_run(
    db: AsyncSession,
    tool_run_id: uuid.UUID,
) -> ToolRun | None:
    """Fetch a single tool run with its artifacts."""
    result = await db.execute(
        select(ToolRun)
        .options(selectinload(ToolRun.artifacts))
        .where(ToolRun.id == tool_run_id)
    )
    return result.scalar_one_or_none()


async def get_tool_runs(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    tool_name: str | None = None,
) -> Sequence[ToolRun]:
    """Fetch tool runs for a session."""
    stmt = select(ToolRun).where(ToolRun.session_id == session_id)
    if tool_name:
        stmt = stmt.where(ToolRun.tool_name == tool_name)
    stmt = stmt.order_by(ToolRun.started_at.desc().nullslast())
    result = await db.execute(stmt)
    return result.scalars().all()


# ═══════════════════════════════════════════════════════════════
# Artifacts
# ═══════════════════════════════════════════════════════════════


async def create_artifact(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    tool_run_id: uuid.UUID | None = None,
    artifact_type: str,
    content: str | None = None,
    file_path: str | None = None,
) -> Artifact:
    """Insert a new artifact and return it."""
    artifact = Artifact(
        session_id=session_id,
        tool_run_id=tool_run_id,
        artifact_type=artifact_type,
        content=content,
        file_path=file_path,
    )
    db.add(artifact)
    await db.flush()
    await db.refresh(artifact)
    return artifact


async def get_artifacts(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    artifact_type: str | None = None,
) -> Sequence[Artifact]:
    """Fetch artifacts for a session."""
    stmt = select(Artifact).where(Artifact.session_id == session_id)
    if artifact_type:
        stmt = stmt.where(Artifact.artifact_type == artifact_type)
    stmt = stmt.order_by(Artifact.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()
