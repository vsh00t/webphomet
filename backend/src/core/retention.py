"""Data retention policy — configurable cleanup of old sessions and artifacts."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import async_session_factory
from src.db.models import PentestSession, Finding, Artifact, ToolRun, Target

logger = logging.getLogger(__name__)

# Default retention: 30 days.  Override with RETENTION_DAYS env var.
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "30"))


async def purge_old_sessions(days: int | None = None) -> dict:
    """Delete sessions older than *days* (default: RETENTION_DAYS).

    Cascade deletes all children (targets, findings, artifacts, tool_runs).
    Returns stats dict.
    """
    days = days or RETENTION_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async with async_session_factory() as db:
        # Count what will be removed
        count_q = select(func.count()).select_from(PentestSession).where(
            PentestSession.created_at < cutoff
        )
        total = (await db.execute(count_q)).scalar() or 0

        if total == 0:
            logger.info("retention: nothing to purge (cutoff=%s)", cutoff.isoformat())
            return {"purged_sessions": 0, "cutoff": cutoff.isoformat()}

        # Collect file paths from artifacts to delete on disk
        art_q = (
            select(Artifact.file_path)
            .join(PentestSession, Artifact.session_id == PentestSession.id)
            .where(PentestSession.created_at < cutoff)
            .where(Artifact.file_path.isnot(None))
        )
        rows = (await db.execute(art_q)).scalars().all()
        file_paths = [p for p in rows if p]

        # Cascade delete
        stmt = delete(PentestSession).where(PentestSession.created_at < cutoff)
        await db.execute(stmt)
        await db.commit()

        # Cleanup orphaned files
        removed_files = 0
        for fp in file_paths:
            try:
                if os.path.exists(fp):
                    os.remove(fp)
                    removed_files += 1
            except OSError:
                logger.warning("retention: failed to remove file %s", fp)

        logger.info(
            "retention: purged %d sessions, %d artifact files (cutoff=%s)",
            total,
            removed_files,
            cutoff.isoformat(),
        )
        return {
            "purged_sessions": total,
            "removed_files": removed_files,
            "cutoff": cutoff.isoformat(),
        }


async def get_retention_stats() -> dict:
    """Return current data sizes for monitoring."""
    async with async_session_factory() as db:
        sessions = (await db.execute(select(func.count()).select_from(PentestSession))).scalar() or 0
        findings = (await db.execute(select(func.count()).select_from(Finding))).scalar() or 0
        artifacts = (await db.execute(select(func.count()).select_from(Artifact))).scalar() or 0
        tool_runs = (await db.execute(select(func.count()).select_from(ToolRun))).scalar() or 0
        targets = (await db.execute(select(func.count()).select_from(Target))).scalar() or 0

        return {
            "sessions": sessions,
            "findings": findings,
            "artifacts": artifacts,
            "tool_runs": tool_runs,
            "targets": targets,
            "retention_days": RETENTION_DAYS,
        }
