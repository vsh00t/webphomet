"""Caido ↔ WebPhomet bidirectional finding sync service.

Provides two main operations:
1. **pull** — Fetch findings from Caido, deduplicate, and upsert into the
   WebPhomet DB.
2. **push** — Take WebPhomet DB findings that have a ``caido_request_id``
   but no ``caido_finding_id``, push them to Caido, and back-fill the
   ``caido_finding_id`` column.

Both directions are idempotent thanks to the ``caido_finding_id`` unique
index on the findings table.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.models import Severity

import uuid

logger = logging.getLogger(__name__)

# Mapping of Caido reporter strings to default severity
_DEFAULT_SEVERITY = Severity.INFO


def _map_severity(caido_finding: dict[str, Any]) -> str:
    """Map Caido finding data to a Severity enum value.

    Caido findings don't have a native severity field, so we default to
    INFO for imported findings.  The agent can later upgrade them.
    """
    return _DEFAULT_SEVERITY.value


async def pull_findings_from_caido(
    db: AsyncSession,
    session_id: uuid.UUID,
    caido_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Import Caido findings into the WebPhomet DB.

    Parameters
    ----------
    db:
        Active async database session.
    session_id:
        WebPhomet pentest session to associate findings with.
    caido_findings:
        List of finding dicts as returned by the MCP Caido ``pull_findings``
        RPC method.  Each dict should have ``caido_finding_id``, ``title``,
        ``description``, ``reporter``, and optionally ``caido_request_id``.

    Returns
    -------
    dict with created/skipped/error counts.
    """
    created = 0
    skipped = 0
    errors = 0

    for cf in caido_findings:
        caido_id = cf.get("caido_finding_id", "")
        if not caido_id:
            errors += 1
            continue

        # Deduplicate — skip if already in DB
        existing = await dal.get_finding_by_caido_id(db, caido_id)
        if existing is not None:
            skipped += 1
            continue

        try:
            await dal.create_finding(
                db,
                session_id=session_id,
                vuln_type="imported",
                title=cf.get("title", "Imported from Caido"),
                severity=_map_severity(cf),
                description=cf.get("description"),
                caido_finding_id=caido_id,
                caido_request_id=cf.get("caido_request_id"),
            )
            created += 1
        except Exception as exc:
            logger.warning(
                "Failed to import Caido finding %s: %s", caido_id, exc
            )
            errors += 1

    await db.flush()
    return {"created": created, "skipped": skipped, "errors": errors}


async def push_findings_to_caido(
    db: AsyncSession,
    session_id: uuid.UUID,
    push_results: list[dict[str, str]],
) -> dict[str, Any]:
    """Back-fill caido_finding_id for findings that were pushed to Caido.

    Parameters
    ----------
    db:
        Active async database session.
    session_id:
        WebPhomet pentest session.
    push_results:
        List of ``{"webphomet_finding_id": ..., "caido_finding_id": ...}``
        dicts returned by the MCP Caido ``sync_findings`` RPC.

    Returns
    -------
    dict with updated count.
    """
    updated = 0
    for item in push_results:
        wp_id = item.get("webphomet_finding_id", "")
        caido_id = item.get("caido_finding_id", "")
        if not wp_id or not caido_id:
            continue
        try:
            await dal.update_finding_caido_ids(
                db,
                uuid.UUID(wp_id),
                caido_finding_id=caido_id,
            )
            updated += 1
        except Exception as exc:
            logger.warning(
                "Failed to back-fill caido_finding_id for %s: %s", wp_id, exc
            )

    await db.flush()
    return {"updated": updated}
