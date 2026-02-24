"""Tool result persistence — parses outputs and stores structured data in DB.

This module bridges the gap between raw tool execution (stdout/stderr) and
stored, queryable data (targets, findings, artifacts).  Called by Celery
workers after a tool finishes.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.models import RunStatus
from src.parsers.dispatch import has_parser, parse_tool_output
from src.parsers.httpx import HttpxResult
from src.parsers.nmap import NmapResult
from src.parsers.nuclei import NucleiResult
from src.parsers.secret_scanner import SecretScanResult
from src.parsers.site_mirror import SiteMirrorResult
from src.parsers.subfinder import SubfinderResult
from src.parsers.whatweb import WhatWebResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main persistence entry point
# ---------------------------------------------------------------------------


async def persist_tool_result(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    tool_run_id: uuid.UUID,
    tool_name: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> dict[str, Any]:
    """Parse, store, and return structured results for a tool execution.

    1. Marks the ToolRun as completed (SUCCESS or FAILED).
    2. Stores raw output as an artifact.
    3. If a parser exists, parses the output and stores structured data
       (targets, findings) in the DB.
    4. Stores the parsed JSON as an additional artifact.

    Parameters
    ----------
    db:
        Active async DB session.
    session_id:
        UUID of the pentest session.
    tool_run_id:
        UUID of the ToolRun record.
    tool_name:
        Name of the tool (e.g. "nmap", "subfinder").
    stdout:
        Raw stdout from execution.
    stderr:
        Raw stderr from execution.
    exit_code:
        Process exit code.

    Returns
    -------
    Summary dict with counts of persisted entities.
    """
    status = RunStatus.SUCCESS if (exit_code == 0 or exit_code is None) else RunStatus.FAILED

    # 1. Complete the tool run record
    await dal.complete_tool_run(
        db,
        tool_run_id,
        status=status,
        stdout=stdout[:500_000] if stdout else None,  # cap at 500KB
        stderr=stderr[:100_000] if stderr else None,
        exit_code=exit_code,
    )

    # 2. Store raw output as artifact
    await dal.create_artifact(
        db,
        session_id=session_id,
        tool_run_id=tool_run_id,
        artifact_type=f"{tool_name}_raw",
        content=stdout[:500_000] if stdout else "",
    )

    summary: dict[str, Any] = {
        "tool_name": tool_name,
        "tool_run_id": str(tool_run_id),
        "status": status.value,
        "targets_created": 0,
        "findings_created": 0,
        "artifacts_created": 1,  # raw artifact
    }

    # 3. Parse and store structured data if parser available
    if not has_parser(tool_name) or not stdout:
        return summary

    parsed = parse_tool_output(tool_name, stdout)

    # Store parsed JSON as artifact
    parsed_dict = parsed.to_dict() if hasattr(parsed, "to_dict") else parsed
    await dal.create_artifact(
        db,
        session_id=session_id,
        tool_run_id=tool_run_id,
        artifact_type=f"{tool_name}_parsed",
        content=json.dumps(parsed_dict, indent=2, default=str),
    )
    summary["artifacts_created"] += 1

    # 4. Extract and persist entities based on tool type
    if isinstance(parsed, NmapResult):
        summary.update(await _persist_nmap(db, session_id, parsed))
    elif isinstance(parsed, SubfinderResult):
        summary.update(await _persist_subfinder(db, session_id, parsed))
    elif isinstance(parsed, HttpxResult):
        summary.update(await _persist_httpx(db, session_id, parsed))
    elif isinstance(parsed, WhatWebResult):
        summary.update(await _persist_whatweb(db, session_id, parsed))
    elif isinstance(parsed, NucleiResult):
        summary.update(await _persist_nuclei(db, session_id, parsed))
    elif isinstance(parsed, SecretScanResult):
        summary.update(await _persist_secret_scan(db, session_id, parsed))
    # SiteMirrorResult has no extra entities — stats only

    logger.info(
        "Persisted results for %s (session=%s): %s",
        tool_name,
        session_id,
        summary,
    )
    return summary


# ---------------------------------------------------------------------------
# Tool-specific persistence
# ---------------------------------------------------------------------------


async def _persist_nmap(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: NmapResult,
) -> dict[str, int]:
    """Extract targets from nmap results."""
    targets_created = 0
    for host in result.hosts:
        if host.state != "up":
            continue
        ports_dict = {
            str(s.port): {
                "protocol": s.protocol,
                "state": s.state,
                "service": s.service_name,
                "product": s.product,
                "version": s.version,
            }
            for s in host.services
        }
        await dal.upsert_target(
            db,
            session_id=session_id,
            host=host.hostname or host.ip,
            ports=ports_dict,
            notes=f"OS: {', '.join(host.os_matches)}" if host.os_matches else None,
        )
        targets_created += 1
    return {"targets_created": targets_created}


async def _persist_subfinder(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: SubfinderResult,
) -> dict[str, int]:
    """Extract targets from subfinder results."""
    targets_created = 0
    for entry in result.entries:
        await dal.upsert_target(
            db,
            session_id=session_id,
            host=entry.host,
            notes=f"Source: {entry.source}" if entry.source else None,
        )
        targets_created += 1
    return {"targets_created": targets_created}


async def _persist_httpx(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: HttpxResult,
) -> dict[str, int]:
    """Extract targets with technologies from httpx results."""
    targets_created = 0
    for entry in result.entries:
        host = entry.host or entry.url
        tech_dict = {t: True for t in entry.technologies} if entry.technologies else None
        await dal.upsert_target(
            db,
            session_id=session_id,
            host=host,
            technologies=tech_dict,
            notes=f"[{entry.status_code}] {entry.url} — {entry.title}" if entry.title else None,
        )
        targets_created += 1
    return {"targets_created": targets_created}


async def _persist_whatweb(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: WhatWebResult,
) -> dict[str, int]:
    """Extract technology info from whatweb results."""
    targets_created = 0
    for entry in result.entries:
        tech_dict = {
            p.name: p.version or True
            for p in entry.plugins
        }
        await dal.upsert_target(
            db,
            session_id=session_id,
            host=entry.url,
            technologies=tech_dict,
        )
        targets_created += 1
    return {"targets_created": targets_created}


async def _persist_nuclei(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: NucleiResult,
) -> dict[str, int]:
    """Extract findings from nuclei results."""
    findings_created = 0
    for match in result.matches:
        finding_data = match.to_finding_dict()
        await dal.create_finding(
            db,
            session_id=session_id,
            **finding_data,
        )
        findings_created += 1
    return {"findings_created": findings_created}


async def _persist_secret_scan(
    db: AsyncSession,
    session_id: uuid.UUID,
    result: SecretScanResult,
) -> dict[str, int]:
    """Extract findings from secret scanner results."""
    findings_created = 0
    for finding in result.findings:
        finding_data = finding.to_finding_dict()
        await dal.create_finding(
            db,
            session_id=session_id,
            **finding_data,
        )
        findings_created += 1
    return {"findings_created": findings_created}
