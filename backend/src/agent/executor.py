"""Tool execution dispatch — bridges Z.ai tool_calls to real backend actions.

Each function corresponds to one of the tools defined in ``agent.tools``.
When the LLM emits a ``tool_call``, the orchestrator looks up the function
name here and invokes it.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.models import RunStatus, SessionStatus
from src.core.safe_mode import SafeModePolicy
from src.jobs.celery_app import celery_app

logger = logging.getLogger(__name__)

# Safe mode policy instance
_policy = SafeModePolicy()


# ---------------------------------------------------------------------------
# Dispatcher registry
# ---------------------------------------------------------------------------

_DISPATCH: dict[str, Any] = {}


def register(name: str):
    """Decorator that registers a tool execution function."""

    def wrapper(fn):
        _DISPATCH[name] = fn
        return fn

    return wrapper


async def dispatch(
    name: str,
    arguments: dict[str, Any],
    db: AsyncSession,
) -> str:
    """Dispatch a tool call to its implementation.

    Returns a JSON-encoded string suitable for inserting back as a
    ``tool`` message in the conversation.
    """
    fn = _DISPATCH.get(name)
    if fn is None:
        return json.dumps({"error": f"Unknown tool: {name}"})

    try:
        result = await fn(db=db, **arguments)
        return json.dumps(result, default=str)
    except Exception as e:
        logger.exception("Tool dispatch error for %s", name)
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# Session management
# ═══════════════════════════════════════════════════════════════


@register("create_pentest_session")
async def _create_session(
    db: AsyncSession,
    target_base_url: str,
    app_type: str | None = None,
    scope: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    session = await dal.create_session(
        db,
        target_base_url=target_base_url,
        app_type=app_type,
        scope=scope,
    )
    await db.commit()
    return {
        "session_id": str(session.id),
        "status": session.status.value,
        "target_base_url": session.target_base_url,
    }


@register("get_session_state")
async def _get_session_state(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    session = await dal.get_session(db, uuid.UUID(session_id))
    if session is None:
        return {"error": f"Session {session_id} not found"}

    targets = await dal.get_targets(db, session.id)
    findings_summary = await dal.get_findings_summary(db, session.id)
    tool_runs = await dal.get_tool_runs(db, session.id)

    return {
        "session_id": str(session.id),
        "status": session.status.value,
        "target_base_url": session.target_base_url,
        "targets_count": len(targets),
        "targets": [
            {"host": t.host, "ports": t.ports, "technologies": t.technologies}
            for t in targets[:20]  # cap to avoid token explosion
        ],
        "findings": findings_summary,
        "tool_runs": [
            {
                "id": str(r.id),
                "tool": r.tool_name,
                "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                "exit_code": r.exit_code,
            }
            for r in tool_runs[:30]
        ],
    }


# ═══════════════════════════════════════════════════════════════
# Reconnaissance
# ═══════════════════════════════════════════════════════════════


@register("run_recon")
async def _run_recon(
    db: AsyncSession,
    session_id: str,
    tool_name: str,
    args: str,
    **_: Any,
) -> dict[str, Any]:
    """Queue a recon tool execution via Celery."""
    sid = uuid.UUID(session_id)
    command = f"{tool_name} {args}"

    # Safe mode policy check
    result = _policy.check(
        session_id=session_id,
        tool_name=tool_name,
        command=command,
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db,
        session_id=sid,
        tool_name=tool_name,
        command=command,
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_tool",
        kwargs={
            "session_id": session_id,
            "tool_name": tool_name,
            "command": command,
            "tool_run_id": str(tool_run.id),
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": tool_name,
        "status": "submitted",
    }


@register("get_recon_results")
async def _get_recon_results(
    db: AsyncSession,
    tool_run_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Retrieve the results of a completed tool run."""
    run = await dal.get_tool_run(db, uuid.UUID(tool_run_id))
    if run is None:
        return {"error": f"ToolRun {tool_run_id} not found"}

    status = run.status.value if hasattr(run.status, "value") else str(run.status)

    result: dict[str, Any] = {
        "tool_run_id": str(run.id),
        "tool_name": run.tool_name,
        "status": status,
        "exit_code": run.exit_code,
    }

    if status in ("success", "failed"):
        # Truncate stdout for token safety
        stdout = run.stdout or ""
        if len(stdout) > 8000:
            stdout = stdout[:8000] + "\n... [truncated]"
        result["stdout"] = stdout
        result["stderr"] = run.stderr
    else:
        result["message"] = "Tool is still running. Poll again shortly."

    return result


# ═══════════════════════════════════════════════════════════════
# Static Analysis — Site Mirror + Secret Scanner
# ═══════════════════════════════════════════════════════════════


@register("mirror_site")
async def _mirror_site(
    db: AsyncSession,
    session_id: str,
    url: str,
    depth: int = 8,
    global_timeout: int = 300,
    **_: Any,
) -> dict[str, Any]:
    """Queue a site mirror operation via Celery."""
    sid = uuid.UUID(session_id)

    # Safe mode: mirror is passive — no policy check needed
    tool_run = await dal.create_tool_run(
        db,
        session_id=sid,
        tool_name="site_mirror",
        command=f"mirror_site {url} --depth {depth} --global-timeout {global_timeout}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_mirror",
        kwargs={
            "session_id": session_id,
            "url": url,
            "tool_run_id": str(tool_run.id),
            "depth": depth,
            "global_timeout": global_timeout,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "site_mirror",
        "status": "submitted",
    }


@register("scan_secrets")
async def _scan_secrets(
    db: AsyncSession,
    session_id: str,
    max_findings: int = 500,
    **_: Any,
) -> dict[str, Any]:
    """Queue a secret scan on the mirrored site content via Celery."""
    sid = uuid.UUID(session_id)

    tool_run = await dal.create_tool_run(
        db,
        session_id=sid,
        tool_name="secret_scanner",
        command=f"scan_secrets --session-id {session_id} --max-findings {max_findings}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_secret_scan",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "max_findings": max_findings,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "secret_scanner",
        "status": "submitted",
    }


# ═══════════════════════════════════════════════════════════════
# Analysis
# ═══════════════════════════════════════════════════════════════


@register("parse_nmap_output")
async def _parse_nmap_output(
    db: AsyncSession,
    artifact_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Parse an nmap artifact through the nmap parser."""
    from sqlalchemy import select as sa_select
    from src.db.models import Artifact
    from src.parsers.nmap import parse_nmap

    result = await db.execute(
        sa_select(Artifact).where(Artifact.id == uuid.UUID(artifact_id))
    )
    artifact = result.scalar_one_or_none()
    if artifact is None:
        return {"error": f"Artifact {artifact_id} not found"}

    content = artifact.content or ""
    parsed = parse_nmap(content)
    return {
        "hosts": [h.to_dict() for h in parsed.hosts],
        "total_hosts": len(parsed.hosts),
        "total_open_ports": sum(len(h.services) for h in parsed.hosts),
    }


@register("summarize_findings")
async def _summarize_findings(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    sid = uuid.UUID(session_id)
    summary = await dal.get_findings_summary(db, sid)
    findings = await dal.get_findings(db, sid)

    return {
        "summary": summary,
        "findings": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "vuln_type": f.vuln_type,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
            }
            for f in findings
        ],
    }


@register("correlate_findings")
async def _correlate_findings(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Basic correlation — group findings by host/type, flag attack chains."""
    sid = uuid.UUID(session_id)
    findings = await dal.get_findings(db, sid)

    by_type: dict[str, list[str]] = {}
    severities: list[str] = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severities.append(sev)
        by_type.setdefault(f.vuln_type, []).append(f.title)

    # Simple heuristic for attack chains
    attack_chains: list[str] = []
    types_present = set(by_type.keys())
    if {"sqli", "xss"} & types_present:
        attack_chains.append("SQL Injection + XSS could enable session hijacking")
    if {"ssrf", "rce"} & types_present:
        attack_chains.append("SSRF + RCE could enable internal network pivoting")
    if "auth_bypass" in types_present:
        attack_chains.append("Auth bypass amplifies severity of all other findings")

    return {
        "total_findings": len(findings),
        "vulnerability_types": {k: len(v) for k, v in by_type.items()},
        "attack_chains": attack_chains,
        "risk_level": (
            "critical" if "critical" in severities
            else "high" if "high" in severities
            else "medium" if "medium" in severities
            else "low"
        ),
    }


# ═══════════════════════════════════════════════════════════════
# Reporting
# ═══════════════════════════════════════════════════════════════


@register("build_report")
async def _build_report(
    db: AsyncSession,
    session_id: str,
    format: str = "markdown",
    **_: Any,
) -> dict[str, Any]:
    """Queue report generation via Celery."""
    task = celery_app.send_task(
        "jobs.build_report",
        kwargs={"session_id": session_id, "format": format},
    )
    return {
        "task_id": task.id,
        "status": "report_generation_submitted",
        "format": format,
    }


@register("export_report")
async def _export_report(
    db: AsyncSession,
    report_artifact_id: str,
    output_path: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Retrieve report artifact content."""
    from sqlalchemy import select as sa_select
    from src.db.models import Artifact

    result = await db.execute(
        sa_select(Artifact).where(Artifact.id == uuid.UUID(report_artifact_id))
    )
    artifact = result.scalar_one_or_none()
    if artifact is None:
        return {"error": f"Artifact {report_artifact_id} not found"}

    return {
        "artifact_id": str(artifact.id),
        "file_path": artifact.file_path,
        "content_preview": (artifact.content or "")[:2000],
    }
