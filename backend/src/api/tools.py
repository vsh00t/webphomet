"""Endpoints for tool runs and recon orchestration."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.schemas import ToolRunResponse
from src.core.safe_mode import SafeModePolicy, PolicyViolation
from src.core.scope import ScopeValidator
from src.db import dal
from src.db.database import get_db
from src.jobs.celery_app import celery_app

router = APIRouter()

# Shared safe mode policy instance
_policy = SafeModePolicy()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RunToolRequest(BaseModel):
    """Request to execute a security tool."""

    session_id: uuid.UUID
    tool_name: str
    args: str
    """CLI arguments for the tool (e.g. '-sV -T4 target.com')."""


class MirrorSiteRequest(BaseModel):
    """Request to mirror a website for static analysis."""

    session_id: uuid.UUID
    url: str
    """Target URL to mirror."""
    depth: int = 8
    """Maximum recursion depth (default: 8)."""
    global_timeout: int = 300
    """Global timeout per URL in seconds (default: 300)."""


class ScanSecretsRequest(BaseModel):
    """Request to scan mirrored content for secrets."""

    session_id: uuid.UUID
    max_findings: int = 500
    """Maximum findings to report (default: 500)."""


class RunReconRequest(BaseModel):
    """Request to execute a full recon sweep."""

    session_id: uuid.UUID
    target: str
    """Target domain/IP to scan."""
    tools: list[str] = ["subfinder", "nmap", "httpx", "whatweb"]
    """Which recon tools to run (default: all)."""
    nmap_args: str = "-sV -T4 --top-ports 1000"
    httpx_flags: str = "-json -status-code -tech-detect -title"
    whatweb_flags: str = "--log-json=-"


# ---------------------------------------------------------------------------
# Single tool execution
# ---------------------------------------------------------------------------


@router.post(
    "/run",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Execute a security tool (async)",
)
async def run_tool(
    payload: RunToolRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Submit a security tool for execution via Celery.

    Creates a ToolRun record, dispatches the task, and returns the
    task and run IDs for status polling.
    """
    # Safe mode policy check — build scope from session
    command = f"{payload.tool_name} {payload.args}"

    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    # Build a ScopeValidator from the session's scope config
    scope_cfg = session.scope or {}
    scope_validator = ScopeValidator(
        allowed_hosts=set(scope_cfg.get("allowed_hosts", [])),
        allowed_ips=set(scope_cfg.get("allowed_ips", [])),
        exclusions=set(scope_cfg.get("exclusions", [])),
    )

    # Check scope: validate every target-like argument in the command
    args_list = payload.args.split()
    if scope_validator.allowed_hosts or scope_validator.allowed_ips:
        if not scope_validator.validate_command(payload.tool_name, args_list):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Scope violation: command targets addresses outside the session scope",
            )

    # Check safe mode policy (blocked tools, patterns, rate limit)
    policy = SafeModePolicy(scope_validator=scope_validator)
    try:
        policy.check(
            session_id=str(payload.session_id),
            tool_name=payload.tool_name,
            command=command,
        ).enforce()
    except PolicyViolation as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Policy violation: {exc.reason}",
        )

    # Create ToolRun record
    tool_run = await dal.create_tool_run(
        db,
        session_id=payload.session_id,
        tool_name=payload.tool_name,
        command=command,
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    # Dispatch Celery task
    task = celery_app.send_task(
        "jobs.run_tool",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_name": payload.tool_name,
            "command": command,
            "tool_run_id": str(tool_run.id),
        },
    )

    return {
        "task_id": task.id,
        "tool_run_id": str(tool_run.id),
        "tool_name": payload.tool_name,
        "status": "submitted",
    }


# ---------------------------------------------------------------------------
# Recon orchestration (parallel execution)
# ---------------------------------------------------------------------------


@router.post(
    "/recon",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Execute full recon sweep (parallel)",
)
async def run_recon(
    payload: RunReconRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Launch a parallelized reconnaissance sweep.

    Submits subfinder, nmap, httpx, and whatweb tasks simultaneously.
    Each tool gets its own ToolRun record and Celery task.
    """
    target = payload.target
    tasks: list[dict[str, Any]] = []

    tool_configs = {
        "subfinder": f"-d {target} -json -silent",
        "nmap": f"{payload.nmap_args} {target}",
        "httpx": f"-u {target} {payload.httpx_flags}",
        "whatweb": f"{payload.whatweb_flags} {target}",
    }

    for tool_name in payload.tools:
        args = tool_configs.get(tool_name)
        if args is None:
            continue

        command = f"{tool_name} {args}"
        tool_run = await dal.create_tool_run(
            db,
            session_id=payload.session_id,
            tool_name=tool_name,
            command=command,
        )
        await dal.start_tool_run(db, tool_run.id)

        task = celery_app.send_task(
            "jobs.run_tool",
            kwargs={
                "session_id": str(payload.session_id),
                "tool_name": tool_name,
                "command": command,
                "tool_run_id": str(tool_run.id),
            },
        )

        tasks.append({
            "task_id": task.id,
            "tool_run_id": str(tool_run.id),
            "tool_name": tool_name,
            "command": command,
        })

    await db.commit()

    return {
        "session_id": str(payload.session_id),
        "target": target,
        "tasks": tasks,
        "status": "recon_submitted",
    }


# ---------------------------------------------------------------------------
# Query tool runs
# ---------------------------------------------------------------------------


@router.get(
    "/session/{session_id}",
    response_model=list[ToolRunResponse],
    summary="List tool runs for a session",
)
async def list_tool_runs(
    session_id: uuid.UUID,
    tool_name: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[ToolRunResponse]:
    """Return all tool runs for a session."""
    runs = await dal.get_tool_runs(db, session_id, tool_name=tool_name)
    return [ToolRunResponse.model_validate(r) for r in runs]


@router.get(
    "/{tool_run_id}",
    response_model=ToolRunResponse,
    summary="Get a specific tool run",
)
async def get_tool_run(
    tool_run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ToolRunResponse:
    """Return a single tool run by ID."""
    run = await dal.get_tool_run(db, tool_run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool run {tool_run_id} not found",
        )
    return ToolRunResponse.model_validate(run)


@router.get(
    "/task/{task_id}/status",
    summary="Check Celery task status",
)
async def check_task_status(task_id: str) -> dict[str, Any]:
    """Query the status of a Celery task by its ID."""
    result = celery_app.AsyncResult(task_id)
    response: dict[str, Any] = {
        "task_id": task_id,
        "status": result.status,
    }
    if result.ready():
        response["result"] = result.result
    return response


# ---------------------------------------------------------------------------
# Site Mirror + Secret Scanner
# ---------------------------------------------------------------------------


@router.post(
    "/mirror",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Mirror a website for static analysis",
)
async def mirror_site(
    payload: MirrorSiteRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Download all reachable content from a target URL.

    Two-phase strategy: wget recursive download + smart URL extraction
    from JS/HTML/CSS for lazy-loaded chunks, API endpoints, source maps.
    Results stored in the session's artifacts directory.
    """
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    tool_run = await dal.create_tool_run(
        db,
        session_id=payload.session_id,
        tool_name="site_mirror",
        command=f"mirror_site {payload.url} --depth {payload.depth}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_mirror",
        kwargs={
            "session_id": str(payload.session_id),
            "url": payload.url,
            "tool_run_id": str(tool_run.id),
            "depth": payload.depth,
            "global_timeout": payload.global_timeout,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "status": "submitted",
        "url": payload.url,
    }


@router.post(
    "/scan-secrets",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Scan mirrored site for secrets",
)
async def scan_secrets(
    payload: ScanSecretsRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Scan the previously mirrored content for hardcoded secrets,
    API keys, tokens, passwords, internal IPs, debug endpoints, etc.

    Must run /tools/mirror first for the session.
    Each finding is persisted to the findings table.
    """
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    tool_run = await dal.create_tool_run(
        db,
        session_id=payload.session_id,
        tool_name="secret_scanner",
        command=f"scan_secrets --max-findings {payload.max_findings}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_secret_scan",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "max_findings": payload.max_findings,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "status": "submitted",
    }
