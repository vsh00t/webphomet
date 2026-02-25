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


class SyncCaidoFindingsRequest(BaseModel):
    """Request to sync findings between Caido and WebPhomet DB."""

    session_id: uuid.UUID
    direction: str = "both"
    """Sync direction: 'pull', 'push', or 'both' (default)."""


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


# ---------------------------------------------------------------------------
# Caido Finding Sync
# ---------------------------------------------------------------------------


@router.post(
    "/sync-caido-findings",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bidirectional sync findings between Caido and WebPhomet DB",
)
async def sync_caido_findings(
    payload: SyncCaidoFindingsRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Pull findings from Caido into the DB and/or push DB findings to Caido.

    Direction:
    - ``pull``: Import Caido findings into the DB (deduplicates).
    - ``push``: Push DB findings (with caido_request_id) to Caido.
    - ``both``: Pull first, then push.
    """
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    if payload.direction not in ("pull", "push", "both"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="direction must be 'pull', 'push', or 'both'",
        )

    tool_run = await dal.create_tool_run(
        db,
        session_id=payload.session_id,
        tool_name="caido_sync_findings",
        command=f"sync_caido_findings direction={payload.direction}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.sync_caido_findings",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "direction": payload.direction,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "direction": payload.direction,
        "status": "submitted",
    }


# ---------------------------------------------------------------------------
# Predefined Caido Workflows
# ---------------------------------------------------------------------------


class RunPredefinedWorkflowRequest(BaseModel):
    """Request to execute a predefined security scan workflow."""

    session_id: uuid.UUID
    workflow_name: str
    """Workflow name from registry (sqli_error_detect, xss_reflect_probe, etc.)."""
    host: str
    port: int
    is_tls: bool = False
    base_path: str = "/"
    param_name: str = "id"
    protected_path: str | None = None


@router.post(
    "/run-workflow",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Run a predefined security scan workflow through Caido",
)
async def run_predefined_workflow(
    payload: RunPredefinedWorkflowRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Execute a predefined security workflow that sends crafted requests
    through Caido and auto-creates findings for detected vulnerabilities.

    Available workflows: sqli_error_detect, xss_reflect_probe,
    auth_bypass_probe, open_redirect_check, header_injection.
    """
    from src.services.workflows import WORKFLOW_REGISTRY

    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {payload.session_id} not found",
        )

    if payload.workflow_name not in WORKFLOW_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown workflow: {payload.workflow_name}. "
            f"Available: {', '.join(WORKFLOW_REGISTRY.keys())}",
        )

    tool_run = await dal.create_tool_run(
        db,
        session_id=payload.session_id,
        tool_name=f"workflow_{payload.workflow_name}",
        command=f"run_workflow {payload.workflow_name} {payload.host}:{payload.port}{payload.base_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    wf_params: dict[str, Any] = {
        "host": payload.host,
        "port": payload.port,
        "is_tls": payload.is_tls,
    }
    if payload.workflow_name == "auth_bypass_probe":
        wf_params["protected_path"] = payload.protected_path or payload.base_path
    else:
        wf_params["base_path"] = payload.base_path
        wf_params["param_name"] = payload.param_name

    task = celery_app.send_task(
        "jobs.run_predefined_workflow",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "workflow_name": payload.workflow_name,
            "params": wf_params,
        },
    )

    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "workflow_name": payload.workflow_name,
        "status": "submitted",
    }


# ═══════════════════════════════════════════════════════════════
# DevTools endpoints
# ═══════════════════════════════════════════════════════════════


class DevToolsNavigateRequest(BaseModel):
    session_id: uuid.UUID
    url: str
    wait_until: str = "load"


class DevToolsFullAuditRequest(BaseModel):
    session_id: uuid.UUID
    url: str


class DevToolsGenericRequest(BaseModel):
    """Generic request that only needs session_id (for screenshot, forms, etc.)."""
    session_id: uuid.UUID


class DevToolsJsRequest(BaseModel):
    session_id: uuid.UUID
    script: str


@router.post("/devtools-navigate")
async def devtools_navigate(
    payload: DevToolsNavigateRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Navigate headless browser to a URL."""
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {payload.session_id} not found")

    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="devtools_navigate",
        command=f"devtools_navigate url={payload.url}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "method": "navigate",
            "params": {"url": payload.url, "wait_until": payload.wait_until},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/devtools-full-audit")
async def devtools_full_audit(
    payload: DevToolsFullAuditRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run a combined security audit on a URL."""
    session = await dal.get_session(db, payload.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {payload.session_id} not found")

    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="devtools_full_page_audit",
        command=f"devtools_full_page_audit url={payload.url}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "method": "full_page_audit",
            "params": {"url": payload.url},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/devtools-discover-forms")
async def devtools_discover_forms(
    payload: DevToolsGenericRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Discover HTML forms on the current page."""
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="devtools_discover_forms",
        command="devtools_discover_forms",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "method": "discover_forms",
            "params": {},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/devtools-detect-dom-xss")
async def devtools_detect_dom_xss(
    payload: DevToolsGenericRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Detect DOM XSS sinks on the current page."""
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="devtools_detect_dom_xss",
        command="devtools_detect_dom_xss",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "method": "detect_dom_xss_sinks",
            "params": {},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


# ── Injection tests ──────────────────────────────────────────
class RunInjectionTestsRequest(BaseModel):
    session_id: uuid.UUID
    host: str
    port: int = 80
    is_tls: bool = False
    targets: list[dict[str, Any]] | None = None
    test_types: list[str] | None = None
    cookie: str = ""


@router.post("/run-injection-tests")
async def run_injection_tests(
    payload: RunInjectionTestsRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run OWASP injection & XSS tests against a target."""
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="injection_tests",
        command=f"run_injection_tests {payload.host}:{payload.port}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_injection_tests",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "host": payload.host,
            "port": payload.port,
            "is_tls": payload.is_tls,
            "targets": payload.targets,
            "test_types": payload.test_types,
            "cookie": payload.cookie,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


# ── Auth tests ───────────────────────────────────────────────
class RunAuthTestsRequest(BaseModel):
    session_id: uuid.UUID
    host: str
    port: int = 80
    is_tls: bool = False
    test_types: list[str] | None = None
    login_path: str = "/login"
    cookie: str = ""
    auth_header: str = ""
    username_field: str = "username"
    password_field: str = "password"


@router.post("/run-auth-tests")
async def run_auth_tests(
    payload: RunAuthTestsRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run broken-authentication tests."""
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="auth_tests",
        command=f"run_auth_tests {payload.host}:{payload.port}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.run_auth_tests",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "host": payload.host, "port": payload.port, "is_tls": payload.is_tls,
            "test_types": payload.test_types, "login_path": payload.login_path,
            "cookie": payload.cookie, "auth_header": payload.auth_header,
            "username_field": payload.username_field,
            "password_field": payload.password_field,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


# ── SSRF tests ───────────────────────────────────────────────
class RunSSRFTestsRequest(BaseModel):
    session_id: uuid.UUID
    host: str
    port: int = 80
    is_tls: bool = False
    targets: list[dict[str, Any]] | None = None
    test_types: list[str] | None = None
    cookie: str = ""


@router.post("/run-ssrf-tests")
async def run_ssrf_tests(
    payload: RunSSRFTestsRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Run SSRF tests."""
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="ssrf_tests",
        command=f"run_ssrf_tests {payload.host}:{payload.port}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.run_ssrf_tests",
        kwargs={
            "session_id": str(payload.session_id),
            "tool_run_id": str(tool_run.id),
            "host": payload.host, "port": payload.port, "is_tls": payload.is_tls,
            "targets": payload.targets, "test_types": payload.test_types,
            "cookie": payload.cookie,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


# ═══════════════════════════════════════════════════════════════
# Git/Code — Source-code analysis endpoints (Phase 3.1)
# ═══════════════════════════════════════════════════════════════


class CloneRepoRequest(BaseModel):
    session_id: uuid.UUID
    url: str
    name: str | None = None


class CodeAuditRequest(BaseModel):
    session_id: uuid.UUID
    repo_url: str | None = None
    repo_name: str | None = None
    categories: list[str] | None = None


class SearchCodeRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    query: str
    is_regex: bool = False
    file_pattern: str = "*"


class FindHotspotsRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    categories: list[str] | None = None


class GitLogRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    max_count: int = 20
    file_path: str | None = None


class GitDiffRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    commit_a: str = "HEAD~1"
    commit_b: str = "HEAD"


class GitBlameRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    file_path: str
    start_line: int = 1
    end_line: int = 50


class GetTreeRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    path: str = ""
    max_depth: int = 3


class GetFileRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    file_path: str
    start_line: int = 1
    end_line: int | None = None


@router.post("/clone-repo")
async def clone_repo(
    payload: CloneRepoRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_clone_repo",
        command=f"git clone {payload.url}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "clone_repo", "params": {"url": payload.url, "name": payload.name},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/code-audit")
async def run_code_audit_endpoint(
    payload: CodeAuditRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="code_audit",
        command=f"code_audit {payload.repo_url or payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.run_code_audit",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "repo_url": payload.repo_url, "repo_name": payload.repo_name,
            "categories": payload.categories,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/search-code")
async def search_code_endpoint(
    payload: SearchCodeRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_search_code",
        command=f"search {payload.repo_name} '{payload.query}'",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "search_code",
            "params": {
                "repo_name": payload.repo_name, "query": payload.query,
                "is_regex": payload.is_regex, "file_pattern": payload.file_pattern,
            },
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/find-hotspots")
async def find_hotspots_endpoint(
    payload: FindHotspotsRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_find_hotspots",
        command=f"hotspots {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "find_hotspots",
            "params": {"repo_name": payload.repo_name, "categories": payload.categories},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-log")
async def git_log_endpoint(
    payload: GitLogRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_log",
        command=f"git log {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    params: dict[str, Any] = {"repo_name": payload.repo_name, "max_count": payload.max_count}
    if payload.file_path:
        params["file_path"] = payload.file_path
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_log", "params": params,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-diff")
async def git_diff_endpoint(
    payload: GitDiffRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_diff",
        command=f"git diff {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_diff",
            "params": {"repo_name": payload.repo_name, "commit_a": payload.commit_a, "commit_b": payload.commit_b},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-blame")
async def git_blame_endpoint(
    payload: GitBlameRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_blame",
        command=f"git blame {payload.repo_name}/{payload.file_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_blame",
            "params": {
                "repo_name": payload.repo_name, "file_path": payload.file_path,
                "start_line": payload.start_line, "end_line": payload.end_line,
            },
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-tree")
async def git_tree_endpoint(
    payload: GetTreeRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_get_tree",
        command=f"git tree {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "get_tree",
            "params": {"repo_name": payload.repo_name, "path": payload.path, "max_depth": payload.max_depth},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-file")
async def git_file_endpoint(
    payload: GetFileRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_get_file",
        command=f"git file {payload.repo_name}/{payload.file_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    params: dict[str, Any] = {
        "repo_name": payload.repo_name, "file_path": payload.file_path,
        "start_line": payload.start_line,
    }
    if payload.end_line is not None:
        params["end_line"] = payload.end_line
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "get_file", "params": params,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.get("/list-repos")
async def list_repos_endpoint(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=session_id, tool_name="git_list_repos",
        command="git list_repos",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(session_id), "tool_run_id": str(tool_run.id),
            "method": "list_repos",
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


# ═══════════════════════════════════════════════════════════════
# Mobile traffic analysis (Phase 3.2)
# ═══════════════════════════════════════════════════════════════


class AnalyzeMobileTrafficRequest(BaseModel):
    session_id: uuid.UUID
    host_filter: str | None = None
    limit: int = 200


@router.post("/analyze-mobile-traffic")
async def analyze_mobile_traffic_endpoint(
    payload: AnalyzeMobileTrafficRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="analyze_mobile_traffic",
        command=f"analyze_mobile_traffic host={payload.host_filter}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.analyze_mobile_traffic",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "host_filter": payload.host_filter, "limit": payload.limit,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}