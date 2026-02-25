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
# Caido proxy integration
# ═══════════════════════════════════════════════════════════════


@register("caido_get_requests")
async def _caido_get_requests(
    db: AsyncSession,
    session_id: str,
    limit: int = 50,
    offset: int = 0,
    host: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Fetch intercepted requests from Caido via MCP."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_get_requests",
        command=f"caido_get_requests limit={limit} offset={offset} host={host}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "get_requests",
            "params": {"limit": limit, "offset": offset, "host": host},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_get_requests",
        "status": "submitted",
    }


@register("caido_get_findings")
async def _caido_get_findings(
    db: AsyncSession,
    session_id: str,
    limit: int = 50,
    **_: Any,
) -> dict[str, Any]:
    """Fetch findings from Caido via MCP."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_get_findings",
        command=f"caido_get_findings limit={limit}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "get_findings",
            "params": {"limit": limit},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_get_findings",
        "status": "submitted",
    }


@register("caido_create_finding")
async def _caido_create_finding(
    db: AsyncSession,
    session_id: str,
    title: str,
    description: str | None = None,
    request_id: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Push a finding from WebPhomet to Caido."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_create_finding",
        command=f"caido_create_finding title={title}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "create_finding",
            "params": {
                "title": title,
                "description": description,
                "request_id": request_id,
                "reporter": "webphomet",
            },
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_create_finding",
        "status": "submitted",
    }


@register("caido_get_sitemap")
async def _caido_get_sitemap(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Fetch Caido sitemap."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_get_sitemap",
        command="caido_get_sitemap",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "get_sitemap",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_get_sitemap",
        "status": "submitted",
    }


@register("caido_list_workflows")
async def _caido_list_workflows(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """List workflows from Caido."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_list_workflows",
        command="caido_list_workflows",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "list_workflows",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_list_workflows",
        "status": "submitted",
    }


@register("caido_run_workflow")
async def _caido_run_workflow(
    db: AsyncSession,
    session_id: str,
    workflow_id: str,
    request_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Run a Caido workflow on a request."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_run_workflow",
        command=f"caido_run_workflow workflow={workflow_id} request={request_id}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "run_workflow",
            "params": {
                "workflow_id": workflow_id,
                "request_id": request_id,
            },
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_run_workflow",
        "status": "submitted",
    }


@register("caido_send_request")
async def _caido_send_request(
    db: AsyncSession,
    session_id: str,
    raw_request: str,
    host: str,
    port: int = 443,
    is_tls: bool = True,
    **_: Any,
) -> dict[str, Any]:
    """Send a crafted request through Caido."""
    sid = uuid.UUID(session_id)

    # Safe mode policy for active requests
    result = _policy.check(
        session_id=session_id,
        tool_name="caido_send_request",
        command=f"replay {host}:{port} {raw_request[:100]}",
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_send_request",
        command=f"caido_send_request host={host} port={port}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.caido_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "send_request",
            "params": {
                "raw_request": raw_request,
                "host": host,
                "port": port,
                "is_tls": is_tls,
            },
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_send_request",
        "status": "submitted",
    }


@register("caido_sync_findings")
async def _caido_sync_findings(
    db: AsyncSession,
    session_id: str,
    direction: str = "both",
    **_: Any,
) -> dict[str, Any]:
    """Bidirectional finding sync between Caido and the WebPhomet DB."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="caido_sync_findings",
        command=f"caido_sync_findings direction={direction}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.sync_caido_findings",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "direction": direction,
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "caido_sync_findings",
        "direction": direction,
        "status": "submitted",
    }


@register("caido_run_predefined_workflow")
async def _caido_run_predefined_workflow(
    db: AsyncSession,
    session_id: str,
    workflow_name: str,
    host: str,
    port: int,
    is_tls: bool = False,
    base_path: str = "/",
    param_name: str = "id",
    protected_path: str | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Run a predefined security scan workflow through Caido."""
    sid = uuid.UUID(session_id)

    # Safe mode policy check
    result = _policy.check(
        session_id=session_id,
        tool_name=f"workflow_{workflow_name}",
        command=f"workflow {workflow_name} host={host} port={port} path={base_path}",
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name=f"workflow_{workflow_name}",
        command=f"caido_run_predefined_workflow {workflow_name} {host}:{port}{base_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    # Build params for the workflow
    wf_params: dict[str, Any] = {
        "host": host,
        "port": port,
        "is_tls": is_tls,
    }
    if workflow_name == "auth_bypass_probe":
        wf_params["protected_path"] = protected_path or base_path
    else:
        wf_params["base_path"] = base_path
        wf_params["param_name"] = param_name

    task = celery_app.send_task(
        "jobs.run_predefined_workflow",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "workflow_name": workflow_name,
            "params": wf_params,
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "workflow_name": workflow_name,
        "status": "submitted",
    }


# ═══════════════════════════════════════════════════════════════
# DevTools (headless Chrome) integration
# ═══════════════════════════════════════════════════════════════


@register("devtools_navigate")
async def _devtools_navigate(
    db: AsyncSession,
    session_id: str,
    url: str,
    wait_until: str = "load",
    **_: Any,
) -> dict[str, Any]:
    """Navigate headless browser to a URL."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_navigate",
        command=f"devtools_navigate url={url} wait_until={wait_until}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "navigate",
            "params": {"url": url, "wait_until": wait_until},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_navigate",
        "status": "submitted",
    }


@register("devtools_screenshot")
async def _devtools_screenshot(
    db: AsyncSession,
    session_id: str,
    full_page: bool = False,
    **_: Any,
) -> dict[str, Any]:
    """Take a screenshot of the current page."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_screenshot",
        command=f"devtools_screenshot full_page={full_page}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "screenshot",
            "params": {"full_page": full_page},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_screenshot",
        "status": "submitted",
    }


@register("devtools_discover_forms")
async def _devtools_discover_forms(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Discover forms on the current page."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_discover_forms",
        command="devtools_discover_forms",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "discover_forms",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_discover_forms",
        "status": "submitted",
    }


@register("devtools_discover_links")
async def _devtools_discover_links(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Discover links on the current page."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_discover_links",
        command="devtools_discover_links",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "discover_links",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_discover_links",
        "status": "submitted",
    }


@register("devtools_detect_dom_xss")
async def _devtools_detect_dom_xss(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Detect DOM XSS sinks on the current page."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_detect_dom_xss",
        command="devtools_detect_dom_xss",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "detect_dom_xss_sinks",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_detect_dom_xss",
        "status": "submitted",
    }


@register("devtools_execute_js")
async def _devtools_execute_js(
    db: AsyncSession,
    session_id: str,
    script: str,
    **_: Any,
) -> dict[str, Any]:
    """Execute JavaScript in the browser context."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_execute_js",
        command=f"devtools_execute_js script={script[:80]}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "execute_js",
            "params": {"script": script},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_execute_js",
        "status": "submitted",
    }


@register("devtools_get_cookies")
async def _devtools_get_cookies(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Get cookies from the browser context."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_get_cookies",
        command="devtools_get_cookies",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "get_cookies",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_get_cookies",
        "status": "submitted",
    }


@register("devtools_get_storage")
async def _devtools_get_storage(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Get localStorage/sessionStorage contents."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_get_storage",
        command="devtools_get_storage",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "get_storage",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_get_storage",
        "status": "submitted",
    }


@register("devtools_check_security_headers")
async def _devtools_check_security_headers(
    db: AsyncSession,
    session_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Check security headers from the last navigation."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_check_security_headers",
        command="devtools_check_security_headers",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "check_security_headers",
            "params": {},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_check_security_headers",
        "status": "submitted",
    }


@register("devtools_full_page_audit")
async def _devtools_full_page_audit(
    db: AsyncSession,
    session_id: str,
    url: str,
    **_: Any,
) -> dict[str, Any]:
    """Combined full page security audit."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="devtools_full_page_audit",
        command=f"devtools_full_page_audit url={url}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.devtools_call",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "method": "full_page_audit",
            "params": {"url": url},
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "devtools_full_page_audit",
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


# ═══════════════════════════════════════════════════════════════
# Discovery & Mapping
# ═══════════════════════════════════════════════════════════════


@register("run_discovery")
async def _run_discovery(
    db: AsyncSession,
    session_id: str,
    url: str,
    max_crawl_depth: int = 2,
    **_: Any,
) -> dict[str, Any]:
    """Queue automated discovery & mapping via Celery."""
    sid = uuid.UUID(session_id)
    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="discovery",
        command=f"run_discovery url={url} depth={max_crawl_depth}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_discovery",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "base_url": url,
            "max_crawl_depth": max_crawl_depth,
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "discovery",
        "status": "submitted",
    }


@register("run_injection_tests")
async def _run_injection_tests(
    db: AsyncSession,
    session_id: str,
    host: str,
    port: int,
    is_tls: bool = False,
    targets: list[dict] | None = None,
    test_types: list[str] | None = None,
    cookie: str = "",
    **_: Any,
) -> dict[str, Any]:
    """Queue OWASP injection & XSS tests via Celery."""
    sid = uuid.UUID(session_id)

    # Safe mode policy check
    result = _policy.check(
        session_id=session_id,
        tool_name="injection_tests",
        command=f"injection_tests {host}:{port} types={test_types}",
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="injection_tests",
        command=f"run_injection_tests {host}:{port} types={test_types}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_injection_tests",
        kwargs={
            "session_id": session_id,
            "tool_run_id": str(tool_run.id),
            "host": host,
            "port": port,
            "is_tls": is_tls,
            "targets": targets,
            "test_types": test_types,
            "cookie": cookie,
        },
    )
    return {
        "tool_run_id": str(tool_run.id),
        "task_id": task.id,
        "tool_name": "injection_tests",
        "status": "submitted",
    }


@register("run_auth_tests")
async def _run_auth_tests(
    db: AsyncSession,
    session_id: str,
    host: str,
    port: int,
    is_tls: bool = False,
    test_types: list[str] | None = None,
    login_path: str = "/login",
    cookie: str = "",
    auth_header: str = "",
    idor_path_pattern: str = "/api/users/{id}",
    username_field: str = "username",
    password_field: str = "password",
    **_: Any,
) -> dict[str, Any]:
    """Queue broken-auth tests via Celery."""
    sid = uuid.UUID(session_id)
    result = _policy.check(
        session_id=session_id, tool_name="auth_tests",
        command=f"auth_tests {host}:{port} types={test_types}",
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="auth_tests",
        command=f"run_auth_tests {host}:{port} types={test_types}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_auth_tests",
        kwargs={
            "session_id": session_id, "tool_run_id": str(tool_run.id),
            "host": host, "port": port, "is_tls": is_tls,
            "test_types": test_types, "login_path": login_path,
            "cookie": cookie, "auth_header": auth_header,
            "idor_path_pattern": idor_path_pattern,
            "username_field": username_field, "password_field": password_field,
        },
    )
    return {
        "tool_run_id": str(tool_run.id), "task_id": task.id,
        "tool_name": "auth_tests", "status": "submitted",
    }


@register("run_ssrf_tests")
async def _run_ssrf_tests(
    db: AsyncSession,
    session_id: str,
    host: str,
    port: int,
    is_tls: bool = False,
    targets: list[dict] | None = None,
    test_types: list[str] | None = None,
    cookie: str = "",
    **_: Any,
) -> dict[str, Any]:
    """Queue SSRF tests via Celery."""
    sid = uuid.UUID(session_id)
    result = _policy.check(
        session_id=session_id, tool_name="ssrf_tests",
        command=f"ssrf_tests {host}:{port} types={test_types}",
    )
    if not result.allowed:
        return {"error": f"Policy violation: {result.reason}", "rule": result.rule}

    tool_run = await dal.create_tool_run(
        db, session_id=sid, tool_name="ssrf_tests",
        command=f"run_ssrf_tests {host}:{port} types={test_types}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()

    task = celery_app.send_task(
        "jobs.run_ssrf_tests",
        kwargs={
            "session_id": session_id, "tool_run_id": str(tool_run.id),
            "host": host, "port": port, "is_tls": is_tls,
            "targets": targets, "test_types": test_types, "cookie": cookie,
        },
    )
    return {
        "tool_run_id": str(tool_run.id), "task_id": task.id,
        "tool_name": "ssrf_tests", "status": "submitted",
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
