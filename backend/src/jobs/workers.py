"""Celery worker tasks for WebPhomet.

Tasks are synchronous (Celery requirement) but internally use asyncio
to communicate with MCP servers and the async DB layer.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from src.config import settings
from src.jobs.celery_app import celery_app
from src.mcp.gateway import MCPGateway

logger = logging.getLogger(__name__)

# Initialize MCP Gateway with server URLs from environment
mcp_gateway = MCPGateway(
    server_urls={
        "cli-security": settings.MCP_CLI_SECURITY_URL,
        "caido": settings.MCP_CAIDO_URL,
        "devtools": settings.MCP_DEVTOOLS_URL,
    }
)


def _run_async(coro: Any) -> Any:
    """Helper: run an async coroutine from sync Celery context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _persist_security_findings(
    session_id: str,
    findings: list[dict[str, Any]],
) -> int:
    """Persist individual security findings to the findings table.

    Returns the count of findings created.
    """
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from src.config import settings
    from src.db import dal

    if not findings:
        return 0

    _engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_size=2,
        max_overflow=0,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    created = 0
    try:
        async with _session_factory() as db:
            try:
                for f in findings:
                    await dal.create_finding(
                        db,
                        session_id=uuid.UUID(session_id),
                        vuln_type=f.get("vuln_type", "unknown"),
                        title=f.get("title", "Untitled Finding"),
                        severity=f.get("severity", "info"),
                        description=f.get("description") or f"{f.get('vuln_type', '')} vulnerability detected at {f.get('url', 'unknown')} parameter {f.get('param', 'N/A')}",
                        evidence=f.get("evidence", "")[:2000],
                        poc=f.get("payload", ""),
                        recommendation=f.get("recommendation"),
                        caido_request_id=f.get("request_id"),
                    )
                    created += 1
                await db.commit()
                logger.info(
                    "Persisted %d security findings for session %s",
                    created, session_id,
                )
            except Exception:
                await db.rollback()
                logger.exception("Failed to persist security findings for session %s", session_id)
    finally:
        await _engine.dispose()
    return created


async def _persist_result(
    session_id: str,
    tool_run_id: str,
    tool_name: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> dict[str, Any]:
    """Persist tool result using the DB persistence layer.

    Creates a *fresh* async engine each call so that Celery fork-pool
    workers (each with their own event loop) never reuse asyncpg
    connections attached to a stale loop.
    """
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from src.config import settings
    from src.db.persistence import persist_tool_result

    _engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_size=2,
        max_overflow=0,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(
        bind=_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    try:
        async with _session_factory() as db:
            try:
                summary = await persist_tool_result(
                    db,
                    session_id=uuid.UUID(session_id),
                    tool_run_id=uuid.UUID(tool_run_id),
                    tool_name=tool_name,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                )
                await db.commit()
                return summary
            except Exception:
                await db.rollback()
                raise
    finally:
        await _engine.dispose()


@celery_app.task(bind=True, name="jobs.run_tool")  # type: ignore[misc]
def run_tool(
    self: Any,
    session_id: str,
    tool_name: str,
    command: str,
    args: dict[str, Any] | None = None,
    tool_run_id: str | None = None,
) -> dict[str, Any]:
    """Execute a security tool inside the MCP CLI-Security container.

    Communicates with the MCP CLI-Security server over JSON-RPC, then
    persists parsed results in the database.

    Parameters
    ----------
    session_id:
        UUID of the pentest session.
    tool_name:
        Name of the security tool to execute (e.g., "nmap", "subfinder").
    command:
        Full command string for the tool.
    args:
        Optional additional arguments (for future use).
    tool_run_id:
        Optional pre-created ToolRun UUID.  If not provided, the result
        is still returned but not persisted to the DB.

    Returns
    -------
    dict with execution results (stdout, stderr, exit_code, persistence summary).
    """
    logger.info(
        "Running tool %s for session %s: %s",
        tool_name,
        session_id,
        command,
    )

    try:
        result = _run_async(
            mcp_gateway.call(
                server="cli-security",
                method="run_command",
                params={
                    "tool_name": tool_name,
                    "args": command.replace(f"{tool_name} ", ""),
                },
            )
        )

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code")

        logger.info(
            "Tool %s completed for session %s (exit_code=%s)",
            tool_name,
            session_id,
            exit_code,
        )

        # Persist results to DB if tool_run_id provided
        persistence_summary: dict[str, Any] = {}
        if tool_run_id:
            try:
                persistence_summary = _run_async(
                    _persist_result(
                        session_id=session_id,
                        tool_run_id=tool_run_id,
                        tool_name=tool_name,
                        stdout=stdout,
                        stderr=stderr,
                        exit_code=exit_code,
                    )
                )
            except Exception as e:
                logger.exception("Failed to persist results for %s", tool_name)
                persistence_summary = {"error": str(e)}

        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "tool_run_id": tool_run_id,
            "status": "success",
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "error": result.get("error"),
            "persistence": persistence_summary,
        }

    except Exception as e:
        logger.exception("Failed to execute tool %s", tool_name)
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Site Mirror task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(bind=True, name="jobs.run_mirror")  # type: ignore[misc]
def run_mirror(
    self: Any,
    session_id: str,
    url: str,
    tool_run_id: str | None = None,
    depth: int = 8,
    global_timeout: int = 300,
) -> dict[str, Any]:
    """Mirror a website via the MCP CLI-Security mirror_site method.

    Calls the MCP server's ``mirror_site`` JSON-RPC method which runs
    wget recursively + smart URL extraction.
    """
    logger.info(
        "Mirroring site %s for session %s (depth=%d, timeout=%d)",
        url, session_id, depth, global_timeout,
    )

    try:
        result = _run_async(
            mcp_gateway.call(
                server="cli-security",
                method="mirror_site",
                params={
                    "url": url,
                    "session_id": session_id,
                    "depth": depth,
                    "global_timeout": global_timeout,
                },
            )
        )

        # Convert the result dict to JSON string for persistence
        stdout = json.dumps(result, indent=2)
        exit_code = 0 if "error" not in result else 1

        logger.info(
            "Mirror completed for session %s: %d files, %d bytes",
            session_id,
            result.get("total_files", 0),
            result.get("total_size_bytes", 0),
        )

        # Persist results
        persistence_summary: dict[str, Any] = {}
        if tool_run_id:
            try:
                persistence_summary = _run_async(
                    _persist_result(
                        session_id=session_id,
                        tool_run_id=tool_run_id,
                        tool_name="site_mirror",
                        stdout=stdout,
                        stderr="",
                        exit_code=exit_code,
                    )
                )
            except Exception as e:
                logger.exception("Failed to persist mirror results")
                persistence_summary = {"error": str(e)}

        return {
            "session_id": session_id,
            "tool_name": "site_mirror",
            "tool_run_id": tool_run_id,
            "status": "success",
            "url": url,
            "total_files": result.get("total_files", 0),
            "total_size_bytes": result.get("total_size_bytes", 0),
            "elapsed_seconds": result.get("elapsed_seconds", 0),
            "stdout": stdout,
            "persistence": persistence_summary,
        }

    except Exception as e:
        logger.exception("Failed to mirror site %s", url)
        return {
            "session_id": session_id,
            "tool_name": "site_mirror",
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Secret Scanner task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(bind=True, name="jobs.run_secret_scan")  # type: ignore[misc]
def run_secret_scan(
    self: Any,
    session_id: str,
    tool_run_id: str | None = None,
    max_findings: int = 500,
) -> dict[str, Any]:
    """Scan mirrored site content for secrets via MCP CLI-Security.

    Calls the MCP server's ``scan_secrets`` JSON-RPC method which scans
    all files in the session's mirror directory for hardcoded secrets,
    API keys, tokens, passwords, etc.
    """
    logger.info(
        "Scanning secrets for session %s (max_findings=%d)",
        session_id, max_findings,
    )

    try:
        result = _run_async(
            mcp_gateway.call(
                server="cli-security",
                method="scan_secrets",
                params={
                    "session_id": session_id,
                    "max_findings": max_findings,
                },
            )
        )

        stdout = json.dumps(result, indent=2)
        exit_code = 0 if "error" not in result else 1

        logger.info(
            "Secret scan completed for session %s: %d findings in %d files",
            session_id,
            result.get("total_findings", 0),
            result.get("total_files_scanned", 0),
        )

        # Persist results
        persistence_summary: dict[str, Any] = {}
        if tool_run_id:
            try:
                persistence_summary = _run_async(
                    _persist_result(
                        session_id=session_id,
                        tool_run_id=tool_run_id,
                        tool_name="secret_scanner",
                        stdout=stdout,
                        stderr="",
                        exit_code=exit_code,
                    )
                )
            except Exception as e:
                logger.exception("Failed to persist secret scan results")
                persistence_summary = {"error": str(e)}

        return {
            "session_id": session_id,
            "tool_name": "secret_scanner",
            "tool_run_id": tool_run_id,
            "status": "success",
            "total_findings": result.get("total_findings", 0),
            "total_files_scanned": result.get("total_files_scanned", 0),
            "severity_summary": result.get("severity_summary", {}),
            "stdout": stdout,
            "persistence": persistence_summary,
        }

    except Exception as e:
        logger.exception("Failed to scan secrets for session %s", session_id)
        return {
            "session_id": session_id,
            "tool_name": "secret_scanner",
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


@celery_app.task(bind=True, name="jobs.run_agent")  # type: ignore[misc]
def run_agent(
    self: Any,
    session_id: str,
    max_iterations: int = 30,
    model: str | None = None,
) -> dict[str, Any]:
    """Run the autonomous agent loop for a pentest session.

    This is a long-running task that drives the full pentesting cycle.
    """
    logger.info("Starting agent task for session %s", session_id)
    from src.agent.orchestrator import run_agent_sync

    return run_agent_sync(session_id, max_iterations=max_iterations, model=model)


@celery_app.task(bind=True, name="jobs.build_report")  # type: ignore[misc]
def build_report(self: Any, session_id: str, format: str = "markdown") -> dict[str, Any]:
    """Generate a pentesting report for the given session.

    Loads all session data from the DB, renders the Jinja2 template,
    stores the report as an artifact, and returns file path.

    Parameters
    ----------
    session_id:
        UUID of the pentest session.
    format:
        Output format: "markdown" or "pdf".

    Returns
    -------
    dict with report artifact information.
    """
    logger.info("Building report for session %s (format=%s)", session_id, format)

    async def _generate() -> dict[str, Any]:
        from src.db import dal
        from src.db.database import async_session_factory
        from src.reporting.builder import ReportBuilder

        async with async_session_factory() as db:
            session = await dal.get_session(db, uuid.UUID(session_id))
            if session is None:
                return {"error": f"Session {session_id} not found"}

            targets = await dal.get_targets(db, session.id)
            findings = await dal.get_findings(db, session.id)
            tool_runs = await dal.get_tool_runs(db, session.id)

            # Convert ORM objects to dicts for the template
            session_dict = {
                "id": str(session.id),
                "target_base_url": session.target_base_url,
                "app_type": session.app_type,
                "scope": session.scope,
                "status": session.status.value,
            }
            targets_list = [
                {
                    "host": t.host,
                    "ports": t.ports,
                    "technologies": t.technologies,
                }
                for t in targets
            ]
            findings_list = [
                {
                    "id": str(f.id),
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "likelihood": f.likelihood,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                    "poc": f.poc,
                    "recommendation": f.recommendation,
                    "references": f.references,
                }
                for f in findings
            ]
            tool_runs_list = [
                {
                    "tool_name": r.tool_name,
                    "command": r.command,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "exit_code": r.exit_code,
                }
                for r in tool_runs
            ]

            builder = ReportBuilder()
            metadata = {"date": "auto", "tester": "WebPhomet Agent"}

            # Always generate Markdown
            report_md = builder.render_markdown(
                session=session_dict,
                targets=targets_list,
                findings=findings_list,
                tool_runs=tool_runs_list,
                metadata=metadata,
            )

            reports_dir = Path("/app/artifacts") / session_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            report_path = reports_dir / "report.md"
            builder.save(report_md, report_path)

            artifact = await dal.create_artifact(
                db,
                session_id=session.id,
                artifact_type="report_markdown",
                content=report_md,
                file_path=str(report_path),
            )

            result_info: dict[str, Any] = {
                "session_id": session_id,
                "status": "success",
                "format": format,
                "markdown_artifact_id": str(artifact.id),
                "markdown_path": str(report_path),
                "findings_count": len(findings_list),
            }

            # Generate PDF if requested
            if format == "pdf":
                try:
                    pdf_path = reports_dir / "report.pdf"
                    actual_path = builder.generate_pdf(
                        session=session_dict,
                        targets=targets_list,
                        findings=findings_list,
                        tool_runs=tool_runs_list,
                        metadata=metadata,
                        output_path=pdf_path,
                    )
                    pdf_artifact = await dal.create_artifact(
                        db,
                        session_id=session.id,
                        artifact_type="report_pdf",
                        file_path=str(actual_path),
                    )
                    result_info["pdf_artifact_id"] = str(pdf_artifact.id)
                    result_info["pdf_path"] = str(actual_path)
                except Exception as pdf_err:
                    logger.warning("PDF generation failed: %s", pdf_err)
                    result_info["pdf_error"] = str(pdf_err)

            await db.commit()
            return result_info

    try:
        return _run_async(_generate())
    except Exception as e:
        logger.exception("Failed to build report for session %s", session_id)
        return {
            "session_id": session_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Caido proxy tasks
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.caido_call", bind=True)
def caido_call(
    self,
    session_id: str,
    tool_run_id: str,
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generic Caido MCP call — dispatches any method to the mcp-caido server."""

    async def _execute():
        logger.info(
            "Caido call %s for session %s (tool_run=%s)",
            method, session_id, tool_run_id,
        )

        try:
            result = await mcp_gateway.call(
                server="caido",
                method=method,
                params=params or {},
            )
        except Exception as exc:
            logger.error("Caido MCP call %s failed: %s", method, exc)
            await _persist_result(
                session_id=session_id,
                tool_run_id=tool_run_id,
                tool_name=f"caido_{method}",
                stdout="",
                stderr=str(exc),
                exit_code=1,
            )
            raise

        stdout = json.dumps(result, indent=2, default=str)
        logger.info("Caido %s completed for session %s", method, session_id)

        persistence = await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name=f"caido_{method}",
            stdout=stdout,
            stderr="",
            exit_code=0,
        )

        return {
            "session_id": session_id,
            "tool_name": f"caido_{method}",
            "tool_run_id": tool_run_id,
            "status": "success",
            "result": result,
            "persistence": persistence,
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Caido call %s failed for session %s", method, session_id)
        return {
            "session_id": session_id,
            "tool_name": f"caido_{method}",
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Caido ↔ DB finding sync task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.sync_caido_findings", bind=True)
def sync_caido_findings(
    self,
    session_id: str,
    tool_run_id: str,
    direction: str = "both",
) -> dict[str, Any]:
    """Bidirectional finding sync between Caido and the WebPhomet DB.

    Parameters
    ----------
    session_id:
        UUID of the pentest session.
    tool_run_id:
        Pre-created ToolRun UUID for tracking.
    direction:
        ``"pull"`` = Caido → DB only,
        ``"push"`` = DB → Caido only,
        ``"both"`` = pull then push (default).
    """

    async def _execute():
        from src.db import dal
        from src.services.caido_sync import (
            pull_findings_from_caido,
            push_findings_to_caido,
        )
        from sqlalchemy.ext.asyncio import (
            AsyncSession as _AsyncSession,
            async_sessionmaker as _async_sessionmaker,
            create_async_engine as _create_async_engine,
        )

        sid = uuid.UUID(session_id)
        pull_summary: dict[str, Any] = {}
        push_summary: dict[str, Any] = {}

        # Fresh engine per worker call (avoids stale asyncpg loops in fork-pool)
        _engine = _create_async_engine(
            settings.DATABASE_URL, echo=False,
            pool_size=2, max_overflow=0, pool_pre_ping=True,
        )
        _sf = _async_sessionmaker(
            bind=_engine, class_=_AsyncSession, expire_on_commit=False,
        )

        try:
            # --- PULL: Caido → DB ---
            if direction in ("pull", "both"):
                logger.info("Pulling findings from Caido for session %s", session_id)
                try:
                    caido_result = await mcp_gateway.call(
                        server="caido",
                        method="pull_findings",
                        params={"limit": 200},
                    )
                    caido_findings = caido_result.get("findings", [])
                    async with _sf() as db:
                        pull_summary = await pull_findings_from_caido(
                            db, sid, caido_findings,
                        )
                        await db.commit()
                    logger.info(
                        "Pull complete: %d created, %d skipped",
                        pull_summary.get("created", 0),
                        pull_summary.get("skipped", 0),
                    )
                except Exception as exc:
                    logger.exception("Pull from Caido failed")
                    pull_summary = {"error": str(exc)}

            # --- PUSH: DB → Caido ---
            if direction in ("push", "both"):
                logger.info("Pushing findings to Caido for session %s", session_id)
                try:
                    async with _sf() as db:
                        pending = await dal.get_findings_without_caido_id(db, sid)
                        if pending:
                            payload = [
                                {
                                    "id": str(f.id),
                                    "title": f.title,
                                    "description": f.description or "",
                                    "request_id": f.caido_request_id,
                                    "dedupe_key": f"wp-{f.id}",
                                }
                                for f in pending
                            ]
                            push_result = await mcp_gateway.call(
                                server="caido",
                                method="sync_findings",
                                params={"findings": payload},
                            )
                            synced_ids = push_result.get("synced_ids", [])
                            backfill = await push_findings_to_caido(
                                db, sid, synced_ids,
                            )
                            await db.commit()
                            push_summary = {
                                "pushed": push_result.get("synced", 0),
                                "skipped": push_result.get("skipped", 0),
                                "errors": push_result.get("errors", 0),
                                "backfilled": backfill.get("updated", 0),
                            }
                        else:
                            push_summary = {"pushed": 0, "message": "No pending findings to push"}
                    logger.info(
                        "Push complete: %s",
                        push_summary,
                    )
                except Exception as exc:
                    logger.exception("Push to Caido failed")
                    push_summary = {"error": str(exc)}
        finally:
            await _engine.dispose()

        # Persist result
        combined = json.dumps(
            {"pull": pull_summary, "push": push_summary, "direction": direction},
            indent=2,
            default=str,
        )
        await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name="caido_sync_findings",
            stdout=combined,
            stderr="",
            exit_code=0,
        )

        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "success",
            "direction": direction,
            "pull": pull_summary,
            "push": push_summary,
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Sync caido findings failed for %s", session_id)
        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Predefined Caido workflow task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.run_predefined_workflow", bind=True)
def run_predefined_workflow(
    self,
    session_id: str,
    tool_run_id: str,
    workflow_name: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a predefined security workflow via Caido.

    Parameters
    ----------
    session_id:
        UUID of the pentest session.
    tool_run_id:
        Pre-created ToolRun UUID for tracking.
    workflow_name:
        Name from WORKFLOW_REGISTRY (sqli_error_detect, xss_reflect_probe, etc.).
    params:
        Workflow parameters: host, port, is_tls, base_path, param_name, etc.
    """

    async def _execute():
        from src.services.workflows import WORKFLOW_REGISTRY

        wf_params = params or {}

        workflow_fn = WORKFLOW_REGISTRY.get(workflow_name)
        if workflow_fn is None:
            return {
                "session_id": session_id,
                "tool_run_id": tool_run_id,
                "status": "failed",
                "error": f"Unknown workflow: {workflow_name}",
            }

        logger.info(
            "Running predefined workflow '%s' for session %s (params=%s)",
            workflow_name, session_id, wf_params,
        )

        # send_fn wraps MCP → Caido send_request
        async def send_fn(raw_request, host, port, is_tls):
            return await mcp_gateway.call(
                server="caido",
                method="send_request",
                params={
                    "raw_request": raw_request,
                    "host": host,
                    "port": port,
                    "is_tls": is_tls,
                },
            )

        # create_finding_fn wraps MCP → Caido create_finding
        async def create_finding_fn(request_id, title, description):
            return await mcp_gateway.call(
                server="caido",
                method="create_finding",
                params={
                    "request_id": request_id,
                    "title": title,
                    "description": description,
                    "reporter": "webphomet",
                },
            )

        wf_result = await workflow_fn(
            send_fn,
            create_finding_fn,
            **wf_params,
        )

        stdout = json.dumps(wf_result.to_dict(), indent=2, default=str)
        logger.info(
            "Workflow '%s' completed: %d findings, %d requests sent",
            workflow_name,
            len(wf_result.findings),
            wf_result.requests_sent,
        )

        await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name=f"workflow_{workflow_name}",
            stdout=stdout,
            stderr="\n".join(wf_result.errors) if wf_result.errors else "",
            exit_code=0,
        )

        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "workflow_name": workflow_name,
            "status": "success",
            "findings_count": len(wf_result.findings),
            "requests_sent": wf_result.requests_sent,
            "findings": wf_result.findings,
            "errors": wf_result.errors,
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Workflow %s failed for %s", workflow_name, session_id)
        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "workflow_name": workflow_name,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# DevTools (headless Chrome) tasks
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.devtools_call", bind=True)
def devtools_call(
    self,
    session_id: str,
    tool_run_id: str,
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generic DevTools MCP call — dispatches any method to mcp-devtools."""

    async def _execute():
        logger.info(
            "DevTools call %s for session %s (tool_run=%s)",
            method, session_id, tool_run_id,
        )

        try:
            result = await mcp_gateway.call(
                server="devtools",
                method=method,
                params=params or {},
            )
        except Exception as exc:
            logger.error("DevTools MCP call %s failed: %s", method, exc)
            await _persist_result(
                session_id=session_id,
                tool_run_id=tool_run_id,
                tool_name=f"devtools_{method}",
                stdout="",
                stderr=str(exc),
                exit_code=1,
            )
            raise

        stdout = json.dumps(result, indent=2, default=str)
        logger.info("DevTools %s completed for session %s", method, session_id)

        persistence = await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name=f"devtools_{method}",
            stdout=stdout,
            stderr="",
            exit_code=0,
        )

        return {
            "session_id": session_id,
            "tool_name": f"devtools_{method}",
            "tool_run_id": tool_run_id,
            "status": "success",
            "result": result,
            "persistence": persistence,
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("DevTools call %s failed for session %s", method, session_id)
        return {
            "session_id": session_id,
            "tool_name": f"devtools_{method}",
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# Discovery & Mapping task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.run_discovery", bind=True)
def run_discovery_task(
    self,
    session_id: str,
    tool_run_id: str,
    base_url: str,
    max_crawl_depth: int = 2,
) -> dict[str, Any]:
    """Run automated discovery & mapping against a target URL.

    Combines DevTools crawling (forms, links, DOM XSS, headers) with
    Caido sitemap data and technology fingerprinting.
    """

    async def _execute():
        from src.services.discovery import run_discovery

        logger.info(
            "Discovery for session %s: %s (depth=%d)",
            session_id, base_url, max_crawl_depth,
        )

        async def devtools_call(method, params):
            return await mcp_gateway.call(
                server="devtools", method=method, params=params,
            )

        async def caido_call(method, params):
            return await mcp_gateway.call(
                server="caido", method=method, params=params,
            )

        result = await run_discovery(
            devtools_call=devtools_call,
            caido_call=caido_call,
            base_url=base_url,
            max_crawl_depth=max_crawl_depth,
        )

        stdout = json.dumps(result.to_dict(), indent=2, default=str)
        logger.info(
            "Discovery complete for %s: %d endpoints, %d forms detected",
            base_url, len(result.endpoints), len(result.forms),
        )

        await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name="discovery",
            stdout=stdout,
            stderr="\n".join(result.errors) if result.errors else "",
            exit_code=0,
        )

        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "success",
            "total_endpoints": len(result.endpoints),
            "total_forms": len(result.forms),
            "technologies": result.technologies,
            "security_headers_score": result.security_headers.get("score"),
            "dom_xss_sinks": len(result.dom_xss_sinks),
            "errors": result.errors,
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Discovery failed for session %s", session_id)
        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════
# OWASP Injection & XSS testing task
# ═══════════════════════════════════════════════════════════════


@celery_app.task(name="jobs.run_injection_tests", bind=True)
def run_injection_tests(
    self,
    session_id: str,
    tool_run_id: str,
    host: str,
    port: int,
    is_tls: bool = False,
    targets: list[dict[str, Any]] | None = None,
    test_types: list[str] | None = None,
    cookie: str = "",
) -> dict[str, Any]:
    """Run OWASP injection & XSS test suite against target parameters.

    Parameters
    ----------
    targets:
        List of dicts with {path, param, method, extra_params}.
        If None, tests the root path with 'id' param.
    test_types:
        Tests to run: sqli, xss_reflected, xss_dom, command_injection, ssti.
        Default: all server-side tests.
    cookie:
        Session cookie string for authenticated testing.
    """

    async def _execute():
        from src.services.injection_tests import run_injection_suite

        _targets = targets or [{"path": "/", "param": "id", "method": "GET"}]

        logger.info(
            "Injection tests for session %s: %d targets, types=%s",
            session_id, len(_targets), test_types,
        )

        async def send_fn(raw_request, h, p, tls):
            return await mcp_gateway.call(
                server="caido",
                method="send_request",
                params={
                    "raw_request": raw_request,
                    "host": h,
                    "port": p,
                    "is_tls": tls,
                },
            )

        async def devtools_call(method, params):
            return await mcp_gateway.call(
                server="devtools",
                method=method,
                params=params,
            )

        results = await run_injection_suite(
            send_fn=send_fn,
            devtools_call=devtools_call,
            host=host,
            port=port,
            is_tls=is_tls,
            targets=_targets,
            test_types=test_types,
            cookie=cookie,
        )

        all_findings = []
        total_requests = 0
        all_errors = []
        for r in results:
            total_requests += r.requests_sent
            all_errors.extend(r.errors)
            for f in r.findings:
                all_findings.append(f.to_dict() if hasattr(f, "to_dict") else {
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "severity": f.severity,
                    "url": f.url,
                    "param": f.param,
                    "payload": f.payload,
                    "evidence": f.evidence[:500],
                    "request_id": f.request_id,
                })

        combined = {
            "total_findings": len(all_findings),
            "total_requests": total_requests,
            "findings": all_findings,
            "test_results": [r.to_dict() for r in results],
            "errors": all_errors,
        }

        stdout = json.dumps(combined, indent=2, default=str)
        logger.info(
            "Injection tests done: %d findings, %d requests",
            len(all_findings), total_requests,
        )

        await _persist_result(
            session_id=session_id,
            tool_run_id=tool_run_id,
            tool_name="injection_tests",
            stdout=stdout,
            stderr="\n".join(all_errors) if all_errors else "",
            exit_code=0,
        )

        # Persist individual findings to the findings table
        findings_created = await _persist_security_findings(session_id, all_findings)

        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "success",
            "total_findings": len(all_findings),
            "findings_persisted": findings_created,
            "total_requests": total_requests,
            "findings": all_findings[:20],  # cap for Celery result
            "errors": all_errors[:10],
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Injection tests failed for session %s", session_id)
        return {
            "session_id": session_id,
            "tool_run_id": tool_run_id,
            "status": "failed",
            "error": str(e),
        }


# ── Auth tests ───────────────────────────────────────────────
@celery_app.task(name="jobs.run_auth_tests", bind=True)
def run_auth_tests(
    self,
    session_id: str,
    tool_run_id: str,
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
) -> dict[str, Any]:
    """Run broken-auth test suite."""

    async def _execute():
        from src.services.auth_tests import run_auth_tests as _run

        logger.info("Auth tests for session %s, types=%s", session_id, test_types)

        async def send_fn(raw_request, h, p, tls):
            return await mcp_gateway.call(
                server="caido",
                method="send_request",
                params={"raw_request": raw_request, "host": h, "port": p, "is_tls": tls},
            )

        results = await _run(
            send_fn=send_fn,
            host=host, port=port, is_tls=is_tls,
            test_types=test_types,
            login_path=login_path,
            cookie=cookie,
            auth_header=auth_header,
            idor_path_pattern=idor_path_pattern,
            username_field=username_field,
            password_field=password_field,
        )

        all_findings = []
        total_requests = 0
        all_errors = []
        for r in results:
            total_requests += r.requests_sent
            all_errors.extend(r.errors)
            for f in r.findings:
                all_findings.append(f.to_dict())

        combined = {
            "total_findings": len(all_findings),
            "total_requests": total_requests,
            "findings": all_findings,
            "test_results": [r.to_dict() for r in results],
            "errors": all_errors,
        }
        stdout = json.dumps(combined, indent=2, default=str)
        logger.info("Auth tests done: %d findings, %d requests", len(all_findings), total_requests)

        await _persist_result(
            session_id=session_id, tool_run_id=tool_run_id,
            tool_name="auth_tests", stdout=stdout,
            stderr="\n".join(all_errors) if all_errors else "", exit_code=0,
        )

        # Persist individual findings to the findings table
        findings_created = await _persist_security_findings(session_id, all_findings)

        return {
            "session_id": session_id, "tool_run_id": tool_run_id,
            "status": "success", "total_findings": len(all_findings),
            "findings_persisted": findings_created,
            "total_requests": total_requests,
            "findings": all_findings[:20], "errors": all_errors[:10],
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("Auth tests failed for session %s", session_id)
        return {"session_id": session_id, "tool_run_id": tool_run_id, "status": "failed", "error": str(e)}


# ── SSRF tests ───────────────────────────────────────────────
@celery_app.task(name="jobs.run_ssrf_tests", bind=True)
def run_ssrf_tests(
    self,
    session_id: str,
    tool_run_id: str,
    host: str,
    port: int,
    is_tls: bool = False,
    targets: list[dict[str, Any]] | None = None,
    test_types: list[str] | None = None,
    cookie: str = "",
) -> dict[str, Any]:
    """Run SSRF test suite."""

    async def _execute():
        from src.services.ssrf_tests import run_ssrf_tests as _run

        _targets = targets or [{"path": "/", "param": "url", "method": "GET"}]
        logger.info("SSRF tests for session %s: %d targets, types=%s", session_id, len(_targets), test_types)

        async def send_fn(raw_request, h, p, tls):
            return await mcp_gateway.call(
                server="caido",
                method="send_request",
                params={"raw_request": raw_request, "host": h, "port": p, "is_tls": tls},
            )

        results = await _run(
            send_fn=send_fn, host=host, port=port, is_tls=is_tls,
            targets=_targets, test_types=test_types, cookie=cookie,
        )

        all_findings = []
        total_requests = 0
        all_errors = []
        for r in results:
            total_requests += r.requests_sent
            all_errors.extend(r.errors)
            for f in r.findings:
                all_findings.append(f.to_dict())

        combined = {
            "total_findings": len(all_findings),
            "total_requests": total_requests,
            "findings": all_findings,
            "test_results": [r.to_dict() for r in results],
            "errors": all_errors,
        }
        stdout = json.dumps(combined, indent=2, default=str)
        logger.info("SSRF tests done: %d findings, %d requests", len(all_findings), total_requests)

        await _persist_result(
            session_id=session_id, tool_run_id=tool_run_id,
            tool_name="ssrf_tests", stdout=stdout,
            stderr="\n".join(all_errors) if all_errors else "", exit_code=0,
        )

        # Persist individual findings to the findings table
        findings_created = await _persist_security_findings(session_id, all_findings)

        return {
            "session_id": session_id, "tool_run_id": tool_run_id,
            "status": "success", "total_findings": len(all_findings),
            "findings_persisted": findings_created,
            "total_requests": total_requests,
            "findings": all_findings[:20], "errors": all_errors[:10],
        }

    try:
        return _run_async(_execute())
    except Exception as e:
        logger.exception("SSRF tests failed for session %s", session_id)
        return {"session_id": session_id, "tool_run_id": tool_run_id, "status": "failed", "error": str(e)}