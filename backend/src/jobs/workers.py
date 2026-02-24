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
