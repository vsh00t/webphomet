"""Agent Reasoning Loop — autonomous plan → execute → evaluate cycle.

This module implements the core orchestration logic that lets GLM-4.5/4.6
autonomously drive a pentesting engagement.  The loop:

    1. **Plan** — ask the LLM what to do next given the current state
    2. **Execute** — dispatch every tool_call returned by the LLM
    3. **Evaluate** — feed results back, let the LLM decide next step
    4. **Terminate** — stop when the LLM signals or limits are hit

The loop is stateless between invocations — all state is in the DB
(session, targets, findings, tool_runs) and in the message history.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

import redis as _sync_redis
import threading as _threading

from src.agent.client import ZaiClient
from src.agent.executor import dispatch
from src.agent.tools import ALL_TOOLS
from src.config import settings
from src.core.breakpoints import BreakpointAction, BreakpointPhase, breakpoint_manager
from src.core.ws_manager import ws_breakpoint_callback, ws_manager
from src.db import dal
from src.db.database import async_session_factory
from src.db.models import SessionStatus

# ---------------------------------------------------------------------------
# Cooperative stop via Redis key
# ---------------------------------------------------------------------------

_STOP_KEY_PREFIX = "webphomet:stop:"
_redis_local = _threading.local()


def _get_sync_redis() -> _sync_redis.Redis:
    """Per-thread sync Redis client (fork-safe for Celery)."""
    if not hasattr(_redis_local, "client") or _redis_local.client is None:
        _redis_local.client = _sync_redis.from_url(
            settings.REDIS_URL, decode_responses=True,
        )
    return _redis_local.client


def _is_stop_requested(session_id: uuid.UUID) -> bool:
    """Check whether a stop signal exists for this session."""
    try:
        return _get_sync_redis().exists(f"{_STOP_KEY_PREFIX}{session_id}") > 0
    except Exception:
        return False


def request_stop(session_id: str | uuid.UUID) -> None:
    """Set the stop flag (TTL 10 min) so the running agent exits cleanly."""
    _get_sync_redis().setex(f"{_STOP_KEY_PREFIX}{session_id}", 600, "1")


def clear_stop(session_id: str | uuid.UUID) -> None:
    """Remove the stop flag (called when an agent starts)."""
    try:
        _get_sync_redis().delete(f"{_STOP_KEY_PREFIX}{session_id}")
    except Exception:
        pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ITERATIONS = 30
"""Absolute cap on tool-call loops to prevent runaway agents."""

TOOL_POLL_INTERVAL = 5.0
"""Seconds to wait when polling for async tool results."""

MAX_POLL_ATTEMPTS = 120
"""Max poll cycles (10 min at 5s interval) before giving up on a tool run."""

SYSTEM_PROMPT = """\
You are WebPhomet Agent, an expert autonomous penetration tester. You drive a
full pentest lifecycle: reconnaissance → enumeration → vulnerability scanning →
exploitation analysis → reporting.

## Rules
- Always work within the defined scope. Never scan out-of-scope targets.
- Start with passive/active recon before moving to vulnerability scanning.
- When a tool is submitted, check its results before proceeding.
- Record all findings with proper severity, evidence, and recommendations.
- If SAFE_MODE is enabled, do NOT run destructive or exploit tools.
- When all planned tests are complete, generate a final report.
- Be methodical: enumerate first, then target high-value services.
- Correlate findings from multiple tools to identify attack chains.
- **IMPORTANT**: After discovering vulnerabilities, ALWAYS use caido_create_finding
  to push each finding into Caido BEFORE generating the final report. This is a
  mandatory step — do not skip it. Push every finding individually with a clear
  title and description.

## Available session info
- Session ID: {session_id}
- Target: {target_base_url}
- Scope: {scope}
- Safe mode: {safe_mode}

## Workflow
1. Create/verify session → 2. Subdomain enumeration → 3. Port scanning →
4. HTTP probing → 5. Technology detection → 6. Vulnerability scanning →
7. Finding correlation → 8. **Push findings to Caido** (caido_create_finding) →
9. Report generation
"""


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------


@dataclass
class AgentState:
    """Tracks the agent's conversation and iteration state."""

    session_id: uuid.UUID
    messages: list[dict[str, Any]] = field(default_factory=list)
    iteration: int = 0
    pending_tool_runs: dict[str, str] = field(default_factory=dict)
    """Map of tool_run_id → task_id for async polls."""
    finished: bool = False
    error: str | None = None


# ---------------------------------------------------------------------------
# Reasoning loop
# ---------------------------------------------------------------------------


class AgentOrchestrator:
    """Drives the autonomous pentesting agent loop.

    Usage::

        orchestrator = AgentOrchestrator(session_id)
        result = await orchestrator.run()
    """

    def __init__(
        self,
        session_id: uuid.UUID,
        *,
        max_iterations: int = MAX_ITERATIONS,
        model: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.max_iterations = max_iterations
        self.client = ZaiClient(model=model)
        self.state = AgentState(session_id=session_id)

    # ── public entry point ──────────────────────────────────

    async def run(self) -> dict[str, Any]:
        """Execute the full agent loop until completion or limit.

        Returns a summary dict with run statistics and the final
        message from the agent.
        """
        logger.info("Starting agent loop for session %s", self.session_id)

        try:
            await self._initialize()
            clear_stop(self.session_id)  # remove any leftover stop signal

            while not self.state.finished and self.state.iteration < self.max_iterations:
                # ── cooperative stop check ──
                if _is_stop_requested(self.session_id):
                    logger.info("Stop requested for session %s — exiting loop", self.session_id)
                    self.state.error = "Stopped by operator"
                    await ws_manager.send_to_session(
                        str(self.session_id), "agent_stopped",
                        {"reason": "Stopped by operator", "iteration": self.state.iteration},
                    )
                    break

                self.state.iteration += 1
                logger.info(
                    "Agent iteration %d/%d for session %s",
                    self.state.iteration,
                    self.max_iterations,
                    self.session_id,
                )
                await self._step()

            if self.state.iteration >= self.max_iterations and not self.state.finished:
                logger.warning("Agent hit max iterations for session %s", self.session_id)
                self.state.error = "Max iterations reached"

        except Exception as e:
            logger.exception("Agent loop error for session %s", self.session_id)
            self.state.error = str(e)
        finally:
            await self.client.close()
            clear_stop(self.session_id)
            # Mark session as failed/completed depending on stop reason
            status = SessionStatus.COMPLETED if self.state.finished else SessionStatus.FAILED
            try:
                async with async_session_factory() as db:
                    await dal.update_session_status(db, self.session_id, status)
                    await db.commit()
            except Exception:
                logger.exception("Failed to update session status after agent exit")

        return self._build_summary()

    # ── initialization ──────────────────────────────────────

    async def _initialize(self) -> None:
        """Load session from DB and build the system prompt."""
        # Wire WebSocket callback for breakpoints
        breakpoint_manager.set_ws_callback(ws_breakpoint_callback)

        async with async_session_factory() as db:
            session = await dal.get_session(db, self.session_id)
            if session is None:
                raise ValueError(f"Session {self.session_id} not found")

            # Update session status to RUNNING
            await dal.update_session_status(db, self.session_id, SessionStatus.RUNNING)
            await db.commit()

            system_msg = SYSTEM_PROMPT.format(
                session_id=str(self.session_id),
                target_base_url=session.target_base_url,
                scope=json.dumps(session.scope or {}),
                safe_mode=settings.SAFE_MODE,
            )

            self.state.messages = [
                {"role": "system", "content": system_msg},
                {
                    "role": "user",
                    "content": (
                        f"Begin the penetration test for {session.target_base_url}. "
                        f"Start with reconnaissance. Session ID: {self.session_id}"
                    ),
                },
            ]

    # ── phase detection ───────────────────────────────────────

    # Map tool names to the phase they belong to for breakpoint detection
    _TOOL_PHASE_MAP: dict[str, BreakpointPhase] = {
        "run_recon": BreakpointPhase.PRE_RECON,
        "get_recon_results": BreakpointPhase.POST_RECON,
        "run_discovery": BreakpointPhase.PRE_SCANNING,
        "run_injection_tests": BreakpointPhase.POST_SCANNING,
        "run_auth_tests": BreakpointPhase.POST_OWASP,
        "run_ssrf_tests": BreakpointPhase.POST_OWASP,
        "build_report": BreakpointPhase.PRE_REPORT,
    }

    _EXPLOIT_TOOLS = {"run_injection_tests", "run_auth_tests", "run_ssrf_tests"}

    def _detect_phase(self, tool_name: str) -> BreakpointPhase | None:
        """Detect the current pentest phase from the tool being called."""
        return self._TOOL_PHASE_MAP.get(tool_name)

    # ── single step ─────────────────────────────────────────

    async def _step(self) -> None:
        """Execute one plan → execute → evaluate cycle."""
        sid = str(self.session_id)

        # 1. Call LLM
        response = await self.client.chat(
            messages=self.state.messages,
            tools=ALL_TOOLS,
            temperature=0.15,
            max_tokens=4096,
        )

        choices = response.get("choices", [])
        if not choices:
            self.state.finished = True
            return

        message = choices[0].get("message", {})
        finish_reason = choices[0].get("finish_reason", "")

        # Append assistant message to history
        self.state.messages.append(message)

        # Notify via WebSocket: agent thinking
        await ws_manager.send_to_session(sid, "agent_message", {
            "iteration": self.state.iteration,
            "content": (message.get("content") or "")[:500],
            "has_tool_calls": bool(message.get("tool_calls")),
        })

        # 2. Check if LLM wants to call tools
        tool_calls = message.get("tool_calls")
        if not tool_calls:
            # LLM responded with text — check if it signals completion
            content = message.get("content", "")
            if any(kw in content.lower() for kw in [
                "pentest complete",
                "assessment complete",
                "report generated",
                "testing is complete",
                "all tests complete",
            ]):
                self.state.finished = True
                await self._finalize_session()
            elif finish_reason == "stop":
                # LLM stopped without tool calls — might need a nudge
                self.state.messages.append({
                    "role": "user",
                    "content": (
                        "Continue the penetration test. "
                        "Use the available tools to proceed with the next phase. "
                        "If all testing is complete, generate the final report."
                    ),
                })
            return

        # 3. Execute each tool call
        async with async_session_factory() as db:
            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                try:
                    fn_args = json.loads(tc["function"]["arguments"])
                except (json.JSONDecodeError, KeyError):
                    fn_args = {}

                tc_id = tc.get("id", str(uuid.uuid4()))

                logger.info(
                    "Agent calling tool: %s(%s)",
                    fn_name,
                    json.dumps(fn_args)[:200],
                )

                # ── Breakpoint checks ──────────────────────
                # Phase breakpoint
                phase = self._detect_phase(fn_name)
                if phase:
                    bp = await breakpoint_manager.check_phase(sid, phase, context=fn_name)
                    if bp and bp.action == BreakpointAction.REJECTED:
                        self.state.messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": json.dumps({
                                "error": f"Operator rejected at {phase.value}: {bp.operator_message}",
                                "action": "rejected",
                            }),
                        })
                        continue

                # Pre-exploit breakpoint
                if fn_name in self._EXPLOIT_TOOLS:
                    bp = await breakpoint_manager.check_phase(
                        sid, BreakpointPhase.PRE_EXPLOIT,
                        context=f"About to run exploit tool: {fn_name}",
                    )
                    if bp and bp.action == BreakpointAction.REJECTED:
                        self.state.messages.append({
                            "role": "tool",
                            "tool_call_id": tc_id,
                            "content": json.dumps({
                                "error": f"Operator rejected exploit: {bp.operator_message}",
                                "action": "rejected",
                            }),
                        })
                        continue
                    if bp and bp.action == BreakpointAction.MODIFIED and bp.modified_args:
                        fn_args.update(bp.modified_args)

                # Tool-specific breakpoint
                tool_bp = await breakpoint_manager.check_tool(sid, fn_name, fn_args)
                if tool_bp and tool_bp.action == BreakpointAction.REJECTED:
                    self.state.messages.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": json.dumps({
                            "error": f"Operator rejected tool {fn_name}: {tool_bp.operator_message}",
                            "action": "rejected",
                        }),
                    })
                    continue
                if tool_bp and tool_bp.action == BreakpointAction.MODIFIED and tool_bp.modified_args:
                    fn_args.update(tool_bp.modified_args)

                # ── Dispatch ───────────────────────────────
                # Notify WS: tool started
                await ws_manager.send_to_session(sid, "tool_started", {
                    "tool_name": fn_name,
                    "args": {k: str(v)[:100] for k, v in fn_args.items()},
                    "iteration": self.state.iteration,
                })

                result_str = await dispatch(fn_name, fn_args, db)

                # Track async tool runs for polling
                try:
                    result_data = json.loads(result_str)
                    if result_data.get("status") == "submitted":
                        trid = result_data.get("tool_run_id")
                        tid = result_data.get("task_id")
                        if trid and tid:
                            self.state.pending_tool_runs[trid] = tid

                    # Notify WS: tool dispatched
                    await ws_manager.send_to_session(sid, "tool_dispatched", {
                        "tool_name": fn_name,
                        "tool_run_id": result_data.get("tool_run_id"),
                        "task_id": result_data.get("task_id"),
                    })
                except (json.JSONDecodeError, AttributeError):
                    pass

                # Append tool result to conversation
                self.state.messages.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": result_str,
                })

        # 4. If we have pending tool runs, poll for completion
        if self.state.pending_tool_runs:
            await self._poll_pending_runs()

    # ── async polling ───────────────────────────────────────

    async def _poll_pending_runs(self) -> None:
        """Poll pending tool runs and feed results back when complete."""
        if not self.state.pending_tool_runs:
            return

        sid = str(self.session_id)
        completed: list[str] = []
        polls = 0

        while self.state.pending_tool_runs and polls < MAX_POLL_ATTEMPTS:
            await asyncio.sleep(TOOL_POLL_INTERVAL)
            polls += 1

            # Check stop signal during long polling waits
            if _is_stop_requested(self.session_id):
                logger.info("Stop requested during polling for session %s", self.session_id)
                self.state.pending_tool_runs.clear()
                break

            async with async_session_factory() as db:
                for trid in list(self.state.pending_tool_runs):
                    run = await dal.get_tool_run(db, uuid.UUID(trid))
                    if run is None:
                        completed.append(trid)
                        continue

                    status = run.status.value if hasattr(run.status, "value") else str(run.status)
                    if status in ("success", "failed"):
                        # Feed result back as a user message so the LLM knows
                        stdout = run.stdout or ""
                        if len(stdout) > 6000:
                            stdout = stdout[:6000] + "\n... [truncated]"

                        self.state.messages.append({
                            "role": "user",
                            "content": (
                                f"Tool run {trid} ({run.tool_name}) completed.\n"
                                f"Status: {status}\n"
                                f"Exit code: {run.exit_code}\n"
                                f"Output:\n```\n{stdout}\n```\n"
                                f"Stderr: {run.stderr or 'none'}\n\n"
                                "Analyse these results and decide what to do next."
                            ),
                        })
                        completed.append(trid)

                        # Notify WS: tool completed
                        await ws_manager.send_to_session(sid, "tool_completed", {
                            "tool_run_id": trid,
                            "tool_name": run.tool_name,
                            "status": status,
                            "exit_code": run.exit_code,
                            "output_preview": (run.stdout or "")[:500],
                        })

            for trid in completed:
                self.state.pending_tool_runs.pop(trid, None)
            completed.clear()

            # If only some are done, break out to let LLM process
            if not self.state.pending_tool_runs:
                break

    # ── finalization ────────────────────────────────────────

    async def _finalize_session(self) -> None:
        """Mark the session as COMPLETED when the agent signals done."""
        try:
            async with async_session_factory() as db:
                await dal.update_session_status(
                    db, self.session_id, SessionStatus.COMPLETED
                )
                await db.commit()
            logger.info("Session %s marked as COMPLETED", self.session_id)
        except Exception:
            logger.exception("Failed to finalize session %s", self.session_id)

    # ── summary ─────────────────────────────────────────────

    def _build_summary(self) -> dict[str, Any]:
        """Build a summary of the agent run."""
        # Extract the last assistant text message
        last_text = ""
        for msg in reversed(self.state.messages):
            if msg.get("role") == "assistant" and msg.get("content"):
                last_text = msg["content"]
                break

        return {
            "session_id": str(self.session_id),
            "iterations": self.state.iteration,
            "max_iterations": self.max_iterations,
            "finished": self.state.finished,
            "error": self.state.error,
            "total_messages": len(self.state.messages),
            "last_response": last_text[:2000],
        }


# ---------------------------------------------------------------------------
# Celery task wrapper
# ---------------------------------------------------------------------------


def run_agent_sync(session_id: str, **kwargs: Any) -> dict[str, Any]:
    """Synchronous wrapper for Celery — runs the agent loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Reset the async DB engine so its pool binds to **this** loop
    from src.db.database import reset_engine
    reset_engine()

    try:
        # Create the orchestrator INSIDE the new loop so that any async
        # resources (httpx.AsyncClient, DB pools) bind to the correct loop.
        async def _run() -> dict[str, Any]:
            orchestrator = AgentOrchestrator(uuid.UUID(session_id), **kwargs)
            return await orchestrator.run()

        return loop.run_until_complete(_run())
    finally:
        loop.close()
