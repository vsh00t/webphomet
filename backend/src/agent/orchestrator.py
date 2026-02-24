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

from src.agent.client import ZaiClient
from src.agent.executor import dispatch
from src.agent.tools import ALL_TOOLS
from src.config import settings
from src.db import dal
from src.db.database import async_session_factory
from src.db.models import SessionStatus

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

## Available session info
- Session ID: {session_id}
- Target: {target_base_url}
- Scope: {scope}
- Safe mode: {safe_mode}

## Workflow
1. Create/verify session → 2. Subdomain enumeration → 3. Port scanning →
4. HTTP probing → 5. Technology detection → 6. Vulnerability scanning →
7. Finding correlation → 8. Report generation
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

            while not self.state.finished and self.state.iteration < self.max_iterations:
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

        return self._build_summary()

    # ── initialization ──────────────────────────────────────

    async def _initialize(self) -> None:
        """Load session from DB and build the system prompt."""
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

    # ── single step ─────────────────────────────────────────

    async def _step(self) -> None:
        """Execute one plan → execute → evaluate cycle."""
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

                result_str = await dispatch(fn_name, fn_args, db)

                # Track async tool runs for polling
                try:
                    result_data = json.loads(result_str)
                    if result_data.get("status") == "submitted":
                        trid = result_data.get("tool_run_id")
                        tid = result_data.get("task_id")
                        if trid and tid:
                            self.state.pending_tool_runs[trid] = tid
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

        completed: list[str] = []
        polls = 0

        while self.state.pending_tool_runs and polls < MAX_POLL_ATTEMPTS:
            await asyncio.sleep(TOOL_POLL_INTERVAL)
            polls += 1

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
    try:
        orchestrator = AgentOrchestrator(uuid.UUID(session_id), **kwargs)
        return loop.run_until_complete(orchestrator.run())
    finally:
        loop.close()
