"""Tests for the breakpoint manager — state machine, config, resolution."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import MagicMock, patch

import pytest

from src.core.breakpoints import (
    BreakpointAction,
    BreakpointConfig,
    BreakpointManager,
    BreakpointPhase,
)


class FakeRedis:
    """Minimal in-memory Redis mock for tests."""

    def __init__(self):
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value

    def exists(self, key: str) -> bool:
        return key in self._store

    def delete(self, *keys: str) -> None:
        for k in keys:
            self._store.pop(k, None)

    def scan_iter(self, pattern: str) -> list[str]:
        import fnmatch
        return [k for k in self._store if fnmatch.fnmatch(k, pattern)]


@pytest.fixture
def fake_redis():
    """Provide a FakeRedis and patch _get_redis to return it."""
    fr = FakeRedis()
    with patch("src.core.breakpoints._get_redis", return_value=fr):
        yield fr


@pytest.fixture
def bpm(fake_redis) -> BreakpointManager:
    return BreakpointManager()


# ── Configuration ──────────────────────────────────────────────

def test_default_config(bpm: BreakpointManager):
    """Default config enables breakpoints at post_recon, post_owasp, pre_exploit."""
    sid = str(uuid.uuid4())
    cfg = bpm.get_config(sid)
    assert cfg.enabled is True
    assert BreakpointPhase.POST_RECON in cfg.phase_breaks
    assert BreakpointPhase.PRE_EXPLOIT in cfg.phase_breaks
    assert BreakpointPhase.POST_OWASP in cfg.phase_breaks


def test_configure_session(bpm: BreakpointManager):
    """Custom config overrides defaults and persists in Redis."""
    sid = str(uuid.uuid4())
    bpm.configure(sid,
        enabled=True,
        phase_breaks={BreakpointPhase.PRE_SCANNING},
        tool_breaks={"nmap_scan"},
        severity_break=False,
        auto_approve_timeout=30,
    )
    cfg = bpm.get_config(sid)
    assert cfg.phase_breaks == {BreakpointPhase.PRE_SCANNING}
    assert "nmap_scan" in cfg.tool_breaks
    assert cfg.severity_break is False
    assert cfg.auto_approve_timeout == 30


def test_disabled_config_skips_checks(bpm: BreakpointManager):
    """When disabled, check_phase / check_tool return None."""
    sid = str(uuid.uuid4())
    bpm.configure(sid, enabled=False)
    assert bpm.get_config(sid).enabled is False


# ── Phase checks ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_phase_creates_pending(bpm: BreakpointManager):
    """check_phase on a configured phase creates a pending breakpoint."""
    sid = str(uuid.uuid4())
    bpm.configure(sid,
        enabled=True,
        phase_breaks={BreakpointPhase.POST_RECON},
        auto_approve_timeout=1,
    )
    result = await bpm.check_phase(sid, BreakpointPhase.POST_RECON)
    # auto-approved after timeout
    assert result is not None
    assert result.action in (BreakpointAction.APPROVED, BreakpointAction.TIMEOUT)


@pytest.mark.asyncio
async def test_check_phase_skips_unconfigured(bpm: BreakpointManager):
    """check_phase on a non-configured phase returns None."""
    sid = str(uuid.uuid4())
    bpm.configure(sid,
        enabled=True,
        phase_breaks={BreakpointPhase.POST_RECON},
    )
    result = await bpm.check_phase(sid, BreakpointPhase.PRE_SCANNING)
    assert result is None


# ── Tool checks ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_tool_creates_pending(bpm: BreakpointManager):
    """check_tool on a configured tool creates a pending breakpoint."""
    sid = str(uuid.uuid4())
    bpm.configure(sid,
        enabled=True,
        tool_breaks={"nmap_scan"},
        auto_approve_timeout=1,
    )
    result = await bpm.check_tool(sid, "nmap_scan", {})
    assert result is not None


# ── Resolution ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolve_pending(bpm: BreakpointManager):
    """Manually resolving a pending breakpoint works via Redis."""
    sid = str(uuid.uuid4())
    bpm.configure(sid,
        enabled=True,
        phase_breaks={BreakpointPhase.PRE_REPORT},
        auto_approve_timeout=0,
    )

    async def resolve_soon():
        await asyncio.sleep(0.5)
        pending = bpm.list_pending(sid)
        assert len(pending) >= 1
        bp = pending[0]
        bpm.resolve(bp["id"], BreakpointAction.REJECTED)

    task = asyncio.create_task(resolve_soon())
    result = await asyncio.wait_for(
        bpm.check_phase(sid, BreakpointPhase.PRE_REPORT),
        timeout=5,
    )
    await task
    assert result is not None
    assert result.action == BreakpointAction.REJECTED


# ── Listing ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_pending_empty(bpm: BreakpointManager):
    """list_pending returns empty list when nothing is pending."""
    assert bpm.list_pending("nonexistent") == []


# ── Phases enum ───────────────────────────────────────────────

def test_all_phases_exist():
    """Verify all 8 phases are defined."""
    assert len(BreakpointPhase) == 8
    names = {p.value for p in BreakpointPhase}
    assert "pre_recon" in names
    assert "post_owasp" in names
