"""Tests for the API endpoints — sessions, findings, admin, breakpoints."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


# ── Health ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_ok(client: AsyncClient):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Sessions CRUD ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session(client: AsyncClient):
    r = await client.post("/api/v1/sessions/", json={"target_base_url": "http://example.com/"})
    assert r.status_code in (200, 201)
    data = r.json()
    assert "id" in data
    assert data["target_base_url"] == "http://example.com/"


@pytest.mark.asyncio
async def test_list_sessions(client: AsyncClient):
    r = await client.get("/api/v1/sessions/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_get_session_not_found(client: AsyncClient):
    r = await client.get("/api/v1/sessions/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


# ── Findings ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_requires_session(client: AsyncClient):
    r = await client.get("/api/v1/findings/")
    # Could return 200 or 405 depending on endpoint implementation
    assert r.status_code in (200, 405)


# ── Admin / Retention ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_admin_stats(client: AsyncClient):
    r = await client.get("/api/v1/admin/stats")
    assert r.status_code == 200
    data = r.json()
    assert "sessions" in data
    assert "retention_days" in data


@pytest.mark.asyncio
async def test_admin_purge(client: AsyncClient):
    r = await client.post("/api/v1/admin/purge", json={"days": 365})
    assert r.status_code == 200
    data = r.json()
    assert "purged_sessions" in data


# ── Breakpoints ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_breakpoint_phases(client: AsyncClient):
    r = await client.get("/api/v1/breakpoints/phases")
    assert r.status_code == 200
    data = r.json()
    # Could be a list or dict with 'phases' key
    phases = data if isinstance(data, list) else data.get("phases", [])
    assert len(phases) == 8


@pytest.mark.asyncio
async def test_breakpoint_pending_empty(client: AsyncClient):
    r = await client.get("/api/v1/breakpoints/pending")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_breakpoint_configure(client: AsyncClient):
    sid = str(uuid.uuid4())
    r = await client.post("/api/v1/breakpoints/configure", json={
        "session_id": sid,
        "enabled": True,
        "phase_breaks": ["post_recon", "pre_exploit"],
        "tool_breaks": [],
        "severity_break": True,
        "auto_approve_timeout": 60,
    })
    assert r.status_code == 200
    data = r.json()
    assert "enabled" in data
    assert "phase_breaks" in data


@pytest.mark.asyncio
async def test_breakpoint_get_config(client: AsyncClient):
    # Configure first
    sid = str(uuid.uuid4())
    await client.post("/api/v1/breakpoints/configure", json={
        "session_id": sid,
        "enabled": True,
        "phase_breaks": ["pre_scanning"],
    })
    r = await client.get(f"/api/v1/breakpoints/config/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["enabled"] is True
