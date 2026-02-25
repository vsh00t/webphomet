"""Tests for correlation API endpoints."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_correlations_empty(client: AsyncClient):
    """GET /api/v1/correlations/session/{id} returns empty for new session."""
    r = await client.get(f"/api/v1/correlations/session/{uuid.uuid4()}")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_run_correlation_validation(client: AsyncClient):
    """POST /api/v1/correlations/run requires proper payload."""
    r = await client.post("/api/v1/correlations/run", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_run_correlation_no_findings(client: AsyncClient):
    """Running correlation with no findings should return empty list."""
    sid = str(uuid.uuid4())
    # Create session first
    await client.post("/api/v1/sessions/", json={"target_base_url": "http://test.com"})

    r = await client.post("/api/v1/correlations/run", json={
        "session_id": sid,
        "repo_name": "test-repo",
        "hotspots": [
            {
                "file": "src/db.py",
                "line": 10,
                "category": "sqli",
                "pattern_desc": "test",
                "code_snippet": "cursor.execute(query)",
                "severity": "high",
            },
        ],
        "min_confidence": 0.3,
        "persist": False,
    })
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    # No findings to correlate with, so results should be empty
    assert len(data) == 0


@pytest.mark.asyncio
async def test_correlations_for_finding(client: AsyncClient):
    """GET /api/v1/correlations/finding/{id} should return list."""
    r = await client.get(f"/api/v1/correlations/finding/{uuid.uuid4()}")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_clear_correlations(client: AsyncClient):
    """DELETE /api/v1/correlations/session/{id} should clear correlations."""
    r = await client.delete(f"/api/v1/correlations/session/{uuid.uuid4()}")
    assert r.status_code == 200
    data = r.json()
    assert "deleted" in data
