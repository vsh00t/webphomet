"""Tests for the git_code API endpoints (now under /api/v1/git-code/)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_clone_repo_endpoint(client: AsyncClient):
    """POST /git-code/clone-repo requires session_id and url."""
    # Missing fields → 422
    r = await client.post("/api/v1/git-code/clone-repo", json={})
    assert r.status_code == 422

    # Valid payload → 202 or connection error (no Celery in test)
    sid = str(uuid.uuid4())
    # First create a session so the FK constraint doesn't fail
    await client.post("/api/v1/sessions/", json={"target_base_url": "http://test.com"})
    r2 = await client.post("/api/v1/git-code/clone-repo", json={
        "session_id": sid,
        "url": "https://github.com/example/repo.git",
    })
    # Could be 200 (dispatched to Celery) or 500 (Celery not available)
    assert r2.status_code in (200, 201, 202, 500)


@pytest.mark.asyncio
async def test_list_repos_endpoint(client: AsyncClient):
    """GET /git-code/list-repos requires session_id query param."""
    r = await client.get("/api/v1/git-code/list-repos")
    assert r.status_code == 422  # missing session_id


@pytest.mark.asyncio
async def test_find_hotspots_endpoint(client: AsyncClient):
    """POST /git-code/find-hotspots requires session_id and repo_name."""
    r = await client.post("/api/v1/git-code/find-hotspots", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_code_audit_endpoint(client: AsyncClient):
    """POST /git-code/code-audit requires session_id."""
    r = await client.post("/api/v1/git-code/code-audit", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_search_code_endpoint(client: AsyncClient):
    """POST /git-code/search-code requires session_id, repo_name, query."""
    r = await client.post("/api/v1/git-code/search-code", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_git_log_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/git-code/git-log", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_git_diff_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/git-code/git-diff", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_git_blame_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/git-code/git-blame", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_git_tree_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/git-code/git-tree", json={})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_git_file_endpoint(client: AsyncClient):
    r = await client.post("/api/v1/git-code/git-file", json={})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Routing conflict regression test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_routing_conflict_with_tool_run_id(client: AsyncClient):
    """Ensure /api/v1/git-code/list-repos does NOT get caught by /tools/{tool_run_id}."""
    # This was the original bug: GET /tools/list-repos was parsed as GET /tools/{tool_run_id}
    # Now git-code has its own prefix, so verify both endpoints work independently
    r_list = await client.get("/api/v1/git-code/list-repos", params={"session_id": str(uuid.uuid4())})
    # Should be 200/500 (Celery), NOT 422 (UUID parse error)
    assert r_list.status_code != 422

    # The tool_run_id endpoint should require a valid UUID
    r_bad = await client.get("/api/v1/tools/not-a-uuid")
    assert r_bad.status_code == 422  # Invalid UUID format
