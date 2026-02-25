"""Tests for DAL — Data Access Layer CRUD operations."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.models import FindingStatus, RunStatus, SessionStatus


@pytest.fixture
async def db_session(client):
    """Get a fresh DB session for DAL tests."""
    from src.db.database import async_session
    async with async_session() as session:
        yield session


# ── Sessions ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_session(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    assert s.id is not None
    assert s.target_base_url == "http://test.com"
    assert s.status == SessionStatus.CREATED


@pytest.mark.asyncio
async def test_get_session(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await db_session.commit()
    fetched = await dal.get_session(db_session, s.id)
    assert fetched is not None
    assert fetched.id == s.id


@pytest.mark.asyncio
async def test_get_session_not_found(db_session: AsyncSession):
    result = await dal.get_session(db_session, uuid.uuid4())
    assert result is None


@pytest.mark.asyncio
async def test_list_sessions(db_session: AsyncSession):
    await dal.create_session(db_session, target_base_url="http://a.com")
    await dal.create_session(db_session, target_base_url="http://b.com")
    await db_session.commit()
    sessions = await dal.list_sessions(db_session)
    assert len(sessions) >= 2


@pytest.mark.asyncio
async def test_update_session_status(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await db_session.commit()
    await dal.update_session_status(db_session, s.id, SessionStatus.RUNNING)
    await db_session.commit()
    fetched = await dal.get_session(db_session, s.id)
    assert fetched.status == SessionStatus.RUNNING


# ── Targets ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_target(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    t = await dal.create_target(
        db_session, session_id=s.id, host="test.com",
        ports={"80": "http"}, technologies={"server": "nginx"},
    )
    assert t.host == "test.com"
    assert t.ports["80"] == "http"


@pytest.mark.asyncio
async def test_upsert_target_new(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    t = await dal.upsert_target(db_session, session_id=s.id, host="new.com")
    assert t.host == "new.com"


@pytest.mark.asyncio
async def test_upsert_target_existing(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_target(db_session, session_id=s.id, host="test.com", ports={"80": "http"})
    await db_session.flush()
    t = await dal.upsert_target(
        db_session, session_id=s.id, host="test.com",
        ports={"443": "https"}, notes="updated",
    )
    assert t.ports.get("443") == "https"


@pytest.mark.asyncio
async def test_get_targets(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_target(db_session, session_id=s.id, host="a.com")
    await dal.create_target(db_session, session_id=s.id, host="b.com")
    targets = await dal.get_targets(db_session, s.id)
    assert len(targets) == 2


# ── Findings ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_finding(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    f = await dal.create_finding(
        db_session,
        session_id=s.id,
        vuln_type="xss",
        title="Reflected XSS",
        severity="high",
        description="XSS in search param",
    )
    assert f.title == "Reflected XSS"
    assert f.vuln_type == "xss"


@pytest.mark.asyncio
async def test_get_findings_filtered(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_finding(db_session, session_id=s.id, vuln_type="xss", title="XSS1", severity="high")
    await dal.create_finding(db_session, session_id=s.id, vuln_type="sqli", title="SQLi1", severity="critical")
    await db_session.flush()
    highs = await dal.get_findings(db_session, s.id, severity="high")
    assert len(highs) == 1
    assert highs[0].vuln_type == "xss"


@pytest.mark.asyncio
async def test_get_findings_summary(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_finding(db_session, session_id=s.id, vuln_type="xss", title="XSS", severity="high")
    await dal.create_finding(db_session, session_id=s.id, vuln_type="sqli", title="SQLi", severity="critical")
    await db_session.flush()
    summary = await dal.get_findings_summary(db_session, s.id)
    assert summary["total"] == 2
    assert "by_severity" in summary
    assert "by_type" in summary


@pytest.mark.asyncio
async def test_update_finding_status(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    f = await dal.create_finding(db_session, session_id=s.id, vuln_type="xss", title="XSS", severity="high")
    await db_session.flush()
    await dal.update_finding_status(db_session, f.id, FindingStatus.CONFIRMED)
    await db_session.flush()
    findings = await dal.get_findings(db_session, s.id, status="confirmed")
    assert len(findings) == 1


# ── Tool Runs ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_tool_run(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    tr = await dal.create_tool_run(
        db_session, session_id=s.id, tool_name="nmap", command="nmap -sV target.com",
    )
    assert tr.tool_name == "nmap"
    assert tr.status == RunStatus.PENDING


@pytest.mark.asyncio
async def test_start_and_complete_tool_run(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    tr = await dal.create_tool_run(
        db_session, session_id=s.id, tool_name="nmap", command="nmap -sV target.com",
    )
    await dal.start_tool_run(db_session, tr.id)
    await db_session.flush()
    # Verify running
    fetched = await dal.get_tool_run(db_session, tr.id)
    assert fetched.status == RunStatus.RUNNING
    assert fetched.started_at is not None

    await dal.complete_tool_run(
        db_session, tr.id,
        status=RunStatus.SUCCESS,
        stdout="PORT STATE SERVICE\n80/tcp open http",
        exit_code=0,
    )
    await db_session.flush()
    fetched2 = await dal.get_tool_run(db_session, tr.id)
    assert fetched2.status == RunStatus.SUCCESS
    assert fetched2.finished_at is not None


@pytest.mark.asyncio
async def test_get_tool_runs(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_tool_run(db_session, session_id=s.id, tool_name="nmap", command="nmap")
    await dal.create_tool_run(db_session, session_id=s.id, tool_name="httpx", command="httpx")
    runs = await dal.get_tool_runs(db_session, s.id)
    assert len(runs) == 2
    # Filter by tool_name
    nmap_runs = await dal.get_tool_runs(db_session, s.id, tool_name="nmap")
    assert len(nmap_runs) == 1


# ── Artifacts ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_artifact(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    a = await dal.create_artifact(
        db_session, session_id=s.id,
        artifact_type="nmap_output",
        content="PORT STATE SERVICE\n80/tcp open http",
    )
    assert a.artifact_type == "nmap_output"


@pytest.mark.asyncio
async def test_get_artifacts(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    await dal.create_artifact(db_session, session_id=s.id, artifact_type="nmap_output", content="out")
    await dal.create_artifact(db_session, session_id=s.id, artifact_type="screenshot", file_path="/tmp/ss.png")
    arts = await dal.get_artifacts(db_session, s.id)
    assert len(arts) == 2
    nmap_arts = await dal.get_artifacts(db_session, s.id, artifact_type="nmap_output")
    assert len(nmap_arts) == 1


# ── Correlations ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_correlation(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    f = await dal.create_finding(
        db_session, session_id=s.id, vuln_type="sqli", title="SQLi", severity="high",
    )
    c = await dal.create_correlation(
        db_session,
        session_id=s.id,
        finding_id=f.id,
        repo_name="myrepo",
        hotspot_file="src/db.py",
        hotspot_line=42,
        hotspot_category="sqli",
        confidence=0.75,
    )
    assert c.confidence == 0.75
    assert c.hotspot_category == "sqli"


@pytest.mark.asyncio
async def test_get_correlations(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    f = await dal.create_finding(
        db_session, session_id=s.id, vuln_type="xss", title="XSS", severity="medium",
    )
    await dal.create_correlation(
        db_session, session_id=s.id, finding_id=f.id,
        repo_name="r", hotspot_file="f.py", hotspot_line=1,
        hotspot_category="xss", confidence=0.8,
    )
    await dal.create_correlation(
        db_session, session_id=s.id, finding_id=f.id,
        repo_name="r", hotspot_file="g.py", hotspot_line=2,
        hotspot_category="xss", confidence=0.3,
    )
    await db_session.flush()
    all_corrs = await dal.get_correlations(db_session, s.id)
    assert len(all_corrs) == 2
    high_corrs = await dal.get_correlations(db_session, s.id, min_confidence=0.5)
    assert len(high_corrs) == 1


@pytest.mark.asyncio
async def test_delete_correlations_for_session(db_session: AsyncSession):
    s = await dal.create_session(db_session, target_base_url="http://test.com")
    f = await dal.create_finding(
        db_session, session_id=s.id, vuln_type="xss", title="XSS", severity="medium",
    )
    await dal.create_correlation(
        db_session, session_id=s.id, finding_id=f.id,
        repo_name="r", hotspot_file="f.py", hotspot_line=1,
        hotspot_category="xss", confidence=0.6,
    )
    await db_session.flush()
    count = await dal.delete_correlations_for_session(db_session, s.id)
    assert count == 1
    remaining = await dal.get_correlations(db_session, s.id)
    assert len(remaining) == 0
