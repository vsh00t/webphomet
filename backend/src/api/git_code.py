"""Git/Code — Source-code analysis API endpoints (Phase 3.1).

Extracted from tools.py to avoid routing conflict with the
``/{tool_run_id}`` catch-all path parameter.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.database import get_db
from src.jobs.celery_app import celery_app

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CloneRepoRequest(BaseModel):
    session_id: uuid.UUID
    url: str
    name: str | None = None


class CodeAuditRequest(BaseModel):
    session_id: uuid.UUID
    repo_url: str | None = None
    repo_name: str | None = None
    categories: list[str] | None = None


class SearchCodeRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    query: str
    is_regex: bool = False
    file_pattern: str = "*"


class FindHotspotsRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    categories: list[str] | None = None


class GitLogRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    max_count: int = 20
    file_path: str | None = None


class GitDiffRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    commit_a: str = "HEAD~1"
    commit_b: str = "HEAD"


class GitBlameRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    file_path: str
    start_line: int = 1
    end_line: int = 50


class GetTreeRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    path: str = ""
    max_depth: int = 3


class GetFileRequest(BaseModel):
    session_id: uuid.UUID
    repo_name: str
    file_path: str
    start_line: int = 1
    end_line: int | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/clone-repo")
async def clone_repo(
    payload: CloneRepoRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_clone_repo",
        command=f"git clone {payload.url}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "clone_repo", "params": {"url": payload.url, "name": payload.name},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/code-audit")
async def run_code_audit_endpoint(
    payload: CodeAuditRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="code_audit",
        command=f"code_audit {payload.repo_url or payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.run_code_audit",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "repo_url": payload.repo_url, "repo_name": payload.repo_name,
            "categories": payload.categories,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/search-code")
async def search_code_endpoint(
    payload: SearchCodeRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_search_code",
        command=f"search {payload.repo_name} '{payload.query}'",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "search_code",
            "params": {
                "repo_name": payload.repo_name, "query": payload.query,
                "is_regex": payload.is_regex, "file_pattern": payload.file_pattern,
            },
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/find-hotspots")
async def find_hotspots_endpoint(
    payload: FindHotspotsRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_find_hotspots",
        command=f"hotspots {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "find_hotspots",
            "params": {"repo_name": payload.repo_name, "categories": payload.categories},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-log")
async def git_log_endpoint(
    payload: GitLogRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_log",
        command=f"git log {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    params: dict[str, Any] = {"repo_name": payload.repo_name, "max_count": payload.max_count}
    if payload.file_path:
        params["file_path"] = payload.file_path
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_log", "params": params,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-diff")
async def git_diff_endpoint(
    payload: GitDiffRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_diff",
        command=f"git diff {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_diff",
            "params": {"repo_name": payload.repo_name, "commit_a": payload.commit_a, "commit_b": payload.commit_b},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-blame")
async def git_blame_endpoint(
    payload: GitBlameRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_blame",
        command=f"git blame {payload.repo_name}/{payload.file_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "git_blame",
            "params": {
                "repo_name": payload.repo_name, "file_path": payload.file_path,
                "start_line": payload.start_line, "end_line": payload.end_line,
            },
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-tree")
async def git_tree_endpoint(
    payload: GetTreeRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_get_tree",
        command=f"git tree {payload.repo_name}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "get_tree",
            "params": {"repo_name": payload.repo_name, "path": payload.path, "max_depth": payload.max_depth},
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.post("/git-file")
async def git_file_endpoint(
    payload: GetFileRequest, db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=payload.session_id, tool_name="git_get_file",
        command=f"git file {payload.repo_name}/{payload.file_path}",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    params: dict[str, Any] = {
        "repo_name": payload.repo_name, "file_path": payload.file_path,
        "start_line": payload.start_line,
    }
    if payload.end_line is not None:
        params["end_line"] = payload.end_line
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(payload.session_id), "tool_run_id": str(tool_run.id),
            "method": "get_file", "params": params,
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}


@router.get("/list-repos")
async def list_repos_endpoint(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    tool_run = await dal.create_tool_run(
        db, session_id=session_id, tool_name="git_list_repos",
        command="git list_repos",
    )
    await dal.start_tool_run(db, tool_run.id)
    await db.commit()
    task = celery_app.send_task(
        "jobs.git_code_call",
        kwargs={
            "session_id": str(session_id), "tool_run_id": str(tool_run.id),
            "method": "list_repos",
        },
    )
    return {"tool_run_id": str(tool_run.id), "task_id": task.id, "status": "submitted"}
