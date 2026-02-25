"""FastAPI JSON-RPC server for MCP Git/Code.

Exposes repository management, code analysis, and security hotspot
detection via JSON-RPC 2.0.
"""

from __future__ import annotations

import inspect
import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from server import GitCodeServer

# ── JSON-RPC models ──────────────────────────────────────────


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int
    method: str
    params: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


# ── Server instance ──────────────────────────────────────────

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mcp-git-code")

server = GitCodeServer()

# ── Method handlers ──────────────────────────────────────────

METHOD_HANDLERS: dict[str, Any] = {
    # Repo management
    "clone_repo": server.clone_repo,
    "list_repos": server.list_repos,
    "get_repo_stats": server.get_repo_stats,
    # File access
    "get_tree": server.get_tree,
    "get_file": server.get_file,
    # Search
    "search_code": server.search_code,
    # Security analysis
    "find_hotspots": server.find_hotspots,
    "extract_functions": server.extract_functions,
    "full_security_audit": server.full_security_audit,
    # Git operations
    "git_log": server.git_log,
    "git_diff": server.git_diff,
    "git_blame": server.git_blame,
}

TOOLS_LIST = [
    {
        "name": "clone_repo",
        "description": "Clone a git repository for analysis",
        "parameters": {
            "url": {"type": "string", "description": "Git clone URL"},
            "name": {"type": "string", "description": "Local name for the repo (optional)"},
        },
    },
    {
        "name": "list_repos",
        "description": "List all available repositories",
        "parameters": {},
    },
    {
        "name": "get_repo_stats",
        "description": "Get comprehensive statistics for a repository (languages, line counts, hotspot indicators)",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
        },
    },
    {
        "name": "get_tree",
        "description": "Get directory tree of a repository",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "path": {"type": "string", "description": "Subdirectory path (optional)"},
            "max_depth": {"type": "integer", "description": "Max depth to traverse (default: 3)"},
        },
    },
    {
        "name": "get_file",
        "description": "Read file content with optional line range",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "file_path": {"type": "string", "description": "Relative file path within the repo"},
            "start_line": {"type": "integer", "description": "Starting line (default: 1)"},
            "end_line": {"type": "integer", "description": "Ending line (optional, max 500 lines)"},
        },
    },
    {
        "name": "search_code",
        "description": "Search for code patterns in a repository (text or regex)",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "query": {"type": "string", "description": "Search pattern (text or regex)"},
            "is_regex": {"type": "boolean", "description": "Whether query is regex (default: false)"},
            "file_pattern": {"type": "string", "description": "Glob pattern for files (e.g. '*.py')"},
            "max_results": {"type": "integer", "description": "Max results (default: 50)"},
        },
    },
    {
        "name": "find_hotspots",
        "description": "Scan repository for security-sensitive code patterns (sinks, hardcoded secrets, etc.)",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "categories": {
                "type": "array",
                "description": "Categories to scan: sqli, xss, command_injection, ssrf, path_traversal, crypto, deserialization (default: all)",
            },
            "max_results": {"type": "integer", "description": "Max hotspots to return (default: 100)"},
        },
    },
    {
        "name": "extract_functions",
        "description": "Extract function/method definitions from a source file",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "file_path": {"type": "string", "description": "Relative file path"},
        },
    },
    {
        "name": "full_security_audit",
        "description": "Run complete security audit: stats + hotspots + prioritized target list + recommendation",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
        },
    },
    {
        "name": "git_log",
        "description": "Get git commit log for a repository or specific file",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "max_count": {"type": "integer", "description": "Max commits (default: 20)"},
            "file_path": {"type": "string", "description": "Optional file to filter history"},
        },
    },
    {
        "name": "git_diff",
        "description": "Get diff between two commits",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "commit_a": {"type": "string", "description": "First commit (default: HEAD~1)"},
            "commit_b": {"type": "string", "description": "Second commit (default: HEAD)"},
            "file_path": {"type": "string", "description": "Optional file filter"},
        },
    },
    {
        "name": "git_blame",
        "description": "Get git blame for specific line range of a file",
        "parameters": {
            "repo_name": {"type": "string", "description": "Name of the repository"},
            "file_path": {"type": "string", "description": "Relative file path"},
            "start_line": {"type": "integer", "description": "Start line (default: 1)"},
            "end_line": {"type": "integer", "description": "End line (default: 50)"},
        },
    },
]


# ── FastAPI application ──────────────────────────────────────

app = FastAPI(title="MCP Git/Code", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mcp-git-code"}


@app.post("/rpc")
async def rpc_endpoint(request: Request) -> JsonRpcResponse:
    """Handle JSON-RPC 2.0 requests."""
    body = await request.json()
    rpc = JsonRpcRequest(**body)

    # tools/list meta-method
    if rpc.method == "tools/list":
        return JsonRpcResponse(id=rpc.id, result={"tools": TOOLS_LIST})

    handler = METHOD_HANDLERS.get(rpc.method)
    if handler is None:
        return JsonRpcResponse(
            id=rpc.id,
            error={"code": -32601, "message": f"Method not found: {rpc.method}"},
        )

    try:
        params = rpc.params or {}
        result = handler(**params)

        # Handle async methods if any
        if inspect.isawaitable(result):
            result = await result

        if not isinstance(result, dict):
            result = {"data": result}

        return JsonRpcResponse(id=rpc.id, result=result)
    except TypeError as e:
        return JsonRpcResponse(
            id=rpc.id,
            error={"code": -32602, "message": f"Invalid params: {e}"},
        )
    except Exception as e:
        logger.exception("Error in method %s", rpc.method)
        return JsonRpcResponse(
            id=rpc.id,
            error={"code": -32000, "message": f"Internal error: {e}"},
        )
