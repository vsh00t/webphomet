"""FastAPI JSON-RPC server for MCP Caido.

Mirrors the same JSON-RPC 2.0 pattern as MCP CLI-Security,
exposing Caido proxy operations to the WebPhomet backend.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from caido_client import CaidoClient
from server import CaidoServer

# ---------------------------------------------------------------------------
# JSON-RPC models
# ---------------------------------------------------------------------------


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str
    method: str
    params: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CAIDO_URL = os.environ.get("CAIDO_API_URL", "http://host.docker.internal:8088")
CAIDO_AUTH_TOKEN = os.environ.get("CAIDO_AUTH_TOKEN", "")
CAIDO_REFRESH_TOKEN = os.environ.get("CAIDO_REFRESH_TOKEN", "")

client = CaidoClient(
    base_url=CAIDO_URL,
    auth_token=CAIDO_AUTH_TOKEN,
    refresh_token=CAIDO_REFRESH_TOKEN,
)
caido_server = CaidoServer(client=client)

app = FastAPI(
    title="MCP Caido Server",
    description="JSON-RPC 2.0 gateway to Caido proxy",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Method dispatch table
# ---------------------------------------------------------------------------

METHOD_HANDLERS: dict[str, Any] = {
    # Projects
    "list_projects": lambda p: caido_server.list_projects(),
    "create_project": lambda p: caido_server.create_project(
        name=p.get("name", "WebPhomet"),
    ),
    "select_project": lambda p: caido_server.select_project(
        project_id=p["project_id"],
    ),
    # Requests
    "get_requests": lambda p: caido_server.get_requests(
        limit=p.get("limit", 50),
        offset=p.get("offset", 0),
        host=p.get("host"),
    ),
    "get_request": lambda p: caido_server.get_request(
        request_id=p["request_id"],
    ),
    # Findings
    "get_findings": lambda p: caido_server.get_findings(
        limit=p.get("limit", 50),
        offset=p.get("offset", 0),
    ),
    "create_finding": lambda p: caido_server.create_finding(
        request_id=p["request_id"],
        title=p["title"],
        description=p.get("description"),
        reporter=p.get("reporter", "webphomet"),
        dedupe_key=p.get("dedupe_key"),
    ),
    "sync_findings": lambda p: caido_server.sync_findings_to_caido(
        findings=p["findings"],
    ),
    "pull_findings": lambda p: caido_server.pull_findings(
        limit=p.get("limit", 100),
        offset=p.get("offset", 0),
    ),
    # Scopes
    "get_scopes": lambda p: caido_server.get_scopes(),
    "create_scope": lambda p: caido_server.create_scope(
        name=p["name"],
        allowlist=p["allowlist"],
        denylist=p.get("denylist"),
    ),
    # Sitemap
    "get_sitemap": lambda p: caido_server.get_sitemap(),
    "get_sitemap_tree": lambda p: caido_server.get_sitemap_tree(
        parent_id=p.get("parent_id"),
    ),
    # Intercept
    "get_intercept_status": lambda p: caido_server.get_intercept_status(),
    "toggle_intercept": lambda p: caido_server.toggle_intercept(
        enabled=p.get("enabled", True),
    ),
    # Replay
    "send_request": lambda p: caido_server.send_request(
        raw_request=p["raw_request"],
        host=p["host"],
        port=p.get("port", 443),
        is_tls=p.get("is_tls", True),
    ),
    # Workflows
    "list_workflows": lambda p: caido_server.list_workflows(),
    "run_workflow": lambda p: caido_server.run_workflow(
        workflow_id=p["workflow_id"],
        request_id=p["request_id"],
    ),
    # Automate
    "list_automate_sessions": lambda p: caido_server.list_automate_sessions(
        limit=p.get("limit", 20),
    ),
    # Meta
    "tools/list": lambda p: {
        "tools": [
            {"name": "list_projects", "description": "List Caido projects"},
            {"name": "create_project", "description": "Create a new Caido project", "params": ["name"]},
            {"name": "select_project", "description": "Select/open a Caido project", "params": ["project_id"]},
            {"name": "get_requests", "description": "Fetch intercepted HTTP requests", "params": ["limit", "offset", "host"]},
            {"name": "get_request", "description": "Get a single request by ID", "params": ["request_id"]},
            {"name": "get_findings", "description": "List Caido findings", "params": ["limit", "offset"]},
            {"name": "create_finding", "description": "Create a finding in Caido", "params": ["title", "description", "reporter", "request_id"]},
            {"name": "sync_findings", "description": "Batch push findings to Caido", "params": ["findings"]},
            {"name": "pull_findings", "description": "Pull findings from Caido for import", "params": ["limit", "offset"]},
            {"name": "get_scopes", "description": "List Caido scopes"},
            {"name": "create_scope", "description": "Create a Caido scope", "params": ["name", "allowlist", "denylist"]},
            {"name": "get_sitemap", "description": "Get root sitemap entries"},
            {"name": "get_sitemap_tree", "description": "Get sitemap tree", "params": ["parent_id"]},
            {"name": "get_intercept_status", "description": "Get intercept on/off status"},
            {"name": "toggle_intercept", "description": "Enable/disable interception", "params": ["enabled"]},
            {"name": "send_request", "description": "Send a crafted HTTP request", "params": ["raw_request", "host", "port", "is_tls"]},
            {"name": "list_workflows", "description": "List Caido workflows"},
            {"name": "run_workflow", "description": "Run a workflow on a request", "params": ["workflow_id", "request_id"]},
            {"name": "list_automate_sessions", "description": "List automate/fuzzing sessions", "params": ["limit"]},
        ]
    },
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    reachable = await caido_server.client.health_check()
    return {"status": "ok" if reachable else "degraded", "caido_reachable": reachable}


@app.post("/rpc")
async def rpc(request: Request):
    """JSON-RPC 2.0 endpoint."""
    body = await request.json()

    try:
        rpc_req = JsonRpcRequest(**body)
    except Exception as exc:
        return JsonRpcResponse(
            id="unknown",
            error={"code": -32600, "message": f"Invalid request: {exc}"},
        )

    handler = METHOD_HANDLERS.get(rpc_req.method)
    if handler is None:
        return JsonRpcResponse(
            id=rpc_req.id,
            error={"code": -32601, "message": f"Method not found: {rpc_req.method}"},
        )

    try:
        params = rpc_req.params or {}
        result = handler(params)
        # Support both sync lambdas (tools/list) and async coroutines
        import inspect
        if inspect.isawaitable(result):
            result = await result
        return JsonRpcResponse(id=rpc_req.id, result=result)
    except Exception as exc:
        logger.exception("Error handling %s", rpc_req.method)
        return JsonRpcResponse(
            id=rpc_req.id,
            error={"code": -32000, "message": str(exc)},
        )
