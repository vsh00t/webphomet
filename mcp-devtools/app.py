"""FastAPI JSON-RPC server for MCP DevTools.

Exposes headless Chrome capabilities via JSON-RPC 2.0, following the
same pattern as MCP CLI-Security and MCP Caido.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from browser import BrowserManager
from server import DevToolsServer

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

PROXY_URL = os.environ.get("PROXY_URL", "")  # e.g. http://host.docker.internal:8088

devtools = DevToolsServer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start/stop browser on app lifecycle."""
    yield
    await devtools.shutdown()


app = FastAPI(
    title="MCP DevTools Server",
    description="JSON-RPC 2.0 gateway to headless Chrome via Playwright",
    version="0.1.0",
    lifespan=lifespan,
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
    # Navigation
    "navigate": lambda p: devtools.navigate(
        url=p["url"],
        wait_until=p.get("wait_until", "load"),
        timeout=p.get("timeout", 30000),
        proxy_url=p.get("proxy_url", PROXY_URL or None),
    ),
    # Screenshot
    "screenshot": lambda p: devtools.screenshot(
        full_page=p.get("full_page", False),
    ),
    # DOM
    "get_html": lambda p: devtools.get_html(
        selector=p.get("selector"),
    ),
    "query_selector": lambda p: devtools.query_selector(
        selector=p["selector"],
    ),
    # JS
    "execute_js": lambda p: devtools.execute_js(
        script=p["script"],
    ),
    # Cookies & Storage
    "get_cookies": lambda p: devtools.get_cookies(),
    "set_cookies": lambda p: devtools.set_cookies(
        cookies=p["cookies"],
    ),
    "get_storage": lambda p: devtools.get_storage(),
    # Network & Errors
    "get_network_log": lambda p: devtools.get_network_log(),
    "get_js_errors": lambda p: devtools.get_js_errors(),
    # Discovery
    "discover_forms": lambda p: devtools.discover_forms(),
    "discover_links": lambda p: devtools.discover_links(),
    # Security
    "detect_dom_xss_sinks": lambda p: devtools.detect_dom_xss_sinks(),
    "check_security_headers": lambda p: devtools.check_security_headers(),
    "full_page_audit": lambda p: devtools.full_page_audit(
        url=p["url"],
    ),
    # Meta
    "tools/list": lambda p: {
        "tools": [
            {"name": "navigate", "description": "Navigate to URL", "params": ["url", "wait_until", "timeout", "proxy_url"]},
            {"name": "screenshot", "description": "Take page screenshot", "params": ["full_page"]},
            {"name": "get_html", "description": "Get page/element HTML", "params": ["selector"]},
            {"name": "query_selector", "description": "Query CSS selector", "params": ["selector"]},
            {"name": "execute_js", "description": "Execute JavaScript", "params": ["script"]},
            {"name": "get_cookies", "description": "Get all cookies"},
            {"name": "set_cookies", "description": "Set cookies", "params": ["cookies"]},
            {"name": "get_storage", "description": "Get localStorage/sessionStorage"},
            {"name": "get_network_log", "description": "Get captured network requests"},
            {"name": "get_js_errors", "description": "Get captured JS errors"},
            {"name": "discover_forms", "description": "Find all forms on page"},
            {"name": "discover_links", "description": "Find all links on page"},
            {"name": "detect_dom_xss_sinks", "description": "Scan for DOM XSS sinks"},
            {"name": "check_security_headers", "description": "Check security headers"},
            {"name": "full_page_audit", "description": "Combined security audit", "params": ["url"]},
        ]
    },
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "ok", "browser_started": devtools._started}


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
