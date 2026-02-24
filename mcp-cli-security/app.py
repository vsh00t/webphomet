"""FastAPI HTTP server for MCP CLI-Security.

Exposes a JSON-RPC 2.0 endpoint (/rpc) that wraps the security
CLI tools execution with scope validation.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scope import ScopeValidator
from server import ALLOWED_COMMANDS, CLISecurityServer

# ---------------------------------------------------------------------------
# Pydantic models for JSON-RPC
# ---------------------------------------------------------------------------


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request model."""

    jsonrpc: str = "2.0"
    id: str
    method: str
    params: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    """JSON-RPC 2.0 response model."""

    jsonrpc: str = "2.0"
    id: str
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="MCP CLI-Security Server",
    version="1.0.0",
    description="JSON-RPC server for security CLI tools execution",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize scope validator and CLI server
scope_validator = ScopeValidator()
cli_server = CLISecurityServer(
    scope_validator=scope_validator,
    working_dir="/app/artifacts",
    timeout=600,
)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "mcp-cli-security"}


@app.get("/")
async def root() -> dict[str, Any]:
    """Root endpoint with server info."""
    return {
        "name": "MCP CLI-Security Server",
        "version": "1.0.0",
        "tools": list(ALLOWED_COMMANDS),
    }


@app.post("/rpc")
async def rpc_endpoint(request: JsonRpcRequest) -> JsonRpcResponse:
    """JSON-RPC 2.0 endpoint for tool execution and queries.

    Supported methods:
        - tools/list: List all available tools
        - run_command: Execute a security CLI tool

    Parameters for run_command:
        - tool_name: str (nmap, subfinder, httpx, etc.)
        - args: str (CLI arguments to pass)
    """
    logger.info(
        "JSON-RPC request: method=%s, id=%s",
        request.method,
        request.id,
    )

    try:
        if request.method == "tools/list":
            result = {"tools": cli_server.list_tools()}
            return JsonRpcResponse(id=request.id, result=result)

        elif request.method == "mirror_site":
            if not request.params:
                raise HTTPException(
                    status_code=400,
                    detail="Missing 'params' for mirror_site method",
                )
            result = await cli_server.run_mirror(
                url=request.params["url"],
                session_id=request.params.get("session_id", "default"),
                depth=request.params.get("depth", 8),
                global_timeout=request.params.get("global_timeout", 300),
            )
            return JsonRpcResponse(id=request.id, result=result)

        elif request.method == "scan_secrets":
            if not request.params:
                raise HTTPException(
                    status_code=400,
                    detail="Missing 'params' for scan_secrets method",
                )
            result = await cli_server.run_secret_scan(
                directory=request.params.get("directory"),
                session_id=request.params.get("session_id", "default"),
                max_findings=request.params.get("max_findings", 500),
            )
            if "error" in result and result["error"]:
                return JsonRpcResponse(
                    id=request.id,
                    error={"code": -32603, "message": result["error"]},
                )
            return JsonRpcResponse(id=request.id, result=result)

        elif request.method == "run_command":
            if not request.params:
                raise HTTPException(
                    status_code=400,
                    detail="Missing 'params' for run_command method",
                )

            tool_name = request.params.get("tool_name")
            raw_args = request.params.get("args", "")

            if not tool_name:
                raise HTTPException(
                    status_code=400,
                    detail="Missing 'tool_name' in params",
                )

            result = await cli_server.run_command(tool_name, raw_args)

            # Check for execution error
            if "error" in result and result["error"]:
                return JsonRpcResponse(
                    id=request.id,
                    error={
                        "code": -32603,
                        "message": result["error"],
                        "data": result,
                    },
                )

            return JsonRpcResponse(id=request.id, result=result)

        else:
            return JsonRpcResponse(
                id=request.id,
                error={
                    "code": -32601,
                    "message": f"Method not found: {request.method}",
                },
            )

    except Exception as e:
        logger.exception("Error processing JSON-RPC request")
        return JsonRpcResponse(
            id=request.id,
            error={
                "code": -32603,
                "message": str(e),
            },
        )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def startup_event() -> None:
    """Run on application startup."""
    logger.info("MCP CLI-Security Server started")
    logger.info("Available tools: %s", ", ".join(ALLOWED_COMMANDS))


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Run on application shutdown."""
    logger.info("MCP CLI-Security Server shutting down")


# ---------------------------------------------------------------------------
# Main entry point (for running directly with uvicorn)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9100, log_level="info")
