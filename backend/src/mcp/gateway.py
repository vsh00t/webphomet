"""MCP Gateway — JSON-RPC base for Model Context Protocol communication.

The gateway acts as the bridge between the LLM agent and the various MCP
servers (e.g. the CLI-Security server).  It speaks JSON-RPC 2.0.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JSON-RPC 2.0 helpers
# ---------------------------------------------------------------------------


def _jsonrpc_request(
    method: str,
    params: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request envelope."""
    return {
        "jsonrpc": "2.0",
        "id": request_id or str(uuid.uuid4()),
        "method": method,
        "params": params or {},
    }


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


@dataclass
class MCPGateway:
    """Central gateway that dispatches tool calls to the correct MCP server.

    Parameters
    ----------
    server_urls:
        Mapping of server name → base URL, e.g.
        ``{"cli-security": "http://mcp-cli-security:9100"}``.
    """

    server_urls: dict[str, str] = field(default_factory=dict)
    timeout: float = 300.0

    async def call(
        self,
        server: str,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a JSON-RPC call to the specified MCP server and return the result."""
        base_url = self.server_urls.get(server)
        if base_url is None:
            raise ValueError(f"Unknown MCP server: {server!r}")

        payload = _jsonrpc_request(method, params)
        logger.info("MCP call → %s.%s (id=%s)", server, method, payload["id"])

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{base_url}/rpc",
                json=payload,
            )
        response.raise_for_status()
        body: dict[str, Any] = response.json()

        if body.get("error") is not None:
            logger.error(
                "MCP error from %s.%s: %s",
                server,
                method,
                body["error"],
            )
            raise RuntimeError(f"MCP error: {body['error']}")

        return body.get("result", {})

    async def list_tools(self, server: str) -> list[dict[str, Any]]:
        """Retrieve the list of tools exposed by a MCP server."""
        result = await self.call(server, "tools/list")
        return result.get("tools", [])

    async def close(self) -> None:
        """No-op — clients are created per-call to avoid event loop issues."""
        pass
