"""MCP CLI-Security Server scaffold.

This module implements a JSON-RPC 2.0 server that wraps common security CLI
tools (nmap, subfinder, nuclei, …) and enforces scope validation before
every execution.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from dataclasses import dataclass, field
from typing import Any

from src.core.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed commands whitelist
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "nmap",
        "subfinder",
        "httpx",
        "whatweb",
        "nuclei",
        "ffuf",
        "dalfox",
        "sqlmap",
        "schemathesis",
        "kxss",
    }
)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


@dataclass
class CLISecurityServer:
    """MCP server that executes security CLI tools within scope boundaries.

    Parameters
    ----------
    scope_validator:
        The :class:`ScopeValidator` instance that checks every target
        argument before execution.
    working_dir:
        Directory used as ``cwd`` for subprocess execution.
    timeout:
        Maximum seconds a single tool execution is allowed to run.
    """

    scope_validator: ScopeValidator
    working_dir: str = "/app/artifacts"
    timeout: int = 600
    _tools_registry: dict[str, dict[str, Any]] = field(
        default_factory=dict, repr=False
    )

    def __post_init__(self) -> None:
        """Register available tools."""
        for cmd in ALLOWED_COMMANDS:
            self._tools_registry[cmd] = {
                "name": cmd,
                "description": f"Run the {cmd} security tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "args": {
                            "type": "string",
                            "description": f"CLI arguments to pass to {cmd}",
                        },
                    },
                    "required": ["args"],
                },
            }

    # ------------------------------------------------------------------ #
    # Public API (JSON-RPC handlers)
    # ------------------------------------------------------------------ #

    def list_tools(self) -> list[dict[str, Any]]:
        """Return the list of exposed tools (``tools/list``)."""
        return list(self._tools_registry.values())

    async def run_command(
        self,
        tool_name: str,
        raw_args: str,
    ) -> dict[str, Any]:
        """Execute a tool after validating scope.

        Parameters
        ----------
        tool_name:
            Name of the tool (must be in ``ALLOWED_COMMANDS``).
        raw_args:
            Raw CLI argument string.

        Returns
        -------
        dict with keys ``stdout``, ``stderr``, ``exit_code``.
        """
        # 1. Validate tool name
        if tool_name not in ALLOWED_COMMANDS:
            return {
                "error": f"Command {tool_name!r} is not in the allowed whitelist.",
                "exit_code": -1,
            }

        # 2. Parse and validate scope
        parsed_args = shlex.split(raw_args)
        if not self.scope_validator.validate_command(tool_name, parsed_args):
            return {
                "error": "One or more targets in the command are out of scope.",
                "exit_code": -1,
            }

        # 3. Execute
        full_command = [tool_name, *parsed_args]
        logger.info("Executing: %s", " ".join(full_command))

        try:
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.error("Command timed out after %ds: %s", self.timeout, tool_name)
            return {
                "error": f"Command timed out after {self.timeout}s",
                "exit_code": -1,
            }
        except FileNotFoundError:
            logger.error("Command not found: %s", tool_name)
            return {
                "error": f"Command {tool_name!r} not found in PATH.",
                "exit_code": -1,
            }

        return {
            "stdout": stdout_bytes.decode(errors="replace"),
            "stderr": stderr_bytes.decode(errors="replace"),
            "exit_code": process.returncode,
        }
