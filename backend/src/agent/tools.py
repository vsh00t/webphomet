"""Tool definitions for Z.ai function/tool calling.

Each tool is described following the OpenAI-compatible tool schema so the
LLM agent can decide which tool to invoke at each step of the pentesting
workflow.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _tool(
    name: str,
    description: str,
    parameters: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build an OpenAI-compatible tool definition."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": parameters,
                "required": required or [],
            },
        },
    }


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

create_pentest_session = _tool(
    name="create_pentest_session",
    description=(
        "Create a new pentest session for a given target URL. "
        "Returns the session ID and initial configuration."
    ),
    parameters={
        "target_base_url": {
            "type": "string",
            "description": "Base URL of the target application",
        },
        "app_type": {
            "type": "string",
            "description": "Type of application (web, api, mobile_backend)",
        },
        "scope": {
            "type": "object",
            "description": "Scope configuration with allowed_hosts, allowed_ips, exclusions",
        },
    },
    required=["target_base_url"],
)

get_session_state = _tool(
    name="get_session_state",
    description="Retrieve the current state of a pentest session including targets, findings, and tool runs.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

run_recon = _tool(
    name="run_recon",
    description=(
        "Run a reconnaissance tool (nmap, subfinder, httpx, whatweb) against "
        "the target. The tool runs asynchronously and results can be retrieved "
        "later with get_recon_results."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "tool_name": {
            "type": "string",
            "enum": ["nmap", "subfinder", "httpx", "whatweb"],
            "description": "Name of the recon tool to run",
        },
        "args": {
            "type": "string",
            "description": "CLI arguments for the tool",
        },
    },
    required=["session_id", "tool_name", "args"],
)

get_recon_results = _tool(
    name="get_recon_results",
    description="Retrieve the results of a previously started reconnaissance tool run.",
    parameters={
        "tool_run_id": {
            "type": "string",
            "description": "UUID of the tool run to retrieve results for",
        },
    },
    required=["tool_run_id"],
)


# ---------------------------------------------------------------------------
# Static Analysis — Site Mirror + Secret Scanner
# ---------------------------------------------------------------------------

mirror_site = _tool(
    name="mirror_site",
    description=(
        "Download/mirror all reachable content from a target URL for offline "
        "static analysis. Uses wget recursive download + smart URL extraction "
        "from JS/HTML/CSS to find lazy-loaded chunks, API endpoints, source maps, "
        "and other assets. Returns a summary with file counts, sizes, and types."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "url": {
            "type": "string",
            "description": "Target URL to mirror (e.g. https://example.com/app)",
        },
        "depth": {
            "type": "integer",
            "description": "Maximum recursion depth for wget (default: 8)",
        },
        "global_timeout": {
            "type": "integer",
            "description": "Global timeout in seconds for the mirror operation (default: 300)",
        },
    },
    required=["session_id", "url"],
)

scan_secrets = _tool(
    name="scan_secrets",
    description=(
        "Scan a previously mirrored site directory for hardcoded secrets, "
        "API keys, tokens, passwords, database connection strings, private keys, "
        "internal IPs, debug endpoints, and other sensitive data. "
        "Must run mirror_site first. Creates findings in the database for each "
        "secret discovered."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session (uses the mirror output from that session)",
        },
        "max_findings": {
            "type": "integer",
            "description": "Maximum number of findings to return (default: 500)",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

parse_nmap_output = _tool(
    name="parse_nmap_output",
    description="Parse raw nmap XML/text output into structured port and service data.",
    parameters={
        "artifact_id": {
            "type": "string",
            "description": "UUID of the artifact containing nmap output",
        },
    },
    required=["artifact_id"],
)

summarize_findings = _tool(
    name="summarize_findings",
    description="Generate a summary of all findings for a session, grouped by severity.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

correlate_findings = _tool(
    name="correlate_findings",
    description=(
        "Analyse findings to identify correlated vulnerabilities, "
        "attack chains, and overall risk patterns."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

build_report = _tool(
    name="build_report",
    description="Generate a Markdown pentest report from session data.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "format": {
            "type": "string",
            "enum": ["markdown", "pdf"],
            "description": "Output format for the report",
        },
    },
    required=["session_id"],
)

export_report = _tool(
    name="export_report",
    description="Export a previously generated report to a file.",
    parameters={
        "report_artifact_id": {
            "type": "string",
            "description": "UUID of the report artifact",
        },
        "output_path": {
            "type": "string",
            "description": "File path where the report should be saved",
        },
    },
    required=["report_artifact_id"],
)


# ---------------------------------------------------------------------------
# All tools (convenience list for passing to Z.ai)
# ---------------------------------------------------------------------------

ALL_TOOLS: list[dict[str, Any]] = [
    create_pentest_session,
    get_session_state,
    run_recon,
    get_recon_results,
    mirror_site,
    scan_secrets,
    parse_nmap_output,
    summarize_findings,
    correlate_findings,
    build_report,
    export_report,
]
