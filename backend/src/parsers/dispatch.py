"""Universal parser dispatcher — routes tool output to the correct parser.

Usage:
    from src.parsers.dispatch import parse_tool_output
    result = parse_tool_output("nmap", raw_stdout)
"""

from __future__ import annotations

import logging
from typing import Any

from src.parsers.httpx import HttpxResult, parse_httpx
from src.parsers.nmap import NmapResult, parse_nmap
from src.parsers.nuclei import NucleiResult, parse_nuclei
from src.parsers.secret_scanner import SecretScanResult, parse_secret_scanner
from src.parsers.site_mirror import SiteMirrorResult, parse_site_mirror
from src.parsers.subfinder import SubfinderResult, parse_subfinder
from src.parsers.whatweb import WhatWebResult, parse_whatweb

logger = logging.getLogger(__name__)

# Type alias for any parse result
ParseResult = (
    NmapResult | SubfinderResult | HttpxResult | WhatWebResult
    | NucleiResult | SiteMirrorResult | SecretScanResult
)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PARSER_MAP: dict[str, Any] = {
    "nmap": parse_nmap,
    "subfinder": parse_subfinder,
    "httpx": parse_httpx,
    "whatweb": parse_whatweb,
    "nuclei": parse_nuclei,
    "site_mirror": parse_site_mirror,
    "secret_scanner": parse_secret_scanner,
}

# Tools that don't have a dedicated parser yet — we store raw output
UNPARSED_TOOLS = frozenset({
    "ffuf", "dalfox", "kxss", "sqlmap", "schemathesis",
})


def parse_tool_output(
    tool_name: str,
    raw_output: str,
    **kwargs: Any,
) -> ParseResult | dict[str, Any]:
    """Parse raw tool output into structured data.

    Parameters
    ----------
    tool_name:
        Name of the security tool (e.g. "nmap", "subfinder").
    raw_output:
        Raw stdout/output string from the tool execution.
    **kwargs:
        Additional keyword arguments forwarded to the parser
        (e.g. ``domain`` for subfinder).

    Returns
    -------
    Typed parse result, or a generic dict with the raw output
    if no parser is available.
    """
    parser_fn = _PARSER_MAP.get(tool_name)

    if parser_fn is not None:
        logger.info("Parsing output for tool: %s", tool_name)
        return parser_fn(raw_output, **kwargs)

    # No parser available — return structured raw
    logger.info("No parser for tool %s, storing raw output", tool_name)
    return {
        "tool_name": tool_name,
        "parsed": False,
        "raw_output": raw_output[:50_000],  # cap at 50KB for DB storage
        "truncated": len(raw_output) > 50_000,
    }


def get_available_parsers() -> list[str]:
    """Return list of tool names that have dedicated parsers."""
    return sorted(_PARSER_MAP.keys())


def has_parser(tool_name: str) -> bool:
    """Check if a dedicated parser exists for the given tool."""
    return tool_name in _PARSER_MAP
