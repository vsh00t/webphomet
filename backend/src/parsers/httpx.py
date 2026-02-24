"""Httpx output parser — converts JSON lines output to structured data.

httpx (projectdiscovery) outputs JSON lines with extensive probe data
when invoked with -json flag.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class HttpxEntry:
    """A single httpx probe result."""

    url: str
    host: str = ""
    port: int = 0
    status_code: int = 0
    title: str = ""
    web_server: str = ""
    content_type: str = ""
    content_length: int = 0
    technologies: list[str] = field(default_factory=list)
    cdn: str = ""
    tls: dict[str, Any] = field(default_factory=dict)
    redirect_url: str = ""
    method: str = "GET"
    scheme: str = "https"
    words: int = 0
    lines: int = 0
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "status_code": self.status_code,
            "title": self.title,
            "web_server": self.web_server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "technologies": self.technologies,
            "cdn": self.cdn,
            "tls": self.tls if self.tls else None,
            "redirect_url": self.redirect_url or None,
            "scheme": self.scheme,
        }


@dataclass
class HttpxResult:
    """Complete httpx scan result."""

    entries: list[HttpxEntry] = field(default_factory=list)

    @property
    def total_probed(self) -> int:
        return len(self.entries)

    @property
    def alive_hosts(self) -> list[HttpxEntry]:
        return [e for e in self.entries if 200 <= e.status_code < 500]

    @property
    def unique_technologies(self) -> set[str]:
        techs: set[str] = set()
        for e in self.entries:
            techs.update(e.technologies)
        return techs

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "summary": {
                "total_probed": self.total_probed,
                "alive": len(self.alive_hosts),
                "technologies": sorted(self.unique_technologies),
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary for the LLM agent."""
        lines = [
            f"httpx: {self.total_probed} URL(s) probed, "
            f"{len(self.alive_hosts)} alive",
        ]
        if self.unique_technologies:
            lines.append(f"Technologies: {', '.join(sorted(self.unique_technologies))}")

        for e in self.alive_hosts[:15]:
            tech_str = f" [{', '.join(e.technologies)}]" if e.technologies else ""
            lines.append(
                f"  [{e.status_code}] {e.url} — {e.title or 'no title'}"
                f" ({e.web_server}){tech_str}"
            )
        remaining = len(self.alive_hosts) - 15
        if remaining > 0:
            lines.append(f"  ... and {remaining} more")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_httpx(output: str) -> HttpxResult:
    """Parse httpx JSON lines output (-json flag).

    Parameters
    ----------
    output:
        Raw stdout from httpx execution.

    Returns
    -------
    Parsed HttpxResult.
    """
    result = HttpxResult()

    for line in output.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON httpx line: %.80s", line)
            continue

        entry = HttpxEntry(
            url=data.get("url", data.get("input", "")),
            host=data.get("host", ""),
            port=data.get("port", 0),
            status_code=data.get("status_code", data.get("status-code", 0)),
            title=data.get("title", ""),
            web_server=data.get("webserver", data.get("web_server", "")),
            content_type=data.get("content_type", data.get("content-type", "")),
            content_length=data.get("content_length", data.get("content-length", 0)),
            technologies=data.get("tech", data.get("technologies", [])),
            cdn=data.get("cdn_name", data.get("cdn", "")),
            tls=data.get("tls", {}),
            redirect_url=data.get("final_url", data.get("location", "")),
            method=data.get("method", "GET"),
            scheme=data.get("scheme", "https"),
            words=data.get("words", 0),
            lines=data.get("lines", 0),
        )
        result.entries.append(entry)

    # Fallback: plain text (one URL per line with status)
    if not result.entries:
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith("http"):
                result.entries.append(HttpxEntry(url=line))

    logger.info("Parsed httpx output: %d entries", result.total_probed)
    return result
