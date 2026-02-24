"""WhatWeb output parser — converts JSON output to structured data.

WhatWeb outputs JSON when invoked with --log-json or similar flags.
Also supports parsing the default stdout format.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class WhatWebPlugin:
    """A detected plugin/technology identified by WhatWeb."""

    name: str
    version: str = ""
    string: list[str] = field(default_factory=list)
    certainty: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "string": self.string,
            "certainty": self.certainty,
        }


@dataclass
class WhatWebEntry:
    """Result for a single URL scanned by WhatWeb."""

    url: str
    status_code: int = 0
    plugins: list[WhatWebPlugin] = field(default_factory=list)
    country: str = ""
    ip: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def technologies(self) -> list[str]:
        """Return list of technology names detected."""
        return [p.name for p in self.plugins]

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "plugins": [p.to_dict() for p in self.plugins],
            "technologies": self.technologies,
            "country": self.country,
            "ip": self.ip,
        }


@dataclass
class WhatWebResult:
    """Complete WhatWeb scan result."""

    entries: list[WhatWebEntry] = field(default_factory=list)

    @property
    def total_scanned(self) -> int:
        return len(self.entries)

    @property
    def all_technologies(self) -> set[str]:
        techs: set[str] = set()
        for e in self.entries:
            techs.update(e.technologies)
        # Remove generic/noisy entries
        techs.discard("HTTPServer")
        techs.discard("UncommonHeaders")
        return techs

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "summary": {
                "total_scanned": self.total_scanned,
                "technologies": sorted(self.all_technologies),
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary for the LLM agent."""
        lines = [
            f"WhatWeb: {self.total_scanned} URL(s) scanned",
        ]
        if self.all_technologies:
            lines.append(f"Technologies detected: {', '.join(sorted(self.all_technologies))}")

        for e in self.entries[:10]:
            techs = [
                f"{p.name}" + (f" {p.version}" if p.version else "")
                for p in e.plugins[:8]
            ]
            lines.append(
                f"  [{e.status_code}] {e.url} — {', '.join(techs) if techs else 'none'}"
            )
        if len(self.entries) > 10:
            lines.append(f"  ... and {len(self.entries) - 10} more")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_whatweb_json(data: list[dict[str, Any]]) -> WhatWebResult:
    """Parse WhatWeb JSON array output."""
    result = WhatWebResult()

    for item in data:
        target = item.get("target", "")
        status = item.get("http_status", 0)
        plugins_raw = item.get("plugins", {})

        entry = WhatWebEntry(url=target, status_code=status)

        for plugin_name, plugin_data in plugins_raw.items():
            if isinstance(plugin_data, dict):
                version_list = plugin_data.get("version", [])
                string_list = plugin_data.get("string", [])
                certainty = plugin_data.get("certainty", 100)

                version = version_list[0] if version_list else ""
                entry.plugins.append(
                    WhatWebPlugin(
                        name=plugin_name,
                        version=version,
                        string=string_list if isinstance(string_list, list) else [string_list],
                        certainty=certainty if isinstance(certainty, int) else 100,
                    )
                )
            else:
                entry.plugins.append(WhatWebPlugin(name=plugin_name))

        result.entries.append(entry)

    return result


def _parse_whatweb_text(output: str) -> WhatWebResult:
    """Parse WhatWeb default text output (best effort).

    Typical format:
      http://example.com [200 OK] ... Apache[2.4.41], PHP[7.4.3], Title[...]
    """
    result = WhatWebResult()

    # Pattern: URL [status] plugin1[version], plugin2, ...
    line_pattern = re.compile(
        r"^(https?://\S+)\s+\[(\d+).*?\]\s+(.*)$"
    )
    plugin_pattern = re.compile(
        r"(\w[\w\s.-]*?)(?:\[(.*?)\])?"
    )

    for line in output.strip().splitlines():
        line = line.strip()
        match = line_pattern.match(line)
        if not match:
            continue

        url = match.group(1)
        status_code = int(match.group(2))
        plugins_str = match.group(3)

        entry = WhatWebEntry(url=url, status_code=status_code)

        # Split by comma, parse each plugin
        for part in plugins_str.split(","):
            part = part.strip()
            if not part:
                continue
            p_match = plugin_pattern.match(part)
            if p_match:
                name = p_match.group(1).strip()
                version = (p_match.group(2) or "").strip()
                if name:
                    entry.plugins.append(
                        WhatWebPlugin(name=name, version=version)
                    )

        result.entries.append(entry)

    return result


def parse_whatweb(output: str) -> WhatWebResult:
    """Parse WhatWeb output (auto-detects JSON or text).

    Parameters
    ----------
    output:
        Raw stdout from WhatWeb execution.

    Returns
    -------
    Parsed WhatWebResult.
    """
    stripped = output.strip()

    # Try JSON first
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                result = _parse_whatweb_json(data)
            elif isinstance(data, dict):
                result = _parse_whatweb_json([data])
            else:
                result = _parse_whatweb_text(output)
            logger.info("Parsed WhatWeb JSON: %d entries", result.total_scanned)
            return result
        except json.JSONDecodeError:
            pass

    # Fall back to text
    result = _parse_whatweb_text(output)
    logger.info("Parsed WhatWeb text: %d entries", result.total_scanned)
    return result
