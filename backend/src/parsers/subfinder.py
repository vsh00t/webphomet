"""Subfinder output parser — converts JSON lines output to structured data.

Subfinder outputs one subdomain per line in plain text, or JSON records
when using -json flag.
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
class SubfinderEntry:
    """A single subdomain discovery result."""

    host: str
    source: str = ""
    ip: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "source": self.source,
            "ip": self.ip,
        }


@dataclass
class SubfinderResult:
    """Complete subfinder scan result."""

    entries: list[SubfinderEntry] = field(default_factory=list)
    domain: str = ""

    @property
    def total_subdomains(self) -> int:
        return len(self.entries)

    @property
    def unique_hosts(self) -> set[str]:
        return {e.host for e in self.entries}

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": [e.to_dict() for e in self.entries],
            "summary": {
                "total": self.total_subdomains,
                "unique": len(self.unique_hosts),
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary for the LLM agent."""
        lines = [
            f"Subfinder: {self.total_subdomains} subdomain(s) found"
            + (f" for {self.domain}" if self.domain else ""),
        ]
        # Group by source
        by_source: dict[str, list[str]] = {}
        for e in self.entries:
            src = e.source or "unknown"
            by_source.setdefault(src, []).append(e.host)

        for src, hosts in sorted(by_source.items()):
            lines.append(f"  [{src}] {len(hosts)} hosts")

        # List first 20 subdomains
        hosts_sorted = sorted(self.unique_hosts)
        for h in hosts_sorted[:20]:
            lines.append(f"    - {h}")
        if len(hosts_sorted) > 20:
            lines.append(f"    ... and {len(hosts_sorted) - 20} more")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_subfinder(output: str, domain: str = "") -> SubfinderResult:
    """Parse subfinder output (JSON lines or plain text).

    Parameters
    ----------
    output:
        Raw stdout from subfinder execution.
    domain:
        Root domain that was scanned (for metadata).

    Returns
    -------
    Parsed SubfinderResult.
    """
    result = SubfinderResult(domain=domain)
    seen: set[str] = set()

    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON first (subfinder -json flag)
        if line.startswith("{"):
            try:
                data = json.loads(line)
                host = data.get("host", "").strip()
                if host and host not in seen:
                    seen.add(host)
                    result.entries.append(
                        SubfinderEntry(
                            host=host,
                            source=data.get("source", ""),
                            ip=data.get("ip", ""),
                        )
                    )
                continue
            except json.JSONDecodeError:
                pass

        # Plain text: one subdomain per line
        host = line.strip()
        if host and host not in seen and "." in host:
            seen.add(host)
            result.entries.append(SubfinderEntry(host=host))

    logger.info(
        "Parsed subfinder output: %d subdomains for %s",
        result.total_subdomains,
        domain or "unknown",
    )
    return result
