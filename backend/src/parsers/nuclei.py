"""Nuclei output parser — converts JSON lines output to structured data.

Nuclei outputs JSON lines when invoked with -json or -jsonl flag, each line
representing a matched template/vulnerability.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping to our internal scale
# ---------------------------------------------------------------------------

NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class NucleiMatch:
    """A single nuclei template match (potential vulnerability)."""

    template_id: str
    template_name: str = ""
    severity: str = "info"
    matched_url: str = ""
    matched_at: str = ""
    host: str = ""
    ip: str = ""
    extracted_results: list[str] = field(default_factory=list)
    matcher_name: str = ""
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    curl_command: str = ""
    request: str = ""
    response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "matched_url": self.matched_url,
            "matched_at": self.matched_at,
            "host": self.host,
            "ip": self.ip,
            "extracted_results": self.extracted_results,
            "matcher_name": self.matcher_name,
            "description": self.description,
            "reference": self.reference,
            "tags": self.tags,
            "curl_command": self.curl_command,
        }

    def to_finding_dict(self) -> dict[str, Any]:
        """Convert to a format compatible with our Finding schema."""
        return {
            "vuln_type": self._infer_vuln_type(),
            "title": f"[Nuclei] {self.template_name or self.template_id}",
            "description": self.description or f"Nuclei template {self.template_id} matched at {self.matched_url}",
            "severity": NUCLEI_SEVERITY_MAP.get(self.severity.lower(), "info"),
            "evidence": self._build_evidence(),
            "poc": self.curl_command or self.matched_url,
            "recommendation": f"Review and remediate {self.template_id}. See references for details.",
            "references": {"nuclei_template": self.template_id, "urls": self.reference},
        }

    def _infer_vuln_type(self) -> str:
        """Infer vulnerability type from template tags."""
        tag_set = {t.lower() for t in self.tags}
        if tag_set & {"sqli", "sql-injection", "injection"}:
            return "injection"
        if tag_set & {"xss", "cross-site-scripting"}:
            return "xss"
        if tag_set & {"ssrf"}:
            return "ssrf"
        if tag_set & {"auth", "authentication", "bypass"}:
            return "broken_auth"
        if tag_set & {"exposure", "disclosure", "info-disclosure"}:
            return "info_disclosure"
        if tag_set & {"rce", "remote-code-execution"}:
            return "rce"
        if tag_set & {"lfi", "rfi", "path-traversal"}:
            return "path_traversal"
        return "other"

    def _build_evidence(self) -> str:
        """Build evidence string from match data."""
        parts: list[str] = []
        if self.matched_url:
            parts.append(f"URL: {self.matched_url}")
        if self.matched_at:
            parts.append(f"Matched at: {self.matched_at}")
        if self.matcher_name:
            parts.append(f"Matcher: {self.matcher_name}")
        if self.extracted_results:
            parts.append(f"Extracted: {', '.join(self.extracted_results)}")
        return "\n".join(parts) if parts else ""


@dataclass
class NucleiResult:
    """Complete nuclei scan result."""

    matches: list[NucleiMatch] = field(default_factory=list)

    @property
    def total_matches(self) -> int:
        return len(self.matches)

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for m in self.matches:
            sev = m.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "matches": [m.to_dict() for m in self.matches],
            "summary": {
                "total_matches": self.total_matches,
                "by_severity": self.by_severity,
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary for the LLM agent."""
        lines = [
            f"Nuclei: {self.total_matches} match(es) found",
        ]
        sev = self.by_severity
        if sev:
            sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(sev.items()))
            lines.append(f"  Severity breakdown: {sev_str}")

        for m in self.matches[:15]:
            lines.append(
                f"  [{m.severity.upper()}] {m.template_id} — {m.matched_url}"
            )
        if len(self.matches) > 15:
            lines.append(f"  ... and {len(self.matches) - 15} more")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_nuclei(output: str) -> NucleiResult:
    """Parse nuclei JSON lines output (-json / -jsonl flag).

    Parameters
    ----------
    output:
        Raw stdout from nuclei execution.

    Returns
    -------
    Parsed NucleiResult.
    """
    result = NucleiResult()

    for line in output.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON nuclei line: %.80s", line)
            continue

        info = data.get("info", {})
        match = NucleiMatch(
            template_id=data.get("template-id", data.get("templateID", "")),
            template_name=info.get("name", ""),
            severity=info.get("severity", "info"),
            matched_url=data.get("matched-at", data.get("matched", "")),
            matched_at=data.get("matched-at", ""),
            host=data.get("host", ""),
            ip=data.get("ip", ""),
            extracted_results=data.get("extracted-results", []),
            matcher_name=data.get("matcher-name", ""),
            description=info.get("description", ""),
            reference=info.get("reference", []),
            tags=info.get("tags", []) if isinstance(info.get("tags"), list)
                else info.get("tags", "").split(",") if info.get("tags") else [],
            curl_command=data.get("curl-command", ""),
            request=data.get("request", ""),
            response=data.get("response", ""),
        )
        result.matches.append(match)

    logger.info("Parsed nuclei output: %d matches", result.total_matches)
    return result
