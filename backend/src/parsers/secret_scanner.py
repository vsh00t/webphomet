"""Secret scanner output parser — converts JSON findings to structured data.

The secret_scanner MCP tool returns JSON with an array of findings and
summary statistics.  This parser normalises it for the persistence layer,
mapping each finding to a DB Finding record.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Map scanner severity to DB finding severity
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


@dataclass
class SecretFinding:
    """A single secret/sensitive data finding."""

    file: str = ""
    line: int = 0
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "info"
    match: str = ""       # redacted
    context: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "match": self.match,
            "context": self.context,
            "description": self.description,
        }

    def to_finding_dict(self) -> dict[str, Any]:
        """Convert to kwargs suitable for ``dal.create_finding()``."""
        return {
            "title": f"[{self.rule_id}] {self.rule_name}: {self.file}:{self.line}",
            "severity": _SEVERITY_MAP.get(self.severity, "info"),
            "vuln_type": "hardcoded_secret",
            "description": self.description,
            "evidence": f"File: {self.file}, Line: {self.line}\nMatch: {self.match}\nContext: {self.context}",
            "recommendation": (
                f"Remove or rotate the exposed secret ({self.rule_name}). "
                "Use environment variables or a secrets manager instead."
            ),
        }


@dataclass
class SecretScanResult:
    """Parsed secret scanner output."""

    directory: str = ""
    total_files_scanned: int = 0
    total_findings: int = 0
    severity_summary: dict[str, int] = field(default_factory=dict)
    rules_triggered: dict[str, int] = field(default_factory=dict)
    findings: list[SecretFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "severity_summary": self.severity_summary,
            "rules_triggered": self.rules_triggered,
            "findings": [f.to_dict() for f in self.findings],
        }


def parse_secret_scanner(raw_output: str) -> SecretScanResult:
    """Parse the JSON output of the secret_scanner tool.

    Parameters
    ----------
    raw_output:
        JSON string returned by ``secret_scanner.scan_directory()``.

    Returns
    -------
    SecretScanResult with all findings.
    """
    try:
        data = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse secret_scanner JSON output")
        return SecretScanResult()

    findings = []
    for f in data.get("findings", []):
        findings.append(SecretFinding(
            file=f.get("file", ""),
            line=f.get("line", 0),
            rule_id=f.get("rule_id", ""),
            rule_name=f.get("rule_name", ""),
            severity=f.get("severity", "info"),
            match=f.get("match", ""),
            context=f.get("context", ""),
            description=f.get("description", ""),
        ))

    return SecretScanResult(
        directory=data.get("directory", ""),
        total_files_scanned=data.get("total_files_scanned", 0),
        total_findings=data.get("total_findings", 0),
        severity_summary=data.get("severity_summary", {}),
        rules_triggered=data.get("rules_triggered", {}),
        findings=findings,
    )
