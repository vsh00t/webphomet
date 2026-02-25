"""Code-aware correlation engine.

Matches static-code hotspots (from mcp-git-code ``find_hotspots``) to
dynamic findings stored in the database.  The engine uses vuln-category
mapping, path heuristics, and keyword matching to produce a confidence
score for each *(hotspot, finding)* pair.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from src.db import dal
from src.db.models import Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Category mapping: hotspot category → vuln_type tokens in findings
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, list[str]] = {
    "sqli": [
        "sql_injection", "sqli", "sql injection", "blind sql",
        "union injection", "error-based sql",
    ],
    "xss": [
        "xss", "cross-site scripting", "cross_site_scripting",
        "reflected xss", "stored xss", "dom xss", "dom-based xss",
    ],
    "command_injection": [
        "command_injection", "cmd_injection", "command injection",
        "os command", "rce", "remote code execution", "code execution",
    ],
    "ssrf": [
        "ssrf", "server-side request forgery", "server_side_request_forgery",
    ],
    "path_traversal": [
        "path_traversal", "path traversal", "directory traversal",
        "lfi", "local file inclusion", "file inclusion",
    ],
    "crypto": [
        "weak_crypto", "weak crypto", "insecure crypto",
        "broken cryptography", "insufficient cryptography",
    ],
    "deserialization": [
        "deserialization", "insecure deserialization",
        "unsafe deserialization", "object injection",
    ],
}


@dataclass
class HotspotRecord:
    """Simplified hotspot representation for correlation."""

    file: str
    line: int
    category: str
    pattern_desc: str
    code_snippet: str
    severity: str
    language: str = ""


@dataclass
class CorrelationResult:
    """A single hotspot-to-finding match with confidence."""

    finding_id: uuid.UUID
    finding_title: str
    finding_vuln_type: str
    hotspot: HotspotRecord
    confidence: float
    correlation_type: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    """Lower-case + collapse whitespace."""
    return re.sub(r"\s+", " ", text.strip().lower())


def _category_matches_vuln(category: str, vuln_type: str) -> float:
    """Return a confidence bump if the hotspot category maps to the finding vuln_type."""
    tokens = _CATEGORY_MAP.get(category, [])
    norm = _normalize(vuln_type)
    for tok in tokens:
        if tok in norm:
            return 0.55  # strong category match
    return 0.0


def _keyword_overlap(snippet: str, evidence: str) -> float:
    """Return a small confidence bump based on shared keywords."""
    if not snippet or not evidence:
        return 0.0
    a_words = set(re.findall(r"[a-zA-Z_]{3,}", snippet.lower()))
    b_words = set(re.findall(r"[a-zA-Z_]{3,}", evidence.lower()))
    if not a_words:
        return 0.0
    overlap = len(a_words & b_words) / max(len(a_words), 1)
    return min(overlap * 0.3, 0.15)


def _path_heuristic(hotspot_file: str, finding_evidence: str | None) -> float:
    """Return a confidence bump if the hotspot file appears in finding evidence."""
    if not finding_evidence:
        return 0.0
    basename = hotspot_file.rsplit("/", 1)[-1]
    if basename and basename in finding_evidence:
        return 0.15
    return 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate_hotspots_to_findings(
    hotspots: list[dict[str, Any]],
    findings: Sequence[Finding],
    *,
    min_confidence: float = 0.3,
) -> list[CorrelationResult]:
    """Run the correlation algorithm.

    Parameters
    ----------
    hotspots:
        List of hotspot dicts as returned by mcp-git-code ``find_hotspots``
        (keys: file, line, category, pattern_desc, code_snippet, severity).
    findings:
        Sequence of Finding ORM objects (from the DB).
    min_confidence:
        Drop matches below this threshold.

    Returns
    -------
    List of CorrelationResult sorted by confidence descending.
    """
    results: list[CorrelationResult] = []

    for hs_dict in hotspots:
        hs = HotspotRecord(
            file=hs_dict.get("file", ""),
            line=int(hs_dict.get("line", 0)),
            category=hs_dict.get("category", ""),
            pattern_desc=hs_dict.get("pattern_desc", ""),
            code_snippet=hs_dict.get("code_snippet", ""),
            severity=hs_dict.get("severity", "medium"),
            language=hs_dict.get("language", ""),
        )

        for finding in findings:
            confidence = 0.0
            c_type = "none"
            notes_parts: list[str] = []

            # 1. Category match
            cat_score = _category_matches_vuln(hs.category, finding.vuln_type)
            if cat_score > 0:
                confidence += cat_score
                c_type = "category_match"
                notes_parts.append(f"category '{hs.category}' → vuln_type '{finding.vuln_type}'")

            # 2. Path heuristic
            evidence_text = (finding.evidence or "") + " " + (finding.description or "")
            path_score = _path_heuristic(hs.file, evidence_text)
            if path_score > 0:
                confidence += path_score
                c_type = "category_path_match" if c_type != "none" else "path_match"
                notes_parts.append(f"file '{hs.file}' referenced in evidence")

            # 3. Keyword overlap
            kw_score = _keyword_overlap(hs.code_snippet, evidence_text)
            if kw_score > 0:
                confidence += kw_score
                notes_parts.append(f"keyword overlap ({kw_score:.2f})")

            # 4. Severity alignment bonus
            sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            hs_sev = sev_map.get(hs.severity, 1)
            f_sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            f_sev = sev_map.get(f_sev_str, 1)
            if hs_sev >= 2 and f_sev >= 2 and abs(hs_sev - f_sev) <= 1:
                confidence += 0.05
                notes_parts.append("severity alignment")

            confidence = min(confidence, 1.0)

            if confidence >= min_confidence:
                results.append(CorrelationResult(
                    finding_id=finding.id,
                    finding_title=finding.title,
                    finding_vuln_type=finding.vuln_type,
                    hotspot=hs,
                    confidence=round(confidence, 3),
                    correlation_type=c_type,
                    notes="; ".join(notes_parts),
                ))

    results.sort(key=lambda r: r.confidence, reverse=True)
    return results


async def run_correlation(
    db: AsyncSession,
    *,
    session_id: uuid.UUID,
    repo_name: str,
    hotspots: list[dict[str, Any]],
    min_confidence: float = 0.3,
    persist: bool = True,
) -> list[dict[str, Any]]:
    """High-level: correlate hotspots with findings and optionally persist.

    Parameters
    ----------
    db: AsyncSession
    session_id: session to pull findings from
    repo_name: the repo these hotspots belong to
    hotspots: raw hotspot dicts from mcp-git-code
    min_confidence: threshold for inclusion
    persist: if True, write Correlation rows to DB

    Returns
    -------
    List of correlation dicts for the API response.
    """
    findings = await dal.get_findings(db, session_id)
    matches = correlate_hotspots_to_findings(
        hotspots, findings, min_confidence=min_confidence,
    )

    logger.info(
        "Correlation: %d hotspots × %d findings → %d matches (≥%.1f)",
        len(hotspots), len(findings), len(matches), min_confidence,
    )

    if persist:
        # Clear previous correlations for this session to avoid duplicates
        await dal.delete_correlations_for_session(db, session_id)

        for m in matches:
            await dal.create_correlation(
                db,
                session_id=session_id,
                finding_id=m.finding_id,
                repo_name=repo_name,
                hotspot_file=m.hotspot.file,
                hotspot_line=m.hotspot.line,
                hotspot_category=m.hotspot.category,
                hotspot_snippet=m.hotspot.code_snippet[:2000] if m.hotspot.code_snippet else None,
                confidence=m.confidence,
                correlation_type=m.correlation_type,
                notes=m.notes,
            )
        await db.flush()

    return [
        {
            "finding_id": str(m.finding_id),
            "finding_title": m.finding_title,
            "finding_vuln_type": m.finding_vuln_type,
            "hotspot_file": m.hotspot.file,
            "hotspot_line": m.hotspot.line,
            "hotspot_category": m.hotspot.category,
            "hotspot_snippet": (m.hotspot.code_snippet or "")[:500],
            "confidence": m.confidence,
            "correlation_type": m.correlation_type,
            "notes": m.notes,
        }
        for m in matches
    ]
