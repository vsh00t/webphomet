"""Tests for the correlation engine — matching hotspots to findings."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from src.core.correlator import (
    CorrelationResult,
    HotspotRecord,
    _category_matches_vuln,
    _keyword_overlap,
    _path_heuristic,
    correlate_hotspots_to_findings,
)


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


class TestCategoryMatchesVuln:
    def test_exact_sqli(self):
        assert _category_matches_vuln("sqli", "sql_injection") > 0

    def test_xss_reflected(self):
        assert _category_matches_vuln("xss", "reflected xss in search") > 0

    def test_no_match(self):
        assert _category_matches_vuln("sqli", "xss") == 0.0

    def test_command_injection(self):
        assert _category_matches_vuln("command_injection", "remote code execution") > 0

    def test_ssrf(self):
        assert _category_matches_vuln("ssrf", "server-side request forgery found") > 0

    def test_path_traversal(self):
        assert _category_matches_vuln("path_traversal", "local file inclusion via path traversal") > 0

    def test_crypto(self):
        assert _category_matches_vuln("crypto", "weak crypto: MD5 used for password hashing") > 0

    def test_deserialization(self):
        assert _category_matches_vuln("deserialization", "insecure deserialization of user data") > 0

    def test_unknown_category(self):
        assert _category_matches_vuln("unknown_cat", "sql_injection") == 0.0


class TestKeywordOverlap:
    def test_some_overlap(self):
        snippet = "cursor.execute(query_str)"
        evidence = "The query_str parameter is used in cursor.execute without sanitization"
        score = _keyword_overlap(snippet, evidence)
        assert score > 0

    def test_no_overlap(self):
        score = _keyword_overlap("print('hello')", "XSS in <script>alert</script>")
        assert score == 0.0

    def test_empty_inputs(self):
        assert _keyword_overlap("", "some text") == 0.0
        assert _keyword_overlap("some code", "") == 0.0
        assert _keyword_overlap("", "") == 0.0


class TestPathHeuristic:
    def test_file_in_evidence(self):
        score = _path_heuristic("src/views/login.php", "Vulnerable parameter in login.php line 45")
        assert score > 0

    def test_file_not_in_evidence(self):
        score = _path_heuristic("src/views/login.php", "XSS found in search page")
        assert score == 0.0

    def test_no_evidence(self):
        assert _path_heuristic("src/views/login.php", None) == 0.0


# ---------------------------------------------------------------------------
# Integration test for correlate_hotspots_to_findings
# ---------------------------------------------------------------------------


def _make_finding(
    vuln_type: str = "sql_injection",
    title: str = "SQL Injection",
    severity: str = "high",
    evidence: str | None = None,
    description: str | None = None,
) -> MagicMock:
    """Create a mock Finding ORM object."""
    f = MagicMock()
    f.id = uuid.uuid4()
    f.vuln_type = vuln_type
    f.title = title
    f.severity = MagicMock(value=severity)
    f.evidence = evidence
    f.description = description
    return f


class TestCorrelateHotspotsToFindings:
    def test_category_match(self):
        hotspots = [{
            "file": "src/db.py",
            "line": 42,
            "category": "sqli",
            "pattern_desc": "SQL string concatenation",
            "code_snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
            "severity": "high",
        }]
        findings = [_make_finding(vuln_type="sql_injection", title="SQL Injection in login")]
        results = correlate_hotspots_to_findings(hotspots, findings, min_confidence=0.3)
        assert len(results) >= 1
        assert results[0].correlation_type.startswith("category")
        assert results[0].confidence >= 0.3

    def test_no_match(self):
        hotspots = [{
            "file": "src/auth.py",
            "line": 10,
            "category": "crypto",
            "pattern_desc": "Weak hash",
            "code_snippet": "hashlib.md5(password)",
            "severity": "medium",
        }]
        findings = [_make_finding(vuln_type="xss", title="XSS in search")]
        results = correlate_hotspots_to_findings(hotspots, findings, min_confidence=0.3)
        assert len(results) == 0

    def test_multiple_matches(self):
        hotspots = [
            {
                "file": "src/search.php",
                "line": 15,
                "category": "xss",
                "pattern_desc": "echo unsanitized",
                "code_snippet": "echo $_GET['q']",
                "severity": "high",
            },
            {
                "file": "src/db.php",
                "line": 30,
                "category": "sqli",
                "pattern_desc": "string concat SQL",
                "code_snippet": "$sql = 'SELECT * FROM users WHERE id=' . $_GET['id']",
                "severity": "critical",
            },
        ]
        findings = [
            _make_finding(vuln_type="xss", title="Reflected XSS"),
            _make_finding(vuln_type="sql_injection", title="SQL Injection"),
        ]
        results = correlate_hotspots_to_findings(hotspots, findings, min_confidence=0.3)
        assert len(results) >= 2

    def test_path_boost(self):
        """File path mentioned in evidence should increase confidence."""
        hotspots = [{
            "file": "src/views/login.php",
            "line": 42,
            "category": "sqli",
            "pattern_desc": "SQL concat",
            "code_snippet": "mysql_query('SELECT * FROM users WHERE id=' . $id)",
            "severity": "high",
        }]
        findings = [_make_finding(
            vuln_type="sql_injection",
            title="SQL Injection",
            evidence="Found in login.php at parameter user_id",
        )]
        results = correlate_hotspots_to_findings(hotspots, findings, min_confidence=0.3)
        assert len(results) == 1
        # Should be higher confidence due to path heuristic
        assert results[0].confidence >= 0.55

    def test_empty_inputs(self):
        assert correlate_hotspots_to_findings([], []) == []
        findings = [_make_finding()]
        assert correlate_hotspots_to_findings([], findings) == []

    def test_min_confidence_filter(self):
        hotspots = [{
            "file": "f.py", "line": 1, "category": "crypto",
            "pattern_desc": "md5", "code_snippet": "import hashlib",
            "severity": "low",
        }]
        findings = [_make_finding(vuln_type="weak_crypto", title="Weak Crypto")]
        # Very high threshold
        results = correlate_hotspots_to_findings(hotspots, findings, min_confidence=0.999)
        assert len(results) == 0
