"""Tests for the MCP Git/Code analyzer — SINK_PATTERNS and hotspot detection."""

from __future__ import annotations

import re
import sys
import os

# Add mcp-git-code to path so we can import directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-git-code"))

from code_analyzer import SINK_PATTERNS, LANG_MAP, SKIP_DIRS, Hotspot


# ── SINK_PATTERNS structure ────────────────────────────────────

def test_sink_patterns_has_all_categories():
    expected = {"sqli", "xss", "command_injection", "ssrf", "path_traversal", "crypto", "deserialization"}
    assert set(SINK_PATTERNS.keys()) == expected


def test_sink_patterns_are_valid_regex():
    """Every pattern must compile as a valid regex."""
    for cat, patterns in SINK_PATTERNS.items():
        for entry in patterns:
            try:
                re.compile(entry["pattern"])
            except re.error as e:
                raise AssertionError(f"Invalid regex in {cat}: {entry['pattern']} — {e}")


def test_sink_patterns_detect_sqli():
    """SQLi patterns should match common injection sinks."""
    code_samples = [
        'cursor.execute("SELECT * FROM users WHERE id=" + user_input)',
    ]
    sqli_patterns = [re.compile(e["pattern"], re.IGNORECASE) for e in SINK_PATTERNS["sqli"]]
    for sample in code_samples:
        assert any(p.search(sample) for p in sqli_patterns), f"SQLi not detected in: {sample}"


def test_sink_patterns_detect_command_injection():
    code_samples = [
        'os.system("ping " + host)',
        "exec(user_input)",
    ]
    patterns = [re.compile(e["pattern"], re.IGNORECASE) for e in SINK_PATTERNS["command_injection"]]
    for sample in code_samples:
        assert any(p.search(sample) for p in patterns), f"Cmd injection not detected: {sample}"


def test_sink_patterns_detect_xss():
    code_samples = [
        'document.write(user_input)',
        'element.innerHTML = data',
        'v-html="content"',
    ]
    patterns = [re.compile(e["pattern"], re.IGNORECASE) for e in SINK_PATTERNS["xss"]]
    for sample in code_samples:
        assert any(p.search(sample) for p in patterns), f"XSS not detected: {sample}"


# ── LANG_MAP ──────────────────────────────────────────────────

def test_lang_map_common_extensions():
    assert LANG_MAP.get(".py") == "python"
    assert LANG_MAP.get(".js") == "javascript"
    assert LANG_MAP.get(".php") == "php"
    assert LANG_MAP.get(".java") == "java"


# ── SKIP_DIRS ─────────────────────────────────────────────────

def test_skip_dirs_has_common_dirs():
    assert ".git" in SKIP_DIRS
    assert "node_modules" in SKIP_DIRS
    assert "__pycache__" in SKIP_DIRS


# ── Hotspot dataclass ─────────────────────────────────────────

def test_hotspot_creation():
    h = Hotspot(
        file="src/app.py",
        line=42,
        category="sqli",
        pattern_desc="SQL string concat",
        code_snippet='query = "SELECT * FROM " + table',
        severity="critical",
        language="python",
    )
    assert h.file == "src/app.py"
    assert h.severity == "critical"
