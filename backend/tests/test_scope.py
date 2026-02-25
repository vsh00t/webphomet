"""Tests for the MCP CLI-Security scope validator."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "mcp-cli-security"))

from scope import ScopeValidator


# ── Initialization ─────────────────────────────────────────────

def test_scope_validator_defaults():
    sv = ScopeValidator()
    assert sv.allowed_hosts == set()
    assert sv.allowed_ip_ranges == []
    assert sv.blocked_ip_set == set()


def test_scope_validator_with_hosts():
    sv = ScopeValidator(allowed_hosts=["example.com"])
    assert "example.com" in sv.allowed_hosts


# ── Target extraction ─────────────────────────────────────────

def test_looks_like_target():
    sv = ScopeValidator()
    assert sv._looks_like_target("example.com")
    assert sv._looks_like_target("192.168.1.1")
    assert sv._looks_like_target("http://example.com/")
    assert not sv._looks_like_target("-sV")
    assert not sv._looks_like_target("--script")


# ── Scope validation ──────────────────────────────────────────

def test_in_scope_allowed_host():
    sv = ScopeValidator(allowed_hosts=["target.com"])
    assert sv._is_target_in_scope("target.com")
    assert sv._is_target_in_scope("sub.target.com")  # subdomain match


def test_out_of_scope_host():
    sv = ScopeValidator(allowed_hosts=["target.com"])
    assert not sv._is_target_in_scope("evil.com")


def test_blocked_ip():
    sv = ScopeValidator(allowed_hosts=["target.com"], blocked_ips=["10.0.0.0/8"])
    assert not sv._is_target_in_scope("10.0.0.1")


def test_validate_command_nmap():
    sv = ScopeValidator(allowed_hosts=["scanme.nmap.org"])
    assert sv.validate_command("nmap", ["-sV", "scanme.nmap.org"])


def test_validate_command_out_of_scope():
    sv = ScopeValidator(allowed_hosts=["target.com"])
    assert not sv.validate_command("nmap", ["-sV", "evil.com"])


def test_empty_scope_allows_all():
    """When no restrictions, everything passes."""
    sv = ScopeValidator()
    assert sv.validate_command("nmap", ["-sV", "anything.com"])
