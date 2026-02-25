"""Tests for security middleware and utilities."""

import pytest
from httpx import ASGITransport, AsyncClient

from src.core.security import (
    _TokenBucket,
    mask_secret,
    sanitize_tool_arg,
)


# ---------------------------------------------------------------------------
# sanitize_tool_arg
# ---------------------------------------------------------------------------


class TestSanitizeToolArg:
    def test_clean_input(self):
        assert sanitize_tool_arg("example.com") == "example.com"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_tool_arg("example.com; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_tool_arg("foo | cat /etc/passwd")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_tool_arg("`whoami`")

    def test_rejects_dollar(self):
        with pytest.raises(ValueError, match="dangerous"):
            sanitize_tool_arg("$(id)")

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError, match="traversal"):
            sanitize_tool_arg("../../etc/passwd")

    def test_allows_path_when_flag_set(self):
        assert sanitize_tool_arg("../../etc/passwd", allow_path=True) == "../../etc/passwd"

    def test_strips_whitespace(self):
        assert sanitize_tool_arg("  hello  ") == "hello"


# ---------------------------------------------------------------------------
# mask_secret
# ---------------------------------------------------------------------------


class TestMaskSecret:
    def test_short(self):
        assert mask_secret("abc") == "****"

    def test_normal(self):
        assert mask_secret("sk-abcdef1234") == "sk-a********"

    def test_visible_chars(self):
        assert mask_secret("abcdefgh", visible=2) == "ab******"


# ---------------------------------------------------------------------------
# TokenBucket
# ---------------------------------------------------------------------------


class TestTokenBucket:
    def test_allows_burst(self):
        bucket = _TokenBucket(rate=1.0, burst=5)
        for _ in range(5):
            assert bucket.allow("ip1") is True

    def test_rejects_after_burst(self):
        bucket = _TokenBucket(rate=0.0, burst=2)
        assert bucket.allow("ip1") is True
        assert bucket.allow("ip1") is True
        assert bucket.allow("ip1") is False

    def test_different_keys_independent(self):
        bucket = _TokenBucket(rate=0.0, burst=1)
        assert bucket.allow("a") is True
        assert bucket.allow("b") is True
        assert bucket.allow("a") is False

    def test_cleanup(self):
        bucket = _TokenBucket(rate=1.0, burst=5)
        bucket.allow("old")
        bucket.cleanup(max_age=0.0)
        assert "old" not in bucket._buckets


# ---------------------------------------------------------------------------
# Security headers via main app
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_security_headers():
    """Health endpoint must return security headers."""
    from src.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.asyncio
async def test_rate_limit_returns_429():
    """Flooding requests should eventually get 429."""
    from src.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        results = [await client.get("/health") for _ in range(200)]
    codes = {r.status_code for r in results}
    # At least some should succeed, and at least one 429 expected
    assert 200 in codes
    assert 429 in codes
