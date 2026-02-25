"""Tests for config module — settings loading and defaults."""

from __future__ import annotations

from src.config import Settings


def test_default_settings():
    """Settings can be instantiated with defaults (env vars may override)."""
    s = Settings()
    assert s.SAFE_MODE is True
    assert s.MAX_PARALLELISM == 5
    assert s.LOG_LEVEL == "INFO"
    assert isinstance(s.CORS_ORIGINS, list)


def test_settings_fields_present():
    """All expected fields exist on Settings."""
    s = Settings()
    fields = set(s.model_fields.keys())
    expected = {
        "DATABASE_URL", "REDIS_URL", "ZAI_API_KEY", "ZAI_BASE_URL", "ZAI_MODEL",
        "CAIDO_API_URL", "CAIDO_API_KEY", "CAIDO_AUTH_TOKEN", "CAIDO_REFRESH_TOKEN",
        "MCP_CLI_SECURITY_URL", "MCP_CAIDO_URL", "MCP_DEVTOOLS_URL", "MCP_GIT_CODE_URL",
        "SAFE_MODE", "MAX_PARALLELISM", "LOG_LEVEL", "CORS_ORIGINS",
    }
    missing = expected - fields
    assert not missing, f"Missing settings fields: {missing}"
