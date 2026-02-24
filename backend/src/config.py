"""Application settings loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration — values are read from env vars / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://webphomet:webphomet@postgres:5432/webphomet"
    )

    # ── Redis / Celery ───────────────────────────────────
    REDIS_URL: str = "redis://redis:6379/0"

    # ── Z.ai Agent ───────────────────────────────────────
    ZAI_API_KEY: str = ""
    ZAI_BASE_URL: str = "https://api.z.ai/api/coding/paas/v4"
    ZAI_MODEL: str = "glm-5"

    # ── Caido Integration ────────────────────────────────
    CAIDO_API_URL: str = "http://host.docker.internal:8080"
    CAIDO_API_KEY: str = ""

    # ── MCP Servers ───────────────────────────────────────
    MCP_CLI_SECURITY_URL: str = "http://mcp-cli-security:9100"

    # ── Safety & Performance ─────────────────────────────
    SAFE_MODE: bool = True
    MAX_PARALLELISM: int = 5

    # ── Logging ──────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    # ── CORS ─────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]


settings = Settings()
