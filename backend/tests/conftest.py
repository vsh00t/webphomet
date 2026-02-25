"""Shared test fixtures for WebPhomet."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

# Override DATABASE_URL before any imports that read settings
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from src.main import app
from src.db.database import Base


@pytest.fixture(autouse=True)
async def _setup_test_db():
    """Create all tables before each test, then drop after."""
    from src.db import models as _models  # noqa: F401
    from src.db.database import engine as _orig_engine

    # Use the engine as configured (now sqlite)
    async with _orig_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _orig_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """Yield an async HTTP test client bound to the FastAPI app."""
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
