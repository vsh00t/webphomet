"""WebPhomet FastAPI application entry point."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.router import api_router
from src.config import settings
from src.core.logging import setup_logging
from src.db.database import engine

# ---------------------------------------------------------------------------
# Lifespan – startup / shutdown hooks
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Run startup and shutdown logic for the application."""
    setup_logging()

    # Import models so SQLAlchemy metadata is populated
    from src.db import models as _models  # noqa: F401
    from src.db.database import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Shutdown: dispose the engine connection pool
    await engine.dispose()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="WebPhomet",
    summary="Autonomous Pentesting Orchestration Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# -- CORS (restrictive by default; open up as needed) ----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- Routers ---------------------------------------------------------------
app.include_router(api_router, prefix="/api/v1")


# -- Health endpoint -------------------------------------------------------

@app.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    """Liveness / readiness probe."""
    return {"status": "ok"}
