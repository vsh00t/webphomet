"""API router — aggregates all sub-routers."""

from fastapi import APIRouter

from src.api.sessions import router as sessions_router
from src.api.findings import router as findings_router
from src.api.tools import router as tools_router
from src.api.agent import router as agent_router

api_router = APIRouter()

api_router.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
api_router.include_router(findings_router, prefix="/findings", tags=["findings"])
api_router.include_router(tools_router, prefix="/tools", tags=["tools"])
api_router.include_router(agent_router, prefix="/agent", tags=["agent"])
