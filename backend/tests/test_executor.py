"""Tests for the executor dispatch mechanism."""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.agent.executor import dispatch, _DISPATCH, register


def test_register_decorator():
    """@register should add a function to the _DISPATCH dict."""
    original_len = len(_DISPATCH)

    @register("__test_tool_xyz__")
    async def _dummy(**kwargs):
        return {"ok": True}

    assert "__test_tool_xyz__" in _DISPATCH
    # Clean up
    del _DISPATCH["__test_tool_xyz__"]


@pytest.mark.asyncio
async def test_dispatch_unknown_tool():
    """Dispatching an unknown tool should return an error JSON."""
    db = AsyncMock()
    result = await dispatch("this_tool_does_not_exist", {}, db)
    data = json.loads(result)
    assert "error" in data
    assert "Unknown tool" in data["error"]


@pytest.mark.asyncio
async def test_dispatch_known_tool():
    """Dispatching a registered tool should call the function."""
    db = AsyncMock()

    @register("__test_dispatch_tool__")
    async def _test_fn(db, **kwargs):
        return {"result": "success", "session_id": kwargs.get("session_id")}

    result = await dispatch("__test_dispatch_tool__", {"session_id": "abc"}, db)
    data = json.loads(result)
    assert data["result"] == "success"
    assert data["session_id"] == "abc"
    del _DISPATCH["__test_dispatch_tool__"]


@pytest.mark.asyncio
async def test_dispatch_handles_exception():
    """Dispatch should catch exceptions and return error JSON."""
    db = AsyncMock()

    @register("__test_error_tool__")
    async def _error_fn(db, **kwargs):
        raise ValueError("test error message")

    result = await dispatch("__test_error_tool__", {}, db)
    data = json.loads(result)
    assert "error" in data
    assert "test error message" in data["error"]
    del _DISPATCH["__test_error_tool__"]


def test_core_tools_registered():
    """Key tools should be in the dispatch registry."""
    expected = [
        "create_pentest_session",
        "get_session_state",
        "run_recon",
        "get_recon_results",
        "mirror_site",
        "scan_secrets",
    ]
    for name in expected:
        assert name in _DISPATCH, f"'{name}' not registered in executor dispatch"
