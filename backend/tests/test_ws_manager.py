"""Tests for the WebSocket connection manager."""

from __future__ import annotations

import pytest

from src.core.ws_manager import ConnectionManager


def test_connection_manager_singleton():
    """Module-level manager is a ConnectionManager instance."""
    from src.core.ws_manager import ws_manager
    assert isinstance(ws_manager, ConnectionManager)


def test_connection_manager_empty_sessions():
    """No connections initially."""
    cm = ConnectionManager()
    assert cm._sessions == {}
    assert cm._global == set()
