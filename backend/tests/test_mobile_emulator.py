"""Tests for the mobile emulator integration module."""

from __future__ import annotations

import pytest

from src.services.mobile_emulator import (
    Platform,
    EmulatorInstance,
    check_prerequisites,
    _has,
)


def test_emulator_instance_creation():
    inst = EmulatorInstance(
        platform=Platform.ANDROID,
        device_name="Pixel_4_API_33",
    )
    assert inst.platform == Platform.ANDROID
    assert inst.device_name == "Pixel_4_API_33"
    assert inst.status == "created"
    assert inst.pid is None
    assert inst.error is None


def test_platform_enum():
    assert Platform.ANDROID.value == "android"
    assert Platform.IOS.value == "ios"


def test_check_prerequisites_returns_dict():
    result = check_prerequisites()
    assert isinstance(result, dict)
    assert "adb" in result
    assert "emulator" in result
    assert "xcrun" in result
    assert "frida" in result
    assert "appium" in result
    assert isinstance(result["adb"], bool)


def test_has_known_command():
    """At least 'python3' or 'python' should be findable."""
    assert _has("python3") or _has("python") or _has("cat")


def test_has_nonexistent_command():
    assert _has("this_command_definitely_does_not_exist_xyz123") is False


@pytest.mark.asyncio
async def test_emulator_status_endpoint(client):
    """GET /api/v1/tools/mobile/emulator-status should return status info."""
    from httpx import AsyncClient
    if not isinstance(client, AsyncClient):
        pytest.skip("Needs async client")
    r = await client.get("/api/v1/tools/mobile/emulator-status")
    assert r.status_code == 200
    data = r.json()
    assert "prerequisites" in data
    assert "android" in data
    assert "ios" in data
