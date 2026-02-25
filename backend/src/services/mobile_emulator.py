"""Mobile emulator integration helpers.

Provides utilities for managing mobile emulator instances and routing
their traffic through the Caido proxy for interception.  Supports both
Android (via ``emulator`` CLI / ADB) and iOS Simulator (via ``xcrun``).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"


@dataclass
class EmulatorInstance:
    """Tracks a running emulator."""

    platform: Platform
    device_name: str
    proxy_host: str = "host.docker.internal"
    proxy_port: int = 8088
    pid: int | None = None
    status: str = "created"  # created | booting | ready | stopped | error
    error: str | None = None


# ---------------------------------------------------------------------------
# Tool availability checks
# ---------------------------------------------------------------------------


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def check_prerequisites() -> dict[str, Any]:
    """Return which mobile-testing tools are available."""
    return {
        "adb": _has("adb"),
        "emulator": _has("emulator"),
        "xcrun": _has("xcrun"),
        "frida": _has("frida"),
        "appium": _has("appium"),
        "mitmproxy_cert_installed": False,  # placeholder
    }


# ---------------------------------------------------------------------------
# Android helpers
# ---------------------------------------------------------------------------


async def list_android_avds() -> list[str]:
    """List available Android Virtual Devices."""
    if not _has("emulator"):
        return []
    proc = await asyncio.create_subprocess_exec(
        "emulator", "-list-avds",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return [line.strip() for line in stdout.decode().splitlines() if line.strip()]


async def start_android_emulator(
    avd_name: str,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8088,
    *,
    no_window: bool = True,
    wipe_data: bool = False,
) -> EmulatorInstance:
    """Launch an Android emulator with HTTP proxy configured."""
    inst = EmulatorInstance(
        platform=Platform.ANDROID,
        device_name=avd_name,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    )

    if not _has("emulator"):
        inst.status = "error"
        inst.error = "Android 'emulator' command not found in PATH"
        return inst

    cmd = [
        "emulator", f"@{avd_name}",
        "-http-proxy", f"http://{proxy_host}:{proxy_port}",
    ]
    if no_window:
        cmd.append("-no-window")
    if wipe_data:
        cmd.append("-wipe-data")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        inst.pid = proc.pid
        inst.status = "booting"
        logger.info("Android emulator '%s' started (PID %s)", avd_name, proc.pid)
    except Exception as e:
        inst.status = "error"
        inst.error = str(e)

    return inst


async def configure_android_proxy(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8088,
) -> dict[str, Any]:
    """Configure proxy on a connected Android device/emulator via ADB."""
    if not _has("adb"):
        return {"success": False, "error": "adb not found"}

    commands = [
        ["adb", "shell", "settings", "put", "global", "http_proxy", f"{proxy_host}:{proxy_port}"],
    ]

    results = []
    for cmd in commands:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        results.append({
            "cmd": " ".join(cmd),
            "returncode": proc.returncode,
            "stdout": stdout.decode().strip(),
            "stderr": stderr.decode().strip(),
        })

    return {"success": all(r["returncode"] == 0 for r in results), "results": results}


async def install_ca_cert_android(cert_path: str) -> dict[str, Any]:
    """Push a CA certificate to an Android device for HTTPS interception."""
    if not _has("adb"):
        return {"success": False, "error": "adb not found"}

    # Push cert and install as system CA
    cmds = [
        ["adb", "push", cert_path, "/sdcard/ca-cert.pem"],
        ["adb", "shell", "su", "-c",
         "cp /sdcard/ca-cert.pem /system/etc/security/cacerts/ && chmod 644 /system/etc/security/cacerts/ca-cert.pem"],
    ]

    results = []
    for cmd in cmds:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            results.append({
                "cmd": " ".join(cmd),
                "returncode": proc.returncode,
                "stdout": stdout.decode().strip(),
                "stderr": stderr.decode().strip(),
            })
        except Exception as e:
            results.append({"cmd": " ".join(cmd), "error": str(e)})

    return {"success": all(r.get("returncode", 1) == 0 for r in results), "results": results}


# ---------------------------------------------------------------------------
# iOS Simulator helpers
# ---------------------------------------------------------------------------


async def list_ios_simulators() -> list[dict[str, str]]:
    """List available iOS simulators."""
    if not _has("xcrun"):
        return []

    proc = await asyncio.create_subprocess_exec(
        "xcrun", "simctl", "list", "devices", "--json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()

    import json
    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError:
        return []

    devices = []
    for runtime, devs in data.get("devices", {}).items():
        for d in devs:
            if d.get("isAvailable"):
                devices.append({
                    "name": d["name"],
                    "udid": d["udid"],
                    "state": d["state"],
                    "runtime": runtime.split(".")[-1] if "." in runtime else runtime,
                })
    return devices


async def boot_ios_simulator(udid: str) -> dict[str, Any]:
    """Boot an iOS simulator by UDID."""
    if not _has("xcrun"):
        return {"success": False, "error": "xcrun not found"}

    proc = await asyncio.create_subprocess_exec(
        "xcrun", "simctl", "boot", udid,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return {
        "success": proc.returncode == 0,
        "stdout": stdout.decode().strip(),
        "stderr": stderr.decode().strip(),
    }


async def configure_ios_proxy(
    udid: str,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8088,
) -> dict[str, Any]:
    """Set HTTP proxy on an iOS simulator (macOS only)."""
    if not _has("xcrun"):
        return {"success": False, "error": "xcrun not found"}

    # Use networksetup-like approach via simctl
    # Note: iOS simulators inherit the host network, so we configure the host proxy
    import platform as _platform
    if _platform.system() != "Darwin":
        return {"success": False, "error": "iOS simulator only available on macOS"}

    # For simulators, the proxy is typically configured at the macOS network level
    # or via a configuration profile
    return {
        "success": True,
        "note": (
            f"iOS Simulator uses host network. Configure macOS proxy to "
            f"{proxy_host}:{proxy_port} or install a .mobileconfig profile."
        ),
    }


# ---------------------------------------------------------------------------
# High-level convenience
# ---------------------------------------------------------------------------


async def get_emulator_status() -> dict[str, Any]:
    """Return an overview of available emulators and prerequisites."""
    prereqs = check_prerequisites()
    android_avds = await list_android_avds() if prereqs["adb"] or prereqs["emulator"] else []
    ios_sims = await list_ios_simulators() if prereqs["xcrun"] else []

    return {
        "prerequisites": prereqs,
        "android": {
            "available_avds": android_avds,
            "count": len(android_avds),
        },
        "ios": {
            "available_simulators": ios_sims,
            "count": len(ios_sims),
        },
    }
