"""Security hardening middleware and utilities.

Provides:
- API key authentication (optional, via ``X-API-Key`` header)
- Rate limiting (token bucket per IP)
- Request size limiting
- Security response headers
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# API Key Authentication
# ---------------------------------------------------------------------------


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Validate ``X-API-Key`` header when API_KEY is configured.

    Skips authentication for:
    - Health endpoint (``/health``)
    - OpenAPI docs (``/docs``, ``/openapi.json``)
    - WebSocket upgrades
    """

    SKIP_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}

    async def dispatch(self, request: Request, call_next):
        api_key = getattr(settings, "API_KEY", "")
        if not api_key:
            # No API key configured → skip auth
            return await call_next(request)

        path = request.url.path
        if path in self.SKIP_PATHS or path.startswith("/api/v1/ws"):
            return await call_next(request)

        provided = request.headers.get("X-API-Key", "")
        if not provided or not hmac.compare_digest(provided, api_key):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Rate Limiting (in-memory token bucket)
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Simple token bucket rate limiter per client IP."""

    def __init__(self, rate: float = 10.0, burst: int = 50):
        self.rate = rate      # tokens per second
        self.burst = burst    # max tokens
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.burst), now))
        elapsed = now - last
        tokens = min(self.burst, tokens + elapsed * self.rate)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False

    def cleanup(self, max_age: float = 300.0):
        """Remove stale entries older than max_age seconds."""
        now = time.monotonic()
        stale = [k for k, (_, t) in self._buckets.items() if now - t > max_age]
        for k in stale:
            del self._buckets[k]


_limiter = _TokenBucket(rate=20.0, burst=100)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limit requests by client IP using an in-memory token bucket."""

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        if not _limiter.allow(client_ip):
            logger.warning("Rate limit exceeded for %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again shortly."},
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related response headers."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        return response


# ---------------------------------------------------------------------------
# Request Size Limiting
# ---------------------------------------------------------------------------


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with bodies larger than the configured limit."""

    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body too large. Max: {self.MAX_SIZE} bytes"},
            )
        return await call_next(request)


# ---------------------------------------------------------------------------
# Registration helper
# ---------------------------------------------------------------------------


def install_security_middleware(app: FastAPI) -> None:
    """Install all security middleware on the FastAPI app.

    Call this during application startup (after CORS middleware).
    """
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)

    api_key = getattr(settings, "API_KEY", "")
    if api_key:
        app.add_middleware(APIKeyMiddleware)
        logger.info("API key authentication enabled")
    else:
        logger.info("API key authentication disabled (API_KEY not set)")


# ---------------------------------------------------------------------------
# Input Sanitisation helpers (use in endpoint validators)
# ---------------------------------------------------------------------------

import re as _re

# Patterns commonly used in OS command injection
_DANGEROUS_SHELL_CHARS = _re.compile(r"[;&|`$(){}!<>]")
# Path-traversal sequences
_PATH_TRAVERSAL = _re.compile(r"\.\.[/\\]")


def sanitize_tool_arg(value: str, *, allow_path: bool = False) -> str:
    """Strip or reject dangerous characters from user-supplied tool arguments.

    Raises ``ValueError`` if suspicious content is found.
    """
    if _DANGEROUS_SHELL_CHARS.search(value):
        raise ValueError(f"Potentially dangerous characters in argument: {value!r}")
    if not allow_path and _PATH_TRAVERSAL.search(value):
        raise ValueError(f"Path traversal detected in argument: {value!r}")
    return value.strip()


def mask_secret(value: str, visible: int = 4) -> str:
    """Return a masked representation of a secret string for safe logging."""
    if len(value) <= visible:
        return "****"
    return value[:visible] + "*" * (len(value) - visible)
