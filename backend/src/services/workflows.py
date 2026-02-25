"""Predefined Caido-based scan workflows.

Each workflow is a composable recipe that orchestrates multiple Caido RPC
calls (send_request, create_finding, etc.) to perform a specific security
check.  The agent invokes them via the ``caido_run_predefined_workflow``
tool.

Workflow registry
-----------------
- **sqli_error_detect** — inject SQL metacharacters, detect error-based SQLi
- **xss_reflect_probe** — inject XSS canary, detect reflection
- **auth_bypass_probe** — replay requests without auth / with weak auth
- **open_redirect_check** — test redirect parameters for open redirect
- **header_injection** — test for CRLF/header injection in parameters
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Workflow definition
# ---------------------------------------------------------------------------

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "1; SELECT 1--",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(0)--",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*\Wmysqli?\w*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"\bORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"SQLite\/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite",
    r"SQLITE_ERROR",
    r"sqlite3\.OperationalError",
    r"SQL error|sql_error|syntax error",
    r"Unclosed quotation mark",
    r"Incorrect syntax near",
    r"ODBC SQL Server Driver",
    r"You have an error in your SQL syntax",
]

XSS_CANARIES = [
    "<script>alert('XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'-alert(1)-'",
    "<img src=x onerror=prompt(1)>",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com@legit.com",
    "javascript:alert(1)",
]

HEADER_INJECTION_PAYLOADS = [
    "value%0d%0aX-Injected: true",
    "value\r\nX-Injected: true",
    "value%0aSet-Cookie: evil=1",
]


@dataclass
class WorkflowResult:
    """Result of a predefined workflow execution."""

    workflow_name: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    requests_sent: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_name": self.workflow_name,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "requests_sent": self.requests_sent,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Individual workflow implementations
# ---------------------------------------------------------------------------


async def sqli_error_detect(
    send_fn,
    create_finding_fn,
    *,
    host: str,
    port: int,
    is_tls: bool,
    base_path: str = "/",
    param_name: str = "id",
) -> WorkflowResult:
    """Inject SQL metacharacters and look for error-based SQLi indicators.

    Parameters
    ----------
    send_fn:
        Async callable: send_fn(raw_request, host, port, is_tls) -> dict
    create_finding_fn:
        Async callable: create_finding_fn(request_id, title, description) -> dict
    """
    result = WorkflowResult(workflow_name="sqli_error_detect")

    for payload in SQLI_PAYLOADS:
        raw = (
            f"GET {base_path}?{param_name}={payload} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        try:
            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1

            body = resp.get("request", {}).get("response_body", "")
            raw_resp = resp.get("request", {}).get("raw_response", "")
            check_text = body or raw_resp or ""

            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, check_text, re.IGNORECASE):
                    req_id = resp.get("request", {}).get("id")
                    finding = {
                        "title": f"SQL Injection (Error-based) — {param_name}",
                        "description": (
                            f"Payload `{payload}` on parameter `{param_name}` "
                            f"at `{base_path}` triggered a SQL error pattern: "
                            f"`{pattern}`."
                        ),
                        "severity": "high",
                        "vuln_type": "sqli",
                        "param": param_name,
                        "payload": payload,
                        "pattern_matched": pattern,
                        "request_id": req_id,
                    }
                    result.findings.append(finding)
                    if req_id and create_finding_fn:
                        try:
                            await create_finding_fn(
                                req_id,
                                finding["title"],
                                finding["description"],
                            )
                        except Exception as exc:
                            result.errors.append(f"create_finding: {exc}")
                    break  # one match per payload is enough
        except Exception as exc:
            result.errors.append(f"send_request({payload!r}): {exc}")

    return result


async def xss_reflect_probe(
    send_fn,
    create_finding_fn,
    *,
    host: str,
    port: int,
    is_tls: bool,
    base_path: str = "/",
    param_name: str = "q",
) -> WorkflowResult:
    """Inject XSS canary strings and check for reflection in response body."""
    result = WorkflowResult(workflow_name="xss_reflect_probe")

    for canary in XSS_CANARIES:
        raw = (
            f"GET {base_path}?{param_name}={canary} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Accept: text/html\r\n"
            f"Connection: close\r\n\r\n"
        )
        try:
            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1

            body = resp.get("request", {}).get("response_body", "")
            raw_resp = resp.get("request", {}).get("raw_response", "")
            check_text = body or raw_resp or ""

            if canary in check_text:
                req_id = resp.get("request", {}).get("id")
                finding = {
                    "title": f"Reflected XSS — {param_name}",
                    "description": (
                        f"Canary `{canary}` on parameter `{param_name}` "
                        f"at `{base_path}` was reflected in the response body."
                    ),
                    "severity": "high",
                    "vuln_type": "xss",
                    "param": param_name,
                    "payload": canary,
                    "request_id": req_id,
                }
                result.findings.append(finding)
                if req_id and create_finding_fn:
                    try:
                        await create_finding_fn(
                            req_id, finding["title"], finding["description"],
                        )
                    except Exception as exc:
                        result.errors.append(f"create_finding: {exc}")
        except Exception as exc:
            result.errors.append(f"send_request({canary!r}): {exc}")

    return result


async def auth_bypass_probe(
    send_fn,
    create_finding_fn,
    *,
    host: str,
    port: int,
    is_tls: bool,
    protected_path: str,
    auth_header: str = "",
    expected_status: int = 200,
) -> WorkflowResult:
    """Replay a request to a protected endpoint without authentication.

    Compares response status with and without auth to detect bypass.
    """
    result = WorkflowResult(workflow_name="auth_bypass_probe")

    # 1) Request without auth
    raw_no_auth = (
        f"GET {protected_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        resp = await send_fn(raw_no_auth, host, port, is_tls)
        result.requests_sent += 1
        status_no_auth = resp.get("request", {}).get("status_code", 0)

        if status_no_auth == expected_status:
            req_id = resp.get("request", {}).get("id")
            finding = {
                "title": f"Auth Bypass — {protected_path}",
                "description": (
                    f"Protected endpoint `{protected_path}` returned "
                    f"status {status_no_auth} without authentication."
                ),
                "severity": "critical",
                "vuln_type": "auth_bypass",
                "path": protected_path,
                "request_id": req_id,
            }
            result.findings.append(finding)
            if req_id and create_finding_fn:
                try:
                    await create_finding_fn(
                        req_id, finding["title"], finding["description"],
                    )
                except Exception as exc:
                    result.errors.append(f"create_finding: {exc}")
    except Exception as exc:
        result.errors.append(f"no_auth_request: {exc}")

    # 2) Request with manipulated auth (e.g. empty bearer, admin:admin)
    for bad_auth in ["Bearer invalid", "Basic YWRtaW46YWRtaW4="]:
        raw_bad_auth = (
            f"GET {protected_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Authorization: {bad_auth}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        try:
            resp = await send_fn(raw_bad_auth, host, port, is_tls)
            result.requests_sent += 1
            status_bad = resp.get("request", {}).get("status_code", 0)

            if status_bad == expected_status:
                req_id = resp.get("request", {}).get("id")
                finding = {
                    "title": f"Auth Bypass (weak credential) — {protected_path}",
                    "description": (
                        f"Endpoint `{protected_path}` returned {status_bad} "
                        f"with credential `{bad_auth}`."
                    ),
                    "severity": "critical",
                    "vuln_type": "auth_bypass",
                    "path": protected_path,
                    "auth_used": bad_auth,
                    "request_id": req_id,
                }
                result.findings.append(finding)
                if req_id and create_finding_fn:
                    try:
                        await create_finding_fn(
                            req_id, finding["title"], finding["description"],
                        )
                    except Exception as exc:
                        result.errors.append(f"create_finding: {exc}")
        except Exception as exc:
            result.errors.append(f"bad_auth_request({bad_auth}): {exc}")

    return result


async def open_redirect_check(
    send_fn,
    create_finding_fn,
    *,
    host: str,
    port: int,
    is_tls: bool,
    base_path: str = "/",
    param_name: str = "url",
) -> WorkflowResult:
    """Test redirect parameters for open redirect vulnerabilities."""
    result = WorkflowResult(workflow_name="open_redirect_check")

    for payload in REDIRECT_PAYLOADS:
        raw = (
            f"GET {base_path}?{param_name}={payload} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        try:
            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1

            status = resp.get("request", {}).get("status_code", 0)
            headers_raw = resp.get("request", {}).get("raw_response", "")
            location_match = re.search(
                r"Location:\s*(.+)", headers_raw, re.IGNORECASE
            )
            location = location_match.group(1).strip() if location_match else ""

            if status in (301, 302, 303, 307, 308) and (
                "evil.com" in location or "javascript:" in location.lower()
            ):
                req_id = resp.get("request", {}).get("id")
                finding = {
                    "title": f"Open Redirect — {param_name}",
                    "description": (
                        f"Parameter `{param_name}` at `{base_path}` caused "
                        f"a redirect to `{location}` with payload `{payload}`."
                    ),
                    "severity": "medium",
                    "vuln_type": "open_redirect",
                    "param": param_name,
                    "payload": payload,
                    "location": location,
                    "request_id": req_id,
                }
                result.findings.append(finding)
                if req_id and create_finding_fn:
                    try:
                        await create_finding_fn(
                            req_id, finding["title"], finding["description"],
                        )
                    except Exception as exc:
                        result.errors.append(f"create_finding: {exc}")
        except Exception as exc:
            result.errors.append(f"send_request({payload!r}): {exc}")

    return result


async def header_injection_check(
    send_fn,
    create_finding_fn,
    *,
    host: str,
    port: int,
    is_tls: bool,
    base_path: str = "/",
    param_name: str = "name",
) -> WorkflowResult:
    """Test for CRLF / header injection in parameters."""
    result = WorkflowResult(workflow_name="header_injection")

    for payload in HEADER_INJECTION_PAYLOADS:
        raw = (
            f"GET {base_path}?{param_name}={payload} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        try:
            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1

            raw_resp = resp.get("request", {}).get("raw_response", "")
            if "X-Injected: true" in raw_resp or "Set-Cookie: evil" in raw_resp:
                req_id = resp.get("request", {}).get("id")
                finding = {
                    "title": f"Header Injection (CRLF) — {param_name}",
                    "description": (
                        f"Parameter `{param_name}` at `{base_path}` allows "
                        f"header injection via CRLF. Payload: `{payload}`."
                    ),
                    "severity": "high",
                    "vuln_type": "header_injection",
                    "param": param_name,
                    "payload": payload,
                    "request_id": req_id,
                }
                result.findings.append(finding)
                if req_id and create_finding_fn:
                    try:
                        await create_finding_fn(
                            req_id, finding["title"], finding["description"],
                        )
                    except Exception as exc:
                        result.errors.append(f"create_finding: {exc}")
        except Exception as exc:
            result.errors.append(f"send_request({payload!r}): {exc}")

    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

WORKFLOW_REGISTRY: dict[str, Any] = {
    "sqli_error_detect": sqli_error_detect,
    "xss_reflect_probe": xss_reflect_probe,
    "auth_bypass_probe": auth_bypass_probe,
    "open_redirect_check": open_redirect_check,
    "header_injection": header_injection_check,
}

WORKFLOW_DESCRIPTIONS: dict[str, str] = {
    "sqli_error_detect": (
        "Inject SQL metacharacters into a parameter and detect error-based SQL injection "
        "by matching known DBMS error patterns in responses."
    ),
    "xss_reflect_probe": (
        "Inject XSS canary strings and check if they are reflected unescaped in the response body."
    ),
    "auth_bypass_probe": (
        "Replay requests to a protected endpoint without authentication or with weak credentials "
        "to detect authentication bypass."
    ),
    "open_redirect_check": (
        "Test redirect parameters (url, next, redirect, etc.) for open redirect vulnerabilities."
    ),
    "header_injection": (
        "Test parameters for CRLF/header injection by injecting newline characters."
    ),
}
