"""MCP DevTools Server — business logic layer.

Wraps BrowserManager with session awareness and convenience methods
for the agent's security testing needs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from browser import BrowserManager

logger = logging.getLogger(__name__)


@dataclass
class DevToolsServer:
    """High-level MCP DevTools server."""

    browser: BrowserManager = field(default_factory=BrowserManager)
    _started: bool = False

    async def ensure_browser(self, proxy_url: str | None = None) -> None:
        """Start browser if not already running."""
        if not self._started:
            await self.browser.start(proxy_url=proxy_url)
            self._started = True

    async def shutdown(self) -> None:
        """Stop the browser."""
        if self._started:
            await self.browser.stop()
            self._started = False

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def navigate(
        self,
        url: str,
        wait_until: str = "load",
        timeout: int = 30000,
        proxy_url: str | None = None,
    ) -> dict[str, Any]:
        """Navigate to a URL."""
        await self.ensure_browser(proxy_url=proxy_url)
        result = await self.browser.navigate(url, wait_until=wait_until, timeout=timeout)
        return result

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------

    async def screenshot(self, full_page: bool = False) -> dict[str, Any]:
        """Take a screenshot of the current page."""
        await self.ensure_browser()
        return await self.browser.screenshot(full_page=full_page)

    # ------------------------------------------------------------------
    # DOM
    # ------------------------------------------------------------------

    async def get_html(self, selector: str | None = None) -> dict[str, Any]:
        """Get HTML of page or element."""
        await self.ensure_browser()
        return await self.browser.get_html(selector=selector)

    async def query_selector(self, selector: str) -> dict[str, Any]:
        """Query elements matching CSS selector."""
        await self.ensure_browser()
        return await self.browser.query_selector_all(selector)

    # ------------------------------------------------------------------
    # JS execution
    # ------------------------------------------------------------------

    async def execute_js(self, script: str) -> dict[str, Any]:
        """Run JavaScript in page context."""
        await self.ensure_browser()
        return await self.browser.execute_js(script)

    # ------------------------------------------------------------------
    # Cookies & Storage
    # ------------------------------------------------------------------

    async def get_cookies(self) -> dict[str, Any]:
        """Get all cookies."""
        await self.ensure_browser()
        return await self.browser.get_cookies()

    async def set_cookies(self, cookies: list[dict[str, Any]]) -> dict[str, Any]:
        """Set cookies."""
        await self.ensure_browser()
        return await self.browser.set_cookies(cookies)

    async def get_storage(self) -> dict[str, Any]:
        """Get localStorage + sessionStorage."""
        await self.ensure_browser()
        return await self.browser.get_storage()

    # ------------------------------------------------------------------
    # Network & errors
    # ------------------------------------------------------------------

    async def get_network_log(self) -> dict[str, Any]:
        """Get network requests captured during last navigation."""
        await self.ensure_browser()
        return await self.browser.get_network_log()

    async def get_js_errors(self) -> dict[str, Any]:
        """Get JS errors captured during last navigation."""
        await self.ensure_browser()
        return await self.browser.get_js_errors()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover_forms(self) -> dict[str, Any]:
        """Find all forms on the current page."""
        await self.ensure_browser()
        return await self.browser.discover_forms()

    async def discover_links(self) -> dict[str, Any]:
        """Find all links on the current page."""
        await self.ensure_browser()
        return await self.browser.discover_links()

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    async def detect_dom_xss_sinks(self) -> dict[str, Any]:
        """Scan page for DOM XSS sinks."""
        await self.ensure_browser()
        return await self.browser.detect_dom_xss_sinks()

    async def check_security_headers(self) -> dict[str, Any]:
        """Analyze response headers for security misconfigurations."""
        await self.ensure_browser()

        headers = self.browser._last_response_headers
        if not headers:
            return {"error": "No response headers captured. Navigate to a page first."}

        # Normalize header names to lower-case for lookup
        lower_headers = {k.lower(): v for k, v in headers.items()}

        SECURITY_HEADERS = {
            "content-security-policy": "CSP — prevents XSS, data injection",
            "x-frame-options": "Clickjacking protection",
            "strict-transport-security": "HSTS — enforce HTTPS",
            "x-content-type-options": "Prevents MIME sniffing",
            "referrer-policy": "Controls referrer info leakage",
            "permissions-policy": "Controls browser feature access",
            "x-xss-protection": "Legacy XSS filter (informational)",
        }

        present = []
        missing = []
        for header, desc in SECURITY_HEADERS.items():
            val = lower_headers.get(header)
            if val:
                present.append({"header": header, "value": val, "description": desc})
            else:
                missing.append({"header": header, "description": desc})

        # Cookie flags check
        cookie_issues = []
        set_cookie = lower_headers.get("set-cookie", "")
        if set_cookie:
            if "secure" not in set_cookie.lower():
                cookie_issues.append("Missing Secure flag on Set-Cookie")
            if "httponly" not in set_cookie.lower():
                cookie_issues.append("Missing HttpOnly flag on Set-Cookie")
            if "samesite" not in set_cookie.lower():
                cookie_issues.append("Missing SameSite attribute on Set-Cookie")

        return {
            "present": present,
            "missing": missing,
            "cookie_issues": cookie_issues,
            "total_present": len(present),
            "total_missing": len(missing),
            "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
        }

    async def full_page_audit(self, url: str) -> dict[str, Any]:
        """Combined security audit: navigate, discover, detect."""
        await self.ensure_browser()
        nav = await self.browser.navigate(url)
        if "error" in nav:
            return {"error": nav["error"]}

        forms = await self.browser.discover_forms()
        links = await self.browser.discover_links()
        cookies = await self.browser.get_cookies()
        storage = await self.browser.get_storage()
        sinks = await self.browser.detect_dom_xss_sinks()
        js_errors = await self.browser.get_js_errors()
        network = await self.browser.get_network_log()
        sec_headers = await self.check_security_headers()

        return {
            "navigation": nav,
            "forms": {"total": forms["total"], "forms": forms["forms"][:20]},
            "links": {"total": links["total"], "sample": links["links"][:30]},
            "cookies": cookies,
            "storage": storage,
            "dom_xss_sinks": sinks,
            "js_errors": js_errors,
            "security_headers": sec_headers,
            "network_summary": {
                "total_requests": network["total"],
                "by_type": {},
            },
        }
