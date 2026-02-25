"""Headless Chrome browser manager via Playwright.

Provides a high-level async interface for:
- Navigating to URLs
- Capturing screenshots
- Extracting DOM content / JS execution
- Harvesting cookies and localStorage
- Collecting network requests (XHR, fetch)
- Detecting client-side issues (JS errors, DOM XSS sinks)
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

logger = logging.getLogger(__name__)


@dataclass
class NetworkEntry:
    """Captured network request."""

    url: str
    method: str
    status: int | None = None
    resource_type: str = ""
    response_body: str | None = None


@dataclass
class JSError:
    """Captured JS console error."""

    message: str
    url: str = ""
    line: int = 0


@dataclass
class BrowserManager:
    """Managed headless Chromium instance."""

    _playwright: Playwright | None = field(default=None, repr=False)
    _browser: Browser | None = field(default=None, repr=False)
    _context: BrowserContext | None = field(default=None, repr=False)
    _page: Page | None = field(default=None, repr=False)
    _network_log: list[NetworkEntry] = field(default_factory=list)
    _js_errors: list[JSError] = field(default_factory=list)
    _last_response_headers: dict[str, str] = field(default_factory=dict)
    _proxy_url: str | None = None

    async def start(self, proxy_url: str | None = None) -> None:
        """Launch headless Chromium."""
        self._proxy_url = proxy_url
        self._playwright = await async_playwright().start()

        launch_opts: dict[str, Any] = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        }
        if proxy_url:
            launch_opts["proxy"] = {"server": proxy_url}

        self._browser = await self._playwright.chromium.launch(**launch_opts)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36 WebPhomet/1.0"
            ),
        )
        self._page = await self._context.new_page()

        # Wire up event listeners
        self._network_log.clear()
        self._js_errors.clear()
        self._page.on("response", self._on_response)
        self._page.on("console", self._on_console)
        self._page.on("pageerror", self._on_page_error)

        logger.info("Browser started (proxy=%s)", proxy_url or "none")

    async def stop(self) -> None:
        """Shut down the browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None
        logger.info("Browser stopped")

    @property
    def page(self) -> Page:
        if not self._page:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._page

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    async def _on_response(self, response) -> None:
        try:
            entry = NetworkEntry(
                url=response.url,
                method=response.request.method,
                status=response.status,
                resource_type=response.request.resource_type,
            )
            self._network_log.append(entry)
        except Exception:
            pass

    def _on_console(self, msg) -> None:
        if msg.type == "error":
            self._js_errors.append(JSError(message=msg.text))

    def _on_page_error(self, error) -> None:
        self._js_errors.append(JSError(message=str(error)))

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    async def navigate(
        self,
        url: str,
        wait_until: str = "load",
        timeout: int = 30000,
    ) -> dict[str, Any]:
        """Navigate to URL and return page info."""
        self._network_log.clear()
        self._js_errors.clear()

        try:
            response = await self.page.goto(
                url, wait_until=wait_until, timeout=timeout,
            )
        except Exception as exc:
            return {"error": str(exc), "url": url}

        # Capture response headers from main document
        if response:
            try:
                hdrs = await response.all_headers()
                self._last_response_headers = hdrs
            except Exception:
                self._last_response_headers = {}

        return {
            "url": self.page.url,
            "title": await self.page.title(),
            "status": response.status if response else None,
            "network_requests": len(self._network_log),
            "js_errors": len(self._js_errors),
        }

    # ------------------------------------------------------------------
    # Screenshot
    # ------------------------------------------------------------------

    async def screenshot(
        self,
        full_page: bool = False,
        quality: int = 80,
    ) -> dict[str, Any]:
        """Capture a screenshot as base64 PNG/JPEG."""
        data = await self.page.screenshot(
            full_page=full_page,
            type="png",
        )
        b64 = base64.b64encode(data).decode()
        return {
            "format": "png",
            "size_bytes": len(data),
            "base64": b64[:200] + "..." if len(b64) > 200 else b64,
            "base64_full": b64,
        }

    # ------------------------------------------------------------------
    # DOM inspection
    # ------------------------------------------------------------------

    async def get_html(self, selector: str | None = None) -> dict[str, Any]:
        """Get HTML content (full page or specific element)."""
        if selector:
            element = await self.page.query_selector(selector)
            if element is None:
                return {"error": f"Selector '{selector}' not found"}
            html = await element.inner_html()
        else:
            html = await self.page.content()

        return {
            "url": self.page.url,
            "html_length": len(html),
            "html": html[:10000] if len(html) > 10000 else html,
        }

    async def query_selector_all(
        self, selector: str,
    ) -> dict[str, Any]:
        """Query all elements matching a CSS selector."""
        elements = await self.page.query_selector_all(selector)
        results = []
        for el in elements[:100]:  # cap at 100
            text = await el.text_content() or ""
            tag = await el.evaluate("e => e.tagName")
            attrs = await el.evaluate(
                "e => Object.fromEntries([...e.attributes].map(a => [a.name, a.value]))"
            )
            results.append({
                "tag": tag,
                "text": text[:200],
                "attributes": attrs,
            })
        return {"selector": selector, "count": len(results), "elements": results}

    # ------------------------------------------------------------------
    # JavaScript execution
    # ------------------------------------------------------------------

    async def execute_js(self, script: str) -> dict[str, Any]:
        """Execute JavaScript in the page context and return result."""
        try:
            result = await self.page.evaluate(script)
            return {"result": result}
        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------
    # Cookies & Storage
    # ------------------------------------------------------------------

    async def get_cookies(self) -> dict[str, Any]:
        """Get all cookies for the current context."""
        cookies = await self._context.cookies() if self._context else []
        return {
            "cookies": [
                {
                    "name": c["name"],
                    "value": c["value"],
                    "domain": c["domain"],
                    "path": c["path"],
                    "secure": c["secure"],
                    "httpOnly": c["httpOnly"],
                    "sameSite": c.get("sameSite", ""),
                }
                for c in cookies
            ],
            "total": len(cookies),
        }

    async def set_cookies(self, cookies: list[dict[str, Any]]) -> dict[str, Any]:
        """Set cookies in the browser context."""
        if self._context:
            await self._context.add_cookies(cookies)
        return {"set": len(cookies)}

    async def get_storage(self) -> dict[str, Any]:
        """Dump localStorage and sessionStorage."""
        local = await self.page.evaluate(
            "() => Object.fromEntries(Object.entries(localStorage))"
        )
        session = await self.page.evaluate(
            "() => Object.fromEntries(Object.entries(sessionStorage))"
        )
        return {
            "localStorage": local,
            "sessionStorage": session,
            "localStorage_keys": len(local) if isinstance(local, dict) else 0,
            "sessionStorage_keys": len(session) if isinstance(session, dict) else 0,
        }

    # ------------------------------------------------------------------
    # Network log
    # ------------------------------------------------------------------

    async def get_network_log(self) -> dict[str, Any]:
        """Return captured network requests since last navigation."""
        entries = [
            {
                "url": e.url,
                "method": e.method,
                "status": e.status,
                "type": e.resource_type,
            }
            for e in self._network_log
        ]
        return {"entries": entries, "total": len(entries)}

    async def get_js_errors(self) -> dict[str, Any]:
        """Return captured JS errors since last navigation."""
        errors = [{"message": e.message, "url": e.url} for e in self._js_errors]
        return {"errors": errors, "total": len(errors)}

    # ------------------------------------------------------------------
    # Forms discovery
    # ------------------------------------------------------------------

    async def discover_forms(self) -> dict[str, Any]:
        """Discover all forms on the current page."""
        forms = await self.page.evaluate("""() => {
            return Array.from(document.querySelectorAll('form')).map((f, i) => ({
                index: i,
                action: f.action,
                method: f.method || 'GET',
                id: f.id || null,
                name: f.name || null,
                inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(inp => ({
                    tag: inp.tagName.toLowerCase(),
                    type: inp.type || null,
                    name: inp.name || null,
                    id: inp.id || null,
                    value: inp.value || null,
                    placeholder: inp.placeholder || null,
                })),
            }));
        }""")
        return {"forms": forms, "total": len(forms)}

    # ------------------------------------------------------------------
    # Links / anchors
    # ------------------------------------------------------------------

    async def discover_links(self) -> dict[str, Any]:
        """Extract all links from the current page."""
        links = await self.page.evaluate("""() => {
            return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                href: a.href,
                text: a.textContent.trim().substring(0, 100),
                rel: a.rel || null,
                target: a.target || null,
            }));
        }""")
        return {"links": links, "total": len(links)}

    # ------------------------------------------------------------------
    # DOM XSS sink detection
    # ------------------------------------------------------------------

    async def detect_dom_xss_sinks(self) -> dict[str, Any]:
        """Scan page JS for dangerous DOM XSS sinks."""
        results = await self.page.evaluate("""() => {
            const sinks = [
                'document.write', 'document.writeln',
                'innerHTML', 'outerHTML',
                'insertAdjacentHTML',
                'eval(', 'setTimeout(', 'setInterval(',
                'Function(',
                'document.location', 'window.location',
                'location.href', 'location.assign', 'location.replace',
            ];
            const scripts = Array.from(document.querySelectorAll('script'));
            const findings = [];
            for (const s of scripts) {
                const code = s.textContent || '';
                for (const sink of sinks) {
                    if (code.includes(sink)) {
                        findings.push({
                            sink: sink,
                            scriptSrc: s.src || '(inline)',
                            snippet: code.substring(
                                Math.max(0, code.indexOf(sink) - 50),
                                code.indexOf(sink) + sink.length + 50
                            ),
                        });
                    }
                }
            }
            return findings;
        }""")
        return {"sinks": results, "total": len(results)}
