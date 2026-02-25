"""Discovery & Mapping service.

Provides automated crawling and attack-surface enumeration by combining:
- DevTools headless browser (form discovery, link extraction, DOM analysis)
- Caido proxy (sitemap, intercepted traffic)
- Technology fingerprinting via response headers and page content

The agent orchestrates discovery using these tools to build a comprehensive
map of the target application before launching vulnerability tests.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Technology fingerprinting rules
# ---------------------------------------------------------------------------

TECH_SIGNATURES: list[dict[str, Any]] = [
    # Server headers
    {"type": "header", "header": "server", "pattern": r"nginx", "tech": "nginx"},
    {"type": "header", "header": "server", "pattern": r"apache", "tech": "Apache"},
    {"type": "header", "header": "server", "pattern": r"Express", "tech": "Express.js"},
    {"type": "header", "header": "x-powered-by", "pattern": r"PHP", "tech": "PHP"},
    {"type": "header", "header": "x-powered-by", "pattern": r"Express", "tech": "Express.js"},
    {"type": "header", "header": "x-powered-by", "pattern": r"ASP\.NET", "tech": "ASP.NET"},
    {"type": "header", "header": "x-aspnet-version", "pattern": r".", "tech": "ASP.NET"},
    # HTML meta / body patterns
    {"type": "body", "pattern": r"wp-content|wordpress", "tech": "WordPress"},
    {"type": "body", "pattern": r"Joomla", "tech": "Joomla"},
    {"type": "body", "pattern": r"drupal", "tech": "Drupal"},
    {"type": "body", "pattern": r"react|__NEXT_DATA__|_next/", "tech": "React"},
    {"type": "body", "pattern": r"ng-app|angular", "tech": "Angular"},
    {"type": "body", "pattern": r"vue\.js|__vue__", "tech": "Vue.js"},
    {"type": "body", "pattern": r"jquery", "tech": "jQuery"},
    {"type": "body", "pattern": r"bootstrap", "tech": "Bootstrap"},
    {"type": "body", "pattern": r"swagger|openapi", "tech": "Swagger/OpenAPI"},
    {"type": "body", "pattern": r"graphql|__schema", "tech": "GraphQL"},
    # Cookie patterns
    {"type": "cookie", "pattern": r"PHPSESSID", "tech": "PHP"},
    {"type": "cookie", "pattern": r"JSESSIONID", "tech": "Java"},
    {"type": "cookie", "pattern": r"ASP\.NET_SessionId", "tech": "ASP.NET"},
    {"type": "cookie", "pattern": r"connect\.sid", "tech": "Express.js"},
    {"type": "cookie", "pattern": r"csrftoken", "tech": "Django"},
    {"type": "cookie", "pattern": r"laravel_session", "tech": "Laravel"},
]


@dataclass
class DiscoveredEndpoint:
    """A discovered URL endpoint."""

    url: str
    method: str = "GET"
    source: str = ""  # "link", "form", "sitemap", "crawl"
    params: list[str] = field(default_factory=list)
    auth_required: bool = False
    status_code: int | None = None


@dataclass
class DiscoveryResult:
    """Combined discovery findings."""

    base_url: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    security_headers: dict[str, Any] = field(default_factory=dict)
    dom_xss_sinks: list[dict[str, Any]] = field(default_factory=list)
    js_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "total_endpoints": len(self.endpoints),
            "unique_paths": len(set(urlparse(e.url).path for e in self.endpoints)),
            "endpoints": [
                {
                    "url": e.url,
                    "method": e.method,
                    "source": e.source,
                    "params": e.params,
                    "auth_required": e.auth_required,
                    "status_code": e.status_code,
                }
                for e in self.endpoints[:200]  # cap output
            ],
            "total_forms": len(self.forms),
            "forms": self.forms[:50],
            "technologies": self.technologies,
            "cookies": self.cookies,
            "security_headers": self.security_headers,
            "dom_xss_sinks": self.dom_xss_sinks,
            "js_errors": self.js_errors,
            "errors": self.errors,
        }


def fingerprint_technologies(
    headers: dict[str, str],
    body: str,
    cookies: list[dict[str, Any]],
) -> list[str]:
    """Identify technologies from response headers, body, and cookies."""
    techs: set[str] = set()
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    lower_body = body.lower()[:50000]  # limit scan scope
    cookie_str = " ".join(c.get("name", "") for c in cookies).lower()

    for sig in TECH_SIGNATURES:
        sig_type = sig["type"]
        pattern = sig["pattern"]
        tech = sig["tech"]

        if sig_type == "header":
            val = lower_headers.get(sig["header"], "")
            if val and re.search(pattern, val, re.IGNORECASE):
                techs.add(tech)
        elif sig_type == "body":
            if re.search(pattern, lower_body, re.IGNORECASE):
                techs.add(tech)
        elif sig_type == "cookie":
            if re.search(pattern, cookie_str, re.IGNORECASE):
                techs.add(tech)

    return sorted(techs)


def extract_endpoints_from_links(
    links: list[dict[str, Any]],
    base_url: str,
) -> list[DiscoveredEndpoint]:
    """Convert link discovery results to endpoints."""
    endpoints = []
    parsed_base = urlparse(base_url)
    seen = set()

    for link in links:
        href = link.get("href", "")
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        # Resolve relative URLs
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)

        # Only include same-origin or target-scope URLs
        if parsed.netloc and parsed.netloc != parsed_base.netloc:
            continue

        path_key = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        if path_key in seen:
            continue
        seen.add(path_key)

        # Extract query params
        params = []
        if parsed.query:
            params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]

        endpoints.append(
            DiscoveredEndpoint(
                url=full_url,
                method="GET",
                source="link",
                params=params,
            )
        )

    return endpoints


def extract_endpoints_from_forms(
    forms: list[dict[str, Any]],
    base_url: str,
) -> list[DiscoveredEndpoint]:
    """Convert form discovery results to endpoints."""
    endpoints = []
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        full_url = urljoin(base_url, action) if action else base_url

        params = []
        for inp in form.get("inputs", []):
            name = inp.get("name")
            if name:
                params.append(name)

        endpoints.append(
            DiscoveredEndpoint(
                url=full_url,
                method=method,
                source="form",
                params=params,
            )
        )

    return endpoints


def extract_endpoints_from_sitemap(
    sitemap_edges: list[dict[str, Any]],
    base_url: str,
) -> list[DiscoveredEndpoint]:
    """Convert Caido sitemap entries to endpoints."""
    endpoints = []
    parsed_base = urlparse(base_url)
    seen = set()

    for entry in sitemap_edges:
        node = entry.get("node", {})
        url = node.get("url", "")
        if not url:
            # Build URL from host + path
            host = node.get("host", parsed_base.netloc)
            path = node.get("path", "/")
            scheme = "https" if node.get("isTls") else "http"
            port = node.get("port", 443 if scheme == "https" else 80)
            if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                url = f"{scheme}://{host}{path}"
            else:
                url = f"{scheme}://{host}:{port}{path}"

        if url in seen:
            continue
        seen.add(url)

        endpoints.append(
            DiscoveredEndpoint(
                url=url,
                method=node.get("method", "GET"),
                source="sitemap",
            )
        )

    return endpoints


async def run_discovery(
    devtools_call,
    caido_call,
    base_url: str,
    max_crawl_depth: int = 2,
) -> DiscoveryResult:
    """Execute a full discovery pass against a target.

    Parameters
    ----------
    devtools_call:
        Async callable: (method, params) → dict result
    caido_call:
        Async callable: (method, params) → dict result
    base_url:
        Target URL to discover.
    max_crawl_depth:
        Max depth for link-following crawl (default: 2).

    Returns
    -------
    DiscoveryResult with all discovered endpoints, forms, technologies, etc.
    """
    result = DiscoveryResult(base_url=base_url)

    # ── Step 1: Full page audit on base URL ───────────────────
    try:
        audit = await devtools_call("full_page_audit", {"url": base_url})
        nav = audit.get("navigation", {})
        result.forms = audit.get("forms", {}).get("forms", [])
        result.cookies = audit.get("cookies", {}).get("cookies", [])
        result.security_headers = audit.get("security_headers", {})
        result.dom_xss_sinks = audit.get("dom_xss_sinks", {}).get("sinks", [])
        result.js_errors = [e.get("message", "") for e in audit.get("js_errors", {}).get("errors", [])]

        # Links → endpoints
        links = audit.get("links", {}).get("sample", [])
        result.endpoints.extend(extract_endpoints_from_links(links, base_url))

        # Forms → endpoints
        result.endpoints.extend(extract_endpoints_from_forms(result.forms, base_url))

    except Exception as exc:
        result.errors.append(f"DevTools audit failed: {exc}")

    # ── Step 2: Technology fingerprinting ─────────────────────
    try:
        html_result = await devtools_call("get_html", {})
        body = html_result.get("html", "")
        # Use response headers from the audit navigation
        headers = {}
        if result.security_headers:
            # Reconstruct header dict from present headers
            for h in result.security_headers.get("present", []):
                headers[h["header"]] = h["value"]
        result.technologies = fingerprint_technologies(headers, body, result.cookies)
    except Exception as exc:
        result.errors.append(f"Fingerprinting failed: {exc}")

    # ── Step 3: Caido sitemap ────────────────────────────────
    try:
        sitemap = await caido_call("get_sitemap", {})
        edges = sitemap.get("entries", [])
        result.endpoints.extend(extract_endpoints_from_sitemap(edges, base_url))
    except Exception as exc:
        result.errors.append(f"Caido sitemap failed: {exc}")

    # ── Step 4: BFS crawl — follow discovered links ──────────
    if max_crawl_depth > 1:
        visited = {base_url}
        to_visit = [e.url for e in result.endpoints if e.source == "link"]

        for depth in range(1, max_crawl_depth):
            next_batch = []
            for url in to_visit[:20]:  # cap per depth level
                if url in visited:
                    continue
                visited.add(url)

                try:
                    nav = await devtools_call("navigate", {"url": url})
                    if "error" in nav:
                        continue

                    links_result = await devtools_call("discover_links", {})
                    page_links = links_result.get("links", [])
                    new_endpoints = extract_endpoints_from_links(page_links, url)
                    for ep in new_endpoints:
                        if ep.url not in visited:
                            ep.source = f"crawl-d{depth + 1}"
                            result.endpoints.append(ep)
                            next_batch.append(ep.url)

                    # Also discover forms on deeper pages
                    forms_result = await devtools_call("discover_forms", {})
                    page_forms = forms_result.get("forms", [])
                    if page_forms:
                        result.forms.extend(page_forms)
                        result.endpoints.extend(
                            extract_endpoints_from_forms(page_forms, url)
                        )

                except Exception as exc:
                    result.errors.append(f"Crawl {url}: {exc}")

            to_visit = next_batch

    # ── Step 5: Dedup endpoints ──────────────────────────────
    seen = set()
    deduped = []
    for ep in result.endpoints:
        key = f"{ep.method}:{ep.url}"
        if key not in seen:
            seen.add(key)
            deduped.append(ep)
    result.endpoints = deduped

    logger.info(
        "Discovery complete for %s: %d endpoints, %d forms, %d technologies",
        base_url,
        len(result.endpoints),
        len(result.forms),
        len(result.technologies),
    )
    return result
