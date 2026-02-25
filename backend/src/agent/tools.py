"""Tool definitions for Z.ai function/tool calling.

Each tool is described following the OpenAI-compatible tool schema so the
LLM agent can decide which tool to invoke at each step of the pentesting
workflow.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _tool(
    name: str,
    description: str,
    parameters: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    """Build an OpenAI-compatible tool definition."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": parameters,
                "required": required or [],
            },
        },
    }


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

create_pentest_session = _tool(
    name="create_pentest_session",
    description=(
        "Create a new pentest session for a given target URL. "
        "Returns the session ID and initial configuration."
    ),
    parameters={
        "target_base_url": {
            "type": "string",
            "description": "Base URL of the target application",
        },
        "app_type": {
            "type": "string",
            "description": "Type of application (web, api, mobile_backend)",
        },
        "scope": {
            "type": "object",
            "description": "Scope configuration with allowed_hosts, allowed_ips, exclusions",
        },
    },
    required=["target_base_url"],
)

get_session_state = _tool(
    name="get_session_state",
    description="Retrieve the current state of a pentest session including targets, findings, and tool runs.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Reconnaissance
# ---------------------------------------------------------------------------

run_recon = _tool(
    name="run_recon",
    description=(
        "Run a reconnaissance tool (nmap, subfinder, httpx, whatweb) against "
        "the target. The tool runs asynchronously and results can be retrieved "
        "later with get_recon_results."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "tool_name": {
            "type": "string",
            "enum": ["nmap", "subfinder", "httpx", "whatweb"],
            "description": "Name of the recon tool to run",
        },
        "args": {
            "type": "string",
            "description": "CLI arguments for the tool",
        },
    },
    required=["session_id", "tool_name", "args"],
)

get_recon_results = _tool(
    name="get_recon_results",
    description="Retrieve the results of a previously started reconnaissance tool run.",
    parameters={
        "tool_run_id": {
            "type": "string",
            "description": "UUID of the tool run to retrieve results for",
        },
    },
    required=["tool_run_id"],
)


# ---------------------------------------------------------------------------
# Static Analysis — Site Mirror + Secret Scanner
# ---------------------------------------------------------------------------

mirror_site = _tool(
    name="mirror_site",
    description=(
        "Download/mirror all reachable content from a target URL for offline "
        "static analysis. Uses wget recursive download + smart URL extraction "
        "from JS/HTML/CSS to find lazy-loaded chunks, API endpoints, source maps, "
        "and other assets. Returns a summary with file counts, sizes, and types."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "url": {
            "type": "string",
            "description": "Target URL to mirror (e.g. https://example.com/app)",
        },
        "depth": {
            "type": "integer",
            "description": "Maximum recursion depth for wget (default: 8)",
        },
        "global_timeout": {
            "type": "integer",
            "description": "Global timeout in seconds for the mirror operation (default: 300)",
        },
    },
    required=["session_id", "url"],
)

scan_secrets = _tool(
    name="scan_secrets",
    description=(
        "Scan a previously mirrored site directory for hardcoded secrets, "
        "API keys, tokens, passwords, database connection strings, private keys, "
        "internal IPs, debug endpoints, and other sensitive data. "
        "Must run mirror_site first. Creates findings in the database for each "
        "secret discovered."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session (uses the mirror output from that session)",
        },
        "max_findings": {
            "type": "integer",
            "description": "Maximum number of findings to return (default: 500)",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Caido proxy integration
# ---------------------------------------------------------------------------

caido_get_requests = _tool(
    name="caido_get_requests",
    description=(
        "Fetch intercepted HTTP requests from Caido proxy. "
        "Returns recent proxy traffic including method, path, host, status code, "
        "and response time. Use host filter to focus on a specific target."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "limit": {
            "type": "integer",
            "description": "Max requests to return (default: 50)",
        },
        "offset": {
            "type": "integer",
            "description": "Pagination offset (default: 0)",
        },
        "host": {
            "type": "string",
            "description": "Filter by target host (e.g. 'dvwa.local')",
        },
    },
    required=["session_id"],
)

caido_get_findings = _tool(
    name="caido_get_findings",
    description=(
        "Fetch findings/issues discovered by Caido. "
        "These are vulnerabilities Caido has identified through its own scanning. "
        "Results include title, description, host, path, and reporter."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "limit": {
            "type": "integer",
            "description": "Max findings to return (default: 50)",
        },
    },
    required=["session_id"],
)

caido_create_finding = _tool(
    name="caido_create_finding",
    description=(
        "Push a finding from WebPhomet into Caido for tracking and deduplication. "
        "Useful for synchronizing automated findings back to the proxy tool."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "title": {
            "type": "string",
            "description": "Finding title",
        },
        "description": {
            "type": "string",
            "description": "Finding description with details",
        },
        "request_id": {
            "type": "string",
            "description": "Caido request ID to associate with the finding",
        },
    },
    required=["session_id", "title"],
)

caido_get_sitemap = _tool(
    name="caido_get_sitemap",
    description=(
        "Get the Caido sitemap showing all discovered URLs/endpoints from proxy traffic. "
        "Returns a tree structure of hosts and paths observed through the proxy."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

caido_list_workflows = _tool(
    name="caido_list_workflows",
    description=(
        "List available Caido workflows (active, passive, convert). "
        "Workflows automate request analysis and transformation in Caido."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

caido_run_workflow = _tool(
    name="caido_run_workflow",
    description=(
        "Run a Caido workflow on a specific intercepted request. "
        "Use list_workflows first to find available workflow IDs."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "workflow_id": {
            "type": "string",
            "description": "Caido workflow ID to run",
        },
        "request_id": {
            "type": "string",
            "description": "Caido request ID to run the workflow on",
        },
    },
    required=["session_id", "workflow_id", "request_id"],
)

caido_send_request = _tool(
    name="caido_send_request",
    description=(
        "Send a crafted HTTP request through Caido's replay facility. "
        "Useful for testing payloads, verifying vulnerabilities with PoC, "
        "and fuzzing specific parameters."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "raw_request": {
            "type": "string",
            "description": "Raw HTTP request string (e.g. 'GET /path HTTP/1.1\\nHost: target')",
        },
        "host": {
            "type": "string",
            "description": "Target host to send to",
        },
        "port": {
            "type": "integer",
            "description": "Target port (default: 443)",
        },
        "is_tls": {
            "type": "boolean",
            "description": "Whether to use TLS (default: true)",
        },
    },
    required=["session_id", "raw_request", "host"],
)

caido_sync_findings = _tool(
    name="caido_sync_findings",
    description=(
        "Bidirectional sync of findings between Caido and the WebPhomet database. "
        "Direction 'pull' imports Caido findings into the DB (deduplicates by caido_finding_id). "
        "Direction 'push' sends DB findings that have a caido_request_id to Caido. "
        "Direction 'both' does pull then push. Use after scanning to consolidate findings."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "direction": {
            "type": "string",
            "enum": ["pull", "push", "both"],
            "description": "Sync direction: pull (Caido→DB), push (DB→Caido), both (default)",
        },
    },
    required=["session_id"],
)

caido_run_predefined_workflow = _tool(
    name="caido_run_predefined_workflow",
    description=(
        "Run a predefined security scan workflow through Caido. Available workflows: "
        "sqli_error_detect (SQL injection via error patterns), "
        "xss_reflect_probe (reflected XSS detection), "
        "auth_bypass_probe (test protected endpoints without auth), "
        "open_redirect_check (test redirect parameters), "
        "header_injection (CRLF/header injection test). "
        "Each workflow sends crafted requests and auto-creates findings in Caido."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "workflow_name": {
            "type": "string",
            "enum": [
                "sqli_error_detect",
                "xss_reflect_probe",
                "auth_bypass_probe",
                "open_redirect_check",
                "header_injection",
            ],
            "description": "Name of the predefined workflow to run",
        },
        "host": {
            "type": "string",
            "description": "Target host (e.g. 'localhost')",
        },
        "port": {
            "type": "integer",
            "description": "Target port (e.g. 4280 for DVWA)",
        },
        "is_tls": {
            "type": "boolean",
            "description": "Whether to use TLS (default: false for local targets)",
        },
        "base_path": {
            "type": "string",
            "description": "URL path to test (e.g. '/vulnerabilities/sqli/')",
        },
        "param_name": {
            "type": "string",
            "description": "Parameter name to inject into (e.g. 'id', 'q')",
        },
        "protected_path": {
            "type": "string",
            "description": "For auth_bypass_probe: the protected endpoint path",
        },
    },
    required=["session_id", "workflow_name", "host", "port"],
)


# ---------------------------------------------------------------------------
# DevTools (headless Chrome) integration
# ---------------------------------------------------------------------------

devtools_navigate = _tool(
    name="devtools_navigate",
    description=(
        "Navigate the headless browser to a URL and capture the page. "
        "Returns status code, final URL, page title, number of network requests, "
        "and any console/JS errors encountered during load."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "url": {
            "type": "string",
            "description": "URL to navigate to",
        },
        "wait_until": {
            "type": "string",
            "enum": ["load", "domcontentloaded", "networkidle", "commit"],
            "description": "When to consider navigation finished (default: load)",
        },
    },
    required=["session_id", "url"],
)

devtools_screenshot = _tool(
    name="devtools_screenshot",
    description=(
        "Take a screenshot of the current browser page. "
        "Returns a base64-encoded PNG image suitable for visual analysis "
        "and evidence collection."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "full_page": {
            "type": "boolean",
            "description": "Capture full scrollable page vs. viewport only (default: false)",
        },
    },
    required=["session_id"],
)

devtools_discover_forms = _tool(
    name="devtools_discover_forms",
    description=(
        "Discover all HTML forms on the current page. Returns form action URLs, "
        "methods, and all input fields with their types and names. "
        "Essential for identifying attack surfaces and injectable parameters."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_discover_links = _tool(
    name="devtools_discover_links",
    description=(
        "Discover all links (anchors, nav elements) on the current page. "
        "Returns href, text content, and whether each link is internal or external."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_detect_dom_xss = _tool(
    name="devtools_detect_dom_xss",
    description=(
        "Scan the current page's JavaScript for DOM XSS sinks — dangerous patterns "
        "like innerHTML, document.write, eval, location assignment, etc. "
        "Returns a list of sinks found with the JS source context."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_execute_js = _tool(
    name="devtools_execute_js",
    description=(
        "Execute arbitrary JavaScript in the browser context and return the result. "
        "Useful for extracting dynamic data, testing DOM manipulation, "
        "or probing client-side security controls."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "script": {
            "type": "string",
            "description": "JavaScript code to execute",
        },
    },
    required=["session_id", "script"],
)

devtools_get_cookies = _tool(
    name="devtools_get_cookies",
    description=(
        "Get all cookies for the current page context. "
        "Returns name, value, domain, path, secure, httpOnly, sameSite attributes. "
        "Useful for cookie security analysis."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_get_storage = _tool(
    name="devtools_get_storage",
    description=(
        "Get localStorage and sessionStorage contents for the current page. "
        "Useful for finding tokens, session data, and sensitive info in client storage."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_check_security_headers = _tool(
    name="devtools_check_security_headers",
    description=(
        "Check the response headers of the last navigation for security headers. "
        "Evaluates: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, "
        "Referrer-Policy, Permissions-Policy. Reports missing or weak headers."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

devtools_full_page_audit = _tool(
    name="devtools_full_page_audit",
    description=(
        "Combined security audit: navigates to URL, discovers forms and links, "
        "extracts cookies and storage, detects DOM XSS sinks, captures JS errors, "
        "checks security headers, and logs network activity — all in one call. "
        "Returns a comprehensive page security profile."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "url": {
            "type": "string",
            "description": "URL to audit",
        },
    },
    required=["session_id", "url"],
)


# ---------------------------------------------------------------------------
# Discovery & Mapping
# ---------------------------------------------------------------------------

run_discovery = _tool(
    name="run_discovery",
    description=(
        "Run automated discovery & mapping against a target URL. "
        "Combines DevTools crawling (form/link discovery, DOM XSS sinks, "
        "security headers) with Caido sitemap data and technology fingerprinting. "
        "BFS-crawls discovered links up to max_crawl_depth. "
        "Returns complete attack surface: endpoints, forms, technologies, "
        "cookies, security header analysis, and potential DOM XSS sinks."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "url": {
            "type": "string",
            "description": "Target base URL to discover (e.g. http://localhost:4280/)",
        },
        "max_crawl_depth": {
            "type": "integer",
            "description": "Maximum BFS crawl depth for link following (default: 2)",
        },
    },
    required=["session_id", "url"],
)


# ---------------------------------------------------------------------------
# OWASP Injection & XSS Testing
# ---------------------------------------------------------------------------

run_injection_tests = _tool(
    name="run_injection_tests",
    description=(
        "Run automated OWASP injection & XSS test suite against discovered parameters. "
        "Tests include: sqli (error-based + blind time-based), xss_reflected, xss_dom "
        "(via headless Chrome), command_injection, ssti (Server-Side Template Injection). "
        "Provide a list of targets (path + param pairs) discovered by run_discovery. "
        "Use cookie parameter for authenticated testing against protected pages."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "host": {
            "type": "string",
            "description": "Target host (e.g. 'localhost')",
        },
        "port": {
            "type": "integer",
            "description": "Target port (e.g. 4280 for DVWA)",
        },
        "is_tls": {
            "type": "boolean",
            "description": "Whether to use TLS (default: false)",
        },
        "targets": {
            "type": "array",
            "description": "List of injection targets: [{path, param, method, extra_params}]",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "URL path to test"},
                    "param": {"type": "string", "description": "Parameter name to inject into"},
                    "method": {"type": "string", "description": "HTTP method (GET or POST)"},
                },
            },
        },
        "test_types": {
            "type": "array",
            "description": "Tests to run: sqli, xss_reflected, xss_dom, command_injection, ssti",
            "items": {"type": "string"},
        },
        "cookie": {
            "type": "string",
            "description": "Session cookie string for authenticated testing",
        },
    },
    required=["session_id", "host", "port"],
)


run_auth_tests = _tool(
    name="run_auth_tests",
    description=(
        "Run broken-authentication test suite. Tests include: default_credentials "
        "(tries common user:pass combos), session_fixation, cookie_flags "
        "(Secure/HttpOnly/SameSite), jwt_none_alg (JWT none-algorithm bypass), "
        "idor (Insecure Direct Object Reference)."
    ),
    parameters={
        "session_id": {"type": "string", "description": "Pentest session UUID"},
        "host": {"type": "string", "description": "Target host"},
        "port": {"type": "integer", "description": "Target port"},
        "is_tls": {"type": "boolean", "description": "Use TLS (default false)"},
        "test_types": {
            "type": "array",
            "description": "Tests: default_credentials, session_fixation, cookie_flags, jwt_none_alg, idor",
            "items": {"type": "string"},
        },
        "login_path": {"type": "string", "description": "Login page path (default /login)"},
        "cookie": {"type": "string", "description": "Session cookie for auth testing"},
        "auth_header": {"type": "string", "description": "Authorization header value (for JWT tests)"},
        "idor_path_pattern": {"type": "string", "description": "Path with {id} placeholder for IDOR tests"},
        "username_field": {"type": "string", "description": "Login form username field name"},
        "password_field": {"type": "string", "description": "Login form password field name"},
    },
    required=["session_id", "host", "port"],
)


run_ssrf_tests = _tool(
    name="run_ssrf_tests",
    description=(
        "Run SSRF (Server-Side Request Forgery) test suite against URL/path parameters. "
        "Tests include: ssrf_internal (localhost/private IPs), ssrf_cloud_metadata "
        "(AWS/GCP/Azure metadata endpoints), ssrf_protocol (file://, gopher://)."
    ),
    parameters={
        "session_id": {"type": "string", "description": "Pentest session UUID"},
        "host": {"type": "string", "description": "Target host"},
        "port": {"type": "integer", "description": "Target port"},
        "is_tls": {"type": "boolean", "description": "Use TLS (default false)"},
        "targets": {
            "type": "array",
            "description": "Targets: [{path, param, method, extra_params}]",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "param": {"type": "string", "description": "URL/redirect parameter to inject into"},
                    "method": {"type": "string"},
                },
            },
        },
        "test_types": {
            "type": "array",
            "description": "Tests: ssrf_internal, ssrf_cloud_metadata, ssrf_protocol",
            "items": {"type": "string"},
        },
        "cookie": {"type": "string", "description": "Session cookie"},
    },
    required=["session_id", "host", "port"],
)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

parse_nmap_output = _tool(
    name="parse_nmap_output",
    description="Parse raw nmap XML/text output into structured port and service data.",
    parameters={
        "artifact_id": {
            "type": "string",
            "description": "UUID of the artifact containing nmap output",
        },
    },
    required=["artifact_id"],
)

summarize_findings = _tool(
    name="summarize_findings",
    description="Generate a summary of all findings for a session, grouped by severity.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)

correlate_findings = _tool(
    name="correlate_findings",
    description=(
        "Analyse findings to identify correlated vulnerabilities, "
        "attack chains, and overall risk patterns."
    ),
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

build_report = _tool(
    name="build_report",
    description="Generate a Markdown pentest report from session data.",
    parameters={
        "session_id": {
            "type": "string",
            "description": "UUID of the pentest session",
        },
        "format": {
            "type": "string",
            "enum": ["markdown", "pdf"],
            "description": "Output format for the report",
        },
    },
    required=["session_id"],
)

export_report = _tool(
    name="export_report",
    description="Export a previously generated report to a file.",
    parameters={
        "report_artifact_id": {
            "type": "string",
            "description": "UUID of the report artifact",
        },
        "output_path": {
            "type": "string",
            "description": "File path where the report should be saved",
        },
    },
    required=["report_artifact_id"],
)


# ---------------------------------------------------------------------------
# Git/Code — Source Code Analysis (Phase 3.1)
# ---------------------------------------------------------------------------

git_clone_repo = _tool(
    name="git_clone_repo",
    description="Clone a git repository for source code analysis and code-aware dynamic testing.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "url": {"type": "string", "description": "Git clone URL (https:// or git://)"},
        "name": {"type": "string", "description": "Optional local name for the cloned repo"},
    },
    required=["session_id", "url"],
)

git_list_repos = _tool(
    name="git_list_repos",
    description="List all available repositories cloned for analysis.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
    },
    required=["session_id"],
)

git_get_tree = _tool(
    name="git_get_tree",
    description="Get directory tree of a repository to understand its structure.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "path": {"type": "string", "description": "Subdirectory path (optional, default: root)"},
        "max_depth": {"type": "integer", "description": "Maximum tree depth (default: 3)"},
    },
    required=["session_id", "repo_name"],
)

git_get_file = _tool(
    name="git_get_file",
    description="Read source file content with optional line range from a cloned repository.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "file_path": {"type": "string", "description": "Relative file path within the repo"},
        "start_line": {"type": "integer", "description": "Starting line number (default: 1)"},
        "end_line": {"type": "integer", "description": "Ending line number (optional)"},
    },
    required=["session_id", "repo_name", "file_path"],
)

git_search_code = _tool(
    name="git_search_code",
    description="Search for code patterns (text or regex) in a repository. Find security-sensitive code, API endpoints, auth logic.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "query": {"type": "string", "description": "Search pattern (text or regex)"},
        "is_regex": {"type": "boolean", "description": "Whether query is regex (default: false)"},
        "file_pattern": {"type": "string", "description": "Glob pattern for files (e.g. '*.py')"},
    },
    required=["session_id", "repo_name", "query"],
)

git_find_hotspots = _tool(
    name="git_find_hotspots",
    description="Scan repository for security-sensitive code patterns (sinks, hardcoded secrets, unsafe crypto). Categories: sqli, xss, command_injection, ssrf, path_traversal, crypto, deserialization.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "categories": {"type": "array", "items": {"type": "string"}, "description": "Categories to scan (default: all)"},
    },
    required=["session_id", "repo_name"],
)

run_code_audit = _tool(
    name="run_code_audit",
    description="Run complete code security audit: clone repo, analyze stats, detect hotspots, generate prioritized target list for dynamic testing, persist hotspots as findings.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_url": {"type": "string", "description": "Git clone URL (if repo not yet cloned)"},
        "repo_name": {"type": "string", "description": "Name of already-cloned repo (alternative to repo_url)"},
        "categories": {"type": "array", "items": {"type": "string"}, "description": "Hotspot categories to focus on (default: all)"},
    },
    required=["session_id"],
)

git_log = _tool(
    name="git_log",
    description="Get git commit history for a repository or specific file.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "max_count": {"type": "integer", "description": "Max commits to return (default: 20)"},
        "file_path": {"type": "string", "description": "Optional file to filter history"},
    },
    required=["session_id", "repo_name"],
)

git_diff = _tool(
    name="git_diff",
    description="Get diff between two commits to identify recent changes in source code.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "commit_a": {"type": "string", "description": "First commit (default: HEAD~1)"},
        "commit_b": {"type": "string", "description": "Second commit (default: HEAD)"},
    },
    required=["session_id", "repo_name"],
)

git_blame = _tool(
    name="git_blame",
    description="Get git blame for a file line range — identify who authored security-sensitive code.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "repo_name": {"type": "string", "description": "Name of the repository"},
        "file_path": {"type": "string", "description": "Relative file path"},
        "start_line": {"type": "integer", "description": "Start line (default: 1)"},
        "end_line": {"type": "integer", "description": "End line (default: 50)"},
    },
    required=["session_id", "repo_name", "file_path"],
)

summarize_risks = _tool(
    name="summarize_risks",
    description="Analyze a code snippet and summarize security risks using AI. Evaluates code context, language, and potential vulnerabilities.",
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "code_snippet": {"type": "string", "description": "The code to analyze (max 5000 chars)"},
        "language": {"type": "string", "description": "Programming language of the snippet"},
        "context": {"type": "string", "description": "Additional context (e.g. 'handles user login')"},
    },
    required=["session_id", "code_snippet", "language"],
)


# ── Mobile testing tools ────────────────────────────────────

analyze_mobile_traffic = _tool(
    name="analyze_mobile_traffic",
    description=(
        "Analyze mobile app traffic captured by Caido proxy. Pulls intercepted requests, "
        "groups by API endpoint, identifies auth mechanisms (Bearer, cookies, API keys), "
        "detects sensitive data patterns, and maps the full API surface. "
        "Produces a structured report for further OWASP testing."
    ),
    parameters={
        "session_id": {"type": "string", "description": "UUID of the pentest session"},
        "host_filter": {"type": "string", "description": "Filter by target API host (e.g. api.target.com)"},
        "limit": {"type": "integer", "description": "Max requests to analyze (default: 200)"},
    },
    required=["session_id"],
)


# ---------------------------------------------------------------------------
# All tools (convenience list for passing to Z.ai)
# ---------------------------------------------------------------------------

ALL_TOOLS: list[dict[str, Any]] = [
    create_pentest_session,
    get_session_state,
    run_recon,
    get_recon_results,
    mirror_site,
    scan_secrets,
    caido_get_requests,
    caido_get_findings,
    caido_create_finding,
    caido_get_sitemap,
    caido_list_workflows,
    caido_run_workflow,
    caido_send_request,
    caido_sync_findings,
    caido_run_predefined_workflow,
    devtools_navigate,
    devtools_screenshot,
    devtools_discover_forms,
    devtools_discover_links,
    devtools_detect_dom_xss,
    devtools_execute_js,
    devtools_get_cookies,
    devtools_get_storage,
    devtools_check_security_headers,
    devtools_full_page_audit,
    run_discovery,
    run_injection_tests,
    run_auth_tests,
    run_ssrf_tests,
    git_clone_repo,
    git_list_repos,
    git_get_tree,
    git_get_file,
    git_search_code,
    git_find_hotspots,
    run_code_audit,
    git_log,
    git_diff,
    git_blame,
    summarize_risks,
    analyze_mobile_traffic,
    parse_nmap_output,
    summarize_findings,
    correlate_findings,
    build_report,
    export_report,
]
