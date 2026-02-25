"""Caido GraphQL client with instance-token authentication.

Uses a pre-provisioned instance token (extracted from Caido's Electron
localStorage) and can refresh it automatically via the ``refreshAuthenticationToken``
mutation.  All GraphQL queries/mutations match the actual Caido v0.46+ schema.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# GraphQL fragments — verified against Caido introspected schema
# ---------------------------------------------------------------------------

_REQUEST_FRAGMENT = """
fragment RequestFields on Request {
    id host method path query length port isTls
    fileExtension source alteration edited createdAt
    response { id statusCode length roundtripTime createdAt }
}
"""

_FINDING_FRAGMENT = """
fragment FindingFields on Finding {
    id title description host path reporter dedupeKey hidden createdAt
    request { id host method path }
}
"""

_SITEMAP_ENTRY_FRAGMENT = """
fragment SitemapEntryFields on SitemapEntry {
    id label kind parentId hasDescendants
}
"""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


@dataclass
class CaidoClient:
    """GraphQL client for Caido proxy with instance-token auth."""

    base_url: str = "http://host.docker.internal:8088"
    auth_token: str = ""
    refresh_token: str = ""
    _token_expires: float = 0.0
    timeout: float = 30.0

    def __post_init__(self):
        if not self.auth_token:
            self.auth_token = os.environ.get("CAIDO_AUTH_TOKEN", "")
        if not self.refresh_token:
            self.refresh_token = os.environ.get("CAIDO_REFRESH_TOKEN", "")
        # Give a generous initial expiry — token was issued for ~1 year
        if not self._token_expires:
            self._token_expires = time.time() + 86400 * 365

    # ------------------------------------------------------------------
    # Networking helpers
    # ------------------------------------------------------------------

    def _base_headers(self) -> dict[str, str]:
        """Headers sent with every request.

        Caido rejects requests whose Host header is not localhost,
        so we spoof Host + Origin when calling from a Docker container.
        """
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        return {
            "Content-Type": "application/json",
            "Host": f"localhost:{parsed.port or 8088}",
            "Origin": f"http://localhost:{parsed.port or 8088}",
        }

    async def _ensure_token(self) -> str:
        """Return current access token, refreshing if near expiry."""
        if self.auth_token and time.time() < self._token_expires - 300:
            return self.auth_token

        if not self.refresh_token:
            raise RuntimeError("No refresh token available — cannot renew auth")

        logger.info("Refreshing Caido instance token …")
        headers = self._base_headers()
        # Refresh does NOT require auth bearer — it IS the auth flow
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/graphql",
                json={
                    "query": """
                        mutation Refresh($rt: Token!) {
                            refreshAuthenticationToken(refreshToken: $rt) {
                                ... on AuthenticationToken {
                                    accessToken expiresAt refreshToken scopes
                                }
                                ... on AuthenticationUserError {
                                    code
                                }
                            }
                        }
                    """,
                    "variables": {"rt": self.refresh_token},
                },
                headers=headers,
            )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result = data.get("refreshAuthenticationToken", {})

        if result.get("code"):
            raise RuntimeError(f"Token refresh failed: {result['code']}")

        self.auth_token = result["accessToken"]
        if result.get("refreshToken"):
            self.refresh_token = result["refreshToken"]

        from datetime import datetime

        expires_str = result["expiresAt"]
        expires_dt = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
        self._token_expires = expires_dt.timestamp()

        logger.info("Token refreshed, expires at %s", expires_str)
        return self.auth_token

    async def _gql(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        """Execute a GraphQL query against Caido."""
        headers = self._base_headers()
        if auth:
            token = await self._ensure_token()
            headers["Authorization"] = f"Bearer {token}"

        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/graphql",
                json=payload,
                headers=headers,
            )
        resp.raise_for_status()
        body = resp.json()

        if body.get("errors"):
            # On auth error, clear token and retry once
            for err in body["errors"]:
                ext = err.get("extensions", {})
                caido_ext = ext.get("CAIDO", {})
                if caido_ext.get("code") == "AUTHORIZATION":
                    self.auth_token = ""
                    self._token_expires = 0
                    token = await self._ensure_token()
                    headers["Authorization"] = f"Bearer {token}"
                    async with httpx.AsyncClient(timeout=self.timeout) as c2:
                        resp = await c2.post(
                            f"{self.base_url}/graphql",
                            json=payload,
                            headers=headers,
                        )
                    resp.raise_for_status()
                    body = resp.json()
                    break

        if body.get("errors") and not body.get("data"):
            raise RuntimeError(f"Caido GraphQL errors: {body['errors']}")

        return body.get("data", {})

    # ==================================================================
    # Project management
    # ==================================================================

    async def list_projects(self) -> list[dict[str, Any]]:
        data = await self._gql(
            """{ projects { id name status size readOnly createdAt updatedAt } }"""
        )
        return data.get("projects", [])

    async def get_current_project(self) -> dict[str, Any] | None:
        data = await self._gql(
            """{ currentProject { project { id name version status } readOnly } }"""
        )
        return data.get("currentProject")

    async def create_project(
        self, name: str, temporary: bool = False
    ) -> dict[str, Any]:
        data = await self._gql(
            """
            mutation($name: String!, $temporary: Boolean!) {
                createProject(input: { name: $name, temporary: $temporary }) {
                    project { id name status }
                    error { __typename }
                }
            }
            """,
            variables={"name": name, "temporary": temporary},
        )
        result = data.get("createProject", {})
        if result.get("error"):
            raise RuntimeError(f"Failed to create project: {result['error']}")
        return result.get("project", {})

    async def select_project(self, project_id: str) -> bool:
        await self._gql(
            """mutation($id: ID!) { selectProject(id: $id) { __typename } }""",
            variables={"id": project_id},
        )
        return True

    # ==================================================================
    # Requests (intercepted traffic)
    # ==================================================================

    async def get_requests(
        self,
        first: int = 50,
        after: str | None = None,
        scope_id: str | None = None,
    ) -> dict[str, Any]:
        variables: dict[str, Any] = {"first": first}
        if after:
            variables["after"] = after

        filter_clause = ""
        if scope_id:
            filter_clause = ", filter: {scope: {id: $scopeId}}"
            variables["scopeId"] = scope_id

        data = await self._gql(
            f"""
            {_REQUEST_FRAGMENT}
            query($first: Int!, $after: String) {{
                requests(first: $first, after: $after{filter_clause}) {{
                    edges {{ cursor node {{ ...RequestFields }} }}
                    pageInfo {{ hasNextPage endCursor }}
                    count {{ total }}
                }}
            }}
            """,
            variables=variables,
        )
        return data.get("requests", {})

    async def get_requests_by_offset(
        self,
        limit: int = 50,
        offset: int = 0,
        host_filter: str | None = None,
    ) -> dict[str, Any]:
        variables: dict[str, Any] = {"limit": limit, "offset": offset}
        filter_var = ""
        filter_arg = ""

        if host_filter:
            filter_var = ", $filter: HTTPQL"
            filter_arg = ", filter: $filter"
            variables["filter"] = f'req.host.eq:"{host_filter}"'

        data = await self._gql(
            f"""
            {_REQUEST_FRAGMENT}
            query($limit: Int!, $offset: Int!{filter_var}) {{
                requestsByOffset(limit: $limit, offset: $offset{filter_arg}) {{
                    edges {{ node {{ ...RequestFields }} }}
                    pageInfo {{ hasPreviousPage hasNextPage }}
                    snapshot
                }}
            }}
            """,
            variables=variables,
        )
        return data.get("requestsByOffset", {})

    async def get_request(self, request_id: str) -> dict[str, Any] | None:
        data = await self._gql(
            f"""
            {_REQUEST_FRAGMENT}
            query($id: ID!) {{ request(id: $id) {{ ...RequestFields }} }}
            """,
            variables={"id": request_id},
        )
        return data.get("request")

    # ==================================================================
    # Findings
    # ==================================================================

    async def get_findings(
        self, limit: int = 50, offset: int = 0
    ) -> dict[str, Any]:
        data = await self._gql(
            f"""
            {_FINDING_FRAGMENT}
            query($limit: Int!, $offset: Int!) {{
                findingsByOffset(limit: $limit, offset: $offset) {{
                    edges {{ node {{ ...FindingFields }} }}
                    pageInfo {{ hasPreviousPage hasNextPage }}
                    snapshot
                }}
            }}
            """,
            variables={"limit": limit, "offset": offset},
        )
        return data.get("findingsByOffset", {})

    async def create_finding(
        self,
        request_id: str,
        title: str,
        reporter: str = "webphomet",
        description: str | None = None,
        dedupe_key: str | None = None,
    ) -> dict[str, Any]:
        """Create a finding.  ``request_id`` is **required** by Caido schema."""
        input_obj: dict[str, Any] = {"title": title, "reporter": reporter}
        if description:
            input_obj["description"] = description
        if dedupe_key:
            input_obj["dedupeKey"] = dedupe_key

        data = await self._gql(
            f"""
            {_FINDING_FRAGMENT}
            mutation($requestId: ID!, $input: CreateFindingInput!) {{
                createFinding(requestId: $requestId, input: $input) {{
                    finding {{ ...FindingFields }}
                    error {{ __typename }}
                }}
            }}
            """,
            variables={"requestId": request_id, "input": input_obj},
        )
        result = data.get("createFinding", {})
        if result.get("error"):
            raise RuntimeError(f"Failed to create finding: {result['error']}")
        return result.get("finding", {})

    async def delete_findings(self, finding_ids: list[str]) -> bool:
        await self._gql(
            """mutation($ids: [ID!]!) { deleteFindings(ids: $ids) { __typename } }""",
            variables={"ids": finding_ids},
        )
        return True

    # ==================================================================
    # Scopes
    # ==================================================================

    async def get_scopes(self) -> list[dict[str, Any]]:
        data = await self._gql(
            """{ scopes { id name allowlist denylist indexed } }"""
        )
        return data.get("scopes", [])

    async def create_scope(
        self,
        name: str,
        allowlist: list[str],
        denylist: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a scope.  Allowlist items use Caido glob format e.g. ``*://localhost:4280``."""
        data = await self._gql(
            """
            mutation($input: CreateScopeInput!) {
                createScope(input: $input) {
                    scope { id name allowlist denylist indexed }
                    error { __typename ... on InvalidGlobTermsUserError { terms } }
                }
            }
            """,
            variables={
                "input": {
                    "name": name,
                    "allowlist": allowlist,
                    "denylist": denylist or [],
                },
            },
        )
        result = data.get("createScope", {})
        if result.get("error"):
            raise RuntimeError(f"Failed to create scope: {result['error']}")
        return result.get("scope", {})

    # ==================================================================
    # Sitemap — returns SitemapEntryConnection (edges/nodes pattern)
    # ==================================================================

    async def get_sitemap_root_entries(
        self, scope_id: str | None = None
    ) -> list[dict[str, Any]]:
        variables: dict[str, Any] = {}
        args = ""
        if scope_id:
            args = "($scopeId: ID)"
            variables["scopeId"] = scope_id

        data = await self._gql(
            f"""
            {_SITEMAP_ENTRY_FRAGMENT}
            query {args} {{
                sitemapRootEntries{("(scopeId: $scopeId)" if scope_id else "")} {{
                    edges {{ node {{ ...SitemapEntryFields }} }}
                }}
            }}
            """,
            variables=variables or None,
        )
        edges = data.get("sitemapRootEntries", {}).get("edges", [])
        return [e["node"] for e in edges]

    async def get_sitemap_descendants(
        self,
        parent_id: str,
        depth: str = "ALL",
    ) -> list[dict[str, Any]]:
        data = await self._gql(
            f"""
            {_SITEMAP_ENTRY_FRAGMENT}
            query($parentId: ID!, $depth: SitemapDescendantsDepth!) {{
                sitemapDescendantEntries(parentId: $parentId, depth: $depth) {{
                    edges {{ node {{ ...SitemapEntryFields }} }}
                }}
            }}
            """,
            variables={"parentId": parent_id, "depth": depth},
        )
        edges = data.get("sitemapDescendantEntries", {}).get("edges", [])
        return [e["node"] for e in edges]

    # ==================================================================
    # Intercept control
    # ==================================================================

    async def get_intercept_status(self) -> dict[str, Any]:
        data = await self._gql("""{ interceptStatus }""")
        return {"status": data.get("interceptStatus")}

    async def pause_intercept(self) -> bool:
        await self._gql("""mutation { pauseIntercept { __typename } }""")
        return True

    async def resume_intercept(self) -> bool:
        await self._gql("""mutation { resumeIntercept { __typename } }""")
        return True

    # ==================================================================
    # Replay — send crafted HTTP requests
    # ==================================================================

    async def send_request(
        self,
        raw_request: str,
        host: str,
        port: int = 443,
        is_tls: bool = True,
    ) -> dict[str, Any]:
        """Send a crafted HTTP request via the Caido Replay system.

        1. ``createReplaySession`` — open a new replay tab
        2. ``startReplayTask``   — fire the raw request (Blob = base64)
        3. Poll the session entry until the response arrives.
        """
        import asyncio
        import base64

        raw_b64 = base64.b64encode(raw_request.encode()).decode()

        # Step 1: create session
        session_data = await self._gql(
            """
            mutation($input: CreateReplaySessionInput!) {
                createReplaySession(input: $input) {
                    session { id name }
                }
            }
            """,
            variables={"input": {}},
        )
        session = session_data["createReplaySession"]["session"]
        session_id = session["id"]
        logger.info("Created replay session %s", session_id)

        # Step 2: start replay task (raw must be base64-encoded Blob)
        task_data = await self._gql(
            """
            mutation($sid: ID!, $input: StartReplayTaskInput!) {
                startReplayTask(sessionId: $sid, input: $input) {
                    task {
                        id
                        replayEntry { id error }
                    }
                    error { __typename }
                }
            }
            """,
            variables={
                "sid": session_id,
                "input": {
                    "connection": {
                        "host": host,
                        "port": port,
                        "isTLS": is_tls,
                    },
                    "raw": raw_b64,
                    "settings": {
                        "placeholders": [],
                        "updateContentLength": True,
                        "connectionClose": True,
                    },
                },
            },
        )
        result = task_data.get("startReplayTask", {})
        if result.get("error"):
            raise RuntimeError(f"Replay task failed: {result['error']}")

        entry_id = result.get("task", {}).get("replayEntry", {}).get("id")
        entry_error = result.get("task", {}).get("replayEntry", {}).get("error")

        # Step 3: poll for the completed request (response may be async)
        request_data = None
        for _ in range(10):
            await asyncio.sleep(0.5)
            poll = await self._gql(
                """
                query($sid: ID!) {
                    replaySession(id: $sid) {
                        activeEntry {
                            id error
                            request {
                                id host method path query
                                response { id statusCode length roundtripTime }
                            }
                        }
                    }
                }
                """,
                variables={"sid": session_id},
            )
            active = poll.get("replaySession", {}).get("activeEntry", {})
            if active and active.get("request"):
                request_data = active["request"]
                entry_error = active.get("error")
                break

        # Step 4: fetch response body via response(id) { raw }
        response_body = ""
        resp_info = (request_data or {}).get("response") or {}
        response_id = resp_info.get("id")
        if response_id:
            try:
                raw_data = await self._gql(
                    """
                    query($id: ID!) {
                        response(id: $id) { raw }
                    }
                    """,
                    variables={"id": response_id},
                )
                raw_b64 = (raw_data.get("response") or {}).get("raw", "")
                if raw_b64:
                    decoded = base64.b64decode(raw_b64).decode("utf-8", errors="replace")
                    if "\r\n\r\n" in decoded:
                        response_body = decoded.split("\r\n\r\n", 1)[1]
                    else:
                        response_body = decoded
            except Exception as e:
                logger.warning("Failed to fetch response body for %s: %s", response_id, e)

        return {
            "session_id": session_id,
            "entry_id": entry_id,
            "error": entry_error,
            "request": request_data,
            "body": response_body,
            "status_code": resp_info.get("statusCode"),
            "id": (request_data or {}).get("id"),
        }

    # ==================================================================
    # Workflows
    # ==================================================================

    async def list_workflows(self) -> list[dict[str, Any]]:
        data = await self._gql(
            """{ workflows { id name kind enabled global } }"""
        )
        return data.get("workflows", [])

    async def run_active_workflow(
        self, workflow_id: str, request_id: str
    ) -> dict[str, Any]:
        data = await self._gql(
            """
            mutation($wid: ID!, $rid: ID!) {
                runActiveWorkflow(id: $wid, requestId: $rid) { __typename }
            }
            """,
            variables={"wid": workflow_id, "rid": request_id},
        )
        return data.get("runActiveWorkflow", {})

    # ==================================================================
    # Automate (fuzzing)
    # ==================================================================

    async def list_automate_sessions(self, first: int = 20) -> dict[str, Any]:
        data = await self._gql(
            """
            query($first: Int!) {
                automateSessions(first: $first) {
                    edges { node { id name createdAt } }
                }
            }
            """,
            variables={"first": first},
        )
        return data.get("automateSessions", {})

    # ==================================================================
    # Health
    # ==================================================================

    async def health_check(self) -> bool:
        try:
            data = await self._gql("{ __typename }", auth=False)
            return data.get("__typename") == "QueryRoot"
        except Exception:
            return False
