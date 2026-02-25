"""MCP Caido Server — business logic layer.

Provides high-level methods that the JSON-RPC endpoint calls.
Wraps the CaidoClient with session awareness and convenience helpers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from caido_client import CaidoClient

logger = logging.getLogger(__name__)


@dataclass
class CaidoServer:
    """High-level Caido MCP server with session context."""

    client: CaidoClient = field(default_factory=CaidoClient)

    # ------------------------------------------------------------------
    # Project management
    # ------------------------------------------------------------------

    async def list_projects(self) -> dict[str, Any]:
        """Return all Caido projects."""
        projects = await self.client.list_projects()
        current = await self.client.get_current_project()
        return {
            "projects": projects,
            "current_project": current,
        }

    async def create_project(self, name: str) -> dict[str, Any]:
        """Create and optionally select a new project."""
        project = await self.client.create_project(name)
        # Auto-select the new project
        await self.client.select_project(project["id"])
        return {"project": project, "selected": True}

    async def select_project(self, project_id: str) -> dict[str, Any]:
        """Select an existing project."""
        await self.client.select_project(project_id)
        current = await self.client.get_current_project()
        return {"current_project": current}

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    async def get_requests(
        self,
        limit: int = 50,
        offset: int = 0,
        host: str | None = None,
    ) -> dict[str, Any]:
        """Fetch intercepted requests with optional host filter."""
        result = await self.client.get_requests_by_offset(
            limit=limit,
            offset=offset,
            host_filter=host,
        )
        edges = result.get("edges", [])
        requests = [e["node"] for e in edges] if edges else []
        return {
            "requests": requests,
            "total": len(requests),
            "has_next": result.get("pageInfo", {}).get("hasNextPage", False),
        }

    async def get_request(self, request_id: str) -> dict[str, Any]:
        """Fetch a single request by ID."""
        req = await self.client.get_request(request_id)
        if not req:
            return {"error": f"Request {request_id} not found"}
        return {"request": req}

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def get_findings(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Fetch findings from Caido."""
        result = await self.client.get_findings(limit=limit, offset=offset)
        edges = result.get("edges", [])
        findings = [e["node"] for e in edges] if edges else []
        return {
            "findings": findings,
            "total": len(findings),
            "has_next": result.get("pageInfo", {}).get("hasNextPage", False),
        }

    async def create_finding(
        self,
        request_id: str,
        title: str,
        description: str | None = None,
        reporter: str = "webphomet",
        dedupe_key: str | None = None,
    ) -> dict[str, Any]:
        """Create a finding in Caido (push from WebPhomet → Caido).

        ``request_id`` is **required** — Caido links every finding to a request.
        """
        finding = await self.client.create_finding(
            request_id=request_id,
            title=title,
            reporter=reporter,
            description=description,
            dedupe_key=dedupe_key,
        )
        return {"finding": finding}

    async def sync_findings_to_caido(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Batch push WebPhomet findings to Caido.

        Each finding dict **must** include ``request_id``.
        Returns created Caido finding IDs for back-linking.
        """
        created = 0
        errors = 0
        skipped = 0
        synced_ids: list[dict[str, str]] = []
        for f in findings:
            rid = f.get("request_id")
            if not rid:
                logger.warning("Skipping finding '%s' — no request_id", f.get("title"))
                skipped += 1
                continue
            try:
                result = await self.client.create_finding(
                    request_id=rid,
                    title=f.get("title", "Untitled"),
                    description=f.get("description"),
                    reporter="webphomet",
                    dedupe_key=f.get("dedupe_key"),
                )
                caido_id = result.get("id", "")
                synced_ids.append({
                    "webphomet_finding_id": f.get("id", ""),
                    "caido_finding_id": caido_id,
                })
                created += 1
            except Exception as exc:
                logger.warning("Failed to sync finding %s: %s", f.get("title"), exc)
                errors += 1
        return {
            "synced": created,
            "errors": errors,
            "skipped": skipped,
            "total": len(findings),
            "synced_ids": synced_ids,
        }

    async def pull_findings(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Pull all findings from Caido for import into WebPhomet DB.

        Returns normalized finding dicts with caido_finding_id so the
        caller can deduplicate before inserting.
        """
        result = await self.client.get_findings(limit=limit, offset=offset)
        edges = result.get("edges", [])
        findings: list[dict[str, Any]] = []
        for edge in edges:
            node = edge.get("node", {})
            finding: dict[str, Any] = {
                "caido_finding_id": node.get("id", ""),
                "title": node.get("title", "Untitled"),
                "description": node.get("description"),
                "reporter": node.get("reporter", ""),
                "caido_request_id": None,
            }
            # Extract associated request ID if present
            req = node.get("request")
            if req and isinstance(req, dict):
                finding["caido_request_id"] = req.get("id")
            findings.append(finding)
        return {
            "findings": findings,
            "total": len(findings),
            "has_next": result.get("pageInfo", {}).get("hasNextPage", False),
        }

    # ------------------------------------------------------------------
    # Scopes
    # ------------------------------------------------------------------

    async def get_scopes(self) -> dict[str, Any]:
        """List all Caido scopes."""
        scopes = await self.client.get_scopes()
        return {"scopes": scopes}

    async def create_scope(
        self,
        name: str,
        allowlist: list[str],
        denylist: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a scope in Caido for the target."""
        scope = await self.client.create_scope(
            name=name,
            allowlist=allowlist,
            denylist=denylist,
        )
        return {"scope": scope}

    # ------------------------------------------------------------------
    # Sitemap
    # ------------------------------------------------------------------

    async def get_sitemap(self) -> dict[str, Any]:
        """Get the root sitemap entries."""
        entries = await self.client.get_sitemap_root_entries()
        return {"entries": entries, "total": len(entries)}

    async def get_sitemap_tree(
        self,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        """Get sitemap tree from root or a specific parent."""
        if parent_id:
            entries = await self.client.get_sitemap_descendants(parent_id)
        else:
            entries = await self.client.get_sitemap_root_entries()
        return {"entries": entries, "total": len(entries)}

    # ------------------------------------------------------------------
    # Intercept control
    # ------------------------------------------------------------------

    async def get_intercept_status(self) -> dict[str, Any]:
        """Get intercept on/off status."""
        return await self.client.get_intercept_status()

    async def toggle_intercept(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable interception."""
        if enabled:
            await self.client.resume_intercept()
        else:
            await self.client.pause_intercept()
        return {"intercept_enabled": enabled}

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    async def send_request(
        self,
        raw_request: str,
        host: str,
        port: int = 443,
        is_tls: bool = True,
    ) -> dict[str, Any]:
        """Send a crafted HTTP request through Caido.

        Caido runs on the host, so translate Docker internal hostnames
        to localhost for proper DNS resolution.
        """
        # Caido (on host) cannot resolve Docker-internal names
        caido_host = host
        if host == "host.docker.internal":
            caido_host = "localhost"

        result = await self.client.send_request(
            raw_request=raw_request,
            host=caido_host,
            port=port,
            is_tls=is_tls,
        )
        # Flatten so callers can access body, status_code, id directly
        return result

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    async def list_workflows(self) -> dict[str, Any]:
        """List available workflows."""
        workflows = await self.client.list_workflows()
        return {"workflows": workflows, "total": len(workflows)}

    async def run_workflow(
        self,
        workflow_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Run a workflow on a specific request."""
        result = await self.client.run_active_workflow(
            workflow_id=workflow_id,
            request_id=request_id,
        )
        return {"result": result}

    # ------------------------------------------------------------------
    # Automate
    # ------------------------------------------------------------------

    async def list_automate_sessions(
        self,
        limit: int = 20,
    ) -> dict[str, Any]:
        """List automate/fuzzing sessions."""
        result = await self.client.list_automate_sessions(first=limit)
        edges = result.get("edges", [])
        sessions = [e["node"] for e in edges] if edges else []
        return {"sessions": sessions, "total": len(sessions)}
