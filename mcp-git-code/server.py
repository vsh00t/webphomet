"""MCP Git/Code server — wraps CodeAnalyzer for JSON-RPC dispatch."""

from __future__ import annotations

import logging
from typing import Any

from code_analyzer import CodeAnalyzer

logger = logging.getLogger(__name__)


class GitCodeServer:
    """High-level server wrapping CodeAnalyzer for JSON-RPC methods."""

    def __init__(self) -> None:
        self.analyzer = CodeAnalyzer()

    # ── Repo management ────────────────────────────────────

    def clone_repo(self, url: str, name: str | None = None) -> dict[str, Any]:
        return self.analyzer.clone_repo(url, name)

    def list_repos(self) -> dict[str, Any]:
        repos = self.analyzer.list_repos()
        return {"repos": repos, "count": len(repos)}

    def get_repo_stats(self, repo_name: str) -> dict[str, Any]:
        return self.analyzer.get_stats(repo_name)

    # ── File access ────────────────────────────────────────

    def get_tree(
        self,
        repo_name: str,
        path: str = "",
        max_depth: int = 3,
    ) -> dict[str, Any]:
        return self.analyzer.get_tree(repo_name, path, max_depth)

    def get_file(
        self,
        repo_name: str,
        file_path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        return self.analyzer.get_file(repo_name, file_path, start_line, end_line)

    # ── Search ─────────────────────────────────────────────

    def search_code(
        self,
        repo_name: str,
        query: str,
        is_regex: bool = False,
        file_pattern: str = "*",
        max_results: int = 50,
    ) -> dict[str, Any]:
        results = self.analyzer.search_code(
            repo_name, query, is_regex, file_pattern, max_results,
        )
        return {"matches": results, "count": len(results)}

    # ── Security analysis ──────────────────────────────────

    def find_hotspots(
        self,
        repo_name: str,
        categories: list[str] | None = None,
        max_results: int = 100,
    ) -> dict[str, Any]:
        hotspots = self.analyzer.find_hotspots(repo_name, categories, max_results)
        # Summarize by category/severity
        by_cat: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        for h in hotspots:
            cat = h.get("category", "unknown")
            sev = h.get("severity", "medium")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_sev[sev] = by_sev.get(sev, 0) + 1

        return {
            "hotspots": hotspots,
            "count": len(hotspots),
            "by_category": by_cat,
            "by_severity": by_sev,
        }

    def extract_functions(
        self,
        repo_name: str,
        file_path: str,
    ) -> dict[str, Any]:
        functions = self.analyzer.extract_functions(repo_name, file_path)
        return {"functions": functions, "count": len(functions)}

    # ── Git operations ─────────────────────────────────────

    def git_log(
        self,
        repo_name: str,
        max_count: int = 20,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        commits = self.analyzer.git_log(repo_name, max_count, file_path)
        return {"commits": commits, "count": len(commits)}

    def git_diff(
        self,
        repo_name: str,
        commit_a: str = "HEAD~1",
        commit_b: str = "HEAD",
        file_path: str | None = None,
    ) -> dict[str, Any]:
        return self.analyzer.git_diff(repo_name, commit_a, commit_b, file_path)

    def git_blame(
        self,
        repo_name: str,
        file_path: str,
        start_line: int = 1,
        end_line: int = 50,
    ) -> dict[str, Any]:
        blames = self.analyzer.git_blame(repo_name, file_path, start_line, end_line)
        return {"blames": blames, "count": len(blames)}

    # ── Combined analysis ──────────────────────────────────

    def full_security_audit(self, repo_name: str) -> dict[str, Any]:
        """Run a complete security audit on a repository.

        Returns stats + hotspots + prioritized endpoint list.
        """
        stats = self.get_repo_stats(repo_name)
        if "error" in stats:
            return stats

        hotspots = self.find_hotspots(repo_name, max_results=200)

        # Extract unique files with hotspots → these are the targets for dynamic testing
        target_files: dict[str, dict[str, Any]] = {}
        for h in hotspots.get("hotspots", []):
            fpath = h["file"]
            if fpath not in target_files:
                target_files[fpath] = {
                    "file": fpath,
                    "language": h.get("language", ""),
                    "categories": set(),
                    "max_severity": "info",
                    "hotspot_count": 0,
                }
            tf = target_files[fpath]
            tf["categories"].add(h["category"])
            tf["hotspot_count"] += 1
            # Update max severity
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            if sev_order.get(h["severity"], 5) < sev_order.get(tf["max_severity"], 5):
                tf["max_severity"] = h["severity"]

        # Convert sets to lists for JSON
        prioritized = []
        for tf in target_files.values():
            tf["categories"] = sorted(tf["categories"])
            prioritized.append(tf)

        # Sort by severity then count
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        prioritized.sort(key=lambda x: (sev_order.get(x["max_severity"], 5), -x["hotspot_count"]))

        return {
            "repo_stats": stats,
            "hotspots_summary": {
                "total": hotspots["count"],
                "by_category": hotspots["by_category"],
                "by_severity": hotspots["by_severity"],
            },
            "prioritized_targets": prioritized[:50],
            "recommendation": self._generate_recommendation(hotspots, stats),
        }

    def _generate_recommendation(
        self,
        hotspots: dict[str, Any],
        stats: dict[str, Any],
    ) -> str:
        """Generate a natural-language recommendation based on analysis."""
        by_sev = hotspots.get("by_severity", {})
        critical = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)
        total = hotspots.get("count", 0)

        if critical > 0:
            return (
                f"URGENT: {critical} critical hotspots found. "
                f"Focus dynamic testing on files with SQL injection and "
                f"command injection sinks that handle user input directly."
            )
        elif high > 0:
            return (
                f"{high} high-severity hotspots detected. "
                f"Prioritize XSS and SSRF sinks for dynamic validation."
            )
        elif total > 0:
            return (
                f"{total} medium/low hotspots found. "
                f"Review crypto weaknesses and potential path traversal."
            )
        return "No significant hotspots detected. Repository appears well-hardened."
