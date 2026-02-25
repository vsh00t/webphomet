"""Git + code analysis engine for MCP Git/Code server.

Provides:
- Repository management (clone, list, get file tree)
- File content access with language detection
- Code search via regex and AST
- Static analysis: sink/source detection, hotspot identification
- Language-aware function extraction via tree-sitter
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REPOS_ROOT = Path(os.getenv("REPOS_ROOT", "/repos"))

# ── Security-sensitive patterns (sinks) ──────────────────────
SINK_PATTERNS: dict[str, list[dict[str, str]]] = {
    "sqli": [
        {"pattern": r"execute\s*\(\s*[\"']?\s*SELECT.*\+", "desc": "String concat in SQL query"},
        {"pattern": r"execute\s*\(\s*f[\"']", "desc": "f-string in SQL execute()"},
        {"pattern": r"cursor\.execute\s*\([^,]*%\s", "desc": "% formatting in SQL"},
        {"pattern": r"\.raw\s*\(\s*[\"'].*\+", "desc": "Raw SQL with concatenation"},
        {"pattern": r"query\s*=\s*[\"'].*\+.*\+", "desc": "SQL query built with +"},
        {"pattern": r"\.executeQuery\s*\(\s*[\"'].*\+", "desc": "Java SQL concat"},
        {"pattern": r"\$_(GET|POST|REQUEST)\[.*\]\s*\.\s*[\"']", "desc": "PHP user input in SQL"},
    ],
    "xss": [
        {"pattern": r"innerHTML\s*=", "desc": "Direct innerHTML assignment"},
        {"pattern": r"document\.write\s*\(", "desc": "document.write() sink"},
        {"pattern": r"\.html\s*\([^)]*\$", "desc": "jQuery .html() with variable"},
        {"pattern": r"dangerouslySetInnerHTML", "desc": "React dangerouslySetInnerHTML"},
        {"pattern": r"v-html\s*=", "desc": "Vue v-html directive"},
        {"pattern": r"\|\s*safe\b", "desc": "Jinja2/Django |safe filter"},
        {"pattern": r"<%=\s*[^-]", "desc": "ERB unescaped output"},
        {"pattern": r"echo\s+\$_(GET|POST|REQUEST)", "desc": "PHP echo user input"},
    ],
    "command_injection": [
        {"pattern": r"os\.system\s*\(", "desc": "os.system() call"},
        {"pattern": r"subprocess\.(call|run|Popen)\s*\(\s*[\"']", "desc": "subprocess with string"},
        {"pattern": r"exec\s*\(", "desc": "exec() call"},
        {"pattern": r"eval\s*\(", "desc": "eval() call"},
        {"pattern": r"Runtime\.getRuntime\(\)\.exec", "desc": "Java Runtime.exec()"},
        {"pattern": r"shell_exec\s*\(", "desc": "PHP shell_exec()"},
        {"pattern": r"system\s*\(\s*\$", "desc": "PHP system() with variable"},
    ],
    "ssrf": [
        {"pattern": r"requests\.(get|post|put|delete|head)\s*\([^)]*\+", "desc": "Python requests with concat URL"},
        {"pattern": r"urllib\.request\.urlopen\s*\(", "desc": "urllib.urlopen()"},
        {"pattern": r"fetch\s*\([^)]*\+", "desc": "JS fetch() with concat URL"},
        {"pattern": r"http\.get\s*\([^)]*\+", "desc": "Node http.get() with concat"},
        {"pattern": r"curl_exec\s*\(", "desc": "PHP curl_exec()"},
        {"pattern": r"file_get_contents\s*\(\s*\$", "desc": "PHP file_get_contents() with var"},
    ],
    "path_traversal": [
        {"pattern": r"open\s*\([^)]*\+", "desc": "File open with concatenation"},
        {"pattern": r"readFile\s*\([^)]*\+", "desc": "readFile with concatenation"},
        {"pattern": r"Path\s*\([^)]*\+", "desc": "Path() with concatenation"},
        {"pattern": r"include\s*\(\s*\$", "desc": "PHP include with variable"},
        {"pattern": r"require\s*\(\s*\$", "desc": "PHP require with variable"},
    ],
    "crypto": [
        {"pattern": r"MD5|md5", "desc": "MD5 hash usage (weak)"},
        {"pattern": r"SHA1|sha1(?!_)", "desc": "SHA1 hash usage (weak)"},
        {"pattern": r"DES\b|DESede", "desc": "DES encryption (weak)"},
        {"pattern": r"password\s*=\s*[\"'][^\"']+[\"']", "desc": "Hardcoded password"},
        {"pattern": r"(api_key|secret|token)\s*=\s*[\"'][^\"']{8,}[\"']", "desc": "Hardcoded secret"},
        {"pattern": r"Math\.random\(\)", "desc": "JS Math.random() for crypto"},
    ],
    "deserialization": [
        {"pattern": r"pickle\.(loads?|Unpickler)", "desc": "Python pickle deserialization"},
        {"pattern": r"yaml\.(load|unsafe_load)\s*\(", "desc": "YAML unsafe load"},
        {"pattern": r"ObjectInputStream", "desc": "Java ObjectInputStream"},
        {"pattern": r"unserialize\s*\(", "desc": "PHP unserialize()"},
        {"pattern": r"JSON\.parse\s*\(.*\+", "desc": "JSON.parse() with concat"},
    ],
}

# ── Language detection by extension ──────────────────────────
LANG_MAP: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript",
    ".java": "java",
    ".go": "golang",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala",
    ".sql": "sql",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html", ".htm": "html",
    ".css": "css",
    ".md": "markdown",
    ".toml": "toml",
    ".ini": "ini", ".cfg": "ini",
    ".env": "dotenv",
}

# Skip these directories during scanning
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", "target", "bin", "obj",
    ".idea", ".vscode", ".gradle", ".mvn",
}

# Skip binary/large files
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".woff", ".woff2", ".ttf", ".eot",
    ".db", ".sqlite", ".sqlite3",
    ".lock",
}

MAX_FILE_SIZE = 512 * 1024  # 512KB


@dataclass
class Hotspot:
    """A security-relevant code location."""
    file: str
    line: int
    category: str
    pattern_desc: str
    code_snippet: str
    severity: str = "medium"
    language: str = ""


@dataclass
class FunctionInfo:
    """Extracted function/method info."""
    name: str
    file: str
    start_line: int
    end_line: int
    language: str
    params: list[str] = field(default_factory=list)
    body_preview: str = ""


@dataclass
class RepoInfo:
    """Basic repo metadata."""
    name: str
    path: str
    languages: dict[str, int]  # lang -> file count
    total_files: int
    total_lines: int


class CodeAnalyzer:
    """Git repository + code analysis engine."""

    def __init__(self, repos_root: Path | None = None):
        self.repos_root = repos_root or REPOS_ROOT
        self.repos_root.mkdir(parents=True, exist_ok=True)

    # ── Repository management ──────────────────────────────

    def clone_repo(self, url: str, name: str | None = None) -> dict[str, Any]:
        """Clone a git repository into the repos directory."""
        if not name:
            name = url.rstrip("/").split("/")[-1].replace(".git", "")

        dest = self.repos_root / name
        if dest.exists():
            return {"status": "exists", "path": str(dest), "name": name}

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "50", url, str(dest)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                return {"status": "error", "error": result.stderr.strip()}
            return {"status": "cloned", "path": str(dest), "name": name}
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Clone timed out (120s)"}

    def list_repos(self) -> list[dict[str, Any]]:
        """List all available repositories."""
        repos = []
        for entry in sorted(self.repos_root.iterdir()):
            if entry.is_dir() and (entry / ".git").exists():
                info = self._get_repo_info(entry)
                repos.append({
                    "name": entry.name,
                    "path": str(entry),
                    "languages": info.languages,
                    "total_files": info.total_files,
                    "total_lines": info.total_lines,
                })
        return repos

    def _get_repo_info(self, repo_path: Path) -> RepoInfo:
        """Gather repo metadata."""
        languages: dict[str, int] = {}
        total_files = 0
        total_lines = 0

        for f in self._walk_files(repo_path):
            total_files += 1
            ext = f.suffix.lower()
            lang = LANG_MAP.get(ext, "other")
            languages[lang] = languages.get(lang, 0) + 1
            try:
                total_lines += sum(1 for _ in f.open("r", errors="ignore"))
            except Exception:
                pass

        return RepoInfo(
            name=repo_path.name,
            path=str(repo_path),
            languages=languages,
            total_files=total_files,
            total_lines=total_lines,
        )

    # ── File tree & content ────────────────────────────────

    def get_tree(self, repo_name: str, path: str = "", max_depth: int = 3) -> dict[str, Any]:
        """Get directory tree of a repo.

        Returns a nested dict: {name, type (file/dir), children?, language?}
        """
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return {"error": f"Repo '{repo_name}' not found"}

        target = repo_path / path
        if not target.exists():
            return {"error": f"Path '{path}' not found in '{repo_name}'"}

        return self._build_tree(target, max_depth, 0)

    def _build_tree(self, path: Path, max_depth: int, current_depth: int) -> dict[str, Any]:
        node: dict[str, Any] = {"name": path.name}

        if path.is_file():
            node["type"] = "file"
            ext = path.suffix.lower()
            node["language"] = LANG_MAP.get(ext, "other")
            try:
                node["size"] = path.stat().st_size
            except Exception:
                pass
            return node

        node["type"] = "dir"
        if current_depth >= max_depth:
            node["truncated"] = True
            return node

        children = []
        try:
            for entry in sorted(path.iterdir()):
                if entry.name in SKIP_DIRS or entry.name.startswith("."):
                    continue
                children.append(self._build_tree(entry, max_depth, current_depth + 1))
        except PermissionError:
            node["error"] = "permission denied"

        node["children"] = children
        return node

    def get_file(
        self,
        repo_name: str,
        file_path: str,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> dict[str, Any]:
        """Read file content with optional line range."""
        full_path = self.repos_root / repo_name / file_path
        if not full_path.exists():
            return {"error": f"File not found: {file_path}"}
        if not full_path.is_file():
            return {"error": f"Not a file: {file_path}"}

        ext = full_path.suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return {"error": f"Binary/unsupported file type: {ext}"}

        try:
            content = full_path.read_text(errors="replace")
        except Exception as e:
            return {"error": f"Cannot read file: {e}"}

        lines = content.splitlines()
        total = len(lines)

        if end_line is None:
            end_line = min(start_line + 499, total)  # cap at 500 lines

        start_line = max(1, start_line)
        end_line = min(end_line, total)

        selected = lines[start_line - 1: end_line]

        return {
            "file": file_path,
            "language": LANG_MAP.get(ext, "other"),
            "total_lines": total,
            "start_line": start_line,
            "end_line": end_line,
            "content": "\n".join(selected),
        }

    # ── Code search ────────────────────────────────────────

    def search_code(
        self,
        repo_name: str,
        query: str,
        is_regex: bool = False,
        file_pattern: str = "*",
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Search for code patterns in a repository."""
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return [{"error": f"Repo '{repo_name}' not found"}]

        if is_regex:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except re.error as e:
                return [{"error": f"Invalid regex: {e}"}]
        else:
            pattern = re.compile(re.escape(query), re.IGNORECASE)

        results = []
        import fnmatch

        for f in self._walk_files(repo_path):
            if file_pattern != "*" and not fnmatch.fnmatch(f.name, file_pattern):
                continue

            try:
                lines = f.read_text(errors="replace").splitlines()
            except Exception:
                continue

            rel_path = str(f.relative_to(repo_path))

            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    results.append({
                        "file": rel_path,
                        "line": i,
                        "content": line.strip()[:200],
                        "language": LANG_MAP.get(f.suffix.lower(), "other"),
                    })
                    if len(results) >= max_results:
                        return results

        return results

    # ── Security analysis (hotspot detection) ──────────────

    def find_hotspots(
        self,
        repo_name: str,
        categories: list[str] | None = None,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """Scan repository for security-sensitive code patterns (sinks/sources).

        Returns prioritized list of hotspots sorted by severity.
        """
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return [{"error": f"Repo '{repo_name}' not found"}]

        cats = categories or list(SINK_PATTERNS.keys())
        hotspots: list[Hotspot] = []

        for f in self._walk_files(repo_path):
            ext = f.suffix.lower()
            lang = LANG_MAP.get(ext, "other")

            try:
                lines = f.read_text(errors="replace").splitlines()
            except Exception:
                continue

            rel_path = str(f.relative_to(repo_path))

            for cat in cats:
                if cat not in SINK_PATTERNS:
                    continue
                for pat_info in SINK_PATTERNS[cat]:
                    try:
                        pattern = re.compile(pat_info["pattern"], re.IGNORECASE)
                    except re.error:
                        continue

                    for i, line in enumerate(lines, 1):
                        if pattern.search(line):
                            # Get context (2 lines before/after)
                            start = max(0, i - 3)
                            end = min(len(lines), i + 2)
                            snippet = "\n".join(lines[start:end])

                            severity = self._rate_hotspot_severity(cat, line, lang)

                            hotspots.append(Hotspot(
                                file=rel_path,
                                line=i,
                                category=cat,
                                pattern_desc=pat_info["desc"],
                                code_snippet=snippet[:500],
                                severity=severity,
                                language=lang,
                            ))

                            if len(hotspots) >= max_results:
                                break
                    if len(hotspots) >= max_results:
                        break
                if len(hotspots) >= max_results:
                    break
            if len(hotspots) >= max_results:
                break

        # Sort: critical > high > medium > low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        hotspots.sort(key=lambda h: severity_order.get(h.severity, 5))

        return [
            {
                "file": h.file,
                "line": h.line,
                "category": h.category,
                "description": h.pattern_desc,
                "code_snippet": h.code_snippet,
                "severity": h.severity,
                "language": h.language,
            }
            for h in hotspots
        ]

    def _rate_hotspot_severity(self, category: str, line: str, lang: str) -> str:
        """Rate hotspot severity based on category and context."""
        # Critical: direct user input in dangerous sinks
        user_input_indicators = [
            "request", "req.body", "req.params", "req.query",
            "$_GET", "$_POST", "$_REQUEST", "params[",
            "input(", "argv", "form.",
        ]
        has_user_input = any(ind in line for ind in user_input_indicators)

        if category in ("sqli", "command_injection", "deserialization"):
            return "critical" if has_user_input else "high"
        elif category in ("xss", "ssrf", "path_traversal"):
            return "high" if has_user_input else "medium"
        elif category == "crypto":
            return "medium"
        return "medium"

    # ── Function extraction ────────────────────────────────

    def extract_functions(
        self,
        repo_name: str,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Extract function/method definitions from a file using regex patterns.

        Supports Python, JavaScript/TypeScript, Java, Go, PHP, Ruby.
        """
        full_path = self.repos_root / repo_name / file_path
        if not full_path.exists():
            return [{"error": f"File not found: {file_path}"}]

        ext = full_path.suffix.lower()
        lang = LANG_MAP.get(ext, "other")

        try:
            content = full_path.read_text(errors="replace")
        except Exception as e:
            return [{"error": str(e)}]

        lines = content.splitlines()
        functions: list[FunctionInfo] = []

        # Language-specific function patterns
        patterns = self._get_function_patterns(lang)

        for pattern in patterns:
            for match in re.finditer(pattern, content, re.MULTILINE):
                line_num = content[:match.start()].count("\n") + 1

                # Try to extract function name from the match
                name = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                # Estimate end line (simple heuristic: next function or end of file)
                end_line = min(line_num + 30, len(lines))

                # Extract params if possible
                params = []
                if match.lastindex and match.lastindex >= 2:
                    params_str = match.group(2)
                    params = [p.strip() for p in params_str.split(",") if p.strip()]

                preview_start = max(0, line_num - 1)
                preview_end = min(len(lines), line_num + 4)
                preview = "\n".join(lines[preview_start:preview_end])

                functions.append(FunctionInfo(
                    name=name.strip(),
                    file=file_path,
                    start_line=line_num,
                    end_line=end_line,
                    language=lang,
                    params=params[:10],
                    body_preview=preview[:300],
                ))

        return [
            {
                "name": f.name,
                "file": f.file,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "language": f.language,
                "params": f.params,
                "body_preview": f.body_preview,
            }
            for f in functions
        ]

    def _get_function_patterns(self, lang: str) -> list[str]:
        """Get regex patterns for function extraction by language."""
        if lang == "python":
            return [
                r"^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)",
                r"^\s*class\s+(\w+)\s*(?:\([^)]*\))?:",
            ]
        elif lang in ("javascript", "typescript"):
            return [
                r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)",
                r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>",
                r"(\w+)\s*\(([^)]*)\)\s*\{",
                r"class\s+(\w+)",
            ]
        elif lang == "java":
            return [
                r"(?:public|private|protected|static|\s)*\s+[\w<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]*)?\{",
                r"class\s+(\w+)",
            ]
        elif lang == "golang":
            return [
                r"func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)",
            ]
        elif lang == "php":
            return [
                r"(?:public|private|protected|static|\s)*function\s+(\w+)\s*\(([^)]*)\)",
                r"class\s+(\w+)",
            ]
        elif lang == "ruby":
            return [
                r"def\s+(\w+[!?]?)\s*(?:\(([^)]*)\))?",
                r"class\s+(\w+)",
            ]
        return []

    # ── Git operations ─────────────────────────────────────

    def git_log(
        self,
        repo_name: str,
        max_count: int = 20,
        file_path: str | None = None,
    ) -> list[dict[str, str]]:
        """Get git commit log."""
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return [{"error": f"Repo '{repo_name}' not found"}]

        cmd = [
            "git", "-C", str(repo_path), "log",
            f"--max-count={max_count}",
            "--format=%H|%an|%ae|%aI|%s",
        ]
        if file_path:
            cmd.extend(["--", file_path])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return [{"error": result.stderr.strip()}]
        except subprocess.TimeoutExpired:
            return [{"error": "git log timed out"}]

        commits = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 4)
            if len(parts) == 5:
                commits.append({
                    "hash": parts[0],
                    "author": parts[1],
                    "email": parts[2],
                    "date": parts[3],
                    "message": parts[4],
                })
        return commits

    def git_diff(
        self,
        repo_name: str,
        commit_a: str = "HEAD~1",
        commit_b: str = "HEAD",
        file_path: str | None = None,
    ) -> dict[str, Any]:
        """Get diff between two commits."""
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return {"error": f"Repo '{repo_name}' not found"}

        cmd = ["git", "-C", str(repo_path), "diff", "--stat", commit_a, commit_b]
        if file_path:
            cmd.extend(["--", file_path])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            stat = result.stdout.strip()
        except Exception as e:
            return {"error": str(e)}

        # Also get the actual diff (limited)
        cmd_diff = ["git", "-C", str(repo_path), "diff", commit_a, commit_b]
        if file_path:
            cmd_diff.extend(["--", file_path])

        try:
            result2 = subprocess.run(cmd_diff, capture_output=True, text=True, timeout=15)
            diff = result2.stdout[:10000]  # cap
        except Exception:
            diff = ""

        return {
            "stat": stat,
            "diff": diff,
            "commit_a": commit_a,
            "commit_b": commit_b,
        }

    def git_blame(
        self,
        repo_name: str,
        file_path: str,
        start_line: int = 1,
        end_line: int = 50,
    ) -> list[dict[str, str]]:
        """Get git blame for specific line range."""
        repo_path = self.repos_root / repo_name
        full = repo_path / file_path
        if not full.exists():
            return [{"error": f"File not found: {file_path}"}]

        cmd = [
            "git", "-C", str(repo_path), "blame",
            f"-L{start_line},{end_line}",
            "--porcelain", file_path,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return [{"error": result.stderr.strip()}]
        except Exception as e:
            return [{"error": str(e)}]

        # Parse porcelain blame output
        blames = []
        current: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if line.startswith("\t"):
                current["code"] = line[1:]
                blames.append(current)
                current = {}
            elif line.startswith("author "):
                current["author"] = line[7:]
            elif line.startswith("author-time "):
                current["timestamp"] = line[12:]
            elif line.startswith("summary "):
                current["commit_msg"] = line[8:]
            elif len(line) == 40 or (len(line) > 40 and line[40] == " "):
                parts = line.split()
                if len(parts) >= 3:
                    current["commit"] = parts[0]
                    current["line"] = parts[2]

        return blames

    # ── Utility ────────────────────────────────────────────

    def _walk_files(self, root: Path):
        """Yield all relevant source files, skipping binaries and hidden dirs."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

            for fname in filenames:
                fpath = Path(dirpath) / fname
                ext = fpath.suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                try:
                    if fpath.stat().st_size > MAX_FILE_SIZE:
                        continue
                except Exception:
                    continue
                yield fpath

    def get_stats(self, repo_name: str) -> dict[str, Any]:
        """Get comprehensive stats for a repository."""
        repo_path = self.repos_root / repo_name
        if not repo_path.exists():
            return {"error": f"Repo '{repo_name}' not found"}

        info = self._get_repo_info(repo_path)

        # Count hotspots per category
        hotspot_counts: dict[str, int] = {}
        for f in self._walk_files(repo_path):
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            for cat, patterns in SINK_PATTERNS.items():
                for pat_info in patterns:
                    try:
                        if re.search(pat_info["pattern"], content, re.IGNORECASE):
                            hotspot_counts[cat] = hotspot_counts.get(cat, 0) + 1
                            break  # one per file per category
                    except re.error:
                        pass

        return {
            "name": info.name,
            "path": info.path,
            "languages": info.languages,
            "total_files": info.total_files,
            "total_lines": info.total_lines,
            "hotspot_indicators": hotspot_counts,
        }
