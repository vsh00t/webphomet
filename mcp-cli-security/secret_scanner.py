"""Secret Scanner — static analysis of downloaded web content.

Scans files in a mirrored site directory for:
  - Hardcoded API keys, tokens, passwords
  - AWS / GCP / Azure credentials
  - JWT tokens
  - Private keys
  - Database connection strings
  - Internal URLs / IPs
  - Debug/admin endpoints
  - Sensitive comments (TODO, FIXME, HACK with security context)
  - Exposed source maps
  - Environment variable references

Outputs JSON with categorised findings, each including:
  file, line, rule, severity, match (redacted), context.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


# ─── Severity levels ─────────────────────────────────────────

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"


# ─── Rule definitions ────────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern  # type: ignore[type-arg]
    description: str


_RULES: list[Rule] = [
    # ── API Keys & Tokens ────────────────────────────────────
    Rule(
        id="SEC-001",
        name="Generic API Key",
        severity=HIGH,
        pattern=re.compile(
            r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""",
            re.IGNORECASE,
        ),
        description="Hardcoded API key detected",
    ),
    Rule(
        id="SEC-002",
        name="Generic Secret/Password",
        severity=CRITICAL,
        pattern=re.compile(
            r"""(?:password|passwd|pwd|secret|token|auth[_-]?token)\s*[:=]\s*['"]([^\s'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        description="Hardcoded password or secret token",
    ),
    Rule(
        id="SEC-003",
        name="Generic Bearer Token",
        severity=CRITICAL,
        pattern=re.compile(
            r"""(?:Bearer\s+)([a-zA-Z0-9_\-\.]{20,})""",
        ),
        description="Exposed bearer/authorization token",
    ),

    # ── Cloud Provider Credentials ───────────────────────────
    Rule(
        id="SEC-010",
        name="AWS Access Key",
        severity=CRITICAL,
        pattern=re.compile(r"(?:^|['\"\s])((AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})"),
        description="AWS Access Key ID",
    ),
    Rule(
        id="SEC-011",
        name="AWS Secret Key",
        severity=CRITICAL,
        pattern=re.compile(
            r"""(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?""",
            re.IGNORECASE,
        ),
        description="AWS Secret Access Key",
    ),
    Rule(
        id="SEC-012",
        name="Google API Key",
        severity=HIGH,
        pattern=re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        description="Google Cloud API key",
    ),
    Rule(
        id="SEC-013",
        name="Google OAuth Client Secret",
        severity=CRITICAL,
        pattern=re.compile(
            r"""client_secret.*?['"]([a-zA-Z0-9_\-]{24,})['"]""",
            re.IGNORECASE,
        ),
        description="Google OAuth client secret",
    ),
    Rule(
        id="SEC-014",
        name="Azure Storage Key",
        severity=CRITICAL,
        pattern=re.compile(
            r"""AccountKey\s*=\s*([a-zA-Z0-9/+=]{44,})""",
            re.IGNORECASE,
        ),
        description="Azure Storage account key",
    ),

    # ── JWT ───────────────────────────────────────────────────
    Rule(
        id="SEC-020",
        name="JWT Token",
        severity=HIGH,
        pattern=re.compile(
            r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-+/=]{10,}"
        ),
        description="Exposed JWT token (may contain claims/secrets)",
    ),

    # ── Private Keys ─────────────────────────────────────────
    Rule(
        id="SEC-030",
        name="Private Key (PEM)",
        severity=CRITICAL,
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        ),
        description="Private key in PEM format",
    ),
    Rule(
        id="SEC-031",
        name="Private Key (PKCS8)",
        severity=CRITICAL,
        pattern=re.compile(
            r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----"
        ),
        description="Encrypted private key (PKCS8)",
    ),

    # ── Database ─────────────────────────────────────────────
    Rule(
        id="SEC-040",
        name="Database Connection String",
        severity=CRITICAL,
        pattern=re.compile(
            r"""(?:mongodb|mysql|postgres(?:ql)?|mssql|redis|amqp)://[^\s'"<>]{10,}""",
            re.IGNORECASE,
        ),
        description="Database connection string with potential credentials",
    ),
    Rule(
        id="SEC-041",
        name="SQL Credentials in Config",
        severity=HIGH,
        pattern=re.compile(
            r"""(?:db_pass(?:word)?|database_password|sql_password)\s*[:=]\s*['"]([^\s'"]+)['"]""",
            re.IGNORECASE,
        ),
        description="Database password in configuration",
    ),

    # ── Internal Infrastructure ──────────────────────────────
    Rule(
        id="SEC-050",
        name="Internal IP Address",
        severity=MEDIUM,
        pattern=re.compile(
            r"""(?:^|[\s'"=])"""
            r"((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
            r"|(?:192\.168\.\d{1,3}\.\d{1,3}))"
        ),
        description="Internal/private IP address leaked",
    ),
    Rule(
        id="SEC-051",
        name="Internal URL/Endpoint",
        severity=MEDIUM,
        pattern=re.compile(
            r"""https?://(?:localhost|127\.0\.0\.1|internal|intranet|staging|dev\.|admin\.)[^\s'"<>]*""",
            re.IGNORECASE,
        ),
        description="Internal, staging, or admin URL exposed",
    ),

    # ── Debug / Admin ────────────────────────────────────────
    Rule(
        id="SEC-060",
        name="Debug Mode Enabled",
        severity=MEDIUM,
        pattern=re.compile(
            r"""(?:DEBUG|debug)\s*[:=]\s*(?:true|1|['"]true['"])""",
            re.IGNORECASE,
        ),
        description="Debug mode appears to be enabled",
    ),
    Rule(
        id="SEC-061",
        name="Admin/Debug Endpoint",
        severity=MEDIUM,
        pattern=re.compile(
            r"""['"](?:/(?:admin|debug|phpinfo|phpmyadmin|_profiler|elmah|trace|actuator|swagger|graphql)[/'"?])""",
            re.IGNORECASE,
        ),
        description="Admin or debug endpoint reference",
    ),
    Rule(
        id="SEC-062",
        name="Source Map Reference",
        severity=LOW,
        pattern=re.compile(r"sourceMappingURL\s*=\s*(\S+\.map)"),
        description="JavaScript source map reference — may expose original source code",
    ),

    # ── Sensitive Comments ───────────────────────────────────
    Rule(
        id="SEC-070",
        name="Security-Relevant Comment",
        severity=LOW,
        pattern=re.compile(
            r"""(?://|/\*|#|<!--)\s*(?:TODO|FIXME|HACK|BUG|XXX|SECURITY|VULNERABLE|UNSAFE|TEMP)\b[^*\n]{5,}""",
            re.IGNORECASE,
        ),
        description="Developer comment with potential security relevance",
    ),

    # ── Miscellaneous Secrets ────────────────────────────────
    Rule(
        id="SEC-080",
        name="Slack Webhook",
        severity=HIGH,
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}"
        ),
        description="Slack incoming webhook URL",
    ),
    Rule(
        id="SEC-081",
        name="GitHub Token",
        severity=CRITICAL,
        pattern=re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}"),
        description="GitHub personal access token or OAuth token",
    ),
    Rule(
        id="SEC-082",
        name="Stripe Key",
        severity=CRITICAL,
        pattern=re.compile(r"(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}"),
        description="Stripe API key (live or test)",
    ),
    Rule(
        id="SEC-083",
        name="SendGrid Key",
        severity=HIGH,
        pattern=re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        description="SendGrid API key",
    ),
    Rule(
        id="SEC-084",
        name="Twilio Key",
        severity=HIGH,
        pattern=re.compile(r"SK[a-f0-9]{32}"),
        description="Twilio API key",
    ),
    Rule(
        id="SEC-085",
        name="Firebase Config",
        severity=MEDIUM,
        pattern=re.compile(
            r"""(?:firebase|firebaseConfig)\s*[:=]\s*\{[^}]*apiKey[^}]+\}""",
            re.IGNORECASE | re.DOTALL,
        ),
        description="Firebase configuration object with API key",
    ),
    Rule(
        id="SEC-086",
        name="Environment Variable Reference",
        severity=INFO,
        pattern=re.compile(
            r"""process\.env\.[A-Z_]{3,}""",
        ),
        description="Reference to environment variable (may indicate secret handling)",
    ),
]


# ─── Scanner ─────────────────────────────────────────────────


SCANNABLE_EXTENSIONS = frozenset(
    {".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".css", ".json",
     ".xml", ".svg", ".map", ".mjs", ".env", ".yml", ".yaml",
     ".toml", ".ini", ".cfg", ".conf", ".properties", ".txt", ".md"}
)

# Skip binary / noise files
SKIP_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
     ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp3", ".mp4",
     ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz", ".br"}
)

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    rule_name: str
    severity: str
    match: str          # redacted
    context: str        # line content (trimmed)
    description: str


def _redact(match_str: str, keep: int = 6) -> str:
    """Redact sensitive match, keeping first few chars."""
    if len(match_str) <= keep + 4:
        return match_str[:4] + "****"
    return match_str[:keep] + "****" + match_str[-3:]


def scan_directory(
    directory: str,
    *,
    max_findings: int = 500,
) -> dict[str, Any]:
    """Scan all files under *directory* and return categorised findings.

    Returns
    -------
    dict with keys: directory, total_files_scanned, total_findings,
    findings (list[dict]), severity_summary (dict), rules_triggered (dict).
    """
    findings: list[Finding] = []
    files_scanned = 0

    for root, _, files in os.walk(directory):
        for fname in files:
            if len(findings) >= max_findings:
                break

            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            if ext and ext not in SCANNABLE_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)

            # Skip large files
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            files_scanned += 1
            rel_path = os.path.relpath(fpath, directory)

            for line_no, line_content in enumerate(lines, start=1):
                if len(findings) >= max_findings:
                    break
                for rule in _RULES:
                    m = rule.pattern.search(line_content)
                    if m:
                        match_text = m.group(1) if m.lastindex else m.group(0)
                        findings.append(Finding(
                            file=rel_path,
                            line=line_no,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            match=_redact(match_text),
                            context=line_content.strip()[:200],
                            description=rule.description,
                        ))

    # Deduplicate exact same file+line+rule
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Summaries
    sev_summary: dict[str, int] = {}
    rules_triggered: dict[str, int] = {}
    for f in unique:
        sev_summary[f.severity] = sev_summary.get(f.severity, 0) + 1
        rules_triggered[f.rule_id] = rules_triggered.get(f.rule_id, 0) + 1

    return {
        "directory": directory,
        "total_files_scanned": files_scanned,
        "total_findings": len(unique),
        "severity_summary": dict(sorted(sev_summary.items())),
        "rules_triggered": dict(sorted(
            rules_triggered.items(), key=lambda x: -x[1]
        )),
        "findings": [asdict(f) for f in unique],
    }


# ─── CLI entry point ─────────────────────────────────────────


def main() -> None:
    """CLI: secret_scanner.py <directory> [--max-findings N]"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan downloaded site content for secrets and sensitive data"
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument(
        "--max-findings", type=int, default=500,
        help="Maximum number of findings to report (default: 500)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(json.dumps({"error": f"Directory not found: {args.directory}"}))
        sys.exit(1)

    result = scan_directory(args.directory, max_findings=args.max_findings)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
