"""Site Mirror — download all reachable content from a target URL.

Two-phase strategy:
  1) wget recursive: downloads HTML, CSS, JS, images, fonts, etc.
  2) Static extraction: parses downloaded JS/HTML/CSS for additional
     URLs (fetch calls, lazy-loaded chunks, source maps, API endpoints)
     and downloads those too.

Designed to run inside the MCP CLI-Security container.
Output is written to /app/artifacts/<session_id>/mirror/<domain>/.
Returns JSON summary on stdout.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


# ─── Defaults (overridable via CLI flags) ─────────────────────
DEFAULT_DEPTH = 8
DEFAULT_WAIT = 0.3
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_GLOBAL_TIMEOUT = 300  # 5 min per URL
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# ─── URL extraction patterns ─────────────────────────────────
_URL_PATTERNS = [
    # Absolute URLs
    re.compile(r"https?://[^\s\"'<>\)\}\]]+", re.IGNORECASE),
    # src, href, url(), data-* attributes
    re.compile(
        r"(?:src|href|action|url)\s*[=:(]\s*[\"']([^\"'>\s]+)[\"']",
        re.IGNORECASE,
    ),
    # fetch() calls
    re.compile(r"fetch\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    # import / require
    re.compile(r"(?:import|require)\s*\(?[\"']([^\"']+)[\"']", re.IGNORECASE),
    # JSON config URLs
    re.compile(
        r"\"(?:url|endpoint|api|href|src|path)\"\s*:\s*\"([^\"]+)\"",
        re.IGNORECASE,
    ),
    # Lazy-loaded chunks (Angular, React, Webpack)
    re.compile(
        r"[\"']([^\"']*\.(?:chunk|bundle|module)\.[^\"']+)[\"']",
        re.IGNORECASE,
    ),
    # Source maps
    re.compile(r"sourceMappingURL=([^\s]+)", re.IGNORECASE),
]

_PARSEABLE_EXTENSIONS = frozenset(
    {".html", ".htm", ".js", ".jsx", ".ts", ".tsx",
     ".css", ".json", ".xml", ".svg", ".map", ".mjs"}
)

_ASSET_EXTENSIONS = frozenset(
    {".js", ".css", ".json", ".woff", ".woff2", ".ttf", ".eot",
     ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
     ".map", ".mjs"}
)


# ─── Helpers ──────────────────────────────────────────────────


def _parse_url_info(url: str) -> dict:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    segments = [s for s in path.split("/") if s]
    return {
        "domain": parsed.netloc.replace(":", "_"),
        "last_dir": segments[-1] if segments else "root",
        "num_dirs": len(segments),
        "path": path,
        "base_url": f"{parsed.scheme}://{parsed.netloc}",
        "netloc": parsed.netloc,
    }


def _build_wget_cmd(url: str, output_dir: str, info: dict, cfg: dict) -> list[str]:
    return [
        "wget",
        "--recursive",
        "--no-parent",
        f"--level={cfg['depth']}",
        "--page-requisites",
        "--adjust-extension",
        "--convert-links",
        "--backup-converted",
        "--no-host-directories",
        f"--cut-dirs={info['num_dirs']}",
        "--directory-prefix", output_dir,
        "--accept", "*",
        f"--timeout={cfg['timeout']}",
        f"--tries={cfg['retries']}",
        f"--wait={cfg['wait']}",
        "--random-wait",
        "--no-check-certificate",
        "--content-disposition",
        f"--user-agent={USER_AGENT}",
        "-e", "robots=off",
        "--header=Accept: text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8",
        "--header=Accept-Language: es-ES,es;q=0.9,en;q=0.8",
        "--header=Accept-Encoding: identity",
        "--header=Sec-Fetch-Dest: document",
        "--header=Sec-Fetch-Mode: navigate",
        "--header=Sec-Fetch-Site: none",
        "--no-verbose",
        "--continue",
        f"--domains={info['netloc']}",
        url,
    ]


# ─── Phase 2: extract additional URLs ────────────────────────


def _extract_urls(directory: str, base_url: str) -> set[str]:
    extra: set[str] = set()
    for root, _, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _PARSEABLE_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue
            for pattern in _URL_PATTERNS:
                for match in pattern.finditer(content):
                    u = (match.group(1) if match.lastindex else match.group(0))
                    u = u.strip().rstrip(",;)}]")
                    if u.startswith("//"):
                        u = "https:" + u
                    elif u.startswith("/"):
                        u = base_url + u
                    if u.startswith("http"):
                        extra.add(u)
    return extra


def _download_extras(urls: set[str], output_dir: str, domain: str) -> int:
    """Download extra assets found in phase 2."""
    filtered: list[str] = []
    for u in urls:
        parsed = urlparse(u)
        if domain not in parsed.netloc:
            continue
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext in _ASSET_EXTENSIONS or not ext:
            local_path = os.path.join(output_dir, parsed.path.lstrip("/"))
            if not os.path.exists(local_path):
                filtered.append(u)

    downloaded = 0
    for u in filtered:
        try:
            parsed = urlparse(u)
            local_path = os.path.join(output_dir, parsed.path.lstrip("/"))
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            result = subprocess.run(
                [
                    "curl", "-sS", "-L",
                    "--max-time", "15",
                    "-H", f"User-Agent: {USER_AGENT}",
                    "-H", "Accept: */*",
                    "-k",
                    "-o", local_path,
                    u,
                ],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0 and os.path.exists(local_path):
                if os.path.getsize(local_path) > 0:
                    downloaded += 1
                else:
                    os.remove(local_path)
        except Exception:
            continue
    return downloaded


# ─── Main mirror routine ─────────────────────────────────────


def mirror_site(
    url: str,
    output_dir: str,
    *,
    depth: int = DEFAULT_DEPTH,
    wait: float = DEFAULT_WAIT,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    global_timeout: int = DEFAULT_GLOBAL_TIMEOUT,
) -> dict:
    """Mirror a site and return a JSON-serialisable summary.

    Returns
    -------
    dict with keys: url, output_dir, phase1_files, phase2_extra_found,
    phase2_downloaded, total_files, total_size_bytes, elapsed_seconds,
    file_types (extension → count).
    """
    info = _parse_url_info(url)
    site_dir = os.path.join(output_dir, info["domain"])
    os.makedirs(site_dir, exist_ok=True)

    cfg = dict(depth=depth, wait=wait, timeout=timeout, retries=retries)
    cmd = _build_wget_cmd(url, site_dir, info, cfg)

    start = time.time()

    # ── Phase 1: wget recursive ──────────────────────────────
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            proc.communicate(timeout=global_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    except Exception:
        pass

    phase1_files = sum(len(fs) for _, _, fs in os.walk(site_dir))

    # ── Phase 2: extract and download extras ─────────────────
    extra_urls = _extract_urls(site_dir, info["base_url"])
    base_domain = urlparse(url).netloc.split(":")[0]
    same_domain = {u for u in extra_urls if base_domain in urlparse(u).netloc}
    phase2_downloaded = _download_extras(same_domain, site_dir, base_domain)

    # ── Summary ──────────────────────────────────────────────
    total_files = sum(len(fs) for _, _, fs in os.walk(site_dir))
    total_size = sum(
        os.path.getsize(os.path.join(d, f))
        for d, _, files in os.walk(site_dir) for f in files
    )

    # File-type histogram
    ext_counts: dict[str, int] = {}
    for _, _, files in os.walk(site_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower() or "(no ext)"
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    elapsed = round(time.time() - start, 1)

    return {
        "url": url,
        "output_dir": site_dir,
        "phase1_files": phase1_files,
        "phase2_extra_found": len(same_domain),
        "phase2_downloaded": phase2_downloaded,
        "total_files": total_files,
        "total_size_bytes": total_size,
        "elapsed_seconds": elapsed,
        "file_types": dict(sorted(ext_counts.items(), key=lambda x: -x[1])),
    }


# ─── CLI entry point ─────────────────────────────────────────

def main() -> None:
    """CLI: site_mirror.py <url> <output_dir> [--depth N] [--timeout N] [--global-timeout N]"""
    import argparse

    parser = argparse.ArgumentParser(description="Mirror a website for offline analysis")
    parser.add_argument("url", help="Target URL to mirror")
    parser.add_argument("output_dir", help="Base directory for downloaded content")
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--wait", type=float, default=DEFAULT_WAIT)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--global-timeout", type=int, default=DEFAULT_GLOBAL_TIMEOUT)

    args = parser.parse_args()
    result = mirror_site(
        args.url,
        args.output_dir,
        depth=args.depth,
        wait=args.wait,
        timeout=args.timeout,
        retries=args.retries,
        global_timeout=args.global_timeout,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
