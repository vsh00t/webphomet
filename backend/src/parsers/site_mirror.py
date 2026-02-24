"""Site mirror output parser — converts JSON summary to structured data.

The site_mirror MCP tool returns a JSON object with download statistics.
This parser normalises it into a SiteMirrorResult for the persistence layer.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SiteMirrorResult:
    """Parsed site mirror output."""

    url: str = ""
    output_dir: str = ""
    phase1_files: int = 0
    phase2_extra_found: int = 0
    phase2_downloaded: int = 0
    total_files: int = 0
    total_size_bytes: int = 0
    elapsed_seconds: float = 0.0
    file_types: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "output_dir": self.output_dir,
            "phase1_files": self.phase1_files,
            "phase2_extra_found": self.phase2_extra_found,
            "phase2_downloaded": self.phase2_downloaded,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "total_size_mb": round(self.total_size_bytes / (1024 * 1024), 2),
            "elapsed_seconds": self.elapsed_seconds,
            "file_types": self.file_types,
        }


def parse_site_mirror(raw_output: str) -> SiteMirrorResult:
    """Parse the JSON output of the site_mirror tool.

    Parameters
    ----------
    raw_output:
        JSON string returned by ``site_mirror.mirror_site()``.

    Returns
    -------
    SiteMirrorResult with download statistics.
    """
    try:
        data = json.loads(raw_output)
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse site_mirror JSON output")
        return SiteMirrorResult()

    return SiteMirrorResult(
        url=data.get("url", ""),
        output_dir=data.get("output_dir", ""),
        phase1_files=data.get("phase1_files", 0),
        phase2_extra_found=data.get("phase2_extra_found", 0),
        phase2_downloaded=data.get("phase2_downloaded", 0),
        total_files=data.get("total_files", 0),
        total_size_bytes=data.get("total_size_bytes", 0),
        elapsed_seconds=data.get("elapsed_seconds", 0.0),
        file_types=data.get("file_types", {}),
    )
