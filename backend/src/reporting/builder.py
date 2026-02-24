"""Report builder — generates pentesting reports using Jinja2 templates.

Supports Markdown and PDF output.  PDF generation uses ``weasyprint``
(HTML intermediary) with a bundled CSS stylesheet.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


@dataclass
class ReportBuilder:
    """Builds pentesting reports from session data.

    Parameters
    ----------
    templates_dir:
        Path to the directory containing Jinja2 templates.
    """

    templates_dir: Path = TEMPLATES_DIR

    def __post_init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_markdown(
        self,
        *,
        session: dict[str, Any],
        targets: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        tool_runs: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Render the Markdown report template with the given data.

        Parameters
        ----------
        session:
            Pentest session data.
        targets:
            List of discovered targets.
        findings:
            List of security findings.
        tool_runs:
            List of tool run records.
        metadata:
            Optional extra metadata (tester name, date, etc.).

        Returns
        -------
        Rendered Markdown string.
        """
        template = self._env.get_template("report.md.j2")
        rendered = template.render(
            session=session,
            targets=targets,
            findings=findings,
            tool_runs=tool_runs,
            metadata=metadata or {},
        )
        logger.info(
            "Rendered report for session %s (%d findings)",
            session.get("id", "?"),
            len(findings),
        )
        return rendered

    def render_html(
        self,
        *,
        session: dict[str, Any],
        targets: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        tool_runs: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Render the HTML report template (used as PDF intermediary)."""
        template = self._env.get_template("report.html.j2")
        return template.render(
            session=session,
            targets=targets,
            findings=findings,
            tool_runs=tool_runs,
            metadata=metadata or {},
        )

    def markdown_to_pdf(
        self,
        markdown_content: str,
        output_path: Path,
    ) -> Path:
        """Convert a Markdown report to PDF via pandoc.

        Falls back to weasyprint (HTML intermediary) if pandoc is
        not available.

        Returns the resolved output path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Try pandoc first (produces better PDFs)
        if self._has_command("pandoc"):
            return self._pandoc_to_pdf(markdown_content, output_path)

        # Fallback: weasyprint via HTML intermediary
        return self._weasyprint_to_pdf(markdown_content, output_path)

    def generate_pdf(
        self,
        *,
        session: dict[str, Any],
        targets: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        tool_runs: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
        output_path: Path,
    ) -> Path:
        """Full pipeline: render HTML → convert to PDF via weasyprint.

        Returns the resolved output path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html = self.render_html(
            session=session,
            targets=targets,
            findings=findings,
            tool_runs=tool_runs,
            metadata=metadata,
        )

        try:
            from weasyprint import HTML  # type: ignore[import-untyped]

            css_path = self.templates_dir / "report.css"
            stylesheets = [str(css_path)] if css_path.exists() else []
            HTML(string=html).write_pdf(
                str(output_path),
                stylesheets=stylesheets,
            )
            logger.info("PDF report generated via weasyprint: %s", output_path)
        except ImportError:
            # Last resort: write HTML with a note
            html_path = output_path.with_suffix(".html")
            html_path.write_text(html, encoding="utf-8")
            logger.warning(
                "weasyprint not available, saved HTML instead: %s", html_path
            )
            return html_path

        return output_path

    def save(self, content: str, output_path: Path) -> Path:
        """Write rendered report content to a file.

        Returns the resolved path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        logger.info("Report saved to %s", output_path)
        return output_path

    # ── private helpers ───────────────────────────────────────

    @staticmethod
    def _has_command(name: str) -> bool:
        """Check if a CLI command is available."""
        try:
            subprocess.run(
                ["which", name],
                capture_output=True,
                check=True,
                timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def _pandoc_to_pdf(markdown: str, output_path: Path) -> Path:
        """Use pandoc to convert Markdown → PDF."""
        proc = subprocess.run(
            [
                "pandoc",
                "-f", "markdown",
                "-t", "pdf",
                "--pdf-engine=xelatex",
                "-V", "geometry:margin=2.5cm",
                "-V", "fontsize=11pt",
                "-o", str(output_path),
            ],
            input=markdown.encode("utf-8"),
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            logger.error("pandoc failed: %s", proc.stderr.decode()[:500])
            raise RuntimeError(f"pandoc PDF generation failed: {proc.stderr.decode()[:200]}")
        logger.info("PDF report generated via pandoc: %s", output_path)
        return output_path

    @staticmethod
    def _weasyprint_to_pdf(markdown: str, output_path: Path) -> Path:
        """Use markdown→HTML→weasyprint pipeline."""
        try:
            import markdown as md_lib  # type: ignore[import-untyped]
            from weasyprint import HTML  # type: ignore[import-untyped]

            html = md_lib.markdown(
                markdown,
                extensions=["tables", "fenced_code", "codehilite"],
            )
            # Wrap in basic HTML doc
            full_html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
body {{ font-family: sans-serif; margin: 2.5cm; font-size: 11pt; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; }}
th {{ background: #f5f5f5; }}
code {{ background: #f8f8f8; padding: 2px 4px; font-size: 0.9em; }}
pre {{ background: #f8f8f8; padding: 12px; overflow-x: auto; }}
h1 {{ color: #c0392b; }}
h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 0.3em; }}
</style>
</head><body>{html}</body></html>"""

            HTML(string=full_html).write_pdf(str(output_path))
            logger.info("PDF report generated via weasyprint: %s", output_path)
            return output_path
        except ImportError as e:
            raise RuntimeError(
                "Neither pandoc nor weasyprint+markdown are available for PDF generation"
            ) from e
