"""PdfReporter — generates a PDF report from the HTML report using WeasyPrint.

Falls back gracefully if WeasyPrint is not installed — logs a warning and skips.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from codeguardian.models.report import ReportArtifact

if TYPE_CHECKING:
    from pathlib import Path

    from codeguardian.models.scan import ScanResult

logger = logging.getLogger(__name__)


class PdfReporter:
    """Generates a PDF report by rendering HTML then converting via WeasyPrint."""

    def render(self, result: ScanResult, output_dir: Path | None) -> ReportArtifact | None:
        """Generate PDF report.

        Requires `weasyprint` package. If not installed, returns None with a warning.
        """
        if output_dir is None:
            return None

        try:
            from weasyprint import HTML  # type: ignore[import-untyped]
        except ImportError:
            logger.warning(
                "PDF report skipped: weasyprint not installed. "
                "Install with: pip install weasyprint"
            )
            return None

        # Generate HTML content first
        html_content = self._build_html(result)
        target = output_dir / "report.pdf"

        try:
            HTML(string=html_content).write_pdf(str(target))
            logger.info("PDF report generated: %s", target)
            return ReportArtifact(format="pdf", path=str(target))
        except Exception as exc:
            logger.error("Failed to generate PDF report: %s", exc)
            return None

    def _build_html(self, result: ScanResult) -> str:
        """Build HTML string optimized for PDF rendering."""
        from html import escape

        profile = result.project_profile
        findings = result.findings

        # Group findings by severity
        severity_groups: dict[str, list] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            severity_groups.setdefault(sev, []).append(f)

        # Build findings table
        findings_rows = []
        for f in sorted(findings, key=lambda x: _severity_rank(x.severity)):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_rows.append(
                f"<tr class='sev-{sev}'>"
                f"<td>{escape(sev.upper())}</td>"
                f"<td>{escape(f.title)}</td>"
                f"<td>{escape(f.location.file_path)}:{f.location.line_start or 0}</td>"
                f"<td>{escape(f.category)}</td>"
                f"<td>{escape(f.fix_suggestion or '')[:100]}</td>"
                f"</tr>"
            )

        # Dimension scores
        dim_rows = []
        for ds in (profile.dimension_scores or []):
            dim_rows.append(
                f"<tr><td>{escape(ds.dimension)}</td>"
                f"<td>{ds.score:.0f}/100</td>"
                f"<td>{escape(ds.risk_level)}</td></tr>"
            )

        findings_table = "\n".join(findings_rows)
        dimensions_table = "\n".join(dim_rows)

        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>CodeGuardian 代码质量审查报告</title>
<style>
  body {{ font-family: 'Noto Sans SC', 'Microsoft YaHei', sans-serif; margin: 40px; color: #333; font-size: 12px; }}
  h1 {{ color: #1a1a2e; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
  h2 {{ color: #16213e; margin-top: 30px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 11px; }}
  th {{ background: #16213e; color: white; }}
  tr:nth-child(even) {{ background: #f9f9f9; }}
  .sev-critical td:first-child {{ background: #dc3545; color: white; font-weight: bold; }}
  .sev-high td:first-child {{ background: #fd7e14; color: white; }}
  .sev-medium td:first-child {{ background: #ffc107; }}
  .sev-low td:first-child {{ background: #28a745; color: white; }}
  .sev-info td:first-child {{ background: #17a2b8; color: white; }}
  .summary-box {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; }}
  .score {{ font-size: 36px; font-weight: bold; color: #1a1a2e; }}
  .footer {{ margin-top: 40px; color: #666; font-size: 10px; border-top: 1px solid #ddd; padding-top: 10px; }}
</style>
</head>
<body>
<h1>CodeGuardian 代码质量审查报告</h1>

<div class="summary-box">
  <p>项目: <strong>{escape(profile.project_name)}</strong></p>
  <p>综合评分: <span class="score">{profile.overall_score:.0f}</span> / 100</p>
  <p>问题总数: <strong>{len(findings)}</strong>
    (Critical: {len(severity_groups.get('critical', []))},
     High: {len(severity_groups.get('high', []))},
     Medium: {len(severity_groups.get('medium', []))},
     Low: {len(severity_groups.get('low', []))})
  </p>
</div>

<h2>维度评分</h2>
<table>
<tr><th>维度</th><th>评分</th><th>风险等级</th></tr>
{dimensions_table}
</table>

<h2>问题详情 ({len(findings)} 项)</h2>
<table>
<tr><th>严重性</th><th>标题</th><th>位置</th><th>类别</th><th>修复建议</th></tr>
{findings_table}
</table>

<div class="footer">
  <p>由 CodeGuardian 自动生成 | 生成时间: {_now_str()}</p>
</div>
</body>
</html>"""


def _severity_rank(severity) -> int:
    """Sort severity (critical first)."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    val = severity.value if hasattr(severity, "value") else str(severity)
    return rank.get(val, 5)


def _now_str() -> str:
    """Current time as string."""
    from datetime import UTC, datetime
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
