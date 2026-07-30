"""Watch command: monitor file changes and auto-rescan."""

import asyncio
import time
from pathlib import Path

import typer

from codeguardian.cli.common import resolve_app_config_path, resolve_project_path, validate_path_exists
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.models.scan import ScanRequest


def watch_command(
    project: str = typer.Argument(".", help="Project path to watch"),
    interval: int = typer.Option(5, "--interval", "-i", help="Polling interval in seconds"),
    review_mode: str = typer.Option("ai_off", "--review-mode", help="AI review mode: ai_off / standard / ultra"),
    report: str = typer.Option("terminal", "--report", "-r", help="Report formats (comma-separated)"),
) -> None:
    """Watch for file changes and auto-rescan on modification."""
    project_path = resolve_project_path(project)
    validate_path_exists(project_path)

    app_config = load_app_config(resolve_app_config_path(project_path))
    report_formats = [fmt.strip() for fmt in report.split(",") if fmt.strip()]

    console.print(f"[bold cyan]👁 Watching[/bold cyan] {project_path}")
    console.print(f"[dim]Interval: {interval}s | Review: {review_mode} | Reports: {', '.join(report_formats)}[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    # Build initial snapshot of file mtimes
    last_snapshot = _snapshot_mtimes(project_path)
    scan_count = 0

    try:
        while True:
            time.sleep(interval)
            current = _snapshot_mtimes(project_path)
            changed = _detect_changes(last_snapshot, current)

            if not changed:
                continue

            scan_count += 1
            console.print(f"\n[yellow]⚡ Change detected ({len(changed)} files) — scan #{scan_count}[/yellow]")
            for f in changed[:5]:
                console.print(f"  [dim]  {f}[/dim]")
            if len(changed) > 5:
                console.print(f"  [dim]  ... and {len(changed) - 5} more[/dim]")

            request = ScanRequest(
                project_path=project_path,
                report_formats=report_formats,
                review_mode=review_mode,
                incremental=True,
            )

            orchestrator = Orchestrator(app_config)
            try:
                result = asyncio.run(orchestrator.run_scan(request))
                score = result.project_profile.overall_score
                finding_count = len(result.findings)
                status = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
                console.print(
                    f"  {status} Score: {score:.0f}/100 | "
                    f"Findings: {finding_count} | "
                    f"Duration: {result.duration_seconds:.1f}s"
                )
            except Exception as e:
                console.print(f"  [red]Scan error: {e}[/red]")

            last_snapshot = current

    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


def _snapshot_mtimes(root: Path) -> dict[str, float]:
    """Build a map of relative_path → mtime for all source files."""
    snapshot: dict[str, float] = {}
    source_extensions = {
        ".py", ".java", ".js", ".ts", ".tsx", ".go", ".cpp", ".c", ".h",
        ".hpp", ".cs", ".lua", ".rs", ".rb", ".yaml", ".yml", ".toml",
        ".json", ".xml", ".sql",
    }
    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in source_extensions:
                continue
            # Skip hidden dirs and common non-source
            rel = str(path.relative_to(root))
            if any(part.startswith(".") or part in {"node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
                   for part in Path(rel).parts):
                continue
            try:
                snapshot[rel] = path.stat().st_mtime
            except OSError:
                pass
    except OSError:
        pass
    return snapshot


def _detect_changes(old: dict[str, float], new: dict[str, float]) -> list[str]:
    """Return list of files that were added or modified."""
    changed: list[str] = []
    for path, mtime in new.items():
        if path not in old or old[path] != mtime:
            changed.append(path)
    return changed
