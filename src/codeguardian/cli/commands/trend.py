"""Trend command: summarize score and risk changes across saved snapshots."""

from __future__ import annotations

from contextlib import suppress

import typer

from rich.table import Table

from codeguardian.cli.common import resolve_project_path, validate_path_exists
from codeguardian.cli.output import console
from codeguardian.models.scan import ScanResult
from codeguardian.storage.snapshots import list_snapshots


def trend_command(
    path: str = typer.Argument(".", help="Path to the project directory"),
    limit: int = typer.Option(5, "--limit", "-n", help="How many recent snapshots to include"),
) -> None:
    """Show the quality trend across recent snapshots for a project."""
    if limit < 2:
        console.print("[red]Invalid limit:[/red] trend analysis needs at least 2 snapshots.")
        raise typer.Exit(code=1)

    project_path = resolve_project_path(path)
    validate_path_exists(project_path)

    snapshot_paths = list_snapshots(project_path=project_path)
    if len(snapshot_paths) < 2:
        console.print(
            "[red]Not enough snapshots found.[/red] "
            f"Expected at least 2 timestamped snapshots under {project_path / '.codeguardian'}."
        )
        raise typer.Exit(code=1)

    snapshots: list[ScanResult] = []
    for snapshot_path in snapshot_paths[:limit]:
        with suppress(ValueError, TypeError):
            snapshots.append(ScanResult.model_validate_json(snapshot_path.read_text(encoding="utf-8")))


    if len(snapshots) < 2:
        console.print("[red]Unable to load enough valid snapshots for trend analysis.[/red]")
        raise typer.Exit(code=1)

    snapshots.sort(key=_snapshot_sort_key)
    first = snapshots[0]
    last = snapshots[-1]

    score_delta = round(last.project_profile.overall_score - first.project_profile.overall_score, 1)
    findings_delta = len(last.findings) - len(first.findings)
    critical_delta = _count_critical(last) - _count_critical(first)
    blocking_delta = _count_blocking(last) - _count_blocking(first)
    trend_status = _classify_trend(score_delta, findings_delta, critical_delta, blocking_delta)
    trend_color = {"improving": "green", "stable": "yellow", "regressing": "red"}[trend_status]

    console.print("\n[bold]Quality Trend[/bold]")
    console.print(f"  Project: [cyan]{last.project_profile.project_name}[/cyan]")
    console.print(f"  Snapshots analyzed: [bold]{len(snapshots)}[/bold]")
    console.print(f"  Trend: [{trend_color}]{trend_status}[/{trend_color}]")
    console.print(
        f"  Score delta: [bold]{score_delta:+.1f}[/bold] | "
        f"Findings delta: {findings_delta:+d} | "
        f"Critical delta: {critical_delta:+d} | "
        f"Blocking delta: {blocking_delta:+d}"
    )

    table = Table(title="Recent Snapshots")
    table.add_column("Time")
    table.add_column("Scan")
    table.add_column("Mode")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Critical", justify="right")
    table.add_column("Blocking", justify="right")

    for snapshot in snapshots:
        table.add_row(
            _format_snapshot_time(snapshot),
            snapshot.scan_id or "-",
            f"{snapshot.coverage}/{snapshot.ai_mode}",
            f"{snapshot.project_profile.overall_score:.1f}",
            str(len(snapshot.findings)),
            str(_count_critical(snapshot)),
            str(_count_blocking(snapshot)),
        )

    console.print(table)


def _snapshot_sort_key(snapshot: ScanResult) -> tuple[str, str]:
    return (snapshot.finished_at or snapshot.started_at or "", snapshot.scan_id or "")


def _format_snapshot_time(snapshot: ScanResult) -> str:
    timestamp = snapshot.finished_at or snapshot.started_at or ""
    if len(timestamp) >= 16:
        return timestamp[:16].replace("T", " ")
    return timestamp or "-"


def _count_critical(snapshot: ScanResult) -> int:
    return sum(1 for finding in snapshot.findings if finding.severity.value == "critical")


def _count_blocking(snapshot: ScanResult) -> int:
    return sum(1 for finding in snapshot.findings if finding.is_blocking)


def _classify_trend(score_delta: float, findings_delta: int, critical_delta: int, blocking_delta: int) -> str:
    if score_delta <= -5 or critical_delta > 0 or blocking_delta > 0:
        return "regressing"
    if score_delta >= 5 and findings_delta <= 0 and critical_delta <= 0 and blocking_delta <= 0:
        return "improving"
    return "stable"
