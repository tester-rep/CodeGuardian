"""Diff command: compare quality between snapshots or Git refs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from codeguardian.cli.common import resolve_project_path, validate_path_exists
from codeguardian.cli.output import console
from codeguardian.core.diff_service import DiffService
from codeguardian.storage.snapshots import load_latest_snapshot

if TYPE_CHECKING:
    from codeguardian.models.scan import DiffResult, ScanResult



def diff_command(
    base: str | None = typer.Argument(None, help="Base snapshot/report JSON path or Git ref"),
    target: str | None = typer.Argument(None, help="Target snapshot/report JSON path or Git ref"),
    baseline: str | None = typer.Option(None, "--baseline", help="Baseline snapshot/report JSON path"),
    project: str | None = typer.Option(None, "--project", "-p", help="Project path used for snapshot lookup or Git ref diff"),
) -> None:
    """Compare two scan states and highlight new/resolved risks."""
    service = DiffService()
    project_path = resolve_project_path(project or ".")

    if baseline:
        if project:
            validate_path_exists(project_path)
        base_result, target_result, base_label, target_label = _resolve_baseline_inputs(service, baseline, project_path)
        diff = service.compare(
            base_result,
            target_result,
            comparison_mode="snapshot",
            base_label=base_label,
            target_label=target_label,
        )
    elif base and target:
        base_path = Path(base).resolve()
        target_path = Path(target).resolve()
        if base_path.exists() and target_path.exists():
            diff = service.compare(
                service.load_result(base_path),
                service.load_result(target_path),
                comparison_mode="snapshot",
                base_label=str(base_path),
                target_label=str(target_path),
            )
        else:
            validate_path_exists(project_path)
            diff = service.compare_git_refs(project_path, base, target)
    else:
        console.print(
            "[red]Usage error:[/red] provide either `diff <base.json> <target.json>`, `diff <base-ref> <target-ref> --project .`, "
            "or `diff --baseline <baseline.json>`."
        )
        raise typer.Exit(code=1)

    _render_diff(diff)


def _resolve_baseline_inputs(
    service: DiffService,
    baseline: str,
    project_path: Path,
) -> tuple[ScanResult, ScanResult, str, str]:

    baseline_path = Path(baseline).resolve()
    if not baseline_path.exists():
        console.print(f"[red]Snapshot/report not found:[/red] {baseline_path}")
        raise typer.Exit(code=1)

    target_result = load_latest_snapshot(project_path=project_path)
    if target_result is None:
        console.print(
            "[red]No latest snapshot found.[/red] "
            f"Expected `.codeguardian/latest.json` under {project_path}."
        )
        raise typer.Exit(code=1)

    return service.load_result(baseline_path), target_result, str(baseline_path), "latest snapshot"


def _render_diff(diff: DiffResult) -> None:

    console.print("\n[bold]Diff summary[/bold]")
    console.print(f"  Mode: [magenta]{diff.comparison_mode}[/magenta]")
    console.print(f"  Base: [green]{diff.base_label or 'base'}[/green]")
    console.print(f"  Target: [cyan]{diff.target_label or 'target'}[/cyan]")
    if diff.merge_base:
        console.print(f"  Merge base: [yellow]{diff.merge_base}[/yellow]")
    if diff.changed_files:
        console.print(f"  Changed files: [bold]{len(diff.changed_files)}[/bold]")
    if diff.touched_hotspots:
        console.print(f"  Touched hotspots: [bold red]{len(diff.touched_hotspots)}[/bold red]")
    console.print(f"  Score: {diff.base_score:.1f} -> {diff.target_score:.1f} ([bold]{diff.score_delta:+.1f}[/bold])")
    console.print(f"  New findings: [red]{len(diff.new_findings)}[/red]")
    console.print(f"  Resolved findings: [green]{len(diff.resolved_findings)}[/green]")

    if diff.regression_metrics:
        console.print("\n[bold]Project metric deltas[/bold]")
        for metric in diff.regression_metrics[:10]:
            unit = metric.unit or ""
            console.print(
                f"  - {metric.metric_name}: {metric.extra.get('base', 0.0):.1f}{unit} -> "
                f"{metric.extra.get('target', 0.0):.1f}{unit} ({metric.value:+.1f}{unit})"
            )

    if diff.changed_files:
        console.print("\n[bold]Changed files[/bold]")
        for file_path in diff.changed_files[:10]:
            console.print(f"  - {file_path}")

    if diff.touched_hotspots:
        console.print("\n[bold red]Touched hotspots[/bold red]")
        for file_path in diff.touched_hotspots[:10]:
            console.print(f"  - {file_path}")

    if diff.new_findings:
        console.print("\n[bold red]New findings[/bold red]")
        for finding in diff.new_findings[:10]:
            console.print(
                f"  - {finding.id} [{finding.severity.value}] {finding.title} "
                f"({finding.location.file_path}:{finding.location.line_start or 1})"
            )

    if diff.resolved_findings:
        console.print("\n[bold green]Resolved findings[/bold green]")
        for finding in diff.resolved_findings[:10]:
            console.print(
                f"  - {finding.id} [{finding.severity.value}] {finding.title} "
                f"({finding.location.file_path}:{finding.location.line_start or 1})"
            )
