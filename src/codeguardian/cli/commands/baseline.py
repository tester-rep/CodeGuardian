"""Baseline command: create or refresh a reusable quality baseline snapshot."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from codeguardian.cli.common import (
    resolve_app_config_path,
    resolve_project_path,
    validate_path_exists,
)
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.core.planner import VALID_DIMENSIONS, find_unsupported_dimensions
from codeguardian.models.scan import ScanRequest, ScanResult
from codeguardian.storage.snapshots import load_latest_snapshot, snapshot_dir_for_project

DEFAULT_BASELINE_FILENAME = "baseline.json"


def baseline_command(
    path: str = typer.Argument(".", help="Path to the project directory"),
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (codeguardian.toml)",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Baseline file path (relative paths are resolved under the project root)",
    ),
    latest: bool = typer.Option(
        False,
        "--latest",
        help="Use the latest saved snapshot instead of running a fresh scan",
    ),
    depth: str | None = typer.Option(
        None,
        "--depth",
        "-d",
        help="Analysis depth for a fresh baseline scan: quick / standard / deep",
    ),
    dimensions: str | None = typer.Option(
        None,
        "--dimensions",
        help=(
            "Comma-separated list of dimensions to include in a fresh baseline scan "
            f"(supported: {', '.join(VALID_DIMENSIONS)}, or all)"
        ),
    ),
    lang: str | None = typer.Option(
        None,
        "--lang",
        "-l",
        help="Comma-separated languages to include in a fresh baseline scan",
    ),
) -> None:
    """Create a baseline snapshot that can suppress already-known findings in future scans."""
    project_path = resolve_project_path(path)
    validate_path_exists(project_path)

    app_config = load_app_config(resolve_app_config_path(project_path, config))
    target_path = _resolve_baseline_output(project_path, output)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if latest:
        result = load_latest_snapshot(project_path=project_path)
        if result is None:
            console.print(
                "[red]No latest snapshot found.[/red] "
                f"Expected `.codeguardian/latest.json` under {project_path}. "
                "Run `codeguardian scan` first or omit `--latest` to build a fresh baseline."
            )
            raise typer.Exit(code=1)
        source_label = "latest snapshot"
    else:
        requested_dimensions = (
            [item.strip() for item in dimensions.split(",") if item.strip()]
            if dimensions
            else app_config.scan.dimensions
        )
        unsupported_dimensions = find_unsupported_dimensions(requested_dimensions)
        if unsupported_dimensions:
            console.print(
                "[red]Unsupported dimension(s):[/red] "
                f"{', '.join(sorted(set(unsupported_dimensions)))}\n"
                f"Supported: {', '.join(VALID_DIMENSIONS)}"
            )
            raise typer.Exit(code=1)

        request = ScanRequest(
            project_path=project_path,
            report_formats=[],
            depth=depth.strip().lower() if depth is not None else app_config.scan.depth,
            dimensions=requested_dimensions,
            languages=[item.strip() for item in lang.split(",") if item.strip()] if lang else app_config.scan.languages,
        )
        result = asyncio.run(Orchestrator(app_config).run_scan(request))
        source_label = "fresh scan"

    _write_baseline_snapshot(target_path, result)

    console.print(f"[green]Baseline saved[/green] {target_path}")
    console.print(f"  Source: [cyan]{source_label}[/cyan]")
    console.print(f"  Score: [bold]{result.project_profile.overall_score:.0f}[/bold]/100")
    console.print(f"  Findings captured: {len(result.findings)}")
    console.print("\n[bold]Next step[/bold]")
    console.print(f"  codeguardian scan {project_path} --baseline {target_path}")


def _resolve_baseline_output(project_path: Path, output: str | None) -> Path:
    if output is None:
        return snapshot_dir_for_project(project_path) / DEFAULT_BASELINE_FILENAME

    target = Path(output)
    if not target.is_absolute():
        target = project_path / target
    return target.resolve()


def _write_baseline_snapshot(target_path: Path, result: ScanResult) -> None:
    target_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
