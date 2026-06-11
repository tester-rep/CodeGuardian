"""Analyze command: single-dimension deep analysis."""

import asyncio

import typer

from codeguardian.cli.common import (
    resolve_app_config_path,
    resolve_project_path,
    validate_path_exists,
)
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import Orchestrator
from codeguardian.core.planner import VALID_DIMENSIONS
from codeguardian.models.scan import ScanRequest


def analyze_command(
    dimension: str = typer.Argument(
        ...,
        help=f"Analysis dimension: {', '.join(VALID_DIMENSIONS)}",
    ),
    path: str = typer.Argument(
        ".",
        help="Project path",
    ),
) -> None:
    """Run a deep analysis of a single dimension."""
    dimension = dimension.lower().strip()
    if dimension not in VALID_DIMENSIONS:
        console.print(
            f"[red]Invalid dimension:[/red] {dimension}\n"
            f"Valid options: {', '.join(VALID_DIMENSIONS)}"
        )
        raise typer.Exit(code=1)

    project_path = resolve_project_path(path)
    validate_path_exists(project_path)

    app_config = load_app_config(resolve_app_config_path(project_path))


    request = ScanRequest(
        project_path=project_path,
        report_formats=["json"],
        depth="deep",
        dimensions=[dimension],
    )

    orchestrator = Orchestrator(app_config)
    result = asyncio.run(orchestrator.run_scan(request))

    console.print(
        f"[green][{dimension.upper()}][/green] Analysis complete — "
        f"Score: {result.project_profile.overall_score:.0f}/100, "
        f"Findings: {len(result.findings)}"
    )
