"""Report command: regenerate reports from latest snapshot."""

from pathlib import Path

import typer

from codeguardian.cli.common import (
    resolve_app_config_path,
    resolve_project_path,
    validate_path_exists,
)
from codeguardian.cli.output import console
from codeguardian.config.loader import load_app_config
from codeguardian.core.orchestrator import SUPPORTED_REPORT_FORMATS
from codeguardian.models.scan import ScanResult
from codeguardian.reporters.html_reporter import HtmlReporter
from codeguardian.reporters.json_reporter import JsonReporter
from codeguardian.reporters.terminal import TerminalReporter
from codeguardian.storage.snapshots import load_latest_snapshot


def _resolve_output_dir(snapshot: ScanResult, configured_output_dir: str) -> Path:
    output_dir = Path(configured_output_dir or "reports")
    if output_dir.is_absolute():
        return output_dir

    project_root = Path(snapshot.project_path).resolve() if snapshot.project_path else Path.cwd()
    return project_root / output_dir


def report_command(
    format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help=f"Report format: {', '.join(SUPPORTED_REPORT_FORMATS)}",
    ),
    input_file: str | None = typer.Option(
        None,
        "--input",
        "-i",
        help="Input JSON snapshot path (overrides --project latest snapshot lookup)",
    ),
    project: str | None = typer.Option(
        None,
        "--project",
        "-p",
        help="Project path used to locate .codeguardian/latest.json",
    ),
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file (codeguardian.toml)",
    ),
) -> None:
    """Regenerate a report from an existing scan snapshot."""
    project_path = resolve_project_path(project) if project else None
    if project_path is not None:
        validate_path_exists(project_path)

    snapshot: ScanResult | None
    if input_file:
        snapshot = ScanResult.model_validate_json(Path(input_file).read_text(encoding="utf-8"))
    else:
        snapshot = load_latest_snapshot(project_path=project_path)


    if snapshot is None:
        lookup_scope = str(project_path) if project_path else "current working directory"
        console.print(
            "[red]No snapshot found.[/red] "
            f"Expected `.codeguardian/latest.json` under {lookup_scope}. "
            "Run 'codeguardian scan' first or pass --input."
        )
        raise typer.Exit(code=1)

    normalized_format = format.lower().strip()
    if normalized_format not in SUPPORTED_REPORT_FORMATS:
        console.print(
            f"[red]Unsupported format:[/red] {format}. "
            f"Supported: {', '.join(SUPPORTED_REPORT_FORMATS)}"
        )
        raise typer.Exit(code=1)

    effective_project_path = project_path
    if effective_project_path is None and snapshot.project_path:
        effective_project_path = Path(snapshot.project_path).resolve()

    app_config = load_app_config(resolve_app_config_path(effective_project_path, config))
    output_dir = _resolve_output_dir(snapshot, app_config.reports.output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    reporters: dict[str, type] = {
        "terminal": TerminalReporter,
        "json": JsonReporter,
        "html": HtmlReporter,
    }

    artifact = reporters[normalized_format]().render(snapshot, output_dir)
    if artifact:
        console.print(f"[green]Generated report:[/green] {artifact.path}")
    else:
        console.print(f"[green]Rendered {normalized_format} report[/green]")
