"""Gate command: quality gate check with exit codes."""

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
from codeguardian.models.scan import ScanRequest
from codeguardian.risk.release_gate import ReleaseGate


def _resolve_gate_config_path(project_path: Path, config: str | None, default_config: str) -> Path:
    candidate = Path(config or default_config)
    if candidate.is_absolute():
        return candidate
    return project_path / candidate


def _print_gate_scope_summary(facts: dict[str, float | bool]) -> None:
    production_findings = int(facts.get("scope.production_findings", 0) or 0)
    test_findings = int(facts.get("scope.test_findings", 0) or 0)
    production_blocking = int(facts.get("scope.production_blocking", 0) or 0)
    test_blocking = int(facts.get("scope.test_blocking", 0) or 0)

    console.print("[dim]Gate scan depth: quick[/dim]")
    console.print(
        "[dim]Gate scope: production-only for score/blocking; tests are reported separately[/dim]"
    )
    console.print(
        f"[dim]Findings -> production: {production_findings}, tests: {test_findings} | "
        f"blocking -> production: {production_blocking}, tests: {test_blocking}[/dim]"
    )



def gate_command(

    path: str = typer.Argument(".", help="Project path"),
    config: str | None = typer.Option(None, "--config", "-c", help="Gate config file (gate.yaml)"),
) -> None:
    """Evaluate whether the project passes quality gates.

    Returns exit code 0 for pass, 1 for failure.
    """
    project_path = resolve_project_path(path)
    validate_path_exists(project_path)

    app_config = load_app_config(resolve_app_config_path(project_path))

    orchestrator = Orchestrator(app_config)

    result = asyncio.run(
        orchestrator.run_scan(
            ScanRequest(
                project_path=project_path,
                report_formats=["json"],
                review_mode="ai_off",
            )
        )
    )

    gate = ReleaseGate(threshold=app_config.risk.default_threshold)

    gate_config_path = _resolve_gate_config_path(project_path, config, app_config.gate.config_path)
    if gate_config_path.exists():
        gate.load_rules(gate_config_path)

    evaluation = gate.evaluate(result)

    if not evaluation.passed:
        console.print("\n[red]Quality Gate FAILED[/red]\n")
        _print_gate_scope_summary(evaluation.facts)
        for reason in evaluation.reasons:
            console.print(f"  [red]X[/red] {reason}")
        for warning in evaluation.warnings:
            console.print(f"  [yellow]![/yellow] {warning}")
        raise typer.Exit(code=1)

    console.print("\n[green]Quality Gate PASSED[/green]")
    _print_gate_scope_summary(evaluation.facts)
    for warning in evaluation.warnings:
        console.print(f"  [yellow]![/yellow] {warning}")


