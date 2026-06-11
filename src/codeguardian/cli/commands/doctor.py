"""Doctor command: check environment and dependencies."""

import importlib
import platform
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path

import typer

from codeguardian.cli.output import console


def _resolve_package_version(distribution_name: str, module: object) -> str:
    """Resolve an installed package version robustly across libraries."""
    try:
        return importlib_metadata.version(distribution_name)
    except importlib_metadata.PackageNotFoundError:
        return getattr(module, "__version__", "installed")


def doctor_command() -> None:
    """Check that the CodeGuardian environment is properly configured."""

    checks_passed = 0
    checks_failed = 0

    def _ok(msg: str) -> None:
        nonlocal checks_passed
        checks_passed += 1
        console.print(f"  [green][OK][/green] {msg}")

    def _fail(msg: str, detail: str = "") -> None:
        nonlocal checks_failed
        checks_failed += 1
        console.print(f"  [red][FAIL][/red] {msg}{f' — {detail}' if detail else ''}")

    def _check_package(
        import_name: str,
        display_name: str,
        install_hint: str,
        distribution_name: str | None = None,
    ) -> None:
        try:
            module = importlib.import_module(import_name)
        except ImportError:
            _fail(f"{display_name} not installed", install_hint)
            return

        version = _resolve_package_version(distribution_name or import_name, module)
        _ok(f"{display_name} {version}")

    console.print("[bold]CodeGuardian Environment Check[/bold]\n")

    # Python version
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 11):
        _ok(f"Python {major}.{minor}")
    else:
        _fail(f"Python {major}.{minor}", "requires 3.11+")

    # Platform
    _ok(f"Platform: {platform.system()} ({platform.machine()})")

    # Package imports
    _check_package("typer", "typer", "pip install typer")
    _check_package("rich", "rich", "pip install rich")
    _check_package("pydantic", "pydantic", "pip install pydantic")
    _check_package("tree_sitter", "tree-sitter", "pip install tree-sitter", "tree-sitter")
    _check_package("yaml", "PyYAML", "pip install PyYAML", "PyYAML")

    # Config file
    config_candidates = [Path("codeguardian.toml"), Path(".codeguardian.toml")]
    config_file = next((candidate for candidate in config_candidates if candidate.exists()), None)
    if config_file is not None:
        _ok(f"Config file exists: {config_file}")
    else:
        console.print(
            "  [yellow][WARN][/yellow] No codeguardian.toml or .codeguardian.toml "
            "(run `codeguardian init`)"
        )


    # Summary
    console.print(f"\n[bold]Result:[/bold] {checks_passed} passed, {checks_failed} failed")
    if checks_failed > 0:
        raise typer.Exit(code=1)
