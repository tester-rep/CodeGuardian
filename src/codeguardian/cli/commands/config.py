"""Config command: view and modify codeguardian.toml settings."""

from pathlib import Path

import typer

from codeguardian.cli.output import console


def config_command(
    action: str = typer.Argument(..., help="Action: show / get / set"),
    key: str = typer.Argument(None, help="Config key (dot-notation, e.g. ai.provider)"),
    value: str = typer.Argument(None, help="Value to set"),
    config_path: str = typer.Option(None, "--config", "-c", help="Path to codeguardian.toml"),
) -> None:
    """View or modify codeguardian.toml configuration."""
    target = Path(config_path) if config_path else _find_config()

    if action == "show":
        _show_config(target)
    elif action == "get":
        if not key:
            console.print("[red]Usage: codeguardian config get <key>[/red]")
            raise typer.Exit(code=1)
        _get_config(target, key)
    elif action == "set":
        if not key or value is None:
            console.print("[red]Usage: codeguardian config set <key> <value>[/red]")
            raise typer.Exit(code=1)
        _set_config(target, key, value)
    else:
        console.print(f"[red]Unknown action: {action}. Use show/get/set.[/red]")
        raise typer.Exit(code=1)


def _find_config() -> Path:
    """Find codeguardian.toml in CWD or parent."""
    for candidate in [Path("codeguardian.toml"), Path(".codeguardian.toml")]:
        if candidate.exists():
            return candidate
    return Path("codeguardian.toml")


def _show_config(path: Path) -> None:
    """Display entire config file."""
    if not path.exists():
        console.print(f"[yellow]No config file found at {path}[/yellow]")
        console.print("[dim]Run 'codeguardian init' to create one.[/dim]")
        return

    content = path.read_text(encoding="utf-8")
    console.print(f"[bold cyan]Config:[/bold cyan] {path.resolve()}\n")
    console.print(content)


def _get_config(path: Path, key: str) -> None:
    """Get a specific config value by dot-notation key."""
    if not path.exists():
        console.print(f"[red]Config file not found: {path}[/red]")
        raise typer.Exit(code=1)

    import tomllib
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    # Navigate dot-notation
    parts = key.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            console.print(f"[red]Key not found: {key}[/red]")
            raise typer.Exit(code=1)

    console.print(f"[cyan]{key}[/cyan] = {current}")


def _set_config(path: Path, key: str, value: str) -> None:
    """Set a config value. Creates file if needed."""
    # Read existing or start fresh
    if path.exists():
        content = path.read_text(encoding="utf-8")
    else:
        content = ""

    # Parse value type
    parsed_value = _parse_value(value)

    # Simple TOML update: find the key and replace, or append
    parts = key.split(".")
    if len(parts) == 2:
        section, field = parts
        content = _update_toml_field(content, section, field, value)
    elif len(parts) == 1:
        # Top-level key
        content = _update_toml_field(content, None, parts[0], value)
    else:
        console.print("[red]Only 1-2 level keys supported (e.g. 'ai.provider')[/red]")
        raise typer.Exit(code=1)

    path.write_text(content, encoding="utf-8")
    console.print(f"[green]✓[/green] Set [cyan]{key}[/cyan] = {value} in {path}")


def _parse_value(value: str) -> object:
    """Attempt to parse string value into appropriate Python type."""
    if value.lower() in {"true", "yes"}:
        return True
    if value.lower() in {"false", "no"}:
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _update_toml_field(content: str, section: str | None, field: str, value: str) -> str:
    """Update or insert a field in TOML content."""
    import re

    # Format value for TOML
    parsed = _parse_value(value)
    if isinstance(parsed, bool):
        toml_value = "true" if parsed else "false"
    elif isinstance(parsed, (int, float)):
        toml_value = str(parsed)
    else:
        toml_value = f'"{value}"'

    lines = content.splitlines(keepends=True)

    if section is None:
        # Top-level field
        pattern = re.compile(rf"^{re.escape(field)}\s*=")
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = f"{field} = {toml_value}\n"
                return "".join(lines)
        # Append at top
        lines.insert(0, f"{field} = {toml_value}\n")
        return "".join(lines)

    # Find section header
    section_header = re.compile(rf"^\[{re.escape(section)}\]")
    section_idx = None
    for i, line in enumerate(lines):
        if section_header.match(line.strip()):
            section_idx = i
            break

    if section_idx is not None:
        # Find field within section
        field_pattern = re.compile(rf"^{re.escape(field)}\s*=")
        next_section = re.compile(r"^\[")
        for i in range(section_idx + 1, len(lines)):
            if next_section.match(lines[i].strip()):
                break
            if field_pattern.match(lines[i].strip()):
                lines[i] = f"{field} = {toml_value}\n"
                return "".join(lines)
        # Insert after section header
        lines.insert(section_idx + 1, f"{field} = {toml_value}\n")
    else:
        # Add new section at end
        lines.append(f"\n[{section}]\n{field} = {toml_value}\n")

    return "".join(lines)
