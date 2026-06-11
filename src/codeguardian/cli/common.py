"""Common utilities for CLI commands."""

import re
import subprocess
import tempfile
from pathlib import Path

CONFIG_FILENAMES = ("codeguardian.toml", ".codeguardian.toml")

_GIT_URL_RE = re.compile(
    r"^(?:https?://|git@|ssh://|git://)"  # Protocol prefix
    r"|\.git$"  # Ends with .git
)


def is_git_url(path: str) -> bool:
    """Check if a string looks like a git repository URL."""
    return bool(_GIT_URL_RE.search(path))


def clone_repo(url: str, branch: str | None = None, depth: int | None = None) -> Path:
    """Clone a git repository to a temporary directory.

    Returns the path to the cloned repository.
    The caller is responsible for cleanup (or use as context manager).
    """
    from codeguardian.cli.output import console

    tmpdir = Path(tempfile.mkdtemp(prefix="codeguardian-clone-"))
    cmd = ["git", "clone"]
    if depth:
        cmd.extend(["--depth", str(depth)])
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, str(tmpdir / "repo")])

    console.print(f"[dim]Cloning {url}...[/dim]")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        from typer import BadParameter
        raise BadParameter(f"Git clone failed: {result.stderr.strip()}")

    cloned_path = tmpdir / "repo"
    console.print(f"[dim]Cloned to {cloned_path}[/dim]")
    return cloned_path


def resolve_project_path(path: str | None) -> Path:
    """Resolve the project path from a string argument, defaulting to current directory."""
    return Path(path or ".").resolve()


def resolve_app_config_path(project_path: Path | None = None, config_path: str | None = None) -> str | None:
    """Resolve the most appropriate app config path for a command invocation.

    Search order:
    1. Explicit ``--config`` path (highest priority)
    2. Target project directory (``codeguardian.toml`` / ``.codeguardian.toml``)
    3. Current working directory (fallback — covers the case where the user
       runs CodeGuardian from its own repo but scans an external project)
    """
    if config_path:
        return str(Path(config_path).resolve())

    # Search in target project directory
    if project_path is not None:
        for filename in CONFIG_FILENAMES:
            candidate = project_path / filename
            if candidate.exists():
                return str(candidate)

    # Fallback: search in current working directory
    cwd = Path.cwd()
    if project_path is None or cwd.resolve() != project_path.resolve():
        for filename in CONFIG_FILENAMES:
            candidate = cwd / filename
            if candidate.exists():
                return str(candidate)

    return None


def validate_path_exists(path: Path) -> None:
    """Raise an error if the path does not exist."""
    if not path.exists():
        from typer import BadParameter

        raise BadParameter(f"Path does not exist: {path}")

