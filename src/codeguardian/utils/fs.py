"""File system utilities."""

from pathlib import Path


def read_text(path: Path) -> str:

    """Read file content as UTF-8 text."""
    return path.read_text(encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    """Read file content as lines (stripped)."""
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
