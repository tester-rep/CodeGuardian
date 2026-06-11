"""Path utilities."""

from pathlib import Path


def ensure_dir(path: Path) -> Path:

    """Ensure a directory exists, creating it if necessary."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def relative_to(root: Path, child: Path) -> Path:
    """Get path of child relative to root."""
    try:
        return child.relative_to(root)
    except ValueError:
        return child
