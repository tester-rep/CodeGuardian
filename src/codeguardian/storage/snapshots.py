"""Snapshot management — save/load scan results as JSON files."""

from contextlib import suppress
from pathlib import Path


from codeguardian.models.scan import ScanResult

DEFAULT_SNAPSHOT_DIRNAME = ".codeguardian"
DEFAULT_SNAPSHOT_FILENAME = "latest.json"
DEFAULT_SNAPSHOT_DIR = Path(DEFAULT_SNAPSHOT_DIRNAME)
LATEST_SNAPSHOT = DEFAULT_SNAPSHOT_DIR / DEFAULT_SNAPSHOT_FILENAME


def snapshot_dir_for_project(project_path: Path | str) -> Path:
    """Return the snapshot directory for a specific project root."""
    return Path(project_path).resolve() / DEFAULT_SNAPSHOT_DIRNAME


def resolve_snapshot_directory(
    directory: Path | str | None = None,
    project_path: Path | str | None = None,
) -> Path:
    """Resolve the directory that should contain scan snapshots."""
    if directory is not None:
        return Path(directory).resolve()
    if project_path is not None:
        return snapshot_dir_for_project(project_path)
    return DEFAULT_SNAPSHOT_DIR


def latest_snapshot_path(
    directory: Path | str | None = None,
    project_path: Path | str | None = None,
) -> Path:
    """Return the path to the latest snapshot file."""
    return resolve_snapshot_directory(directory=directory, project_path=project_path) / DEFAULT_SNAPSHOT_FILENAME


def save_snapshot(
    result: ScanResult,
    directory: Path | str | None = None,
    project_path: Path | str | None = None,
) -> Path:
    """Persist a scan result as a JSON snapshot file."""
    resolved_directory = resolve_snapshot_directory(
        directory=directory,
        project_path=project_path or result.project_path or None,
    )
    resolved_directory.mkdir(parents=True, exist_ok=True)
    target = resolved_directory / DEFAULT_SNAPSHOT_FILENAME
    payload = result.model_dump_json(indent=2)
    target.write_text(payload, encoding="utf-8")

    if result.scan_id:
        ts_file = resolved_directory / f"snapshot-{result.scan_id}.json"
        ts_file.write_text(payload, encoding="utf-8")

    return target


def load_latest_snapshot(
    directory: Path | str | None = None,
    project_path: Path | str | None = None,
) -> ScanResult | None:
    """Load the most recent scan snapshot."""
    target = latest_snapshot_path(directory=directory, project_path=project_path)
    if not target.exists():
        return None

    with suppress(ValueError, TypeError):
        return ScanResult.model_validate_json(target.read_text(encoding="utf-8"))
    return None



def list_snapshots(
    directory: Path | str | None = None,
    project_path: Path | str | None = None,
) -> list[Path]:
    """List all available snapshot files."""
    resolved_directory = resolve_snapshot_directory(directory=directory, project_path=project_path)
    if not resolved_directory.exists():
        return []
    return sorted(
        resolved_directory.glob("snapshot-*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def delete_snapshot(snapshot_path: Path) -> bool:
    """Remove a specific snapshot file."""
    try:
        snapshot_path.unlink()
        return True
    except OSError:
        return False
