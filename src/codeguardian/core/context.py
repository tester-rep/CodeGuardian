"""ScanContext — shared state passed through the entire scan lifecycle."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from codeguardian.config.schema import AppConfig


class ScanContext(BaseModel):
    """Global context for a single scan execution.

    Carries all shared state across phases, avoiding repeated detection
    and redundant loading.
    """

    # Project identification
    scan_id: str = ""
    project_root: str

    # Configuration
    config: AppConfig

    # Detection results (populated in Detection phase)
    detected_languages: list[str] = Field(default_factory=list)
    detected_frameworks: list[str] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    test_frameworks: list[str] = Field(default_factory=list)
    is_git_repo: bool = False
    repo_type: str = "single"  # single / monorepo

    # Execution control
    review_mode: str = "standard"  # ai_off / standard / ultra
    dimensions: list[str] | None = None
    languages: list[str] | None = None
    incremental: bool = False
    since: str | None = None

    # AI deep review cache control
    no_cache: bool = False

    # Internal state (set during execution)
    target_files: list[str] = Field(default_factory=list)
    changed_files: list[str] = Field(default_factory=list)
    changed_lines: dict[str, list[int]] = Field(default_factory=dict)
    cache_refs: dict[str, object] = Field(default_factory=dict)


    @property
    def project_name(self) -> str:
        p = Path(self.project_root)
        name = p.name
        # Handle "." / ".." / "" cases (e.g., project_root=".")
        if not name or name in {".", ".."}:
            return p.resolve().name
        return name

    @property
    def ai_enabled(self) -> bool:
        return self.review_mode != "ai_off"

    def collect_candidate_files(
        self,
        root: Path,
        suffixes: set[str] | None = None,
        ignore_incremental_scope: bool = False,
    ) -> list[Path]:
        """Collect candidate files, honoring incremental target scopes when present.

        Set ``ignore_incremental_scope=True`` to force a full-project scan even in
        incremental mode. Used by the PCI builder so the call graph stays complete
        (cross-function analysis would otherwise run on a truncated graph).
        """
        from codeguardian.utils.ignore import should_ignore

        candidates: list[Path]
        if self.target_files and not ignore_incremental_scope:
            candidates = [(root / rel_path).resolve() for rel_path in self.target_files]
        else:
            candidates = [path for path in root.rglob("*")]

        result: list[Path] = []
        seen: set[Path] = set()
        for path in candidates:
            if path in seen:
                continue
            seen.add(path)
            if should_ignore(path) or not path.is_file():
                continue
            if suffixes and path.suffix.lower() not in suffixes:
                continue
            result.append(path)
        return result


ScanContext.model_rebuild()


