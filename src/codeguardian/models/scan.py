"""Scan model — request/response objects for scan operations."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from codeguardian.models.entity import ClassEntity, FileEntity, FunctionEntity, ModuleEntity
from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric
from codeguardian.models.profile import ProjectProfile, ReleaseConclusion
from codeguardian.models.report import ReportArtifact


class ScanRequest(BaseModel):
    """Input parameters for a scan operation."""

    project_path: Path
    report_formats: list[str] = Field(default_factory=lambda: ["terminal"])
    depth: str = "standard"
    dimensions: list[str] | None = None  # null = all
    languages: list[str] | None = None  # null = auto-detect
    incremental: bool = False
    since: str | None = None  # For git-based incremental scans
    verify_mode: str = "off"  # off / generate / syntax / safe (full planned)
    no_cache: bool = False  # Bypass deep_review + ai_verify cache (force re-run AI)
    drop_false_positives: bool = False  # If True, AI-verified FPs are dropped instead of downgraded to info





class EngineResult(BaseModel):
    """Output from a single analysis engine."""

    engine_name: str
    duration_ms: float = 0.0

    # Entities discovered
    files: list[FileEntity] = Field(default_factory=list)
    functions: list[FunctionEntity] = Field(default_factory=list)
    classes: list[ClassEntity] = Field(default_factory=list)
    modules: list[ModuleEntity] = Field(default_factory=list)

    # Findings and measurements
    findings: list[Finding] = Field(default_factory=list)
    metrics: list[Metric] = Field(default_factory=list)

    # Status
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete result of a scan operation — the unified output of the orchestrator."""

    schema_version: str = "1.0"

    # Metadata
    scan_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    project_path: str = ""
    execution_mode: str = "standard"
    depth: str = "standard"

    # Main results
    project_profile: ProjectProfile
    findings: list[Finding] = Field(default_factory=list)
    supplementary_findings: list[Finding] = Field(default_factory=list)
    metrics: list[Metric] = Field(default_factory=list)

    # Engine execution diagnostics
    engine_warnings: list[str] = Field(default_factory=list)
    engine_errors: list[str] = Field(default_factory=list)

    # Output artifacts (reports generated)

    report_artifacts: list[ReportArtifact] = Field(default_factory=list)

    # Optional AI-enhanced conclusions
    release_conclusion: ReleaseConclusion | None = None
    ai_summary: str | None = None

    # AI token usage statistics (populated when AI is enabled)
    ai_token_usage: dict | None = None

    # Issue clustering and tech debt (populated post-analysis)
    systemic_issues: list[dict] = Field(default_factory=list)
    tech_debt_estimate: dict | None = None

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity.value == "critical" for f in self.findings)

    @property
    def has_blocking_findings(self) -> bool:
        return any(f.blocks_release for f in self.findings)

    def model_post_init(self, __context: object) -> None:
        now = datetime.now(UTC)
        if not self.scan_id:
            self.scan_id = f"{now.strftime('%Y%m%d%H%M%S')}"
        if not self.started_at:
            self.started_at = now.isoformat()
        if not self.finished_at:
            self.finished_at = now.isoformat()



class DiffRequest(BaseModel):
    """Input for diff comparison between two states."""

    base_path: Path | str  # Branch name or baseline file path
    target_path: Path | str  # Branch name or HEAD
    project_root: Path


class DiffResult(BaseModel):
    """Result of a diff comparison."""

    comparison_mode: str = "snapshot"  # snapshot / git
    base_label: str | None = None
    target_label: str | None = None
    merge_base: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    touched_hotspots: list[str] = Field(default_factory=list)
    base_score: float = 0.0
    target_score: float = 0.0
    score_delta: float = 0.0
    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)
    regression_metrics: list[Metric] = Field(default_factory=list)

