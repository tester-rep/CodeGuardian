"""Profile models — aggregated views for modules and projects."""

from pydantic import BaseModel, Field

from codeguardian.models.finding import Finding
from codeguardian.models.metric import Metric


class DimensionScore(BaseModel):
    """Score for a single analysis dimension."""

    dimension: str
    score: float  # 0–100
    status: str = "good"  # good / warning / critical
    findings_count: int = 0
    metrics: list[Metric] = Field(default_factory=list)
    top_issues: list[str] = Field(default_factory=list)


class ModuleReportIssue(BaseModel):
    """Compact finding summary used in module-level reports."""

    id: str
    title: str
    severity: str
    priority: str
    location: str


class ModuleTestingProfile(BaseModel):
    """Testing-focused view for a module."""

    line_coverage: float | None = None
    branch_coverage: float | None = None
    function_coverage: float | None = None
    changed_line_coverage: float | None = None
    mutation_score: float | None = None
    flaky_tests: int = 0
    status: str = "unavailable"  # good / warning / critical / unavailable


class ModuleStabilityProfile(BaseModel):
    """Evolution and stability view for a module."""

    churn_score: float | None = None
    churn_trend: str = "unknown"  # rising / stable / unknown
    hotspot: bool = False
    recent_large_change: bool = False
    author_count: int | None = None
    knowledge_silo_risk: bool | None = None


class ModuleArchitectureProfile(BaseModel):
    """Architecture-focused view for a module."""

    layering_compliant: bool | None = None
    circular_dependencies: int = 0
    fan_in: float | None = None
    fan_out: float | None = None
    instability: float | None = None
    notes: list[str] = Field(default_factory=list)


class ModuleActionItem(BaseModel):
    """Recommended follow-up action for a module."""

    type: str
    priority: str = "recommended"  # must / recommended / optional
    summary: str


class ModuleProfile(BaseModel):
    """Comprehensive profile of a single module."""

    name: str
    path: str

    # Basic info
    file_count: int = 0
    class_count: int = 0
    function_count: int = 0
    language: str | None = None
    loc: int = 0
    sloc: int = 0

    # Risk assessment
    risk_score: float = 0.0
    risk_level: str = "good"  # good / medium / high / critical
    findings: list[Finding] = Field(default_factory=list)
    top_findings: list[ModuleReportIssue] = Field(default_factory=list)

    # Dimension breakdown
    dimension_scores: dict[str, float] = Field(default_factory=dict)

    # Metrics summary
    avg_complexity: float = 0.0
    duplication_rate: float = 0.0
    test_coverage: float | None = None
    branch_coverage: float | None = None
    function_coverage: float | None = None
    churn_score: float | None = None

    # Specialized report sections
    testing_profile: ModuleTestingProfile = Field(default_factory=ModuleTestingProfile)
    historical_stability: ModuleStabilityProfile = Field(default_factory=ModuleStabilityProfile)
    architecture_profile: ModuleArchitectureProfile = Field(default_factory=ModuleArchitectureProfile)
    action_items: list[ModuleActionItem] = Field(default_factory=list)

    # Recommended action
    recommendation: str = "continue_observing"  # immediate_refactor / plan_refactor / continue_observing / no_action


class ProjectProfile(BaseModel):
    """Top-level project profile — the main output of a scan."""

    project_name: str
    overall_score: float = 100.0
    health_status: str = "good"  # good / warning / critical

    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)

    # Scale metrics
    total_files: int = 0
    total_loc: int = 0
    total_sloc: int = 0
    total_functions: int = 0
    total_classes: int = 0

    # Dimension scores
    dimension_scores: list[DimensionScore] = Field(default_factory=list)

    # Modules
    modules: list[ModuleProfile] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity.value == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity.value == "high")

    @property
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for mod in self.modules:
            findings.extend(mod.findings)
        return findings


class ReleaseConclusion(BaseModel):
    """Release gate conclusion."""

    verdict: str  # recommended / conditional / not_recommended / blocked
    review_summary: str | None = None
    review_source: str = "local"  # local / ai
    blocking_items: list[dict[str, str]] = Field(default_factory=list)
    residual_risks: list[dict[str, str]] = Field(default_factory=list)
    suggested_verifications: list[dict[str, str]] = Field(default_factory=list)
    post_release_monitoring: list[dict[str, str]] = Field(default_factory=list)

