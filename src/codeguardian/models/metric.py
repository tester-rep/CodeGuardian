"""Metric model — quantitative measurements for entities."""

from pydantic import BaseModel, Field


class Metric(BaseModel):
    """A single metric value associated with an entity."""

    target_id: str  # ID of the target entity (file path, function name, etc.)
    target_type: str  # "file" / "function" / "module" / "project"
    metric_name: str  # e.g., "cyclomatic_complexity", "line_coverage"
    value: float
    unit: str | None = None  # e.g., "%", "files", "score"
    source_engine: str  # Which engine produced this metric
    dimension: str | None = None  # Which dimension this belongs to
    extra: dict[str, object] = Field(default_factory=dict)  # Additional metadata



# Well-known metric names
class MetricNames:
    FILE_COUNT = "file_count"
    LOC = "loc"
    SLOC = "sloc"
    COMMENT_RATIO = "comment_ratio"
    CYCLOMATIC_COMPLEXITY = "cyclomatic_complexity"
    COGNITIVE_COMPLEXITY = "cognitive_complexity"
    NESTING_DEPTH = "nesting_depth"
    PARAM_COUNT = "param_count"
    DUPLICATION_RATE = "duplication_rate"
    LINE_COVERAGE = "line_coverage"
    BRANCH_COVERAGE = "branch_coverage"
    FUNCTION_COVERAGE = "function_coverage"
    CHANGE_LINE_COVERAGE = "change_line_coverage"
    CHURN_SCORE = "churn_score"
    RISK_SCORE = "risk_score"
    CORE_MODULE_SCORE = "core_module_score"
    MAINTAINABILITY_INDEX = "maintainability_index"


